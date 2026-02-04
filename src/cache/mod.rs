//! In-memory credential cache with TTL and secure memory handling
//!
//! This module provides a thread-safe cache for credentials that:
//! - Stores secrets using `secrecy::SecretString` (prevents accidental logging)
//! - Zeroes memory on drop via `zeroize`
//! - Supports per-entry TTL with automatic expiration
//! - Tracks hit/miss statistics for monitoring

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};

/// A cached credential entry
struct CacheEntry {
    /// The secret value (wrapped for safety)
    value: SecretString,
    /// When this entry was created
    created_at: Instant,
    /// When this entry expires
    expires_at: Instant,
    /// UTC timestamp for external reporting
    expires_at_utc: DateTime<Utc>,
}

impl CacheEntry {
    fn new(value: String, ttl: Duration) -> Self {
        let now = Instant::now();
        let expires_at = now + ttl;
        let expires_at_utc = Utc::now() + chrono::Duration::from_std(ttl).unwrap_or_default();

        Self {
            value: SecretString::from(value),
            created_at: now,
            expires_at,
            expires_at_utc,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    fn get_value(&self) -> String {
        self.value.expose_secret().to_string()
    }
}

// Ensure the value is zeroed when the entry is dropped
impl Drop for CacheEntry {
    fn drop(&mut self) {
        // SecretString handles its own zeroization, but we explicitly note
        // that this is intentional for security
        tracing::trace!("cache entry dropped, memory zeroed");
    }
}

/// Thread-safe credential cache with TTL support
pub struct Cache {
    /// The actual cache storage
    entries: RwLock<HashMap<String, CacheEntry>>,
    /// Default TTL for entries
    default_ttl: Duration,
    /// Maximum TTL allowed
    max_ttl: Duration,
    /// Maximum number of entries
    max_entries: usize,
    /// Cache hit counter
    hits: AtomicU64,
    /// Cache miss counter
    misses: AtomicU64,
}

/// Result of a cache lookup
pub struct CacheResult {
    /// The credential value
    pub value: String,
    /// When this entry expires (for reporting to clients)
    pub expires_at: DateTime<Utc>,
}

impl Cache {
    /// Create a new cache with the given configuration
    pub fn new(default_ttl: Duration, max_ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            default_ttl,
            max_ttl,
            max_entries,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Get a value from the cache
    pub fn get(&self, path: &str) -> Option<CacheResult> {
        let entries = self.entries.read().unwrap();

        if let Some(entry) = entries.get(path) {
            if entry.is_expired() {
                drop(entries); // Release read lock before write
                self.remove(path);
                self.misses.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(path = path, "cache miss (expired)");
                None
            } else {
                self.hits.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(path = path, "cache hit");
                Some(CacheResult {
                    value: entry.get_value(),
                    expires_at: entry.expires_at_utc,
                })
            }
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(path = path, "cache miss");
            None
        }
    }

    /// Insert a value into the cache with optional custom TTL
    pub fn insert(&self, path: &str, value: String, ttl: Option<Duration>) {
        let ttl = ttl
            .map(|t| t.min(self.max_ttl)) // Cap at max_ttl
            .unwrap_or(self.default_ttl);

        let entry = CacheEntry::new(value, ttl);

        let mut entries = self.entries.write().unwrap();

        // If at capacity, evict expired entries first
        if entries.len() >= self.max_entries && !entries.contains_key(path) {
            self.evict_expired_locked(&mut entries);

            // If still at capacity, evict oldest entry
            if entries.len() >= self.max_entries {
                self.evict_oldest_locked(&mut entries);
            }
        }

        entries.insert(path.to_string(), entry);
        tracing::debug!(path = path, ttl_secs = ttl.as_secs(), "cached credential");
    }

    /// Remove a value from the cache
    pub fn remove(&self, path: &str) {
        let mut entries = self.entries.write().unwrap();
        if entries.remove(path).is_some() {
            tracing::debug!(path = path, "removed from cache");
        }
    }

    /// Invalidate all entries matching a prefix
    pub fn invalidate_prefix(&self, prefix: &str) {
        let mut entries = self.entries.write().unwrap();
        let keys_to_remove: Vec<String> = entries
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();

        for key in &keys_to_remove {
            entries.remove(key);
        }

        if !keys_to_remove.is_empty() {
            tracing::debug!(
                prefix = prefix,
                count = keys_to_remove.len(),
                "invalidated cache entries"
            );
        }
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        let mut entries = self.entries.write().unwrap();
        let count = entries.len();
        entries.clear();
        tracing::info!(count = count, "cache cleared");
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let entries = self.entries.read().unwrap();
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        CacheStats {
            entries: entries.len(),
            hits,
            misses,
            hit_ratio: if total > 0 {
                hits as f64 / total as f64
            } else {
                0.0
            },
        }
    }

    /// Run periodic cleanup of expired entries
    pub fn cleanup_expired(&self) {
        let mut entries = self.entries.write().unwrap();
        self.evict_expired_locked(&mut entries);
    }

    /// Evict expired entries (must hold write lock)
    fn evict_expired_locked(&self, entries: &mut HashMap<String, CacheEntry>) {
        let before = entries.len();
        entries.retain(|_, entry| !entry.is_expired());
        let evicted = before - entries.len();
        if evicted > 0 {
            tracing::debug!(count = evicted, "evicted expired cache entries");
        }
    }

    /// Evict the oldest entry (must hold write lock)
    fn evict_oldest_locked(&self, entries: &mut HashMap<String, CacheEntry>) {
        if let Some(oldest_key) = entries
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(k, _)| k.clone())
        {
            entries.remove(&oldest_key);
            tracing::debug!(path = %oldest_key, "evicted oldest cache entry");
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of entries currently in cache
    pub entries: usize,
    /// Total cache hits since startup
    pub hits: u64,
    /// Total cache misses since startup
    pub misses: u64,
    /// Hit ratio (0.0 - 1.0)
    pub hit_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_basic_cache_operations() {
        let cache = Cache::new(
            Duration::from_secs(60),
            Duration::from_secs(3600),
            100,
        );

        // Insert and get
        cache.insert("test/path", "secret_value".to_string(), None);
        let result = cache.get("test/path");
        assert!(result.is_some());
        assert_eq!(result.unwrap().value, "secret_value");

        // Miss
        assert!(cache.get("nonexistent").is_none());

        // Remove
        cache.remove("test/path");
        assert!(cache.get("test/path").is_none());
    }

    #[test]
    fn test_ttl_expiration() {
        let cache = Cache::new(
            Duration::from_millis(50), // Very short TTL
            Duration::from_secs(3600),
            100,
        );

        cache.insert("test/expiring", "value".to_string(), None);
        assert!(cache.get("test/expiring").is_some());

        // Wait for expiration
        sleep(Duration::from_millis(100));

        // Should be expired now
        assert!(cache.get("test/expiring").is_none());
    }

    #[test]
    fn test_custom_ttl() {
        let cache = Cache::new(
            Duration::from_secs(60),
            Duration::from_millis(100), // Max TTL
            100,
        );

        // Custom TTL longer than max should be capped
        cache.insert(
            "test/capped",
            "value".to_string(),
            Some(Duration::from_secs(3600)),
        );

        // Wait past max TTL
        sleep(Duration::from_millis(150));

        // Should be expired because TTL was capped
        assert!(cache.get("test/capped").is_none());
    }

    #[test]
    fn test_stats() {
        let cache = Cache::new(
            Duration::from_secs(60),
            Duration::from_secs(3600),
            100,
        );

        cache.insert("test/a", "value".to_string(), None);

        // Generate hits and misses
        cache.get("test/a"); // hit
        cache.get("test/a"); // hit
        cache.get("test/b"); // miss

        let stats = cache.stats();
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_ratio - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_prefix_invalidation() {
        let cache = Cache::new(
            Duration::from_secs(60),
            Duration::from_secs(3600),
            100,
        );

        cache.insert("claude/api/a", "v1".to_string(), None);
        cache.insert("claude/api/b", "v2".to_string(), None);
        cache.insert("other/path", "v3".to_string(), None);

        cache.invalidate_prefix("claude/");

        assert!(cache.get("claude/api/a").is_none());
        assert!(cache.get("claude/api/b").is_none());
        assert!(cache.get("other/path").is_some());
    }

    #[test]
    fn test_max_entries_eviction() {
        let cache = Cache::new(
            Duration::from_secs(60),
            Duration::from_secs(3600),
            2, // Only 2 entries allowed
        );

        cache.insert("test/a", "v1".to_string(), None);
        sleep(Duration::from_millis(10)); // Ensure different timestamps
        cache.insert("test/b", "v2".to_string(), None);
        sleep(Duration::from_millis(10));
        cache.insert("test/c", "v3".to_string(), None);

        let stats = cache.stats();
        assert_eq!(stats.entries, 2);

        // Oldest entry (test/a) should have been evicted
        assert!(cache.get("test/a").is_none());
        assert!(cache.get("test/b").is_some());
        assert!(cache.get("test/c").is_some());
    }
}
