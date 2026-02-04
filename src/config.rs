//! Configuration loading for Jawn Vault
//!
//! Configuration is loaded from TOML files, with defaults that work
//! out of the box for the houseofjawn setup.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

use crate::VaultError;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,
    /// Cache configuration
    pub cache: CacheConfig,
    /// Pass backend configuration
    pub pass: PassConfig,
    /// Audit logging configuration
    pub audit: AuditConfig,
    /// Token rotation configuration
    pub rotation: RotationConfig,
    /// Alerting configuration
    pub alerting: AlertingConfig,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Path to Unix socket
    pub socket_path: PathBuf,
    /// Socket file permissions (octal)
    pub socket_mode: u32,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Enable caching
    pub enabled: bool,
    /// Default TTL for cache entries in seconds
    pub default_ttl_secs: u64,
    /// Maximum TTL for cache entries in seconds
    pub max_ttl_secs: u64,
    /// Maximum number of entries in cache
    pub max_entries: usize,
}

/// Pass backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PassConfig {
    /// Path to pass binary
    pub binary: PathBuf,
    /// Path to password store
    pub store_path: PathBuf,
    /// Timeout for pass commands in seconds
    pub timeout_secs: u64,
}

/// Audit logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,
    /// Path to SQLite database
    pub db_path: PathBuf,
    /// Retention period in days (0 = forever)
    pub retention_days: u32,
}

/// Token rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RotationConfig {
    /// Enable automatic token rotation
    pub enabled: bool,
    /// Rotation providers
    #[serde(default)]
    pub providers: Vec<RotationProvider>,
}

/// A token rotation provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationProvider {
    /// Provider name (e.g., "slack", "google")
    pub name: String,
    /// Provider type
    pub provider_type: ProviderType,
    /// Paths this provider manages
    pub paths: Vec<String>,
    /// Rotation schedule (cron expression or interval)
    pub schedule: String,
    /// Provider-specific configuration
    #[serde(default)]
    pub config: toml::Table,
}

/// Provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    /// Slack OAuth token refresh
    SlackOauth,
    /// Google OAuth token refresh
    GoogleOauth,
    /// Generic HTTP refresh (POST to URL with refresh token)
    HttpRefresh,
}

/// Alerting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertingConfig {
    /// Enable alerting
    pub enabled: bool,
    /// Telegram bot token (from pass or direct)
    pub telegram_token_path: Option<String>,
    /// Telegram chat ID for alerts
    pub telegram_chat_id: Option<i64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            cache: CacheConfig::default(),
            pass: PassConfig::default(),
            audit: AuditConfig::default(),
            rotation: RotationConfig::default(),
            alerting: AlertingConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        // Use XDG_RUNTIME_DIR if available, otherwise /tmp
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"));

        Self {
            socket_path: runtime_dir.join("jawn-vault.sock"),
            socket_mode: 0o600,
            max_connections: 100,
            request_timeout_secs: 30,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_ttl_secs: 300, // 5 minutes
            max_ttl_secs: 3600,    // 1 hour
            max_entries: 1000,
        }
    }
}

impl Default for PassConfig {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("pass"),
            store_path: dirs::home_dir()
                .map(|h| h.join(".password-store"))
                .unwrap_or_else(|| PathBuf::from("/home/jamditis/.password-store")),
            timeout_secs: 10,
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            db_path: dirs::data_local_dir()
                .map(|d| d.join("jawn-vault").join("audit.db"))
                .unwrap_or_else(|| {
                    PathBuf::from("/home/jamditis/.local/share/jawn-vault/audit.db")
                }),
            retention_days: 90,
        }
    }
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            providers: Vec::new(),
        }
    }
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            telegram_token_path: Some("claude/tokens/telegram-bot".to_string()),
            telegram_chat_id: None,
        }
    }
}

impl Config {
    /// Load configuration from file, falling back to defaults
    pub fn load(path: Option<&PathBuf>) -> Result<Self, VaultError> {
        let config_path = path.cloned().unwrap_or_else(|| {
            dirs::config_dir()
                .map(|d| d.join("jawn-vault").join("config.toml"))
                .unwrap_or_else(|| {
                    PathBuf::from("/home/jamditis/.config/jawn-vault/config.toml")
                })
        });

        if config_path.exists() {
            let contents = std::fs::read_to_string(&config_path)
                .map_err(|e| VaultError::Config(format!("failed to read config: {e}")))?;
            let config: Config = toml::from_str(&contents)
                .map_err(|e| VaultError::Config(format!("failed to parse config: {e}")))?;
            Ok(config)
        } else {
            tracing::info!("no config file found at {}, using defaults", config_path.display());
            Ok(Config::default())
        }
    }

    /// Get the socket path
    pub fn socket_path(&self) -> &PathBuf {
        &self.server.socket_path
    }

    /// Get cache TTL as Duration
    pub fn cache_ttl(&self) -> Duration {
        Duration::from_secs(self.cache.default_ttl_secs)
    }

    /// Get request timeout as Duration
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.server.request_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.cache.enabled);
        assert_eq!(config.cache.default_ttl_secs, 300);
        assert!(config.server.socket_path.to_string_lossy().contains("jawn-vault.sock"));
    }

    #[test]
    fn test_config_parsing() {
        let toml = r#"
[server]
socket_path = "/tmp/test.sock"
socket_mode = 384

[cache]
enabled = false
default_ttl_secs = 60

[pass]
binary = "/usr/bin/pass"

[audit]
enabled = true
retention_days = 30
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.server.socket_path, PathBuf::from("/tmp/test.sock"));
        assert_eq!(config.server.socket_mode, 384); // 0o600 in decimal
        assert!(!config.cache.enabled);
        assert_eq!(config.cache.default_ttl_secs, 60);
        assert_eq!(config.audit.retention_days, 30);
    }
}
