//! Audit logging for Jawn Vault
//!
//! All credential access is logged to SQLite for security auditing.
//! Logs include timestamp, client identity, path accessed, and success/failure.

use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use thiserror::Error;

/// Audit logging errors
#[derive(Error, Debug)]
pub enum AuditError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// A single audit log entry
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// When the access occurred
    pub timestamp: DateTime<Utc>,
    /// Client ID (if authenticated)
    pub client_id: Option<String>,
    /// Client name (if authenticated)
    pub client_name: Option<String>,
    /// Peer process ID (from SO_PEERCRED)
    pub peer_pid: Option<i32>,
    /// Peer user ID (from SO_PEERCRED)
    pub peer_uid: Option<u32>,
    /// Method invoked (get, set, list, etc.)
    pub method: String,
    /// Path accessed (if applicable)
    pub path: Option<String>,
    /// Whether the operation succeeded
    pub success: bool,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Audit log backed by SQLite
pub struct AuditLog {
    /// Database connection
    db: Mutex<Connection>,
    /// Retention period in days (0 = forever)
    retention_days: u32,
}

impl AuditLog {
    /// Create a new audit log with the given database path
    pub fn new(db_path: &Path, retention_days: u32) -> Result<Self, AuditError> {
        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(db_path)?;

        // Enable WAL mode for better concurrent performance
        conn.execute_batch("PRAGMA journal_mode=WAL")?;

        // Create table if it doesn't exist
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_id TEXT,
                client_name TEXT,
                peer_pid INTEGER,
                peer_uid INTEGER,
                method TEXT NOT NULL,
                path TEXT,
                success INTEGER NOT NULL,
                error TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_access_log_timestamp ON access_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_access_log_client ON access_log(client_id);
            CREATE INDEX IF NOT EXISTS idx_access_log_path ON access_log(path);
            "#,
        )?;

        let log = Self {
            db: Mutex::new(conn),
            retention_days,
        };

        // Run initial cleanup
        log.cleanup_old_entries()?;

        Ok(log)
    }

    /// Log an access entry
    pub async fn log(&self, entry: AuditEntry) -> Result<(), AuditError> {
        let db = self.db.lock().unwrap();

        db.execute(
            r#"
            INSERT INTO access_log (
                timestamp, client_id, client_name, peer_pid, peer_uid,
                method, path, success, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                entry.timestamp.to_rfc3339(),
                entry.client_id,
                entry.client_name,
                entry.peer_pid,
                entry.peer_uid,
                entry.method,
                entry.path,
                entry.success as i32,
                entry.error,
            ],
        )?;

        // Log at different levels based on success
        if entry.success {
            tracing::debug!(
                client = entry.client_id,
                method = entry.method,
                path = entry.path,
                "access granted"
            );
        } else {
            tracing::warn!(
                client = entry.client_id,
                method = entry.method,
                path = entry.path,
                error = entry.error,
                "access denied"
            );
        }

        Ok(())
    }

    /// Query recent access logs
    pub fn query_recent(&self, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        let db = self.db.lock().unwrap();

        let mut stmt = db.prepare(
            r#"
            SELECT timestamp, client_id, client_name, peer_pid, peer_uid,
                   method, path, success, error
            FROM access_log
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
        )?;

        let entries = stmt
            .query_map([limit as i64], |row| {
                let timestamp_str: String = row.get(0)?;
                let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                Ok(AuditEntry {
                    timestamp,
                    client_id: row.get(1)?,
                    client_name: row.get(2)?,
                    peer_pid: row.get(3)?,
                    peer_uid: row.get(4)?,
                    method: row.get(5)?,
                    path: row.get(6)?,
                    success: row.get::<_, i32>(7)? != 0,
                    error: row.get(8)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }

    /// Query access logs for a specific path
    pub fn query_by_path(&self, path: &str, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        let db = self.db.lock().unwrap();

        let mut stmt = db.prepare(
            r#"
            SELECT timestamp, client_id, client_name, peer_pid, peer_uid,
                   method, path, success, error
            FROM access_log
            WHERE path = ?
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
        )?;

        let entries = stmt
            .query_map(params![path, limit as i64], |row| {
                let timestamp_str: String = row.get(0)?;
                let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                Ok(AuditEntry {
                    timestamp,
                    client_id: row.get(1)?,
                    client_name: row.get(2)?,
                    peer_pid: row.get(3)?,
                    peer_uid: row.get(4)?,
                    method: row.get(5)?,
                    path: row.get(6)?,
                    success: row.get::<_, i32>(7)? != 0,
                    error: row.get(8)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }

    /// Query access logs for a specific client
    pub fn query_by_client(&self, client_id: &str, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        let db = self.db.lock().unwrap();

        let mut stmt = db.prepare(
            r#"
            SELECT timestamp, client_id, client_name, peer_pid, peer_uid,
                   method, path, success, error
            FROM access_log
            WHERE client_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
        )?;

        let entries = stmt
            .query_map(params![client_id, limit as i64], |row| {
                let timestamp_str: String = row.get(0)?;
                let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                Ok(AuditEntry {
                    timestamp,
                    client_id: row.get(1)?,
                    client_name: row.get(2)?,
                    peer_pid: row.get(3)?,
                    peer_uid: row.get(4)?,
                    method: row.get(5)?,
                    path: row.get(6)?,
                    success: row.get::<_, i32>(7)? != 0,
                    error: row.get(8)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }

    /// Get access statistics
    pub fn get_stats(&self) -> Result<AuditStats, AuditError> {
        let db = self.db.lock().unwrap();

        let total: i64 = db.query_row(
            "SELECT COUNT(*) FROM access_log",
            [],
            |row| row.get(0),
        )?;

        let success_count: i64 = db.query_row(
            "SELECT COUNT(*) FROM access_log WHERE success = 1",
            [],
            |row| row.get(0),
        )?;

        let today_count: i64 = db.query_row(
            "SELECT COUNT(*) FROM access_log WHERE date(timestamp) = date('now')",
            [],
            |row| row.get(0),
        )?;

        let unique_clients: i64 = db.query_row(
            "SELECT COUNT(DISTINCT client_id) FROM access_log WHERE client_id IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let unique_paths: i64 = db.query_row(
            "SELECT COUNT(DISTINCT path) FROM access_log WHERE path IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        Ok(AuditStats {
            total_accesses: total as u64,
            success_count: success_count as u64,
            failure_count: (total - success_count) as u64,
            today_count: today_count as u64,
            unique_clients: unique_clients as u64,
            unique_paths: unique_paths as u64,
        })
    }

    /// Clean up old entries based on retention policy
    pub fn cleanup_old_entries(&self) -> Result<usize, AuditError> {
        if self.retention_days == 0 {
            return Ok(0);
        }

        let db = self.db.lock().unwrap();

        let deleted = db.execute(
            "DELETE FROM access_log WHERE timestamp < datetime('now', ?)",
            [format!("-{} days", self.retention_days)],
        )?;

        if deleted > 0 {
            tracing::info!(count = deleted, "cleaned up old audit log entries");
        }

        Ok(deleted)
    }
}

/// Audit log statistics
#[derive(Debug, Clone)]
pub struct AuditStats {
    /// Total number of access attempts
    pub total_accesses: u64,
    /// Number of successful accesses
    pub success_count: u64,
    /// Number of failed accesses
    pub failure_count: u64,
    /// Number of accesses today
    pub today_count: u64,
    /// Number of unique clients
    pub unique_clients: u64,
    /// Number of unique paths accessed
    pub unique_paths: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_audit_log_basic() {
        let tmp = NamedTempFile::new().unwrap();
        let log = AuditLog::new(tmp.path(), 30).unwrap();

        let entry = AuditEntry {
            timestamp: Utc::now(),
            client_id: Some("test-client".to_string()),
            client_name: Some("Test Client".to_string()),
            peer_pid: Some(1234),
            peer_uid: Some(1000),
            method: "get".to_string(),
            path: Some("claude/api/key".to_string()),
            success: true,
            error: None,
        };

        log.log(entry).await.unwrap();

        let recent = log.query_recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].client_id, Some("test-client".to_string()));
        assert_eq!(recent[0].method, "get");
    }

    #[tokio::test]
    async fn test_audit_stats() {
        let tmp = NamedTempFile::new().unwrap();
        let log = AuditLog::new(tmp.path(), 30).unwrap();

        // Log some entries
        for i in 0..5 {
            let entry = AuditEntry {
                timestamp: Utc::now(),
                client_id: Some(format!("client-{}", i % 2)),
                client_name: None,
                peer_pid: None,
                peer_uid: None,
                method: "get".to_string(),
                path: Some(format!("path/{}", i)),
                success: i % 3 != 0,
                error: if i % 3 == 0 { Some("error".to_string()) } else { None },
            };
            log.log(entry).await.unwrap();
        }

        let stats = log.get_stats().unwrap();
        assert_eq!(stats.total_accesses, 5);
        assert_eq!(stats.unique_clients, 2);
        assert_eq!(stats.unique_paths, 5);
    }

    #[test]
    fn test_query_by_path() {
        let tmp = NamedTempFile::new().unwrap();
        let log = AuditLog::new(tmp.path(), 30).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();

        // Log entries for different paths
        rt.block_on(async {
            log.log(AuditEntry {
                timestamp: Utc::now(),
                client_id: Some("c1".to_string()),
                client_name: None,
                peer_pid: None,
                peer_uid: None,
                method: "get".to_string(),
                path: Some("target/path".to_string()),
                success: true,
                error: None,
            }).await.unwrap();

            log.log(AuditEntry {
                timestamp: Utc::now(),
                client_id: Some("c2".to_string()),
                client_name: None,
                peer_pid: None,
                peer_uid: None,
                method: "get".to_string(),
                path: Some("other/path".to_string()),
                success: true,
                error: None,
            }).await.unwrap();
        });

        let results = log.query_by_path("target/path", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].client_id, Some("c1".to_string()));
    }
}
