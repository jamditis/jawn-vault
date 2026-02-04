//! Client authentication for Jawn Vault
//!
//! Clients authenticate using bearer tokens that are validated against
//! a SQLite database. Each token has associated permissions (path patterns).

use std::path::Path;
use std::sync::Mutex;

use ring::hmac;
use rusqlite::{Connection, params};
use thiserror::Error;

/// Authentication errors
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("invalid token")]
    InvalidToken,

    #[error("token expired")]
    TokenExpired,

    #[error("permission denied for path: {path}")]
    PermissionDenied { path: String },

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// Permission level for a path pattern
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Can read credentials
    Read,
    /// Can read and write credentials
    Write,
    /// Full access including admin operations
    Admin,
}

impl Permission {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }

    /// Check if this permission level allows the given operation
    fn allows(&self, operation: Operation) -> bool {
        match (self, operation) {
            (_, Operation::Read) => true,
            (Permission::Read, _) => false,
            (_, Operation::Write) => true,
            (Permission::Write, _) => false,
            (Permission::Admin, _) => true,
        }
    }
}

/// Operations that can be performed
#[derive(Debug, Clone, Copy)]
pub enum Operation {
    Read,
    Write,
    Admin,
}

/// A client's access grant for a path pattern
#[derive(Debug, Clone)]
pub struct Grant {
    /// Path pattern (supports * and ** wildcards)
    pub pattern: String,
    /// Permission level
    pub permission: Permission,
}

impl Grant {
    /// Check if this grant matches the given path
    fn matches(&self, path: &str) -> bool {
        pattern_matches(&self.pattern, path)
    }
}

/// Check if a glob-like pattern matches a path
fn pattern_matches(pattern: &str, path: &str) -> bool {
    // Simple pattern matching:
    // - * matches any single path segment
    // - ** matches any number of segments
    // - Exact match otherwise

    if pattern == "**" || pattern == "**/*" {
        return true;
    }

    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();

    let mut pi = 0; // pattern index
    let mut ti = 0; // path index

    while pi < pattern_parts.len() && ti < path_parts.len() {
        match pattern_parts[pi] {
            "**" => {
                // ** matches zero or more segments
                if pi == pattern_parts.len() - 1 {
                    return true; // ** at end matches everything
                }
                // Try matching the rest of the pattern at each position
                for skip in 0..=(path_parts.len() - ti) {
                    let remaining_pattern = pattern_parts[pi + 1..].join("/");
                    let remaining_path = path_parts[ti + skip..].join("/");
                    if pattern_matches(&remaining_pattern, &remaining_path) {
                        return true;
                    }
                }
                return false;
            }
            "*" => {
                // * matches exactly one segment
                pi += 1;
                ti += 1;
            }
            segment => {
                if segment != path_parts[ti] {
                    return false;
                }
                pi += 1;
                ti += 1;
            }
        }
    }

    // Both should be exhausted for a complete match
    pi == pattern_parts.len() && ti == path_parts.len()
}

/// A validated client identity with its grants
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    /// Client ID (for logging)
    pub client_id: String,
    /// Client name (human-readable)
    pub client_name: String,
    /// Access grants
    pub grants: Vec<Grant>,
}

impl ClientIdentity {
    /// Check if this client can perform an operation on a path
    pub fn can_access(&self, path: &str, operation: Operation) -> bool {
        self.grants
            .iter()
            .any(|g| g.matches(path) && g.permission.allows(operation))
    }
}

/// Token authenticator backed by SQLite
pub struct Authenticator {
    /// Database connection (Mutex because Connection is Send but not Sync)
    db: Mutex<Connection>,
    /// HMAC key for token signing
    _signing_key: hmac::Key,
}

impl Authenticator {
    /// Create a new authenticator with the given database path
    pub fn new(db_path: &Path) -> Result<Self, AuthError> {
        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let conn = Connection::open(db_path)?;

        // Create tables if they don't exist
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT,
                enabled INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS grants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                pattern TEXT NOT NULL,
                permission TEXT NOT NULL,
                UNIQUE(client_id, pattern)
            );

            CREATE INDEX IF NOT EXISTS idx_grants_client ON grants(client_id);
            "#,
        )?;

        // Generate a signing key (in production, this should be loaded from config)
        let signing_key = hmac::Key::generate(hmac::HMAC_SHA256, &ring::rand::SystemRandom::new())
            .expect("failed to generate signing key");

        Ok(Self {
            db: Mutex::new(conn),
            _signing_key: signing_key,
        })
    }

    /// Validate a token and return the client identity
    pub fn validate(&self, token: &str) -> Result<ClientIdentity, AuthError> {
        let db = self.db.lock().unwrap();

        // For now, use simple token lookup (token == client_id)
        // In production, use HMAC validation
        let token_hash = hash_token(token);

        let mut stmt = db.prepare(
            r#"
            SELECT id, name, expires_at, enabled
            FROM clients
            WHERE token_hash = ?
            "#,
        )?;

        let (client_id, client_name, expires_at, enabled): (String, String, Option<String>, bool) =
            stmt.query_row([&token_hash], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(|_| AuthError::InvalidToken)?;

        if !enabled {
            return Err(AuthError::InvalidToken);
        }

        // Check expiration
        if let Some(expires) = expires_at {
            let expires_dt = chrono::DateTime::parse_from_rfc3339(&expires)
                .map_err(|_| AuthError::InvalidToken)?;
            if expires_dt < chrono::Utc::now() {
                return Err(AuthError::TokenExpired);
            }
        }

        // Load grants
        let mut grant_stmt = db.prepare(
            r#"
            SELECT pattern, permission
            FROM grants
            WHERE client_id = ?
            "#,
        )?;

        let grants: Vec<Grant> = grant_stmt
            .query_map([&client_id], |row| {
                let pattern: String = row.get(0)?;
                let perm_str: String = row.get(1)?;
                Ok((pattern, perm_str))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(pattern, perm_str)| {
                Permission::from_str(&perm_str).map(|permission| Grant { pattern, permission })
            })
            .collect();

        Ok(ClientIdentity {
            client_id,
            client_name,
            grants,
        })
    }

    /// Create a new client and return its token
    pub fn create_client(
        &self,
        name: &str,
        grants: &[(String, Permission)],
        expires_in: Option<chrono::Duration>,
    ) -> Result<String, AuthError> {
        let db = self.db.lock().unwrap();

        // Generate client ID and token
        let client_id = generate_id();
        let token = generate_token();
        let token_hash = hash_token(&token);

        let expires_at = expires_in.map(|d| (chrono::Utc::now() + d).to_rfc3339());

        // Insert client
        db.execute(
            r#"
            INSERT INTO clients (id, name, token_hash, expires_at)
            VALUES (?, ?, ?, ?)
            "#,
            params![&client_id, name, &token_hash, &expires_at],
        )?;

        // Insert grants
        for (pattern, permission) in grants {
            db.execute(
                r#"
                INSERT INTO grants (client_id, pattern, permission)
                VALUES (?, ?, ?)
                "#,
                params![&client_id, pattern, permission.as_str()],
            )?;
        }

        Ok(token)
    }

    /// Revoke a client's access
    pub fn revoke_client(&self, client_id: &str) -> Result<(), AuthError> {
        let db = self.db.lock().unwrap();
        db.execute(
            "UPDATE clients SET enabled = 0 WHERE id = ?",
            [client_id],
        )?;
        Ok(())
    }

    /// List all clients
    pub fn list_clients(&self) -> Result<Vec<(String, String, bool)>, AuthError> {
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare("SELECT id, name, enabled FROM clients")?;
        let clients = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(clients)
    }
}

/// Hash a token for storage
fn hash_token(token: &str) -> String {
    use ring::digest;
    let digest = digest::digest(&digest::SHA256, token.as_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest.as_ref())
}

/// Generate a random ID
fn generate_id() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).expect("failed to generate random bytes");
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
}

/// Generate a random token
fn generate_token() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("failed to generate random bytes");
    format!(
        "vault_{}",
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_pattern_matching() {
        // Exact match
        assert!(pattern_matches("claude/api/anthropic", "claude/api/anthropic"));
        assert!(!pattern_matches("claude/api/anthropic", "claude/api/other"));

        // Single wildcard
        assert!(pattern_matches("claude/api/*", "claude/api/anthropic"));
        assert!(pattern_matches("claude/*/anthropic", "claude/api/anthropic"));
        assert!(!pattern_matches("claude/api/*", "claude/api/nested/path"));

        // Double wildcard
        assert!(pattern_matches("claude/**", "claude/api/anthropic"));
        assert!(pattern_matches("claude/**", "claude/deeply/nested/path"));
        assert!(pattern_matches("**", "anything/at/all"));

        // Mixed
        assert!(pattern_matches("claude/**/token", "claude/api/token"));
        assert!(pattern_matches("claude/**/token", "claude/services/slack/token"));
    }

    #[test]
    fn test_permission_levels() {
        assert!(Permission::Read.allows(Operation::Read));
        assert!(!Permission::Read.allows(Operation::Write));
        assert!(!Permission::Read.allows(Operation::Admin));

        assert!(Permission::Write.allows(Operation::Read));
        assert!(Permission::Write.allows(Operation::Write));
        assert!(!Permission::Write.allows(Operation::Admin));

        assert!(Permission::Admin.allows(Operation::Read));
        assert!(Permission::Admin.allows(Operation::Write));
        assert!(Permission::Admin.allows(Operation::Admin));
    }

    #[test]
    fn test_client_access() {
        let identity = ClientIdentity {
            client_id: "test".to_string(),
            client_name: "Test Client".to_string(),
            grants: vec![
                Grant {
                    pattern: "claude/api/*".to_string(),
                    permission: Permission::Read,
                },
                Grant {
                    pattern: "claude/tokens/**".to_string(),
                    permission: Permission::Write,
                },
            ],
        };

        // Can read from claude/api/*
        assert!(identity.can_access("claude/api/anthropic", Operation::Read));
        assert!(!identity.can_access("claude/api/anthropic", Operation::Write));

        // Can read and write claude/tokens/**
        assert!(identity.can_access("claude/tokens/telegram", Operation::Read));
        assert!(identity.can_access("claude/tokens/telegram", Operation::Write));
        assert!(!identity.can_access("claude/tokens/telegram", Operation::Admin));

        // No access to other paths
        assert!(!identity.can_access("other/path", Operation::Read));
    }

    #[test]
    fn test_authenticator_create_and_validate() {
        let tmp = NamedTempFile::new().unwrap();
        let auth = Authenticator::new(tmp.path()).unwrap();

        // Create a client
        let token = auth
            .create_client(
                "test-client",
                &[("claude/**".to_string(), Permission::Read)],
                None,
            )
            .unwrap();

        // Validate the token
        let identity = auth.validate(&token).unwrap();
        assert_eq!(identity.client_name, "test-client");
        assert!(identity.can_access("claude/api/key", Operation::Read));
    }
}
