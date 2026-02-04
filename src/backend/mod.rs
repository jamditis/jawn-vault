//! Backend trait and implementations for credential storage
//!
//! The primary backend is `pass` (password-store), but the trait allows
//! for alternative implementations like in-memory (for testing).

mod pass;

pub use pass::PassBackend;

use async_trait::async_trait;
use thiserror::Error;

/// Errors that can occur in backend operations
#[derive(Error, Debug)]
pub enum BackendError {
    #[error("credential not found: {path}")]
    NotFound { path: String },

    #[error("command failed: {0}")]
    CommandFailed(String),

    #[error("command timeout after {timeout_secs}s")]
    Timeout { timeout_secs: u64 },

    #[error("invalid output: {0}")]
    InvalidOutput(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Backend trait for credential storage
#[async_trait]
pub trait Backend: Send + Sync {
    /// Get a credential by path
    async fn get(&self, path: &str) -> Result<String, BackendError>;

    /// Set a credential value
    async fn set(&self, path: &str, value: &str) -> Result<(), BackendError>;

    /// Delete a credential
    async fn delete(&self, path: &str) -> Result<(), BackendError>;

    /// List credentials under a prefix
    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, BackendError>;

    /// Check if a credential exists
    async fn exists(&self, path: &str) -> Result<bool, BackendError> {
        match self.get(path).await {
            Ok(_) => Ok(true),
            Err(BackendError::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory mock backend for testing
    pub struct MockBackend {
        store: Mutex<HashMap<String, String>>,
    }

    impl MockBackend {
        pub fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }

        pub fn with_data(data: HashMap<String, String>) -> Self {
            Self {
                store: Mutex::new(data),
            }
        }
    }

    #[async_trait]
    impl Backend for MockBackend {
        async fn get(&self, path: &str) -> Result<String, BackendError> {
            let store = self.store.lock().unwrap();
            store
                .get(path)
                .cloned()
                .ok_or_else(|| BackendError::NotFound { path: path.to_string() })
        }

        async fn set(&self, path: &str, value: &str) -> Result<(), BackendError> {
            let mut store = self.store.lock().unwrap();
            store.insert(path.to_string(), value.to_string());
            Ok(())
        }

        async fn delete(&self, path: &str) -> Result<(), BackendError> {
            let mut store = self.store.lock().unwrap();
            store.remove(path);
            Ok(())
        }

        async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, BackendError> {
            let store = self.store.lock().unwrap();
            let paths: Vec<String> = store
                .keys()
                .filter(|k| {
                    prefix.map_or(true, |p| k.starts_with(p))
                })
                .cloned()
                .collect();
            Ok(paths)
        }
    }
}
