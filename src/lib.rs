//! Jawn Vault - Secure credential proxy with caching and audit logging
//!
//! This library provides the core functionality for the Jawn Vault daemon,
//! including credential caching, pass backend integration, and audit logging.

pub mod audit;
pub mod auth;
pub mod backend;
pub mod cache;
pub mod config;
pub mod protocol;
pub mod server;

use thiserror::Error;

/// Main error type for Jawn Vault operations
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("credential not found: {path}")]
    NotFound { path: String },

    #[error("access denied: {reason}")]
    AccessDenied { reason: String },

    #[error("invalid token")]
    InvalidToken,

    #[error("token expired")]
    TokenExpired,

    #[error("backend error: {0}")]
    Backend(#[from] backend::BackendError),

    #[error("cache error: {0}")]
    Cache(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("audit error: {0}")]
    Audit(#[from] audit::AuditError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type alias for Jawn Vault operations
pub type Result<T> = std::result::Result<T, VaultError>;
