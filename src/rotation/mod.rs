//! Token rotation framework
//!
//! Provides automatic rotation of short-lived credentials (OAuth tokens, etc.)
//! by scheduling periodic refresh operations and writing new values back to the
//! pass backend.

pub mod google;
pub mod http;
pub mod scheduler;
pub mod slack;

use async_trait::async_trait;
use thiserror::Error;

use crate::backend::Backend;

/// Trait for token rotation providers
#[async_trait]
pub trait RotationProvider: Send + Sync {
    /// Provider name (for logging and alerting)
    fn name(&self) -> &str;

    /// Paths managed by this provider (access tokens that get rotated)
    fn paths(&self) -> Vec<String>;

    /// Perform token rotation, returning the new value.
    ///
    /// The backend is passed in so the provider can read refresh tokens
    /// or other supporting credentials it needs.
    async fn rotate(&self, backend: &dyn Backend) -> Result<String, RotationError>;
}

/// Errors that can occur during rotation
#[derive(Debug, Error)]
pub enum RotationError {
    #[error("http request failed: {0}")]
    Http(String),

    #[error("refresh token expired or invalid")]
    RefreshTokenExpired,

    #[error("invalid response: {0}")]
    InvalidResponse(String),

    #[error("backend error: {0}")]
    Backend(String),

    #[error("provider not configured: {0}")]
    NotConfigured(String),
}
