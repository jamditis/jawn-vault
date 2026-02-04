//! Token rotation scheduler (future implementation)
//!
//! This module will handle automatic token refresh for:
//! - Slack OAuth tokens (12h expiry)
//! - Google OAuth tokens (1h expiry)
//! - Any HTTP-based refresh mechanism

// TODO: Phase 4 implementation
// - RotationScheduler using tokio-cron-scheduler
// - Provider trait for different token types
// - SlackOAuthProvider
// - GoogleOAuthProvider
// - HttpRefreshProvider

use async_trait::async_trait;

/// Trait for token rotation providers
#[async_trait]
pub trait RotationProvider: Send + Sync {
    /// Provider name (for logging)
    fn name(&self) -> &str;

    /// Paths managed by this provider
    fn paths(&self) -> &[String];

    /// Perform token rotation, returning the new value
    async fn rotate(&self) -> Result<String, RotationError>;
}

/// Errors that can occur during rotation
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error("http request failed: {0}")]
    Http(String),

    #[error("refresh token expired")]
    RefreshTokenExpired,

    #[error("invalid response: {0}")]
    InvalidResponse(String),

    #[error("backend error: {0}")]
    Backend(String),
}
