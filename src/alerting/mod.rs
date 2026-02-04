//! Alerting for rotation failures (future implementation)
//!
//! This module will send Telegram notifications when:
//! - Token rotation fails
//! - Unusual access patterns detected
//! - Health check failures

// TODO: Phase 4 implementation
// - TelegramAlerter
// - Alert severity levels
// - Rate limiting to prevent alert floods

/// Alerting trait
pub trait Alerter: Send + Sync {
    /// Send an alert
    fn alert(&self, message: &str, severity: AlertSeverity);
}

/// Alert severity levels
#[derive(Debug, Clone, Copy)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}
