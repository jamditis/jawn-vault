//! Alerting for rotation failures and operational events
//!
//! Sends Telegram notifications when:
//! - Token rotation fails
//! - Unusual access patterns detected
//! - Health check failures
//!
//! Includes rate limiting to prevent alert floods.

use std::sync::Mutex;
use std::time::{Duration, Instant};

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

impl AlertSeverity {
    fn emoji(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "ℹ️",
            AlertSeverity::Warning => "⚠️",
            AlertSeverity::Error => "❌",
            AlertSeverity::Critical => "🚨",
        }
    }
}

/// Telegram alerter that sends messages via the Telegram Bot API.
///
/// Rate-limits to at most one alert per `min_interval` to prevent floods.
pub struct TelegramAlerter {
    bot_token: String,
    chat_id: i64,
    min_interval: Duration,
    last_alert: Mutex<Option<Instant>>,
    client: reqwest::Client,
}

impl TelegramAlerter {
    pub fn new(bot_token: String, chat_id: i64) -> Self {
        Self {
            bot_token,
            chat_id,
            min_interval: Duration::from_secs(60),
            last_alert: Mutex::new(None),
            client: reqwest::Client::new(),
        }
    }

    /// Build a TelegramAlerter by reading the bot token from the backend at
    /// startup. Returns `None` if alerting is not configured.
    pub async fn from_config(
        config: &crate::config::AlertingConfig,
        backend: &dyn crate::backend::Backend,
    ) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        let chat_id = config.telegram_chat_id?;
        let token_path = config.telegram_token_path.as_ref()?;

        let bot_token = match backend.get(token_path).await {
            Ok(token) => token,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %token_path,
                    "failed to read telegram bot token, alerting disabled"
                );
                return None;
            }
        };

        Some(Self::new(bot_token, chat_id))
    }

    fn is_rate_limited(&self) -> bool {
        let mut last = self.last_alert.lock().unwrap();
        if let Some(t) = *last {
            if t.elapsed() < self.min_interval {
                return true;
            }
        }
        *last = Some(Instant::now());
        false
    }
}

impl Alerter for TelegramAlerter {
    fn alert(&self, message: &str, severity: AlertSeverity) {
        if self.is_rate_limited() {
            tracing::debug!("alert rate-limited, skipping");
            return;
        }

        let text = format!(
            "{} *jawn-vault* {}\n\n{}",
            severity.emoji(),
            match severity {
                AlertSeverity::Info => "Info",
                AlertSeverity::Warning => "Warning",
                AlertSeverity::Error => "Error",
                AlertSeverity::Critical => "CRITICAL",
            },
            message
        );

        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.bot_token
        );
        let chat_id = self.chat_id;
        let client = self.client.clone();

        // Fire-and-forget: don't block the caller
        tokio::spawn(async move {
            let result = client
                .post(&url)
                .json(&serde_json::json!({
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                }))
                .send()
                .await;

            if let Err(e) = result {
                tracing::error!(error = %e, "failed to send telegram alert");
            }
        });
    }
}

/// A no-op alerter used when alerting is disabled.
pub struct NoopAlerter;

impl Alerter for NoopAlerter {
    fn alert(&self, _message: &str, _severity: AlertSeverity) {}
}
