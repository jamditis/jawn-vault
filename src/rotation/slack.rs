//! Slack OAuth token rotation provider
//!
//! Exchanges a long-lived refresh token for a new short-lived access token
//! via the Slack OAuth v2 API. Slack configurable token rotation tokens
//! expire every 12 hours.

use async_trait::async_trait;
use serde::Deserialize;

use super::{RotationError, RotationProvider};
use crate::backend::Backend;

/// Slack OAuth token rotation provider
pub struct SlackOAuthProvider {
    /// OAuth client ID
    client_id: String,
    /// OAuth client secret (read from pass at this path)
    client_secret_path: String,
    /// Path to the refresh token in the backend
    refresh_token_path: String,
    /// Path where the rotated access token is stored
    access_token_path: String,
}

#[derive(Deserialize)]
struct SlackTokenResponse {
    ok: bool,
    access_token: Option<String>,
    refresh_token: Option<String>,
    error: Option<String>,
}

impl SlackOAuthProvider {
    pub fn new(
        client_id: String,
        client_secret_path: String,
        refresh_token_path: String,
        access_token_path: String,
    ) -> Self {
        Self {
            client_id,
            client_secret_path,
            refresh_token_path,
            access_token_path,
        }
    }

    /// Build from a TOML config table and the paths list from the provider config.
    pub fn from_config(
        config: &toml::Table,
        paths: &[String],
    ) -> Result<Self, RotationError> {
        let client_id = config
            .get("client_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RotationError::NotConfigured("slack: missing client_id".into()))?;

        let client_secret_path = config
            .get("client_secret_path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RotationError::NotConfigured("slack: missing client_secret_path".into())
            })?;

        let refresh_token_path = config
            .get("refresh_token_path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RotationError::NotConfigured("slack: missing refresh_token_path".into())
            })?;

        let access_token_path = paths.first().ok_or_else(|| {
            RotationError::NotConfigured("slack: no paths configured".into())
        })?;

        Ok(Self::new(
            client_id.to_string(),
            client_secret_path.to_string(),
            refresh_token_path.to_string(),
            access_token_path.clone(),
        ))
    }
}

#[async_trait]
impl RotationProvider for SlackOAuthProvider {
    fn name(&self) -> &str {
        "slack"
    }

    fn paths(&self) -> Vec<String> {
        vec![self.access_token_path.clone()]
    }

    async fn rotate(&self, backend: &dyn Backend) -> Result<String, RotationError> {
        let refresh_token = backend
            .get(&self.refresh_token_path)
            .await
            .map_err(|e| RotationError::Backend(e.to_string()))?;

        let client_secret = backend
            .get(&self.client_secret_path)
            .await
            .map_err(|e| RotationError::Backend(e.to_string()))?;

        let client = reqwest::Client::new();
        let resp = client
            .post("https://slack.com/api/oauth.v2.access")
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", client_secret.as_str()),
                ("refresh_token", refresh_token.as_str()),
            ])
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;

        let token_resp: SlackTokenResponse = resp
            .json()
            .await
            .map_err(|e| RotationError::InvalidResponse(e.to_string()))?;

        if !token_resp.ok {
            let err = token_resp.error.unwrap_or_else(|| "unknown error".into());
            if err == "invalid_refresh_token" || err == "token_revoked" {
                return Err(RotationError::RefreshTokenExpired);
            }
            return Err(RotationError::InvalidResponse(err));
        }

        // If Slack returns a new refresh token, store it for next time
        if let Some(new_refresh) = token_resp.refresh_token {
            backend
                .set(&self.refresh_token_path, &new_refresh)
                .await
                .map_err(|e| RotationError::Backend(e.to_string()))?;

            tracing::info!(provider = "slack", "updated refresh token");
        }

        token_resp
            .access_token
            .ok_or_else(|| RotationError::InvalidResponse("no access_token in response".into()))
    }
}
