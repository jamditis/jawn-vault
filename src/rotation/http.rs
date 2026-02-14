//! Generic HTTP token refresh provider
//!
//! Performs token rotation by POSTing a refresh token to a configurable URL
//! and extracting the new access token from the JSON response.

use async_trait::async_trait;

use super::{RotationError, RotationProvider};
use crate::backend::Backend;

/// Generic HTTP token refresh provider
pub struct HttpRefreshProvider {
    /// Provider name for logging
    provider_name: String,
    /// URL to POST the refresh request to
    url: String,
    /// Path to the refresh token in the backend
    refresh_token_path: String,
    /// Path where the rotated access token is stored
    access_token_path: String,
    /// JSON field name containing the new access token in the response
    response_token_field: String,
    /// Form field name to send the refresh token as
    refresh_token_field: String,
}

impl HttpRefreshProvider {
    /// Build from a TOML config table and the paths list from the provider config.
    pub fn from_config(
        name: &str,
        config: &toml::Table,
        paths: &[String],
    ) -> Result<Self, RotationError> {
        let url = config
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RotationError::NotConfigured("http: missing url".into()))?;

        let refresh_token_path = config
            .get("refresh_token_path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RotationError::NotConfigured("http: missing refresh_token_path".into())
            })?;

        let response_token_field = config
            .get("response_token_field")
            .and_then(|v| v.as_str())
            .unwrap_or("access_token");

        let refresh_token_field = config
            .get("refresh_token_field")
            .and_then(|v| v.as_str())
            .unwrap_or("refresh_token");

        let access_token_path = paths.first().ok_or_else(|| {
            RotationError::NotConfigured("http: no paths configured".into())
        })?;

        Ok(Self {
            provider_name: name.to_string(),
            url: url.to_string(),
            refresh_token_path: refresh_token_path.to_string(),
            access_token_path: access_token_path.clone(),
            response_token_field: response_token_field.to_string(),
            refresh_token_field: refresh_token_field.to_string(),
        })
    }
}

#[async_trait]
impl RotationProvider for HttpRefreshProvider {
    fn name(&self) -> &str {
        &self.provider_name
    }

    fn paths(&self) -> Vec<String> {
        vec![self.access_token_path.clone()]
    }

    async fn rotate(&self, backend: &dyn Backend) -> Result<String, RotationError> {
        let refresh_token = backend
            .get(&self.refresh_token_path)
            .await
            .map_err(|e| RotationError::Backend(e.to_string()))?;

        let client = reqwest::Client::new();
        let resp = client
            .post(&self.url)
            .form(&[(self.refresh_token_field.as_str(), refresh_token.as_str())])
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| RotationError::InvalidResponse(e.to_string()))?;

        if !status.is_success() {
            return Err(RotationError::Http(format!(
                "HTTP {}: {}",
                status,
                body
            )));
        }

        body.get(&self.response_token_field)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                RotationError::InvalidResponse(format!(
                    "missing '{}' field in response",
                    self.response_token_field
                ))
            })
    }
}
