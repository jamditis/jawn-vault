//! Request/Response protocol for Jawn Vault
//!
//! All communication happens over Unix sockets using newline-delimited JSON.
//! Each message is a single JSON object followed by a newline.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A request to the vault daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Unique request ID for correlation
    pub id: String,
    /// Bearer token for authentication
    pub auth: String,
    /// The method to invoke
    pub method: Method,
    /// Method-specific parameters
    #[serde(default)]
    pub params: Params,
}

/// Available methods
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// Retrieve a credential
    Get,
    /// Store a credential
    Set,
    /// Delete a credential
    Delete,
    /// List credentials under a prefix
    List,
    /// Health check with cache stats
    Health,
    /// Force token rotation for a path
    Rotate,
    /// Invalidate cache entry
    Invalidate,
}

/// Method parameters
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Params {
    /// Path to the credential (required for get/set/delete/rotate/invalidate)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Value to store (required for set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,

    /// Prefix for listing (optional for list, defaults to root)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,

    /// Custom TTL in seconds for cache entry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

/// A response from the vault daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Request ID for correlation
    pub id: String,
    /// Result on success
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ResponseResult>,
    /// Error on failure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ResponseError>,
}

/// Successful response result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseResult {
    /// Credential value
    Credential(CredentialResult),
    /// List of paths
    List(ListResult),
    /// Health status
    Health(HealthResult),
    /// Simple acknowledgment
    Ok(OkResult),
}

/// Credential retrieval result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResult {
    /// The credential value
    pub value: String,
    /// Whether this was served from cache
    pub cached: bool,
    /// When this cache entry expires (if cached)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// List result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResult {
    /// Paths matching the prefix
    pub paths: Vec<String>,
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResult {
    /// Daemon status
    pub status: String,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Number of cached entries
    pub cache_entries: usize,
    /// Cache hit count since startup
    pub cache_hits: u64,
    /// Cache miss count since startup
    pub cache_misses: u64,
    /// Cache hit ratio (0.0 - 1.0)
    pub cache_hit_ratio: f64,
}

/// Simple OK result for set/delete/invalidate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OkResult {
    pub success: bool,
}

/// Error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseError {
    /// Error code
    pub code: ErrorCode,
    /// Human-readable message
    pub message: String,
}

/// Error codes
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Invalid request format
    InvalidRequest,
    /// Method not found
    MethodNotFound,
    /// Missing required parameter
    MissingParameter,
    /// Credential not found
    NotFound,
    /// Authentication failed
    Unauthorized,
    /// Permission denied
    Forbidden,
    /// Backend error (pass command failed)
    BackendError,
    /// Internal server error
    InternalError,
}

impl Request {
    /// Create a new get request
    pub fn get(id: impl Into<String>, auth: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            auth: auth.into(),
            method: Method::Get,
            params: Params {
                path: Some(path.into()),
                ..Default::default()
            },
        }
    }

    /// Create a new set request
    pub fn set(
        id: impl Into<String>,
        auth: impl Into<String>,
        path: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            auth: auth.into(),
            method: Method::Set,
            params: Params {
                path: Some(path.into()),
                value: Some(value.into()),
                ..Default::default()
            },
        }
    }

    /// Create a new list request
    pub fn list(
        id: impl Into<String>,
        auth: impl Into<String>,
        prefix: Option<String>,
    ) -> Self {
        Self {
            id: id.into(),
            auth: auth.into(),
            method: Method::List,
            params: Params {
                prefix,
                ..Default::default()
            },
        }
    }

    /// Create a new health request
    pub fn health(id: impl Into<String>, auth: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            auth: auth.into(),
            method: Method::Health,
            params: Params::default(),
        }
    }
}

impl Response {
    /// Create a success response with a credential
    pub fn credential(id: impl Into<String>, value: String, cached: bool, expires_at: Option<DateTime<Utc>>) -> Self {
        Self {
            id: id.into(),
            result: Some(ResponseResult::Credential(CredentialResult {
                value,
                cached,
                expires_at,
            })),
            error: None,
        }
    }

    /// Create a success response with a list
    pub fn list(id: impl Into<String>, paths: Vec<String>) -> Self {
        Self {
            id: id.into(),
            result: Some(ResponseResult::List(ListResult { paths })),
            error: None,
        }
    }

    /// Create a success response with health info
    pub fn health(
        id: impl Into<String>,
        uptime_seconds: u64,
        cache_entries: usize,
        cache_hits: u64,
        cache_misses: u64,
    ) -> Self {
        let total = cache_hits + cache_misses;
        let cache_hit_ratio = if total > 0 {
            cache_hits as f64 / total as f64
        } else {
            0.0
        };

        Self {
            id: id.into(),
            result: Some(ResponseResult::Health(HealthResult {
                status: "ok".to_string(),
                uptime_seconds,
                cache_entries,
                cache_hits,
                cache_misses,
                cache_hit_ratio,
            })),
            error: None,
        }
    }

    /// Create a simple OK response
    pub fn ok(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            result: Some(ResponseResult::Ok(OkResult { success: true })),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(id: impl Into<String>, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            result: None,
            error: Some(ResponseError {
                code,
                message: message.into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let req = Request::get("req-1", "token123", "claude/api/anthropic");
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"method\":\"get\""));
        assert!(json.contains("\"path\":\"claude/api/anthropic\""));
    }

    #[test]
    fn test_response_serialization() {
        let resp = Response::credential("req-1", "sk-secret".to_string(), true, None);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"cached\":true"));
        assert!(json.contains("\"value\":\"sk-secret\""));
    }

    #[test]
    fn test_error_response() {
        let resp = Response::error("req-1", ErrorCode::NotFound, "credential not found");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"code\":\"not_found\""));
        assert!(!json.contains("\"result\""));
    }
}
