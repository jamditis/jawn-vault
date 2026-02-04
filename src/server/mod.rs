//! Unix socket server for Jawn Vault
//!
//! Handles client connections, request parsing, and response sending.
//! Uses SO_PEERCRED for additional client verification on Linux.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use crate::audit::{AuditLog, AuditEntry};
use crate::auth::{Authenticator, ClientIdentity, Operation};
use crate::backend::Backend;
use crate::cache::Cache;
use crate::config::Config;
use crate::protocol::{
    ErrorCode, Method, Request, Response,
};
use crate::VaultError;

/// Vault server state
pub struct VaultServer {
    /// Configuration
    config: Config,
    /// Credential backend
    backend: Arc<dyn Backend>,
    /// Credential cache
    cache: Arc<Cache>,
    /// Authenticator
    auth: Arc<Authenticator>,
    /// Audit log
    audit: Arc<AuditLog>,
    /// Server start time
    start_time: Instant,
    /// Connection semaphore for limiting concurrent connections
    connection_semaphore: Arc<Semaphore>,
}

impl VaultServer {
    /// Create a new vault server
    pub fn new(
        config: Config,
        backend: Arc<dyn Backend>,
        cache: Arc<Cache>,
        auth: Arc<Authenticator>,
        audit: Arc<AuditLog>,
    ) -> Self {
        let max_connections = config.server.max_connections;
        Self {
            config,
            backend,
            cache,
            auth,
            audit,
            start_time: Instant::now(),
            connection_semaphore: Arc::new(Semaphore::new(max_connections)),
        }
    }

    /// Run the server
    pub async fn run(self: Arc<Self>) -> Result<(), VaultError> {
        let socket_path = &self.config.server.socket_path;

        // Remove existing socket file if it exists
        if socket_path.exists() {
            std::fs::remove_file(socket_path)?;
        }

        // Ensure parent directory exists
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Bind the listener
        let listener = UnixListener::bind(socket_path)?;

        // Set socket permissions
        let mode = self.config.server.socket_mode;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(mode))?;

        tracing::info!(
            socket = %socket_path.display(),
            mode = format!("{:o}", mode),
            "vault server listening"
        );

        // Accept connections
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let server = Arc::clone(&self);
                    let permit = match self.connection_semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::warn!("connection limit reached, rejecting");
                            continue;
                        }
                    };

                    tokio::spawn(async move {
                        let peer_info = get_peer_info(&stream);
                        tracing::debug!(peer = ?peer_info, "new connection");

                        if let Err(e) = server.handle_connection(stream, peer_info).await {
                            tracing::debug!(error = %e, "connection error");
                        }

                        drop(permit);
                    });
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to accept connection");
                }
            }
        }
    }

    /// Handle a single connection
    async fn handle_connection(
        &self,
        stream: UnixStream,
        peer_info: Option<PeerInfo>,
    ) -> Result<(), VaultError> {
        let timeout = Duration::from_secs(self.config.server.request_timeout_secs);

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        loop {
            line.clear();

            // Read request with timeout
            let read_result = tokio::time::timeout(timeout, reader.read_line(&mut line)).await;

            match read_result {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(_)) => {
                    let response = self.handle_request(&line, &peer_info).await;
                    let response_json = serde_json::to_string(&response)? + "\n";
                    writer.write_all(response_json.as_bytes()).await?;
                }
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "read error");
                    break;
                }
                Err(_) => {
                    tracing::debug!("connection timeout");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single request
    async fn handle_request(&self, line: &str, peer_info: &Option<PeerInfo>) -> Response {
        // Parse request
        let request: Request = match serde_json::from_str(line.trim()) {
            Ok(req) => req,
            Err(e) => {
                return Response::error(
                    "unknown",
                    ErrorCode::InvalidRequest,
                    format!("invalid JSON: {e}"),
                );
            }
        };

        let request_id = request.id.clone();

        // Authenticate
        let identity = match self.auth.validate(&request.auth) {
            Ok(id) => id,
            Err(_) => {
                self.log_access(&request, None, peer_info, false, "auth failed").await;
                return Response::error(&request_id, ErrorCode::Unauthorized, "invalid token");
            }
        };

        // Dispatch to handler
        let result = match request.method {
            Method::Get => self.handle_get(&request, &identity).await,
            Method::Set => self.handle_set(&request, &identity).await,
            Method::Delete => self.handle_delete(&request, &identity).await,
            Method::List => self.handle_list(&request, &identity).await,
            Method::Health => self.handle_health(&request, &identity).await,
            Method::Rotate => self.handle_rotate(&request, &identity).await,
            Method::Invalidate => self.handle_invalidate(&request, &identity).await,
        };

        let (response, success) = match result {
            Ok(resp) => (resp, true),
            Err(e) => {
                let code = match &e {
                    VaultError::NotFound { .. } => ErrorCode::NotFound,
                    VaultError::AccessDenied { .. } => ErrorCode::Forbidden,
                    VaultError::InvalidToken | VaultError::TokenExpired => ErrorCode::Unauthorized,
                    VaultError::Backend(_) => ErrorCode::BackendError,
                    _ => ErrorCode::InternalError,
                };
                (Response::error(&request_id, code, e.to_string()), false)
            }
        };

        // Log access
        self.log_access(&request, Some(&identity), peer_info, success, "").await;

        response
    }

    async fn handle_get(&self, request: &Request, identity: &ClientIdentity) -> Result<Response, VaultError> {
        let path = request.params.path.as_ref()
            .ok_or_else(|| VaultError::Internal("missing path parameter".to_string()))?;

        // Check permission
        if !identity.can_access(path, Operation::Read) {
            return Err(VaultError::AccessDenied {
                reason: format!("no read access to {path}"),
            });
        }

        // Try cache first
        if self.config.cache.enabled {
            if let Some(cached) = self.cache.get(path) {
                return Ok(Response::credential(
                    &request.id,
                    cached.value,
                    true,
                    Some(cached.expires_at),
                ));
            }
        }

        // Fetch from backend
        let value = self.backend.get(path).await
            .map_err(|e| match e {
                crate::backend::BackendError::NotFound { path } => VaultError::NotFound { path },
                other => VaultError::Backend(other),
            })?;

        // Cache the result
        if self.config.cache.enabled {
            let ttl = request.params.ttl_seconds.map(Duration::from_secs);
            self.cache.insert(path, value.clone(), ttl);
        }

        Ok(Response::credential(&request.id, value, false, None))
    }

    async fn handle_set(&self, request: &Request, identity: &ClientIdentity) -> Result<Response, VaultError> {
        let path = request.params.path.as_ref()
            .ok_or_else(|| VaultError::Internal("missing path parameter".to_string()))?;
        let value = request.params.value.as_ref()
            .ok_or_else(|| VaultError::Internal("missing value parameter".to_string()))?;

        // Check permission
        if !identity.can_access(path, Operation::Write) {
            return Err(VaultError::AccessDenied {
                reason: format!("no write access to {path}"),
            });
        }

        // Write to backend
        self.backend.set(path, value).await?;

        // Invalidate cache
        self.cache.remove(path);

        Ok(Response::ok(&request.id))
    }

    async fn handle_delete(&self, request: &Request, identity: &ClientIdentity) -> Result<Response, VaultError> {
        let path = request.params.path.as_ref()
            .ok_or_else(|| VaultError::Internal("missing path parameter".to_string()))?;

        // Check permission (delete requires write)
        if !identity.can_access(path, Operation::Write) {
            return Err(VaultError::AccessDenied {
                reason: format!("no write access to {path}"),
            });
        }

        // Delete from backend
        self.backend.delete(path).await?;

        // Remove from cache
        self.cache.remove(path);

        Ok(Response::ok(&request.id))
    }

    async fn handle_list(&self, request: &Request, identity: &ClientIdentity) -> Result<Response, VaultError> {
        let prefix = request.params.prefix.as_deref();

        // List from backend
        let all_paths = self.backend.list(prefix).await?;

        // Filter to only paths the client can access
        let accessible_paths: Vec<String> = all_paths
            .into_iter()
            .filter(|p| identity.can_access(p, Operation::Read))
            .collect();

        Ok(Response::list(&request.id, accessible_paths))
    }

    async fn handle_health(&self, request: &Request, _identity: &ClientIdentity) -> Result<Response, VaultError> {
        let stats = self.cache.stats();
        let uptime = self.start_time.elapsed().as_secs();

        Ok(Response::health(
            &request.id,
            uptime,
            stats.entries,
            stats.hits,
            stats.misses,
        ))
    }

    async fn handle_rotate(&self, request: &Request, identity: &ClientIdentity) -> Result<Response, VaultError> {
        let path = request.params.path.as_ref()
            .ok_or_else(|| VaultError::Internal("missing path parameter".to_string()))?;

        // Rotation requires admin permission
        if !identity.can_access(path, Operation::Admin) {
            return Err(VaultError::AccessDenied {
                reason: format!("no admin access to {path}"),
            });
        }

        // TODO: Implement rotation trigger
        // For now, just invalidate the cache entry
        self.cache.remove(path);

        Ok(Response::ok(&request.id))
    }

    async fn handle_invalidate(&self, request: &Request, identity: &ClientIdentity) -> Result<Response, VaultError> {
        let path = request.params.path.as_ref()
            .ok_or_else(|| VaultError::Internal("missing path parameter".to_string()))?;

        // Check permission (invalidate requires write to see immediate effect)
        if !identity.can_access(path, Operation::Read) {
            return Err(VaultError::AccessDenied {
                reason: format!("no access to {path}"),
            });
        }

        // Remove from cache
        self.cache.remove(path);

        Ok(Response::ok(&request.id))
    }

    async fn log_access(
        &self,
        request: &Request,
        identity: Option<&ClientIdentity>,
        peer_info: &Option<PeerInfo>,
        success: bool,
        error_msg: &str,
    ) {
        let entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            client_id: identity.map(|i| i.client_id.clone()),
            client_name: identity.map(|i| i.client_name.clone()),
            peer_pid: peer_info.as_ref().map(|p| p.pid),
            peer_uid: peer_info.as_ref().map(|p| p.uid),
            method: format!("{:?}", request.method).to_lowercase(),
            path: request.params.path.clone(),
            success,
            error: if error_msg.is_empty() { None } else { Some(error_msg.to_string()) },
        };

        if let Err(e) = self.audit.log(entry).await {
            tracing::error!(error = %e, "failed to write audit log");
        }
    }
}

/// Information about the connecting peer
#[derive(Debug)]
pub struct PeerInfo {
    pub pid: i32,
    pub uid: u32,
}

/// Get peer credentials from a Unix stream (Linux only)
#[cfg(target_os = "linux")]
fn get_peer_info(stream: &UnixStream) -> Option<PeerInfo> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();

    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if result == 0 {
        Some(PeerInfo {
            pid: cred.pid,
            uid: cred.uid,
        })
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn get_peer_info(_stream: &UnixStream) -> Option<PeerInfo> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_info_struct() {
        let info = PeerInfo { pid: 1234, uid: 1000 };
        assert_eq!(info.pid, 1234);
        assert_eq!(info.uid, 1000);
    }
}
