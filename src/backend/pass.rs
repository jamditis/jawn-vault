//! Pass (password-store) backend implementation
//!
//! This wraps the `pass` command-line tool, handling subprocess execution,
//! output parsing, and error handling.
//!
//! SECURITY NOTE: We use tokio::process::Command which executes binaries directly
//! without shell interpolation, avoiding command injection vulnerabilities.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::Command;
use tokio::time::timeout;

use super::{Backend, BackendError};
use crate::config::PassConfig;

/// Pass backend that wraps the password-store CLI
pub struct PassBackend {
    /// Path to pass binary
    binary: PathBuf,
    /// Path to password store
    store_path: PathBuf,
    /// Command timeout
    timeout: Duration,
}

impl PassBackend {
    /// Create a new pass backend with the given configuration
    pub fn new(config: &PassConfig) -> Self {
        Self {
            binary: config.binary.clone(),
            store_path: config.store_path.clone(),
            timeout: Duration::from_secs(config.timeout_secs),
        }
    }

    /// Execute a pass command and return stdout.
    /// Uses Command::new() which executes the binary directly without a shell,
    /// preventing any command injection from the path argument.
    async fn run_pass(&self, args: &[&str]) -> Result<String, BackendError> {
        let mut cmd = Command::new(&self.binary);
        cmd.args(args)
            .env("PASSWORD_STORE_DIR", &self.store_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        tracing::debug!(
            binary = %self.binary.display(),
            args = ?args,
            "executing pass command"
        );

        let child = cmd.spawn()?;

        let result = timeout(self.timeout, child.wait_with_output()).await;

        match result {
            Ok(Ok(output)) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    // pass outputs a trailing newline, strip it
                    Ok(stdout.trim_end_matches('\n').to_string())
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let stderr_trimmed = stderr.trim();

                    // Check for "not in the password store" error
                    if stderr_trimmed.contains("is not in the password store") {
                        // Extract path from args
                        let path = args.last().unwrap_or(&"unknown");
                        Err(BackendError::NotFound {
                            path: path.to_string(),
                        })
                    } else {
                        Err(BackendError::CommandFailed(format!(
                            "pass {} failed (exit {}): {}",
                            args.first().unwrap_or(&""),
                            output.status.code().unwrap_or(-1),
                            stderr_trimmed
                        )))
                    }
                }
            }
            Ok(Err(e)) => Err(BackendError::Io(e)),
            Err(_) => Err(BackendError::Timeout {
                timeout_secs: self.timeout.as_secs(),
            }),
        }
    }

    /// Execute pass insert with stdin for value.
    /// Uses Command::new() which executes the binary directly without a shell.
    async fn run_pass_insert(&self, path: &str, value: &str) -> Result<(), BackendError> {
        let mut cmd = Command::new(&self.binary);
        cmd.args(["insert", "--force", "--multiline", path])
            .env("PASSWORD_STORE_DIR", &self.store_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        tracing::debug!(path = path, "inserting credential via pass");

        let mut child = cmd.spawn()?;

        // Write value to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(value.as_bytes()).await?;
            // Don't add newline - let the value be exactly what was passed
            drop(stdin); // Close stdin to signal EOF
        }

        let result = timeout(self.timeout, child.wait_with_output()).await;

        match result {
            Ok(Ok(output)) => {
                if output.status.success() {
                    Ok(())
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(BackendError::CommandFailed(format!(
                        "pass insert failed: {}",
                        stderr.trim()
                    )))
                }
            }
            Ok(Err(e)) => Err(BackendError::Io(e)),
            Err(_) => Err(BackendError::Timeout {
                timeout_secs: self.timeout.as_secs(),
            }),
        }
    }
}

#[async_trait]
impl Backend for PassBackend {
    async fn get(&self, path: &str) -> Result<String, BackendError> {
        self.run_pass(&["show", path]).await
    }

    async fn set(&self, path: &str, value: &str) -> Result<(), BackendError> {
        self.run_pass_insert(path, value).await
    }

    async fn delete(&self, path: &str) -> Result<(), BackendError> {
        self.run_pass(&["rm", "--force", path]).await?;
        Ok(())
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, BackendError> {
        // pass ls outputs a tree structure, we need to parse it
        // For simplicity, we'll use find on the store directory
        let search_path = match prefix {
            Some(p) => self.store_path.join(p),
            None => self.store_path.clone(),
        };

        // Use find to get all .gpg files - Command::new executes directly, no shell
        let mut cmd = Command::new("find");
        cmd.args([
            search_path.to_str().unwrap_or("."),
            "-name",
            "*.gpg",
            "-type",
            "f",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        let result = timeout(self.timeout, cmd.output()).await;

        match result {
            Ok(Ok(output)) => {
                if !output.status.success() {
                    return Ok(Vec::new()); // Directory might not exist
                }

                let stdout = String::from_utf8_lossy(&output.stdout);
                let store_path_str = self.store_path.to_string_lossy();

                let paths: Vec<String> = stdout
                    .lines()
                    .filter_map(|line| {
                        // Convert /path/to/store/foo/bar.gpg to foo/bar
                        let line = line.trim();
                        if line.is_empty() {
                            return None;
                        }

                        // Strip store path prefix and .gpg suffix
                        let path = line
                            .strip_prefix(store_path_str.as_ref())?
                            .strip_prefix('/')?
                            .strip_suffix(".gpg")?;

                        Some(path.to_string())
                    })
                    .collect();

                Ok(paths)
            }
            Ok(Err(e)) => Err(BackendError::Io(e)),
            Err(_) => Err(BackendError::Timeout {
                timeout_secs: self.timeout.as_secs(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require pass to be installed and configured
    // They're ignored by default; run with: cargo test -- --ignored

    fn test_config() -> PassConfig {
        PassConfig {
            binary: PathBuf::from("pass"),
            store_path: dirs::home_dir()
                .map(|h| h.join(".password-store"))
                .unwrap_or_else(|| PathBuf::from("/home/jamditis/.password-store")),
            timeout_secs: 10,
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_existing_credential() {
        let backend = PassBackend::new(&test_config());
        // This assumes claude/api/anthropic exists in the password store
        let result = backend.get("claude/api/anthropic").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_nonexistent_credential() {
        let backend = PassBackend::new(&test_config());
        let result = backend.get("nonexistent/path/that/does/not/exist").await;
        assert!(matches!(result, Err(BackendError::NotFound { .. })));
    }

    #[tokio::test]
    #[ignore]
    async fn test_list_credentials() {
        let backend = PassBackend::new(&test_config());
        let result = backend.list(Some("claude/")).await;
        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(!paths.is_empty());
        assert!(paths.iter().all(|p| p.starts_with("claude/")));
    }
}
