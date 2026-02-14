//! Rotation scheduler
//!
//! Runs configured rotation providers on cron schedules, writing rotated
//! values back to the backend and invalidating cache entries.

use std::sync::Arc;

use tokio_cron_scheduler::{Job, JobScheduler};

use super::google::GoogleOAuthProvider;
use super::http::HttpRefreshProvider;
use super::slack::SlackOAuthProvider;
use super::RotationProvider;
use crate::alerting::{AlertSeverity, Alerter};
use crate::backend::Backend;
use crate::cache::Cache;
use crate::config::{ProviderType, RotationConfig};

/// Manages scheduled token rotation jobs.
pub struct RotationScheduler {
    scheduler: JobScheduler,
}

impl RotationScheduler {
    /// Build and start the rotation scheduler from config.
    ///
    /// For each configured provider, creates a cron job that:
    /// 1. Calls `provider.rotate(backend)` to get a new token
    /// 2. Writes the new token to the backend via `backend.set()`
    /// 3. Invalidates the cache entry
    /// 4. Sends an alert on failure
    pub async fn start(
        config: &RotationConfig,
        backend: Arc<dyn Backend>,
        cache: Arc<Cache>,
        alerter: Option<Arc<dyn Alerter>>,
    ) -> Result<Self, anyhow::Error> {
        let scheduler = JobScheduler::new().await?;

        for provider_cfg in &config.providers {
            let provider: Arc<dyn RotationProvider> = match provider_cfg.provider_type {
                ProviderType::SlackOauth => Arc::new(
                    SlackOAuthProvider::from_config(&provider_cfg.config, &provider_cfg.paths)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                ),
                ProviderType::GoogleOauth => Arc::new(
                    GoogleOAuthProvider::from_config(&provider_cfg.config, &provider_cfg.paths)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                ),
                ProviderType::HttpRefresh => Arc::new(
                    HttpRefreshProvider::from_config(
                        &provider_cfg.name,
                        &provider_cfg.config,
                        &provider_cfg.paths,
                    )
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                ),
            };

            let backend = Arc::clone(&backend);
            let cache = Arc::clone(&cache);
            let alerter = alerter.clone();
            let schedule = provider_cfg.schedule.clone();
            let provider_name = provider_cfg.name.clone();

            let job = Job::new_async(schedule.as_str(), move |_uuid, _lock| {
                let provider = Arc::clone(&provider);
                let backend = Arc::clone(&backend);
                let cache = Arc::clone(&cache);
                let alerter = alerter.clone();
                let provider_name = provider_name.clone();

                Box::pin(async move {
                    tracing::info!(provider = %provider_name, "starting token rotation");

                    match provider.rotate(backend.as_ref()).await {
                        Ok(new_value) => {
                            // Write the new token to each managed path
                            for path in provider.paths() {
                                if let Err(e) = backend.set(&path, &new_value).await {
                                    tracing::error!(
                                        provider = %provider_name,
                                        path = %path,
                                        error = %e,
                                        "failed to store rotated token"
                                    );
                                    if let Some(ref a) = alerter {
                                        a.alert(
                                            &format!(
                                                "rotation store failed for {provider_name}/{path}: {e}"
                                            ),
                                            AlertSeverity::Error,
                                        );
                                    }
                                    return;
                                }
                                cache.remove(&path);
                            }

                            tracing::info!(
                                provider = %provider_name,
                                "token rotation succeeded"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                provider = %provider_name,
                                error = %e,
                                "token rotation failed"
                            );
                            if let Some(ref a) = alerter {
                                a.alert(
                                    &format!("rotation failed for {provider_name}: {e}"),
                                    AlertSeverity::Error,
                                );
                            }
                        }
                    }
                })
            })?;

            scheduler.add(job).await?;

            tracing::info!(
                provider = %provider_cfg.name,
                schedule = %provider_cfg.schedule,
                "scheduled rotation job"
            );
        }

        scheduler.start().await?;

        Ok(Self { scheduler })
    }

    /// Trigger an immediate rotation for a specific path.
    ///
    /// Looks through all providers to find one that manages the given path,
    /// then runs it immediately.
    pub async fn rotate_now(
        &self,
        path: &str,
        providers: &[Arc<dyn RotationProvider>],
        backend: &dyn Backend,
        cache: &Cache,
    ) -> Result<(), super::RotationError> {
        for provider in providers {
            if provider.paths().iter().any(|p| p == path) {
                let new_value = provider.rotate(backend).await?;
                backend
                    .set(path, &new_value)
                    .await
                    .map_err(|e| super::RotationError::Backend(e.to_string()))?;
                cache.remove(path);

                tracing::info!(
                    provider = %provider.name(),
                    path = %path,
                    "manual rotation succeeded"
                );
                return Ok(());
            }
        }

        Err(super::RotationError::NotConfigured(format!(
            "no provider manages path: {path}"
        )))
    }

    /// Shut down the scheduler.
    pub async fn shutdown(mut self) -> Result<(), anyhow::Error> {
        self.scheduler.shutdown().await?;
        Ok(())
    }
}
