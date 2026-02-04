//! Jawn Vault - Secure credential proxy daemon
//!
//! Usage:
//!   jawn-vault [OPTIONS]
//!
//! Options:
//!   -c, --config <PATH>  Path to config file
//!   -v, --verbose        Increase log verbosity
//!   --foreground         Run in foreground (don't daemonize)

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use jawn_vault::audit::AuditLog;
use jawn_vault::auth::Authenticator;
use jawn_vault::backend::PassBackend;
use jawn_vault::cache::Cache;
use jawn_vault::config::Config;
use jawn_vault::server::VaultServer;

#[derive(Parser, Debug)]
#[command(name = "jawn-vault")]
#[command(author, version, about = "Secure credential proxy daemon", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Increase log verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Run in foreground (don't daemonize)
    #[arg(long)]
    foreground: bool,

    /// Output logs as JSON
    #[arg(long)]
    json_logs: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Set up logging
    let log_level = match args.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("jawn_vault={log_level},warn")));

    if args.json_logs {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "starting jawn-vault"
    );

    // Load configuration
    let config = Config::load(args.config.as_ref())?;

    tracing::debug!(config = ?config, "loaded configuration");

    // Initialize components
    let backend = Arc::new(PassBackend::new(&config.pass));

    let cache = Arc::new(Cache::new(
        Duration::from_secs(config.cache.default_ttl_secs),
        Duration::from_secs(config.cache.max_ttl_secs),
        config.cache.max_entries,
    ));

    let auth_db_path = config.audit.db_path.parent()
        .map(|p| p.join("auth.db"))
        .unwrap_or_else(|| PathBuf::from("/home/jamditis/.local/share/jawn-vault/auth.db"));

    let auth = Arc::new(Authenticator::new(&auth_db_path)?);

    let audit = Arc::new(AuditLog::new(&config.audit.db_path, config.audit.retention_days)?);

    // Create server
    let server = Arc::new(VaultServer::new(
        config.clone(),
        backend,
        cache.clone(),
        auth.clone(),
        audit,
    ));

    // Spawn cache cleanup task
    let cache_for_cleanup = Arc::clone(&cache);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cache_for_cleanup.cleanup_expired();
        }
    });

    // Run server with graceful shutdown
    let server_handle = tokio::spawn({
        let server = Arc::clone(&server);
        async move {
            if let Err(e) = server.run().await {
                tracing::error!(error = %e, "server error");
            }
        }
    });

    // Wait for shutdown signal
    shutdown_signal().await;

    tracing::info!("shutting down");

    // Abort the server task
    server_handle.abort();

    // Final stats
    let stats = cache.stats();
    tracing::info!(
        cache_entries = stats.entries,
        cache_hits = stats.hits,
        cache_misses = stats.misses,
        cache_hit_ratio = format!("{:.2}%", stats.hit_ratio * 100.0),
        "final statistics"
    );

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("received Ctrl+C");
        }
        _ = terminate => {
            tracing::info!("received SIGTERM");
        }
    }
}
