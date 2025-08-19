//! Main entry point for the Auth Service.
//!
//! This service provides authentication, key management, and token storage.
//! It is designed with security best practices and modularity in mind.

use tokio::net::TcpListener;
mod config;

use auth_service::{
    app,
    config::{self, StoreBackend},
    keys,
    sql_store::SqlStore,
    store::HybridStore,
    ApiDoc, AppState,
};
use common::Store;
use std::sync::Arc;
use utoipa::OpenApi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize enhanced tracing for security events
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,auth_service=debug,security_audit=info".into()),
        )
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    // Validate production secrets first
    if let Err(e) = config::validate_production_secrets() {
        tracing::error!("Production secrets validation failed: {}", e);
        return Err(e);
    }

    // Load configuration
    let cfg = config::AppConfig::from_env()?;
    tracing::info!("Starting auth-service with configuration loaded");

    // Initialize secure keys
    tracing::info!("Initializing secure key management...");
    if let Err(e) = keys::initialize_keys().await {
        tracing::error!(error = %e, "Failed to initialize secure keys");
        return Err(anyhow::anyhow!("Key initialization failed: {}", e));
    }
    tracing::info!("Secure key management initialized successfully");

    // Initialize the unified store based on config
    let store: Arc<dyn Store> = match cfg.store.backend {
        StoreBackend::Sql => {
            let db_url = cfg
                .store
                .database_url
                .as_ref()
                .expect("DATABASE_URL is checked in config");
            let sql_store = SqlStore::new(db_url).await?;
            sql_store.run_migrations().await?;
            tracing::info!("Using SQL store backend.");
            Arc::new(sql_store)
        }
        StoreBackend::Hybrid => {
            tracing::info!("Using Hybrid (in-memory/Redis) store backend.");
            Arc::new(HybridStore::new().await)
        }
    };

    // Initialize policy cache
    let policy_cache_config = auth_service::policy_cache::PolicyCacheConfig::default();
    let policy_cache = Arc::new(auth_service::policy_cache::PolicyCache::new(policy_cache_config));

    // Start policy cache cleanup task
    let cache_clone = policy_cache.clone();
    tokio::spawn(async move {
        auth_service::policy_cache::start_cache_cleanup_task(cache_clone).await;
    });

    // Initialize backpressure system
    let backpressure_config = auth_service::backpressure::BackpressureConfig::from_env();
    let backpressure_state =
        Arc::new(auth_service::backpressure::BackpressureState::new(backpressure_config));
    tracing::info!("Backpressure system initialized");

    // Create application state
    let app_state = AppState {
        store,
        client_credentials: cfg.client_credentials.clone(),
        allowed_scopes: cfg.allowed_scopes.clone(),
        policy_cache,
        backpressure_state,
    };

    // Build application with OpenAPI documentation
    let openapi = ApiDoc::openapi();
    let app = app(app_state.clone())
        .route("/openapi.json", axum::routing::get(|| async move { axum::Json(openapi) }));

    // Start background services
    tokio::spawn(async {
        auth_service::rate_limit_optimized::start_rate_limit_cleanup_task().await;
    });

    tokio::spawn(async {
        auth_service::security_monitoring::init_security_monitoring().await;
    });

    // Start enhanced session cleanup scheduler with graceful shutdown
    use auth_service::session_cleanup::{
        create_and_start_session_cleanup, SessionCleanupConfig, ShutdownSignal,
    };
    use auth_service::session_manager::{SessionConfig, SessionManager};

    let session_cleanup_config = SessionCleanupConfig::default();
    let session_manager = Arc::new(SessionManager::new(SessionConfig::default()));

    tokio::spawn(async move {
        match create_and_start_session_cleanup(session_cleanup_config, session_manager).await {
            Ok(scheduler) => {
                tracing::info!("Session cleanup scheduler started successfully");
                tokio::signal::ctrl_c().await.ok();
                if let Err(e) = scheduler.shutdown(ShutdownSignal::Graceful).await {
                    tracing::warn!(error = %e, "Failed to shutdown session cleanup gracefully");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to start session cleanup scheduler");
            }
        }
    });

    // Start server
    let listener = TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!(
        bind_addr = %cfg.bind_addr,
        rate_limit = cfg.rate_limit_requests_per_minute,
        token_expiry = cfg.token_expiry_seconds,
        "Auth service started successfully"
    );

    // Graceful shutdown handling
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;

    tracing::info!("Auth service shutdown complete");
    Ok(())
}

/// Handle graceful shutdown signals
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        },
    }
}
