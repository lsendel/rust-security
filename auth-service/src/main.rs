//! Main entry point for the Auth Service.
//!
//! This service provides authentication, key management, and token storage.
//! It is designed with security best practices and modularity in mind.

use tokio::net::TcpListener;
mod config;

use auth_service::{
    app,
    keys, // Add keys module import
    store::{redis_store, TokenStore},
    ApiDoc,
    AppState,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
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
    config::validate_production_secrets();

    // Load configuration
    let cfg = config::AppConfig::from_env()?;
    tracing::info!("Starting auth-service with configuration loaded");

    // Initialize secure keys (fixes RSA vulnerability RUSTSEC-2023-0071)
    tracing::info!("Initializing secure key management...");
    if let Err(e) = keys::initialize_keys().await {
        tracing::error!(error = %e, "Failed to initialize secure keys");
        return Err(anyhow::anyhow!("Key initialization failed: {}", e));
    }
    tracing::info!("Secure key management initialized successfully");

    // Initialize token store
    let token_store = if let Some(url) = &cfg.redis_url {
        match redis_store(url).await {
            Ok(s) => {
                tracing::info!("Connected to Redis token store");
                s
            }
            Err(err) => {
                tracing::warn!(error = %err, "Redis unavailable, using in-memory store");
                TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())))
            }
        }
    } else {
        tracing::info!("Using in-memory token store");
        TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())))
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
        token_store,
        client_credentials: cfg.client_credentials.clone(),
        allowed_scopes: cfg.allowed_scopes.clone(),
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
        policy_cache,
        backpressure_state,
    };

    // Build application with OpenAPI documentation
    let openapi = ApiDoc::openapi();
    let app = app(app_state)
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

                // Store scheduler reference for graceful shutdown
                // In a real application, you'd want to store this in the app state
                // for proper shutdown coordination

                // Keep the scheduler running until shutdown
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
