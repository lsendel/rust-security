mod config;

use std::{collections::HashMap, sync::Arc};

use auth_service::{
    app, keys, // Key management module
    store::{redis_store, TokenStore},
    ApiDoc, AppState,
};
use tokio::{net::TcpListener, sync::RwLock};
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
    let backpressure_state = Arc::new(auth_service::backpressure::BackpressureState::new(backpressure_config));
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
    let app = app(app_state).route(
        "/openapi.json",
        axum::routing::get(|| async move { axum::Json(openapi) }),
    );

    // Start background services
    tokio::spawn(async {
        auth_service::rate_limit_optimized::start_rate_limit_cleanup_task().await;
    });

    tokio::spawn(async {
        auth_service::security_monitoring::init_security_monitoring().await;
    });

    tokio::spawn(async {
        auth_service::session_manager::start_session_cleanup_task().await;
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
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Auth service shutdown complete");
    Ok(())
}

/// Handle graceful shutdown signals
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
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
