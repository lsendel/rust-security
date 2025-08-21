//! Main entry point for the Auth Service.
//!
//! This service provides authentication, key management, and token storage.
//! It is designed with security best practices and modularity in mind.

use tokio::net::TcpListener;

use anyhow;
use auth_service::{
    app,
    config::{AppConfig, StoreBackend},
    config_reload::{ConfigReloadEvent, ConfigReloadManager},
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

    // Load configuration
    let cfg = AppConfig::from_env()?;
    tracing::info!("Starting auth-service with configuration loaded");

    // Initialize configuration reload manager
    let config_path = std::env::var("CONFIG_FILE").ok();
    let (config_manager, mut config_events) = ConfigReloadManager::new(cfg.clone(), config_path);
    let config_manager = Arc::new(config_manager);

    // Start configuration reload handler
    let reload_manager = Arc::clone(&config_manager);
    reload_manager.start_reload_handler().await?;

    // Spawn configuration event handler
    let event_manager = Arc::clone(&config_manager);
    tokio::spawn(async move {
        while let Ok(event) = config_events.recv().await {
            match event {
                ConfigReloadEvent::ReloadRequested => {
                    tracing::info!("Configuration reload requested");
                }
                ConfigReloadEvent::ReloadSuccess { version, changes } => {
                    tracing::info!(
                        "Configuration reload successful (version: {}, changes: {})",
                        version,
                        changes.len()
                    );
                    for change in changes {
                        tracing::info!("Configuration change: {}", change);
                    }
                }
                ConfigReloadEvent::ReloadFailed { error, fallback_used } => {
                    tracing::error!(
                        "Configuration reload failed: {} (fallback used: {})",
                        error,
                        fallback_used
                    );
                }
                ConfigReloadEvent::ValidationFailed { errors } => {
                    tracing::error!("Configuration validation failed: {:?}", errors);
                }
            }
        }
    });

    tracing::info!("Configuration reload manager initialized");

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
            let db_url =
                cfg.store.database_url.as_ref().expect("DATABASE_URL is checked in config");
            let sql_store = SqlStore::new(db_url)
                .await
                .map_err(|e| anyhow::anyhow!("SqlStore creation failed: {}", e))?;
            sql_store
                .run_migrations()
                .await
                .map_err(|e| anyhow::anyhow!("Migration failed: {}", e))?;
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

    // Initialize API key store
    let api_key_db_url =
        std::env::var("API_KEY_DATABASE_URL").unwrap_or_else(|_| "sqlite:api_keys.db".to_string());
    let api_key_store = auth_service::api_key_store::ApiKeyStore::new(&api_key_db_url)
        .await
        .expect("Failed to initialize API key store");

    // Initialize session store (using simple fallback for now)
    // TODO: Re-enable Redis session store once Redis compatibility is resolved
    use auth_service::session_store::{RedisSessionStore, SessionStore};
    let redis_url = std::env::var("REDIS_URL").ok();
    let session_store = Arc::new(
        RedisSessionStore::new(None).await  // Use memory-only for now
    ) as Arc<dyn SessionStore>;

    // Create application state
    let app_state = AppState {
        store,
        session_store: session_store.clone(),
        client_credentials: cfg.client_credentials.clone(),
        allowed_scopes: cfg.allowed_scopes.clone(),
        policy_cache,
        backpressure_state,
        api_key_store,
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

    // Start session store cleanup task
    tokio::spawn({
        let session_store = session_store.clone();
        async move {
            auth_service::session_store::start_session_cleanup_task(session_store).await;
        }
    });

    // Start database cleanup task for SQL stores
    if matches!(cfg.store.backend, StoreBackend::Sql) {
        tokio::spawn({
            let store = store.clone();
            async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Every hour
                loop {
                    interval.tick().await;
                    // Try to downcast to SqlStore to call cleanup
                    if let Some(sql_store) = store.as_any().downcast_ref::<SqlStore>() {
                        if let Err(e) = sql_store.cleanup_expired_data().await {
                            tracing::error!("Database cleanup failed: {}", e);
                        }
                    }
                }
            }
        });
    }

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
