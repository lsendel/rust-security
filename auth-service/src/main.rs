use tokio::net::TcpListener;
mod config;

use auth_service::{
    app,
    store::{redis_store, TokenStore},
    ApiDoc, AppState,
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

    // Load configuration
    let cfg = config::AppConfig::from_env()?;
    tracing::info!("Starting auth-service with configuration loaded");

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

    // Create application state
    let app_state = AppState {
        token_store,
        client_credentials: cfg.client_credentials.clone(),
        allowed_scopes: cfg.allowed_scopes.clone(),
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
    };

    // Build application with OpenAPI documentation
    let openapi = ApiDoc::openapi();
    let app = app(app_state).route(
        "/openapi.json",
        axum::routing::get(|| async move { axum::Json(openapi) }),
    );

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
