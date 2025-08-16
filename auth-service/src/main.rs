use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
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
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,auth_service=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
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
    axum::serve(listener, app).await?;

    tracing::info!("Auth service shutdown complete");
    Ok(())
}
