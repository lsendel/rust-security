//! Minimal Auth Service for E2E Testing
//! Simplified version for CI/CD and E2E tests

// Acknowledge unused dependencies for future functionality
#[allow(unused_imports)]
use argon2 as _;
#[allow(unused_imports)]
use async_trait as _;
#[allow(unused_imports)]
use auth_service as _;
#[allow(unused_imports)]
use base64 as _;
#[allow(unused_imports)]
use bcrypt as _;
#[allow(unused_imports)]
use bytes as _;
#[allow(unused_imports)]
use chrono as _;
#[allow(unused_imports)]
use common as _;
#[allow(unused_imports)]
use dashmap as _;
#[allow(unused_imports)]
use data_encoding as _;
#[allow(unused_imports)]
use deadpool_redis as _;
#[allow(unused_imports)]
use dotenvy as _;
#[allow(unused_imports)]
use ed25519_dalek as _;
#[allow(unused_imports)]
use envy as _;
#[allow(unused_imports)]
use futures as _;
#[allow(unused_imports)]
use hex as _;
#[allow(unused_imports)]
use hmac as _;
#[allow(unused_imports)]
use http as _;
#[allow(unused_imports)]
use jsonwebtoken as _;
#[allow(unused_imports)]
use lazy_static as _;
#[allow(unused_imports)]
use num_cpus as _;
#[allow(unused_imports)]
use once_cell as _;
#[allow(unused_imports)]
use prometheus as _;
#[allow(unused_imports)]
use rand as _;
#[allow(unused_imports)]
use redis as _;
#[allow(unused_imports)]
use regex as _;
#[allow(unused_imports)]
use reqwest as _;
#[allow(unused_imports)]
use ring as _;
#[allow(unused_imports)]
use serde_json as _;
#[allow(unused_imports)]
use serde_yaml as _;
#[allow(unused_imports)]
use sha1 as _;
#[allow(unused_imports)]
use sha2 as _;
#[allow(unused_imports)]
use sqlx as _;
#[allow(unused_imports)]
use thiserror as _;
#[allow(unused_imports)]
use toml as _;
#[allow(unused_imports)]
use tower as _;
#[allow(unused_imports)]
use tower_http as _;
#[allow(unused_imports)]
use url as _;
#[allow(unused_imports)]
use urlencoding as _;
#[allow(unused_imports)]
use utoipa as _;
#[allow(unused_imports)]
use validator as _;

use axum::{
    extract::Query,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    error_description: String,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        service: "auth-service".to_string(),
        version: "1.0.0".to_string(),
    })
}

async fn token(
    Query(params): Query<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Simple validation for E2E testing
    if params.grant_type != "client_credentials" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "unsupported_grant_type".to_string(),
                error_description: "Only client_credentials grant type is supported".to_string(),
            }),
        ));
    }

    // Accept any valid-looking credentials for testing
    if params.client_id.is_empty() || params.client_secret.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client authentication failed".to_string(),
            }),
        ));
    }

    // Generate a test token
    let token = format!("test_token_{}", uuid::Uuid::new_v4());

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        scope: params.scope,
    }))
}

fn create_app() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/oauth/token", post(token))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Check for migration flag
    if std::env::args().any(|arg| arg == "--migrate-config") {
        tracing::info!("Running configuration migration...");
        auth_service::config_migration::run_migration()?;
        return Ok(());
    }

    // Initialize static configuration
    let config_manager = auth_service::config_static::ConfigManager::new()?;
    tracing::info!(
        "Loaded static configuration for environment: {:?}",
        config_manager.environment
    );
    tracing::info!(
        "Server will bind to: {}",
        config_manager.static_config.server.bind_addr
    );

    let app = create_app();

    // Use bind address from static config
    let addr = &config_manager.static_config.server.bind_addr;
    tracing::info!(
        "Auth service starting on {} using static configuration",
        addr
    );

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
