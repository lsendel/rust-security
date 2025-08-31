//! Application Router
//!
//! Configures the HTTP routes for the application.

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

use crate::app::AppContainer;
use crate::handlers;

/// Create the application router
pub fn create_router(container: AppContainer) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/api/v1/auth/register", post(handlers::auth::register))
        .route("/api/v1/auth/login", post(handlers::auth::login))
        .route("/api/v1/auth/me", get(handlers::auth::me))
        .route("/api/v1/auth/logout", post(handlers::auth::logout))
        .route("/health", get(health_check))
        .layer(cors)
        .with_state(container)
}

/// Health check endpoint
async fn health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "service": "rust-security-auth-service",
        "version": "2.0.0",
        "features": {
            "user_registration": true,
            "oauth2_flows": true,
            "jwt_authentication": true,
            "multi_factor_auth": false,
            "session_management": true
        }
    }))
}
