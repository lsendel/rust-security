//! API module for auth-service
//!
//! This module contains the main API endpoints and handlers for the authentication service.

use axum::{response::Json, Router};
use serde_json::{json, Value};

/// Create the main API router
pub fn create_router() -> Router {
    Router::new()
        .route("/health", axum::routing::get(health_check))
        .route("/api/v1/status", axum::routing::get(status))
}

/// Health check endpoint
pub async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "auth-service",
        "version": "1.0.0"
    }))
}

/// Status endpoint
pub async fn status() -> Json<Value> {
    Json(json!({
        "service": "auth-service",
        "status": "running",
        "features": [
            "oauth2",
            "jwt",
            "mfa",
            "security-monitoring"
        ]
    }))
}
