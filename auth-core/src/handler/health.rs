//! Health check endpoints

use axum::{extract::State, http::StatusCode, response::Json};
use serde_json::json;

use crate::server::AppState;

/// Simple health check endpoint
pub async fn health_check() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "status": "healthy",
            "version": crate::VERSION,
            "uptime": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        })),
    )
}

/// Kubernetes-style readiness check
pub async fn readiness_check(
    State(_state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    // In a real implementation, you might check:
    // - Database connectivity
    // - External service health
    // - Memory usage
    // For the minimal version, we're always ready

    (
        StatusCode::OK,
        Json(json!({
            "status": "ready",
            "checks": {
                "memory_store": "ok",
                "token_generation": "ok"
            }
        })),
    )
}
