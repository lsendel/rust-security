//! Application Router
//!
//! Configures the HTTP routes for the application.

use axum::{
    routing::{get, post},
    Router,
};
use axum::http::{header, HeaderValue, Method};
use tower_http::cors::CorsLayer;

use crate::app::AppContainer;
use crate::handlers;
// use crate::modules::monitoring::{HealthChecker, MetricsCollector, MetricsMiddleware};  // Modules temporarily disabled

/// Create the application router
pub fn create_router(container: AppContainer) -> Router {
    // Secure CORS: default deny; allow only if ALLOWED_ORIGINS is set
    let cors = match std::env::var("ALLOWED_ORIGINS") {
        Ok(origins) if !origins.trim().is_empty() => {
            let mut layer = CorsLayer::new()
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
            for o in origins.split(',') {
                if let Ok(origin) = o.trim().parse::<HeaderValue>() {
                    layer = layer.allow_origin(origin);
                }
            }
            layer
        }
        _ => CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
    };

    // Create metrics middleware
    // let metrics_middleware = MetricsMiddleware::new(container.metrics_collector.clone());  // Temporarily disabled

    Router::new()
        .route("/api/v1/auth/register", post(handlers::auth::register))
        .route("/api/v1/auth/login", post(handlers::auth::login))
        .route("/api/v1/auth/me", get(handlers::auth::me))
        .route("/api/v1/auth/logout", post(handlers::auth::logout))
        .route("/health", get(health_check))
        .route("/health/detailed", get(detailed_health_check))
        .route("/metrics", get(metrics_endpoint))
        // .layer(metrics_middleware)  // Temporarily disabled
        .layer(cors)
        .with_state(container)
}

/// Basic health check endpoint
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

/// Detailed health check endpoint using the monitoring system
async fn detailed_health_check(
    axum::extract::State(container): axum::extract::State<AppContainer>,
) -> Result<axum::Json<serde_json::Value>, crate::shared::error::AppError> {
    let health_status = container.health_checker.check_health().await
        .map_err(|e| crate::shared::error::AppError::Internal(e.to_string()))?;
    Ok(axum::Json(serde_json::json!(health_status)))
}

/// Prometheus metrics endpoint
async fn metrics_endpoint(
    axum::extract::State(container): axum::extract::State<AppContainer>,
) -> Result<String, crate::shared::error::AppError> {
    let metrics = container.metrics_collector.gather_metrics().await
        .map_err(|e| crate::shared::error::AppError::Internal(e.to_string()))?;
    Ok(metrics.to_string())
}
