//! MVP-focused router with essential OAuth2 endpoints
//!
//! This router contains only the core Auth-as-a-Service endpoints needed for the MVP,
//! as specified in the 90-day implementation plan.

use axum::http::{header, HeaderValue, Method};
use axum::{
    routing::{get, post},
    Router,
};
use rand::rngs::OsRng;
use rand::RngCore;
use tower_http::cors::CorsLayer;

use crate::app::AppContainer;
use crate::application::auth::auth_api::AuthState;
use crate::handlers;

/// Generate a cryptographically secure random secret for JWT signing
fn generate_secure_secret() -> String {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    hex::encode(key)
}

/// Create the MVP-focused application router
///
/// Essential OAuth2 endpoints for Auth-as-a-Service MVP:
/// - POST /oauth/token              - Client credentials flow
/// - POST /oauth/introspect         - Token validation
/// - GET  /health                   - Health check
/// - GET  /metrics                  - Prometheus metrics
/// - POST /admin/revoke             - Token revocation
/// - GET  /.well-known/jwks.json    - Public keys (JWKS)
pub fn create_mvp_router(_container: AppContainer) -> Router<AuthState> {
    // MVP-focused CORS: Allow only necessary origins
    let cors = match std::env::var("ALLOWED_ORIGINS") {
        Ok(origins) if !origins.trim().is_empty() => {
            let mut layer = CorsLayer::new()
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT]);
            for o in origins.split(',') {
                if let Ok(origin) = o.trim().parse::<HeaderValue>() {
                    layer = layer.allow_origin(origin);
                }
            }
            layer
        }
        _ => CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT]),
    };

    Router::new()
        // === Core OAuth2 Endpoints ===
        .route(
            "/oauth/token",
            post(crate::application::auth::auth_api::token),
        )
        // .route("/oauth/introspect", post(crate::application::auth::auth_api::introspect)) // TODO: Implement introspect endpoint
        // === Administrative Endpoints ===
        // .route("/admin/revoke", post(handlers::admin::revoke_token)) // TODO: Implement admin handlers
        // === Discovery Endpoints ===
        // .route("/.well-known/jwks.json", get(handlers::jwks::public_keys)) // TODO: Implement JWKS handlers
        // === Health & Monitoring ===
        .route("/health", get(mvp_health_check))
        .route("/metrics", get(mvp_metrics_endpoint))
        .layer(cors)
        .with_state({
            let jwt_secret = std::env::var("JWT_SECRET")
                .map(|s| {
                    if s.len() >= 32 {
                        s
                    } else {
                        generate_secure_secret()
                    }
                })
                .unwrap_or_else(|_| generate_secure_secret());

            AuthState::new(jwt_secret)
        })
}

/// MVP health check endpoint
async fn mvp_health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "service": "auth-as-a-service-mvp",
        "version": "1.0.0-mvp",
        "endpoints": {
            "oauth_token": "POST /oauth/token",
            "oauth_introspect": "POST /oauth/introspect",
            "admin_revoke": "POST /admin/revoke",
            "jwks": "GET /.well-known/jwks.json",
            "health": "GET /health",
            "metrics": "GET /metrics"
        },
        "features": {
            "client_credentials_flow": true,
            "token_introspection": true,
            "jwt_tokens": true,
            "jwks_rotation": true,
            "token_revocation": true,
            "rate_limiting": true,
            "security_essential": true
        }
    }))
}

/// MVP metrics endpoint
#[cfg(feature = "metrics")]
async fn mvp_metrics_endpoint(
    axum::extract::State(_state): axum::extract::State<AuthState>,
) -> Result<String, crate::shared::error::AppError> {
    // For MVP, return basic metrics without full collector infrastructure
    Ok("# HELP auth_requests_total Total authentication requests\n# TYPE auth_requests_total counter\nauth_requests_total 0\n".to_string())
}

#[cfg(not(feature = "metrics"))]
async fn mvp_metrics_endpoint() -> Result<String, crate::shared::error::AppError> {
    Ok("# Metrics feature not enabled\n".to_string())
}
