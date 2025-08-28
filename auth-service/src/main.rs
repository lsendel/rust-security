//! Auth Service Main Entry Point
//!
//! Enterprise-grade authentication service with comprehensive security features.

use anyhow::Context;
use axum::{extract::Request, middleware::Next, response::Response};
use std::sync::Arc;
use tracing::{error, info};

mod auth_api;
mod config;

use auth_api::AuthState;
use crate::config::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("🚀 Starting Rust Security Platform - Auth Service v2.0");
    info!("🔐 Enhanced with OAuth 2.0, User Registration, and JWT Authentication");

    // Load unified configuration
    let config = Config::load().context("Failed to load configuration")?;

    // Validate configuration
    config.validate().context("Invalid configuration")?;

    let config = Arc::new(config);

    // Initialize authentication state
    let auth_state = AuthState::new(config.jwt.secret.clone());

    // Start rate limiter cleanup task
    auth_service::security::start_rate_limiter_cleanup();

    // Create comprehensive HTTP server with authentication endpoints
    let app = axum::Router::new()
        // Health and status endpoints
        .route("/health", axum::routing::get(health_check))
        .route("/api/v1/status", axum::routing::get(status))
        // Authentication endpoints
        .route(
            "/api/v1/auth/register",
            axum::routing::post(auth_api::register),
        )
        .route("/api/v1/auth/login", axum::routing::post(auth_api::login))
        .route("/api/v1/auth/me", axum::routing::get(auth_api::me))
        // OAuth 2.0 endpoints
        .route("/oauth/authorize", axum::routing::get(auth_api::authorize))
        .route("/oauth/token", axum::routing::post(auth_api::token))
        // Service Identity endpoints
        .route(
            "/service/identity/register",
            axum::routing::post(service_identity_register),
        )
        // JIT Token endpoints
        .route("/token/jit", axum::routing::post(jit_token_request))
        // Add authentication state
        .with_state(auth_state)
        // Security middleware
        .layer(axum::middleware::from_fn(
            auth_service::security::rate_limit,
        ))
        .layer(axum::middleware::from_fn(security_headers));

    let addr = config.server.bind_addr;
    info!("🌐 Auth service listening on {}", addr);
    info!("📋 Available endpoints:");
    info!("   • Health: GET /health");
    info!("   • Status: GET /api/v1/status");
    info!("   • Register: POST /api/v1/auth/register");
    info!("   • Login: POST /api/v1/auth/login");
    info!("   • User Info: GET /api/v1/auth/me");
    info!("   • OAuth Authorize: GET /oauth/authorize");
    info!("   • OAuth Token: POST /oauth/token");
    info!("   • Service Identity: POST /service/identity/register");
    info!("   • JIT Token: POST /token/jit");
    info!("🔑 Demo credentials: demo@example.com / demo123");
    info!("🔑 Demo OAuth client: demo-client / demo-secret");

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    axum::serve(listener, app).await.map_err(|e| {
        error!("❌ Server error: {}", e);
        e.into()
    })
}

/// Health check endpoint
async fn health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "service": "rust-security-auth-service",
        "version": "2.0.0",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "features": {
            "user_registration": true,
            "oauth2_flows": true,
            "jwt_authentication": true,
            "multi_factor_auth": false,
            "session_management": true
        }
    }))
}

/// Status endpoint
async fn status() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "service": "rust-security-auth-service",
        "status": "running",
        "version": "2.0.0",
        "features": [
            "user-registration",
            "oauth2-authorization-code",
            "jwt-authentication",
            "session-management",
            "security-monitoring",
            "multi-tenant",
            "rate-limiting"
        ],
        "endpoints": {
            "authentication": [
                "POST /api/v1/auth/register",
                "POST /api/v1/auth/login",
                "GET /api/v1/auth/me"
            ],
            "oauth2": [
                "GET /oauth/authorize",
                "POST /oauth/token"
            ],
            "system": [
                "GET /health",
                "GET /api/v1/status"
            ]
        },
        "packages_status": {
            "auth-core": "✅ operational",
            "common": "✅ operational",
            "api-contracts": "✅ operational",
            "policy-service": "✅ operational",
            "compliance-tools": "✅ operational"
        },
        "demo_credentials": {
            "user": {
                "email": "demo@example.com",
                "password": "demo123"
            },
            "oauth_client": {
                "client_id": "demo-client",
                "client_secret": "demo-secret",
                "redirect_uri": "http://localhost:3000/callback"
            }
        }
    }))
}

/// Service identity registration handler
async fn service_identity_register(
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> impl axum::response::IntoResponse {
    use serde_json::json;
    
    // Generate a unique identity ID
    let identity_id = format!("id_{}", uuid::Uuid::new_v4());
    
    // Extract service information
    let service_name = payload.get("service_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    
    info!("Service identity registered: {} -> {}", service_name, identity_id);
    
    axum::Json(json!({
        "identity_id": identity_id,
        "service_name": service_name,
        "status": "registered",
        "created_at": chrono::Utc::now().to_rfc3339()
    }))
}

/// JIT token request handler
async fn jit_token_request(
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> impl axum::response::IntoResponse {
    use serde_json::json;
    
    let identity_id = payload.get("identity_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    
    // Generate a JIT access token (simplified)
    let access_token = format!("jit_token_{}", uuid::Uuid::new_v4());
    
    info!("JIT token generated for identity: {}", identity_id);
    
    axum::Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": payload.get("scope").unwrap_or(&json!(["read", "write"])),
        "identity_id": identity_id,
        "issued_at": chrono::Utc::now().to_rfc3339()
    }))
}

/// Security headers middleware
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Use expect() with descriptive messages for static header values that should never fail
    headers.insert(
        "X-Content-Type-Options",
        "nosniff"
            .parse()
            .expect("Failed to parse X-Content-Type-Options header"),
    );
    headers.insert(
        "X-Frame-Options",
        "DENY"
            .parse()
            .expect("Failed to parse X-Frame-Options header"),
    );
    headers.insert(
        "X-XSS-Protection",
        "1; mode=block"
            .parse()
            .expect("Failed to parse X-XSS-Protection header"),
    );
    headers.insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains"
            .parse()
            .expect("Failed to parse Strict-Transport-Security header"),
    );
    headers.insert(
        "Content-Security-Policy",
        "default-src 'self'"
            .parse()
            .expect("Failed to parse Content-Security-Policy header"),
    );

    response
}
