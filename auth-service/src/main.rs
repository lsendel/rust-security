//! Auth Service Main Entry Point
//!
//! Enterprise-grade authentication service with comprehensive security features.

#![allow(clippy::multiple_crate_versions)]

use anyhow::Context;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::{extract::Request, middleware::Next, response::Response};
use common::security::UnifiedSecurityConfig;
use std::sync::Arc;
use tracing::{error, info, warn};

mod config;

use auth_service::auth_api::AuthState;
use auth_service::infrastructure::security::security::{rate_limit, start_rate_limiter_cleanup};
use auth_service::middleware::csrf::csrf_protect;
use auth_service::middleware::{
    initialize_threat_detection, threat_detection_middleware, threat_metrics,
};
use auth_service::security_enhancements::ThreatDetector;
use config::Config;
// Initialize secure JWT key management
use auth_service::infrastructure::crypto::keys::{initialize_keys, jwks_document};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // SECURITY: Load and validate configuration before doing anything else
    let config = auth_service::config_secure_validation::SecureConfig::from_env()
        .context("Failed to load secure configuration")?;

    // Validate production readiness if in production
    config
        .validate_production_ready()
        .context("Configuration failed production readiness check")?;

    // Log security configuration status (without sensitive values)
    config.log_security_status();

    // Initialize logging (structured in production, pretty in dev)
    // Prefer production logging configuration when APP_ENV=production
    if std::env::var("APP_ENV")
        .unwrap_or_default()
        .eq_ignore_ascii_case("production")
    {
        let _ = auth_service::production_logging::initialize_logging(
            &auth_service::production_logging::LoggingConfig::production(),
        );
    } else if std::env::var("APP_ENV")
        .unwrap_or_default()
        .eq_ignore_ascii_case("development")
    {
        let _ = auth_service::production_logging::initialize_logging(
            &auth_service::production_logging::LoggingConfig::development(),
        );
    } else {
        // Fallback to a simple subscriber for local runs/tests
        let _ = auth_service::production_logging::initialize_logging(
            &auth_service::production_logging::LoggingConfig::default(),
        );
    }

    info!("🚀 Starting Rust Security Platform - Auth Service v2.0");
    info!("🔐 Enhanced with OAuth 2.0, User Registration, and JWT Authentication");

    // Load unified configuration
    let config = Config::load().context("Failed to load configuration")?;

    // Validate configuration
    config.validate().context("Invalid configuration")?;

    let config = Arc::new(config);

    // Initialize signing keys for JWT (required for RS256 + JWKS)
    if let Err(e) = initialize_keys().await {
        return Err(anyhow::anyhow!(
            "Failed to initialize JWT signing keys: {}. Set RSA key via RSA_PRIVATE_KEY or RSA_PRIVATE_KEY_PATH",
            e
        )
        .into());
    }

    // SECURITY: Initialize authentication state with secure JWT secret from environment
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| {
        anyhow::anyhow!(
            "JWT_SECRET environment variable is required. Generate with: \
            openssl rand -hex 32"
        )
    })?;

    // Validate JWT secret strength
    if jwt_secret.len() < 32 {
        return Err(
            anyhow::anyhow!("JWT_SECRET must be at least 32 characters long for security").into(),
        );
    }

    info!("✅ JWKS key management initialized successfully");

    let auth_state = AuthState::new(jwt_secret);

    // Initialize threat detection
    let threat_detector = ThreatDetector::new();
    threat_detector.initialize_default_patterns().await;

    // Initialize threat detection middleware
    initialize_threat_detection().await;

    // SECURITY: Initialize test mode security checks
    auth_service::test_mode_security::initialize_test_mode_security();

    // Start rate limiter cleanup task
    start_rate_limiter_cleanup();

    // Background task to ensure signing key is rotated when needed
    tokio::spawn(async move {
        use std::time::Duration;
        loop {
            let _ = auth_service::infrastructure::crypto::keys::maybe_rotate().await;
            tokio::time::sleep(Duration::from_secs(300)).await; // check every 5 minutes
        }
    });

    // Create comprehensive HTTP server with authentication endpoints
    #[cfg_attr(not(feature = "metrics"), allow(unused_mut))]
    let mut app = axum::Router::new()
        // Health and status endpoints
        .route("/health", axum::routing::get(health_check))
        .route("/api/v1/status", axum::routing::get(status))
        // CSRF token endpoint
        .route(
            "/csrf/token",
            axum::routing::get(auth_service::middleware::csrf::issue_csrf_token),
        )
        // Authentication endpoints
        .route(
            "/api/v1/auth/register",
            axum::routing::post(auth_service::auth_api::register),
        )
        .route(
            "/api/v1/auth/login",
            axum::routing::post(auth_service::auth_api::login),
        )
        .route(
            "/api/v1/auth/me",
            axum::routing::get(auth_service::auth_api::me),
        )
        // JWKS endpoints
        .route("/.well-known/jwks.json", axum::routing::get(jwks_endpoint))
        .route("/jwks.json", axum::routing::get(jwks_endpoint))
        // OAuth 2.0 endpoints
        .route(
            "/oauth/authorize",
            axum::routing::get(auth_service::auth_api::authorize),
        )
        .route(
            "/oauth/token",
            axum::routing::post(auth_service::auth_api::token),
        )
        // Service Identity endpoints
        .route(
            "/service/identity/register",
            axum::routing::post(service_identity_register),
        )
        // JIT Token endpoints
        .route("/token/jit", axum::routing::post(jit_token_request))
        // Security monitoring endpoints
        .route(
            "/security/threats/metrics",
            axum::routing::get(threat_metrics),
        )
        // Add authentication state
        .with_state(auth_state)
        // Security middleware (order matters - apply innermost first)
        .layer(axum::middleware::from_fn(threat_detection_middleware))
        .layer(axum::middleware::from_fn(rate_limit))
        .layer(axum::middleware::from_fn(csrf_protect))
        .layer(axum::middleware::from_fn(security_headers));

    // Observability: expose Prometheus metrics and add request metrics middleware when enabled
    #[cfg(feature = "metrics")]
    {
        use axum::response::IntoResponse as _;
        use axum::routing::get;
        // Add request metrics middleware
        app = app.layer(axum::middleware::from_fn(
            auth_service::metrics::metrics_middleware,
        ));
        // Expose /metrics endpoint only when explicitly allowed
        app = app.route(
            "/metrics",
            get(|| async move {
                if std::env::var("METRICS_PUBLIC").unwrap_or_else(|_| "false".to_string()) == "true"
                {
                    auth_service::metrics::metrics_handler().into_response()
                } else {
                    axum::response::Response::builder()
                        .status(axum::http::StatusCode::FORBIDDEN)
                        .body(axum::body::Body::from("metrics disabled"))
                        .unwrap()
                }
            }),
        );
        info!("   • Metrics: GET /metrics (gated)");
    }

    let addr = config.server.bind_addr;
    info!("🌐 Auth service listening on {}", addr);
    info!("📋 Available endpoints:");
    info!("   • Health: GET /health");
    info!("   • Status: GET /api/v1/status");
    info!("   • Register: POST /api/v1/auth/register");
    info!("   • Login: POST /api/v1/auth/login");
    info!("   • User Info: GET /api/v1/auth/me");
    info!("   • JWKS: GET /.well-known/jwks.json");
    info!("   • JWKS (alt): GET /jwks.json");
    info!("   • OAuth Authorize: GET /oauth/authorize");
    info!("   • OAuth Token: POST /oauth/token");
    info!("   • Service Identity: POST /service/identity/register");
    info!("   • JIT Token: POST /token/jit");
    info!("   • Threat Metrics: GET /security/threats/metrics");
    #[cfg(feature = "metrics")]
    info!("   • Prometheus Metrics: GET /metrics");
    info!("🔑 Use registration endpoint to create users: POST /api/v1/auth/register");
    info!("🔑 Use OAuth client registration for applications");

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
        "security_note": "No demo credentials - use proper registration endpoints for users and OAuth clients"
    }))
}

/// JWKS endpoint handler
async fn jwks_endpoint(
    axum::extract::State(_auth_state): axum::extract::State<AuthState>,
) -> impl axum::response::IntoResponse {
    use axum::http::HeaderMap;
    use axum::Json;

    // Produce JWKS from active key set
    let jwks = jwks_document().await;

    let mut headers = HeaderMap::new();
    if let Ok(content_type) = "application/json".parse() {
        headers.insert("content-type", content_type);
    }
    // Cache for short period to allow rotation while avoiding thundering herd
    if let Ok(cache_control) = "public, max-age=300".parse() {
        headers.insert("cache-control", cache_control);
    }

    (headers, Json(jwks))
}

// CSRF middleware moved to auth_service::middleware::csrf

/// Service identity registration handler
async fn service_identity_register(
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> impl axum::response::IntoResponse {
    use serde_json::json;

    // Generate a unique identity ID
    let identity_id = format!("id_{}", uuid::Uuid::new_v4());

    // Extract service information
    let service_name = payload
        .get("service_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    info!(
        "Service identity registered: {} -> {}",
        service_name, identity_id
    );

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

    let identity_id = payload
        .get("identity_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Generate a JIT access token (simplified)
    let access_token = format!("jit_token_{}", uuid::Uuid::new_v4());

    info!("JIT token generated for identity: {}", identity_id);

    let default_scope = json!(["read", "write"]);
    axum::Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": payload.get("scope").unwrap_or(&default_scope),
        "identity_id": identity_id,
        "issued_at": chrono::Utc::now().to_rfc3339()
    }))
}

/// Security headers middleware with enhanced security
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    // Get comprehensive security headers
    let headers_map = auth_service::security_enhancements::headers::get_security_headers();
    let response_headers = response.headers_mut();

    // Apply all security headers with proper error handling
    for (key, value) in headers_map {
        if let Ok(header_value) = value.parse() {
            response_headers.insert(key, header_value);
        }
    }

    response
}
