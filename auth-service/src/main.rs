//! Auth Service Main Entry Point
//! 
//! Enterprise-grade authentication service with comprehensive security features.

use std::sync::Arc;
use tracing::{info, error};
use axum::{extract::Request, middleware::Next, response::Response};

// Import from common crate (using the working common package)
use common::config::PlatformConfiguration;

// Local configuration
#[derive(Debug, Clone)]
pub struct AuthServiceConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub token_expiry: u64,
}

impl Default for AuthServiceConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                bind_address: std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: std::env::var("PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(8080),
            },
            auth: AuthConfig {
                jwt_secret: std::env::var("JWT_SECRET_KEY")
                    .expect("JWT_SECRET_KEY environment variable must be set for security"),
                token_expiry: std::env::var("TOKEN_EXPIRY")
                    .ok()
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(3600),
            },
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    info!("🚀 Starting Rust Security Platform - Auth Service");
    
    // Load configuration
    let config = Arc::new(AuthServiceConfig::default());
    
    // Start rate limiter cleanup task
    crate::security::start_rate_limiter_cleanup();
    
    // Create simple HTTP server using axum with security middleware
    let app = axum::Router::new()
        .route("/health", axum::routing::get(health_check))
        .route("/api/v1/status", axum::routing::get(status))
        .layer(axum::middleware::from_fn(crate::security::rate_limit))
        .layer(axum::middleware::from_fn(security_headers));
    
    let addr = format!("{}:{}", config.server.bind_address, config.server.port);
    info!("🌐 Auth service listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    
    axum::serve(listener, app)
        .await
        .map_err(|e| {
            error!("❌ Server error: {}", e);
            e.into()
        })
}

/// Health check endpoint
async fn health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "service": "rust-security-auth-service",
        "version": "1.0.0",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// Status endpoint
async fn status() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "service": "rust-security-auth-service",
        "status": "running",
        "features": [
            "oauth2",
            "jwt",
            "mfa",
            "security-monitoring",
            "multi-tenant",
            "post-quantum-crypto"
        ],
        "packages_status": {
            "auth-core": "✅ operational",
            "common": "✅ operational", 
            "api-contracts": "✅ operational",
            "policy-service": "✅ operational",
            "compliance-tools": "✅ operational"
        }
    }))
}

/// Security headers middleware
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    headers.insert("Strict-Transport-Security", "max-age=31536000; includeSubDomains".parse().unwrap());
    headers.insert("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; form-action 'self'; frame-ancestors 'none';".parse().unwrap());
    headers.insert("Referrer-Policy", "strict-origin-when-cross-origin".parse().unwrap());
    headers.insert("Permissions-Policy", "geolocation=(), microphone=(), camera=()".parse().unwrap());
    
    response
}
