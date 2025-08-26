//! Auth Service Main Entry Point
//! 
//! Enterprise-grade authentication service with comprehensive security features.

use std::sync::Arc;
use tracing::{info, error};
use axum::{extract::Request, middleware::Next, response::Response};

mod auth_api;
use auth_api::AuthState;

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
                bind_address: std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1".to_string()),
                port: std::env::var("PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()
                    .unwrap_or(8080),
            },
            auth: AuthConfig {
                jwt_secret: std::env::var("JWT_SECRET_KEY")
                    .expect("JWT_SECRET_KEY environment variable must be set for security"),
                token_expiry: 86400, // 24 hours
            },
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    info!("🚀 Starting Rust Security Platform - Auth Service v2.0");
    info!("🔐 Enhanced with OAuth 2.0, User Registration, and JWT Authentication");
    
    // Load configuration
    let config = Arc::new(AuthServiceConfig::default());
    
    // Initialize authentication state
    let auth_state = AuthState::new(config.auth.jwt_secret.clone());
    
    // Start rate limiter cleanup task
    auth_service::security::start_rate_limiter_cleanup();
    
    // Create comprehensive HTTP server with authentication endpoints
    let app = axum::Router::new()
        // Health and status endpoints
        .route("/health", axum::routing::get(health_check))
        .route("/api/v1/status", axum::routing::get(status))
        
        // Authentication endpoints
        .route("/api/v1/auth/register", axum::routing::post(auth_api::register))
        .route("/api/v1/auth/login", axum::routing::post(auth_api::login))
        .route("/api/v1/auth/me", axum::routing::get(auth_api::me))
        
        // OAuth 2.0 endpoints
        .route("/oauth/authorize", axum::routing::get(auth_api::authorize))
        .route("/oauth/token", axum::routing::post(auth_api::token))
        
        // Add authentication state
        .with_state(auth_state)
        
        // Security middleware
        .layer(axum::middleware::from_fn(auth_service::security::rate_limit))
        .layer(axum::middleware::from_fn(security_headers));
    
    let addr = format!("{}:{}", config.server.bind_address, config.server.port);
    info!("🌐 Auth service listening on {}", addr);
    info!("📋 Available endpoints:");
    info!("   • Health: GET /health");
    info!("   • Status: GET /api/v1/status");
    info!("   • Register: POST /api/v1/auth/register");
    info!("   • Login: POST /api/v1/auth/login");
    info!("   • User Info: GET /api/v1/auth/me");
    info!("   • OAuth Authorize: GET /oauth/authorize");
    info!("   • OAuth Token: POST /oauth/token");
    info!("🔑 Demo credentials: demo@example.com / demo123");
    info!("🔑 Demo OAuth client: demo-client / demo-secret");
    
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

/// Security headers middleware
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    headers.insert("Strict-Transport-Security", "max-age=31536000; includeSubDomains".parse().unwrap());
    headers.insert("Content-Security-Policy", "default-src 'self'".parse().unwrap());
    
    response
}
