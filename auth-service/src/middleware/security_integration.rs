//! # Security Middleware Integration
//!
//! This module demonstrates how to integrate all security middleware layers
//! including rate limiting, security headers, and authentication.

use axum::{middleware, Router};
use std::sync::Arc;
use tower::ServiceBuilder;

use crate::security::{
    SecurityHeadersConfig, SecurityHeadersLayer,
    RateLimitConfig, UnifiedRateLimiter, unified_rate_limit_middleware,
};

/// Create a production-ready security stack
pub fn create_secure_router() -> Router {
    // Configure security headers for production
    let headers_config = SecurityHeadersConfig::strict_security();
    
    // Configure rate limiting
    let rate_limit_config = RateLimitConfig {
        per_ip_requests_per_minute: 100,
        per_ip_requests_per_hour: 1000,
        enable_distributed_limiting: true,
        enable_adaptive_limits: true,
        ban_threshold: 5,
        ban_duration_minutes: 60,
        ..Default::default()
    };
    
    let rate_limiter = Arc::new(UnifiedRateLimiter::new(
        rate_limit_config, 
        std::env::var("REDIS_URL").ok()
    ));

    Router::new()
        .layer(
            ServiceBuilder::new()
                // Security headers first (outermost)
                .layer(SecurityHeadersLayer::new(headers_config))
                // Rate limiting second
                .layer(middleware::from_fn_with_state(
                    rate_limiter,
                    unified_rate_limit_middleware
                ))
        )
}

/// Create a development-friendly security stack
pub fn create_development_router() -> Router {
    // Less restrictive headers for development
    let headers_config = SecurityHeadersConfig::development();
    
    // More permissive rate limiting for development
    let rate_limit_config = RateLimitConfig {
        per_ip_requests_per_minute: 1000,
        per_ip_requests_per_hour: 10000,
        enable_distributed_limiting: false,
        ban_threshold: 50,
        ..Default::default()
    };
    
    let rate_limiter = Arc::new(UnifiedRateLimiter::new(
        rate_limit_config, 
        None
    ));

    Router::new()
        .layer(
            ServiceBuilder::new()
                .layer(SecurityHeadersLayer::new(headers_config))
                .layer(middleware::from_fn_with_state(
                    rate_limiter,
                    unified_rate_limit_middleware
                ))
        )
}

/// Create security middleware from environment
pub fn create_router_from_env() -> Router {
    let is_development = std::env::var("DEVELOPMENT_MODE")
        .map(|v| v == "true")
        .unwrap_or(false);

    if is_development {
        create_development_router()
    } else {
        create_secure_router()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, response::Response, routing::get};
    use tower::ServiceExt;

    async fn hello_handler() -> &'static str {
        "Hello, World!"
    }

    #[tokio::test]
    async fn test_production_security_stack() {
        let app = create_secure_router()
            .route("/", get(hello_handler));

        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let headers = response.headers();

        // Verify security headers are present
        assert!(headers.contains_key("strict-transport-security"));
        assert!(headers.contains_key("x-frame-options"));
        assert!(headers.contains_key("x-content-type-options"));
        assert!(headers.contains_key("referrer-policy"));
        
        // Verify strict CSP
        if let Some(csp) = headers.get("content-security-policy") {
            let csp_str = csp.to_str().unwrap();
            assert!(csp_str.contains("object-src 'none'"));
            assert!(csp_str.contains("frame-ancestors 'none'"));
        }
    }

    #[tokio::test]
    async fn test_development_security_stack() {
        let app = create_development_router()
            .route("/", get(hello_handler));

        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let headers = response.headers();

        // Should still have basic security headers but not HSTS
        assert!(!headers.contains_key("strict-transport-security"));
        assert!(headers.contains_key("x-frame-options"));
        assert!(headers.contains_key("x-content-type-options"));
    }
}