//! Middleware Layer
//!
//! Contains cross-cutting concerns (authentication, rate limiting, security headers).

// Re-export existing middleware for compatibility
pub use crate::admin_middleware::*;
pub use crate::security::rate_limiting::*;
// pub use crate::security_headers::*;  // Moved to infrastructure

// Enhanced security middleware
pub mod security_enhanced;
pub use security_enhanced::{InputValidator, RateLimiter, SecurityConfig, SecurityMiddleware};

// Threat detection middleware
pub mod threat_detection;
pub use threat_detection::{
    initialize_threat_detection, threat_detection_middleware, threat_metrics,
};

// Request ID propagation and access logging
pub mod request_id;
pub use request_id::request_id_middleware;

// CSRF middleware
pub mod csrf;
