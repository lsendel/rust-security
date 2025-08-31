//! Middleware Layer
//!
//! Contains cross-cutting concerns (authentication, rate limiting, security headers).

// Re-export existing middleware for compatibility
pub use crate::admin_middleware::*;
pub use crate::rate_limit_secure::*;
// pub use crate::security_headers::*;  // Moved to infrastructure

// Enhanced security middleware
pub mod security_enhanced;
pub use security_enhanced::{SecurityMiddleware, SecurityConfig, RateLimiter, InputValidator};
