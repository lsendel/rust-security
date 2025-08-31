//! Middleware Layer
//!
//! Contains cross-cutting concerns (authentication, rate limiting, security headers).

// Re-export existing middleware for compatibility
pub use crate::admin_middleware::*;
pub use crate::rate_limit_secure::*;
pub use crate::security_headers::*;
