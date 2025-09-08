//! Middleware Layer
//!
//! Contains cross-cutting concerns (authentication, rate limiting, security headers).
//!
//! ## Middleware Organization
//!
//! This module has been consolidated to reduce duplication:
//! - `security_enhanced.rs` and `security_hardening.rs` consolidated into `security_enhanced.rs`
//! - `threat_detection.rs` and `threat_intelligence.rs` consolidated into `threat_detection.rs`
//! - Security middleware organized under `security/` subdirectory

// Security middleware modules
pub mod security;

// Re-export existing middleware for compatibility
pub use crate::security::rate_limiting::*;
pub use security::*;

// Enhanced security middleware (consolidated from security_enhanced + security_hardening)
pub mod security_enhanced;
pub use security_enhanced::{InputValidator, RateLimiter, SecurityConfig, SecurityMiddleware};

// Threat detection middleware (consolidated from threat_detection + threat_intelligence)
pub mod threat_detection;
pub use threat_detection::{
    get_threat_intelligence_service, initialize_threat_detection,
    initialize_threat_intelligence_service, threat_detection_middleware,
    threat_intelligence_middleware, threat_metrics,
};

// Request ID propagation and access logging
pub mod request_id;
pub use request_id::request_id_middleware;

// CSRF middleware
pub mod csrf;

// Security integration (comprehensive security stack)
pub mod security_integration;
