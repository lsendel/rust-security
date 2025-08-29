//! Auth Service Library
//!
//! Enterprise-grade authentication service with comprehensive security features.
//!
//! ## Architecture
//!
//! This service is organized into the following functional areas:
//!
//! ### Core Authentication
//! - JWT handling and validation
//! - Session management
//! - OAuth flows
//! - Token management
//!
//! ### User Management
//! - User registration and profiles
//! - API key management
//! - Service identity handling
//!
//! ### Security
//! - Rate limiting and DDoS protection
//! - Input validation and sanitization
//! - Security headers and monitoring
//! - PII protection
//!
//! ### API & Middleware
//! - HTTP handlers and routing
//! - Authentication middleware
//! - Request/response processing
//!
//! ## Test Configuration
//!
//! All tests include automatic timeouts to prevent hanging:
//! - Unit tests: 60 second timeout
//! - Integration tests: 120 second timeout
//! - Benchmarks: 300 second timeout
//!
//! Tests can be run with custom timeouts using:
//! ```bash
//! RUST_TEST_TIMEOUT=30 cargo test  # 30 second timeout
//! ```
//!
//! ## Test Utilities
//!
//! The service provides test utilities for proper timeout handling:
//!
//! ```rust
//! use tokio::time::{timeout, Duration};
//!
//! #[tokio::test]
//! async fn example_test_with_timeout() {
//!     let test_future = async {
//!         // Your test logic here
//!         tokio::time::sleep(Duration::from_secs(1)).await;
//!         assert!(true);
//!     };
//!
//!     // Timeout after 30 seconds to prevent hanging
//!     timeout(Duration::from_secs(30), test_future)
//!         .await
//!         .expect("Test timed out");
//! }
//! ```
//!
//! ### Data Layer
//! - Redis and SQL storage
//! - Caching mechanisms
//! - Session persistence
//!
//! ### Observability
//! - Metrics and monitoring
//! - Logging and tracing
//! - Health checks

use common::constants;
use std::sync::Arc;

// Core modules - fundamental functionality
pub mod core;
pub mod errors;
pub mod graceful_shutdown;
pub mod production_logging;

// Essential modules for backward compatibility
pub mod app;
pub mod auth_api;
pub mod crypto_unified;
pub mod jwks_rotation;
pub mod jwt_secure;
pub mod keys;
pub mod policy_cache;
pub mod security;
pub mod session_store;
pub mod token_cache;
pub mod validation;
pub mod validation_secure;

// Feature-gated modules
#[cfg(feature = "rate-limiting")]
pub mod admin_replay_protection;
#[cfg(feature = "api-keys")]
pub mod api_key_endpoints;
#[cfg(feature = "api-keys")]
pub mod api_key_store;
#[cfg(feature = "rate-limiting")]
pub mod async_optimized;
#[cfg(feature = "rate-limiting")]
pub mod auth_failure_logging;
#[cfg(feature = "tracing")]
pub mod enhanced_observability;
#[cfg(feature = "monitoring")]
pub mod metrics;
#[cfg(feature = "tracing")]
pub mod observability;
#[cfg(feature = "tracing")]
pub mod observability_init;
#[cfg(feature = "rate-limiting")]
pub mod per_ip_rate_limit;
#[cfg(feature = "monitoring")]
pub mod security_metrics;
#[cfg(feature = "api-keys")]
pub mod sql_store;
#[cfg(feature = "enhanced-session-store")]
pub mod store;
#[cfg(feature = "threat-hunting")]
pub mod threat_user_profiler;
#[cfg(feature = "threat-hunting")]
pub mod threat_hunting_orchestrator;
#[cfg(feature = "threat-hunting")]
pub mod threat_types;
#[cfg(feature = "tracing")]
pub mod tracing_config;

// Core functionality modules
pub mod admin_middleware;
pub mod api_versioning;
pub mod backpressure;
pub mod business_metrics;
pub mod circuit_breaker;
pub mod client_auth;
pub mod config_production;
pub mod config_secure;
pub mod csrf_protection;
pub mod error_handling;
pub mod feature_flags;
pub mod health_check;
pub mod performance_optimizer;
pub mod pii_protection;
pub mod rate_limit_secure;
pub mod redirect_validation;
pub mod scim_filter;
pub mod secure_random;
pub mod security_fixed;
pub mod security_headers;
pub mod security_logging;
pub mod security_monitoring;
pub mod security_tests;
pub mod session_secure;
pub mod test_mode_security;
pub mod tls_security;

// Service-specific modules
pub mod jit_token_manager;
pub mod non_human_monitoring;
pub mod service_identity;
pub mod service_identity_api;

/// Maximum request body size - use centralized constant
pub const MAX_REQUEST_BODY_SIZE: usize = constants::security::MAX_REQUEST_BODY_SIZE;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    #[cfg(feature = "enhanced-session-store")]
    pub store: Arc<crate::store::HybridStore>,
    #[cfg(feature = "api-keys")]
    pub api_key_store: Arc<crate::api_key_store::ApiKeyStore>,
    pub session_store: Arc<crate::session_store::RedisSessionStore>,
    pub token_store: Arc<std::sync::RwLock<std::collections::HashMap<String, common::TokenRecord>>>,
    pub client_credentials: Arc<std::sync::RwLock<std::collections::HashMap<String, String>>>,
    pub allowed_scopes: Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
    pub authorization_codes: Arc<std::sync::RwLock<std::collections::HashMap<String, String>>>,
    pub policy_cache: Arc<crate::policy_cache::PolicyCache>,
    pub backpressure_state: Arc<std::sync::RwLock<bool>>,
    pub jwks_manager: Arc<crate::jwks_rotation::JwksManager>,
}

// Missing function implementation - stub for compilation
pub async fn mint_local_tokens_for_subject(
    _state: &AppState,
    _subject: String,
    _scope: Option<String>,
) -> Result<serde_json::Value, crate::errors::AuthError> {
    // TODO: Implement proper token minting logic
    Ok(serde_json::json!({
        "access_token": "stub_token",
        "token_type": "Bearer",
        "expires_in": 3600
    }))
}

// Missing type definition - stub for compilation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntrospectionRecord {
    pub token: String,
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub exp: Option<i64>,
    // Additional optional fields used by optimized store
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub jti: Option<String>,
    pub mfa_verified: bool,
    pub token_type: Option<String>,
    pub token_binding: Option<String>,
}

// Request/Response types for introspection
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntrospectResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub jti: Option<String>,
    pub token_type: Option<String>,
}

// Additional missing types - stubs for compilation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub id_token: Option<String>,
}

// Missing constants - stubs for compilation
pub const REFRESH_TOKEN_EXPIRY_SECONDS: u64 = 86400 * 30; // 30 days

// Missing function - stub for compilation
#[must_use]
pub const fn get_token_expiry_seconds() -> u64 {
    3600 // 1 hour
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JwtClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<serde_json::Value>, // Can be String or Array
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    pub jti: Option<String>,
    pub token_binding: Option<String>,
}

// Re-export main application function
pub use app::app;

// Re-export error types and functions
pub use errors::{internal_error, AuthError};

// Core modules organized by functionality
pub mod modules {
    pub mod soar {
        pub mod case_management;
    }
}

// Re-export new modular SOAR case management system
pub mod soar_case_management {
    pub use crate::modules::soar::case_management::*;
}
