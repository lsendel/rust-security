//! Auth Service Library
//!
//! Enterprise-grade authentication service with comprehensive security features.

use common::constants;
use std::sync::Arc;

// Core modules providing fundamental functionality
pub mod core;
pub mod graceful_shutdown;
pub mod production_logging;

// Suppress warnings for unused extern crate dependencies
#[allow(unused_extern_crates)]
extern crate http;
#[allow(unused_extern_crates)]
extern crate opentelemetry_otlp;
#[allow(unused_extern_crates)]
extern crate rayon;
#[allow(unused_extern_crates)]
extern crate zeroize;
#[cfg(feature = "enhanced-session-store")]
use crate::store::HybridStore;

/// Maximum request body size - use centralized constant
pub const MAX_REQUEST_BODY_SIZE: usize = constants::security::MAX_REQUEST_BODY_SIZE;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    #[cfg(feature = "enhanced-session-store")]
    pub store: Arc<HybridStore>,
    #[cfg(feature = "api-keys")]
    pub api_key_store: Arc<crate::api_key_store::ApiKeyStore>,
    // Additional fields for test compatibility
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

// Re-export core functionality
pub use lib::core::*;

// Module declarations - organized by functionality
pub mod lib {
    pub mod api;
    pub mod app;
    pub mod core;
}

// All existing module declarations preserved for backward compatibility
pub mod config;
pub mod config_endpoints;

pub mod config_reload;
pub mod config_static;
mod config_tests;
pub mod crypto_secure;
pub mod crypto_unified;
pub mod errors;
pub mod input_sanitizer;
pub mod secure_config;
pub use errors::{internal_error, AuthError};
pub mod jwks_rotation;
pub mod policy_cache;
pub mod rate_limit_secure;
pub mod secrets_manager;
pub mod session_store;
#[cfg(feature = "api-keys")]
pub mod sql_store;
#[cfg(feature = "enhanced-session-store")]
pub mod store;
pub mod token_cache;

// Removed all advanced AI/ML and enterprise security modules for MVP

// Existing working modules
pub mod admin_middleware;
#[cfg(feature = "rate-limiting")]
pub mod admin_replay_protection;
// Removed advanced rate limiting for MVP
// #[cfg(feature = "rate-limiting")]
// pub mod advanced_rate_limit;
// Removed AI threat detection for MVP
// pub mod ai_threat_detection;
// pub mod ai_threat_detection_advanced;
#[cfg(feature = "api-keys")]
pub mod api_key_endpoints;
#[cfg(feature = "api-keys")]
pub mod api_key_store;
pub mod api_versioning;
#[cfg(feature = "rate-limiting")]
pub mod async_optimized;
#[cfg(feature = "rate-limiting")]
pub mod auth_failure_logging;
pub mod backpressure;
pub mod business_metrics;
pub mod circuit_breaker;
// #[cfg(feature = "enhanced-session-store")]
// pub mod cache;
// pub mod circuit_breaker;
pub mod client_auth;
pub mod config_production;
pub mod config_secure;
// Removed connection pool optimizations for MVP
// #[cfg(feature = "enhanced-session-store")]
// pub mod connection_pool_optimized;
pub mod csrf_protection;
// Removed crypto optimizations for MVP
// #[cfg(feature = "rate-limiting")]
// pub mod crypto_optimized;
// Removed database optimizations and enhanced JWT for MVP
// #[cfg(feature = "enhanced-session-store")]
// pub mod database_optimized;
// pub mod enhanced_jwt_validation;
#[cfg(feature = "tracing")]
pub mod enhanced_observability;
pub mod error_handling;
pub mod feature_flags;
// Removed for MVP - pub mod fraud_detection;
pub mod health_check;
// Removed intelligent cache and JWKS features for MVP
// pub mod intelligent_cache;
// pub mod jwks_handler;
// #[cfg(feature = "enhanced-session-store")]
// pub mod jwks_rate_limiter;
// #[cfg(feature = "enhanced-session-store")]
// pub mod jwks_rotation;
pub mod jwt_secure;
// Removed advanced key management for MVP - keep basic keys only
// pub mod key_management;
// pub mod key_rotation;
pub mod keys;
// pub mod keys_optimized;
// pub mod keys_ring; // Temporarily disabled - uses removed RSA dependency
// pub mod keys_secure;
// pub mod main; // Removed - main.rs should not be a module in lib.rs
#[cfg(feature = "monitoring")]
pub mod metrics;
// Removed MFA for MVP
// #[cfg(feature = "enhanced-session-store")]
// pub mod mfa;
// Removed advanced features for MVP
// #[cfg(feature = "monitoring")]
// pub mod monitoring_dashboard;
// pub mod multi_tenant_enterprise;
// Removed OAuth client management for MVP
// #[cfg(feature = "api-keys")]
// pub mod oauth_client_registration;
// #[cfg(feature = "api-keys")]
// pub mod oauth_client_registration_policies;
// #[cfg(feature = "api-keys")]
// pub mod oauth_client_secret_rotation;
#[cfg(feature = "tracing")]
pub mod observability;
// Disabled due to OpenTelemetry version compatibility issues
// #[cfg(feature = "tracing")]
// pub mod observability_advanced;
#[cfg(feature = "tracing")]
pub mod observability_init;
// Removed OIDC providers and OTP for MVP
// #[cfg(feature = "enhanced-session-store")]
// pub mod oidc_github;
// #[cfg(feature = "enhanced-session-store")]
// pub mod oidc_google;
// #[cfg(feature = "enhanced-session-store")]
// pub mod oidc_microsoft;
// pub mod otp_provider;
#[cfg(feature = "rate-limiting")]
pub mod per_ip_rate_limit;
// Removed performance monitoring for MVP
// pub mod performance_monitor;  // Temporarily disabled - requires prometheus feature
// pub mod performance_monitoring; // Temporarily disabled - requires prometheus feature
pub mod performance_optimizer;
// Removed PII protection and policy cache for MVP
// pub mod pii_audit_tests;
pub mod pii_protection;
// #[cfg(feature = "rate-limiting")]
// pub mod policy_cache;
// Removed post-quantum cryptography for MVP
// #[cfg(feature = "post-quantum")]
// pub mod post_quantum_crypto;
// #[cfg(feature = "post-quantum")]
// pub mod pq_integration;
// #[cfg(feature = "post-quantum")]
// pub mod pq_jwt;
// #[cfg(feature = "post-quantum")]
// pub mod pq_key_management;
// #[cfg(feature = "post-quantum")]
// pub mod pq_migration;
// Removed property testing framework for MVP
// #[cfg(test)]
// pub mod property_testing_framework;
// Removed for MVP
// #[cfg(feature = "post-quantum")]
// pub mod quantum_jwt;
// Removed enhanced rate limiting for MVP - keep basic only
// pub mod rate_limit_enhanced;
// #[cfg(feature = "rate-limiting")]
// pub mod rate_limit_optimized;
// pub mod rate_limit_secure;
pub mod redirect_validation;
// Removed resilience features for MVP
// #[cfg(feature = "enhanced-session-store")]
// pub mod resilience_config;
// pub mod resilient_http;
// #[cfg(feature = "enhanced-session-store")]
// pub mod resilient_store;
// Removed SCIM features for MVP
// pub mod scim;
pub mod scim_filter;
// pub mod scim_rbac;
pub mod secure_random;
pub mod security;
// Removed advanced security features for MVP - keep basic security only
// pub mod security_analyzer;
pub mod security_fixed;
pub mod security_headers;
pub mod security_logging;
// pub mod security_logging_enhanced;
#[cfg(feature = "monitoring")]
pub mod security_metrics;
// Removed security monitoring for MVP
// #[cfg(feature = "threat-hunting")]
pub mod security_monitoring;
pub mod security_tests;
// Removed advanced session management for MVP - keep basic only
// #[cfg(feature = "enhanced-session-store")]
// pub mod session_cleanup;
// #[cfg(feature = "enhanced-session-store")]
// pub mod session_manager;
pub mod session_secure;
// #[cfg(feature = "enhanced-session-store")]
// pub mod session_store;
// Removed SOAR (Security Orchestration, Automation and Response) for MVP
// #[cfg(feature = "soar")]
// pub mod soar_case_management;
// #[cfg(feature = "soar")]
// pub mod soar_config_loader;
// #[cfg(feature = "soar")]
// pub mod soar_correlation;
// #[cfg(feature = "soar")]
// pub mod soar_workflow;
// Removed store optimizations for MVP
// #[cfg(feature = "enhanced-session-store")]
// pub mod store_optimized;
pub mod test_mode_security;
// Removed threat hunting modules for MVP
// #[cfg(feature = "threat-hunting")]
// pub mod threat_attack_patterns;
// #[cfg(feature = "threat-hunting")]
// pub mod threat_behavioral_analyzer;
// #[cfg(feature = "threat-hunting")]
// pub mod threat_hunting_orchestrator;
// #[cfg(feature = "threat-hunting")]
// pub mod threat_intelligence;
// #[cfg(feature = "threat-hunting")]
// pub mod threat_response_orchestrator;
// #[cfg(feature = "threat-hunting")]
// pub mod threat_types;
#[cfg(feature = "threat-hunting")]
pub mod threat_user_profiler;
pub mod tls_security;
#[cfg(feature = "tracing")]
pub mod tracing_config;
// Disabled due to OpenTelemetry compatibility issues
// #[cfg(feature = "tracing")]
// pub mod tracing_instrumentation;
pub mod app;
pub mod validation;
pub mod validation_secure;
pub use app::app;
pub mod auth_api;
pub mod jit_token_manager;
pub mod non_human_monitoring;
pub mod service_identity;
pub mod service_identity_api;
// Removed WebAuthn and Zero Trust for MVP
// pub mod webauthn;
// pub mod zero_trust_auth;

// Removed all SOAR module directories for MVP
// #[cfg(feature = "soar")]
// pub mod soar_core;
// #[cfg(feature = "soar")]
// pub mod soar_executors;
// #[cfg(feature = "soar")]
// pub mod soar;
