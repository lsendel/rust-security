//! Auth Service Library
//! 
//! Enterprise-grade authentication service with comprehensive security features.

use std::sync::Arc;
use crate::store::HybridStore;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<HybridStore>,
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
pub mod config_migration;
pub mod config_reload;
pub mod config_static;
mod config_tests;
pub mod crypto_unified;
pub mod errors;
pub use errors::{internal_error, AuthError};
pub mod secrets_manager;
pub mod sql_store;
pub mod store;

// Additional modules (commented out missing ones for now)
// TODO: Implement these modules as needed
/*
pub mod anomaly_detection;
pub mod behavioral_analysis;
pub mod ml_threat_detection;

// Security modules
pub mod advanced_rate_limiting;
pub mod attack_detection;
pub mod compliance_monitoring;
pub mod device_fingerprinting;
pub mod fraud_detection;
pub mod geo_blocking;
pub mod honeypot;
pub mod incident_response;
pub mod risk_scoring;
pub mod security_automation;
pub mod threat_hunting;
*/

// Existing working modules
pub mod admin_middleware;
pub mod admin_replay_protection;
pub mod advanced_rate_limit;
pub mod ai_threat_detection;
pub mod ai_threat_detection_advanced;
pub mod api_key_endpoints;
pub mod api_key_store;
pub mod api_versioning;
pub mod async_optimized;
pub mod auth_failure_logging;
pub mod backpressure;
pub mod business_metrics;
pub mod cache;
pub mod circuit_breaker;
pub mod circuit_breaker_advanced;
pub mod client_auth;
pub mod config_production;
pub mod config_secure;
pub mod connection_pool_optimized;
pub mod csrf_protection;
pub mod crypto_optimized;
pub mod database_optimized;
pub mod enhanced_jwt_validation;
pub mod enhanced_observability;
pub mod error_handling;
pub mod feature_flags;
pub mod fraud_detection;
pub mod health_check;
pub mod intelligent_cache;
pub mod jwks_handler;
pub mod jwks_rate_limiter;
pub mod jwks_rotation;
pub mod jwt_secure;
pub mod key_management;
pub mod key_rotation;
pub mod keys;
pub mod keys_optimized;
pub mod keys_ring;
pub mod keys_secure;
pub mod main;
pub mod metrics;
pub mod mfa;
pub mod monitoring_dashboard;
pub mod multi_tenant_enterprise;
pub mod oauth_client_registration;
pub mod oauth_client_registration_policies;
pub mod oauth_client_secret_rotation;
pub mod observability;
pub mod observability_advanced;
pub mod observability_init;
pub mod oidc_github;
pub mod oidc_google;
pub mod oidc_microsoft;
pub mod otp_provider;
pub mod per_ip_rate_limit;
pub mod performance_monitor;
pub mod performance_monitoring;
pub mod performance_optimizer;
pub mod pii_audit_tests;
pub mod pii_protection;
pub mod policy_cache;
pub mod post_quantum_crypto;
pub mod pq_integration;
pub mod pq_jwt;
pub mod pq_key_management;
pub mod pq_migration;
pub mod property_testing_framework;
pub mod quantum_jwt;
pub mod rate_limit_enhanced;
pub mod rate_limit_optimized;
pub mod rate_limit_secure;
pub mod redirect_validation;
pub mod resilience_config;
pub mod resilient_http;
pub mod resilient_store;
pub mod scim;
pub mod scim_filter;
pub mod scim_rbac;
pub mod secure_random;
pub mod security;
pub mod security_analyzer;
pub mod security_fixed;
pub mod security_headers;
pub mod security_logging;
pub mod security_logging_enhanced;
pub mod security_metrics;
pub mod security_monitoring;
pub mod security_tests;
pub mod session_cleanup;
pub mod session_manager;
pub mod session_secure;
pub mod session_store;
pub mod soar_case_management;
pub mod soar_config_loader;
pub mod soar_correlation;
pub mod soar_workflow;
pub mod store_optimized;
pub mod test_mode_security;
pub mod threat_attack_patterns;
pub mod threat_behavioral_analyzer;
pub mod threat_hunting_orchestrator;
pub mod threat_intelligence;
pub mod threat_response_orchestrator;
pub mod threat_types;
pub mod threat_user_profiler;
pub mod tls_security;
pub mod tracing_config;
pub mod tracing_instrumentation;
pub mod validation;
pub mod validation_secure;
pub mod webauthn;
pub mod zero_trust_auth;

// Module directories
pub mod soar_core;
pub mod soar_executors;
pub mod soar;
