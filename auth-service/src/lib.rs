//! # Rust Security Platform - Authentication Service
//!
//! Enterprise-grade authentication and authorization service built with Rust.
//! Provides OAuth 2.0, SAML, OIDC, and multi-factor authentication capabilities
//! with sub-50ms latency and >1000 RPS throughput.
//!
//! ## Performance Characteristics
//!
//! - **Latency**: <50ms P95 authentication latency
//! - **Throughput**: >1000 RPS sustained load
//! - **Memory**: <512MB per service instance
//! - **Startup**: <5s cold start to ready
//!
//! ## Security Features
//!
//! - **Memory Safety**: Rust prevents buffer overflows and use-after-free
//! - **Threat Detection**: Real-time ML-based threat analysis
//! - **Zero Trust**: Complete request validation and authorization
//! - **Audit Logging**: Comprehensive security event tracking
//!
//! ## Quick Start
//!
//! ```rust
//! use auth_service::{AuthService, Config};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config::from_env()?;
//!     let service = AuthService::new(config).await?;
//!     service.start().await?;
//!     Ok(())
//! }
//! ```
//!
//! A comprehensive, enterprise-grade authentication service built in Rust with advanced
//! security features, threat detection, and production-ready scalability.
//!
//! ## Overview
//!
//! This library provides a complete `OAuth` 2.0 / `OpenID Connect` compatible authentication
//! service with advanced security features including:
//!
//! - **Multi-factor Authentication (MFA)** - `TOTP`, `WebAuthn`, and backup codes
//! - **Advanced Threat Detection** - Real-time request analysis and blocking
//! - **Rate Limiting** - Distributed, adaptive rate limiting with IP banning
//! - **Cryptographic Security** - Post-quantum ready cryptography with hardware acceleration
//! - **Session Management** - Secure, scalable session handling with `Redis` backend
//! - **`OAuth` 2.0 Flows** - Authorization Code, Client Credentials, Device Flow
//! - **`SAML` Integration** - Enterprise SSO with encrypted assertions
//! - **`SCIM` 2.0** - User provisioning and identity management
//! - **Audit Logging** - Comprehensive security event logging
//!
//! ## Quick Start
//!
//! ```rust
//! use auth_service::{AppContainer, create_router};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize the application container with all services
//!     let container = Arc::new(AppContainer::new().await?);
//!
//!     // Create the router with all endpoints
//!     let app = create_router(container);
//!
//!     // Start the server
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//!     axum::serve(listener, app).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Configuration
//!
//! The service supports extensive configuration through environment variables:
//!
//! ```bash
//! # Database configuration
//! DATABASE_URL=postgresql://user:pass@localhost/auth_db
//! REDIS_URL=redis://localhost:6379
//!
//! # Security settings
//! JWT_SECRET=your-256-bit-secret
//! ENCRYPTION_KEY=your-encryption-key
//! RATE_LIMIT_PER_IP_PER_MINUTE=100
//!
//! # Feature flags
//! ENABLE_MFA=true
//! ENABLE_THREAT_DETECTION=true
//! ENABLE_AUDIT_LOGGING=true
//! ```
//!
//! ## Security Considerations
//!
//! This service implements defense-in-depth security:
//!
//! - **Input Validation**: All inputs are validated and sanitized to prevent injection attacks
//! - **Rate Limiting**: Multiple layers of rate limiting prevent brute force attacks
//! - **Threat Detection**: Machine learning based threat detection blocks malicious requests
//! - **Secure Headers**: Comprehensive security headers prevent common web attacks
//! - **Cryptographic Security**: All sensitive data is encrypted at rest and in transit
//! - **Session Security**: Sessions use secure, `HttpOnly` cookies with CSRF protection
//!
//! ## Performance
//!
//! The service is designed for high performance:
//!
//! - **Async/Await**: Fully asynchronous using Tokio runtime
//! - **Connection Pooling**: Database and `Redis` connection pooling
//! - **Caching**: Intelligent caching of frequently accessed data
//! - **Hardware Acceleration**: Uses hardware crypto acceleration when available
//! - **Sharded Data Structures**: Lock-free, concurrent data structures
//!
//! ## Production Deployment
//!
//! For production deployment:
//!
//! ```yaml
//! # docker-compose.yml
//! services:
//!   auth-service:
//!     image: auth-service:latest
//!     environment:
//!       - RUST_LOG=info
//!       - DATABASE_URL=${DATABASE_URL}
//!       - REDIS_URL=${REDIS_URL}
//!       - JWT_SECRET=${JWT_SECRET}
//!     ports:
//!       - "3000:3000"
//!     depends_on:
//!       - postgres
//!       - redis
//! ```

//!
//! ## Architecture
//!
//! This service is organized into the following functional areas:
//!
//! ### Core Authentication
//! - `JWT` handling and validation
//! - Session management
//! - `OAuth` flows
//! - Token management
//!
//! ### User Management
//! - User registration and profiles
//! - `API` key management
//! - Service identity handling
//!
//! ### Security
//! - Rate limiting and `DDoS` protection
//! - Input validation and sanitization
//! - Security headers and monitoring
//! - `PII` protection
//! - SAML assertion encryption
//!
//! ### API & Middleware
//! - `HTTP` handlers and routing
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

pub mod saml_service;

use common::constants;
use std::sync::Arc;

// New modular architecture
pub mod app;
pub mod application;
pub mod billing;
pub mod bootstrap;
pub mod domain;
pub mod handlers;
pub mod infrastructure;
pub mod middleware;
pub mod monitoring;
pub mod security;
pub mod services;
pub mod shared;
pub mod storage;
pub mod threat_user_profiler;

// Common configuration and utilities to reduce duplication
// pub mod common_config; // Moved to infrastructure/config

// Performance optimization utilities
pub mod performance_utils;

// Security enhancements and threat detection
pub mod security_enhancements;

// Legacy modules (to be migrated)
pub mod core;
pub mod errors;
pub mod event_conversion;
pub mod graceful_shutdown;
// pub mod production_logging; // Moved to infrastructure/monitoring

// Essential modules for backward compatibility
// pub mod auth_api; // Moved to application/auth

// New modular auth system (feature-gated)
#[cfg(any(feature = "user-auth", feature = "oauth", feature = "jwt-auth"))]
pub mod auth;
pub mod error_conversion_macro;
// pub mod jwt_secure; // Moved to application/auth

// Re-export jwks_rotation for external tests
pub use infrastructure::crypto::jwks_rotation;
// pub mod validation_framework; // Moved to application/validation
// pub mod validation_secure; // Moved to application/validation

// Infrastructure layer (new modular architecture)

// Comprehensive test suite
#[cfg(test)]
pub mod tests;

// Test mocks
#[cfg(test)]
pub mod mocks;

// Feature-gated modules
// #[cfg(feature = "rate-limiting")]
// pub mod admin_replay_protection; // Moved to middleware/security
// #[cfg(feature = "api-keys")]
// pub mod api_key_endpoints; // Moved to application/api
// #[cfg(feature = "api-keys")]
// pub mod api_key_store; // Moved to application/api
// #[cfg(feature = "rate-limiting")]
// pub mod async_optimized; // Moved to infrastructure/rate_limiting
// #[cfg(feature = "rate-limiting")]
// pub mod auth_failure_logging; // Moved to application/auth

// Threat detection modules
// TODO: Implement threat_types module
// pub mod threat_types;

// Workflow modules (feature-gated)
#[cfg(feature = "soar")]
pub mod workflow;

// Core functionality modules
// pub mod admin_middleware; // Moved to middleware/security
// pub mod api_versioning; // Moved to application/api
pub mod backpressure;
// pub mod business_metrics; // Moved to infrastructure/monitoring
// TODO: Implement circuit_breaker module
// pub mod circuit_breaker;
pub mod client_auth;
pub mod config;
// pub mod config_production; // Moved to infrastructure/config
// pub mod config_secure; // Moved to infrastructure/config
// pub mod config_secure_validation; // Moved to infrastructure/config
pub mod csrf_protection;
pub mod error_handling;
pub mod feature_flags;
pub mod health_check;
pub mod oauth_policies;
pub mod performance_optimizer;
pub mod pii_protection;
// pub mod redirect_validation; // Moved to application/validation
pub mod scim_filter;
pub mod secure_random;
pub mod security_tests;

pub mod test_mode_security;

// Metrics and monitoring modules
#[cfg(feature = "metrics")]
pub mod metrics;
// pub mod security_metrics; // Moved to infrastructure/monitoring

// Service-specific modules
// TODO: Implement adaptive_rate_limiting module
// pub mod adaptive_rate_limiting; // Moved to infrastructure/rate_limiting
pub mod automated_compliance_assessment;
// pub mod immutable_audit_logging; // Moved to infrastructure/monitoring
pub mod jit_token_manager;
// pub mod jwt_blacklist; // Moved to application/auth
// pub mod non_human_monitoring; // Moved to infrastructure/monitoring
pub mod pkce;
pub mod request_fingerprinting;
pub mod security_test_suite;
// pub mod service_identity; // Moved to application/api
// pub mod service_identity_api; // Moved to application/api

/// Maximum request body size - use centralized constant
pub const MAX_REQUEST_BODY_SIZE: usize = constants::security::MAX_REQUEST_BODY_SIZE;

// Re-export main application components
pub use app::{create_router, AppContainer};

// Re-export error types and functions
pub use shared::error::{AppError, AppResult};
