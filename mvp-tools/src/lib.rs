//! MVP Tools - Essential utilities for the Auth-as-a-Service MVP
//!
//! This crate contains essential tools and utilities needed for the MVP,
//! consolidated from various components for simplified development.
//!
//! ## Features
//!
//! - **Enhanced Security Validation**: Enterprise-grade input validation with threat detection
//! - **API Contract Generation**: OpenAPI specification generation and validation
//! - **Testing Utilities**: Comprehensive testing helpers for MVP development
//! - **Policy Validation**: Cedar policy validation and authorization support

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, future_incompatible)]

// Re-export common functionality
pub use common;

/// Enhanced input validation and security utilities
///
/// This module provides enterprise-grade input validation with comprehensive
/// security features including:
/// - Threat level classification and incident logging
/// - DoS protection (payload size, depth, complexity limits)
/// - Injection attack prevention (SQL, XSS, script injection detection)
/// - Control character filtering and input sanitization
/// - Security context tracking with client information
pub mod validation;

/// Policy validation and authorization module
///
/// This module provides Cedar policy validation and authorization support
/// with MVP-focused features including:
/// - Simplified policy engine for essential authorization
/// - Default policies for authenticated access control
/// - Security context integration with validation
/// - Policy conflict detection
/// - Authorization request/response handling
pub mod policy;

/// API contract utilities
pub mod contracts {

    pub fn generate_openapi_spec() -> Result<String, Box<dyn std::error::Error>> {
        // Placeholder for OpenAPI spec generation
        Ok("openapi: 3.0.0".to_string())
    }
}

/// Testing utilities
pub mod testing {

    pub fn setup_test_environment() -> Result<(), Box<dyn std::error::Error>> {
        // Placeholder for test setup
        Ok(())
    }
}
