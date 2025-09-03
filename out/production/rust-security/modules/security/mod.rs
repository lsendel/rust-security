//! Security Module for Enterprise-Grade Security Hardening
//!
//! This module provides comprehensive security features including:
//! - Authentication and authorization
//! - Input validation and sanitization
//! - Secure logging and audit trails
//! - Encryption and data protection
//! - Security monitoring and threat detection
//! - Secure configuration management
//! - Compliance frameworks

pub mod authentication;
pub mod authorization;
pub mod encryption;
pub mod audit;
pub mod input_validation;
pub mod monitoring;
pub mod compliance;
pub mod config;

// Re-export main security types
pub use authentication::{Authenticator, AuthenticationResult, AuthToken};
pub use authorization::{Authorizer, Permission, Role, AuthorizationResult};
pub use encryption::{Encryptor, Decryptor, KeyManager};
pub use audit::{SecurityAuditor, AuditEvent, AuditTrail};
pub use input_validation::{InputValidator, ValidationResult, Sanitizer};
pub use monitoring::{SecurityMonitor, ThreatDetector, SecurityMetrics};
pub use compliance::{ComplianceChecker, SecurityFramework};
pub use config::SecurityConfig;

/// Core security traits and interfaces
pub mod traits {
    use async_trait::async_trait;
    use std::fmt::Debug;

    /// Security service trait
    #[async_trait]
    pub trait SecurityService: Send + Sync + Debug {
        /// Initialize the security service
        async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

        /// Validate security configuration
        async fn validate_config(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

        /// Get security health status
        async fn health_check(&self) -> SecurityHealth;

        /// Shutdown the security service gracefully
        async fn shutdown(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    }

    /// Security health status
    #[derive(Debug, Clone, PartialEq)]
    pub enum SecurityHealth {
        Healthy,
        Degraded(String),
        Critical(String),
        Unknown,
    }

    /// Security context for operations
    #[derive(Debug, Clone)]
    pub struct SecurityContext {
        pub user_id: Option<String>,
        pub session_id: Option<String>,
        pub permissions: Vec<String>,
        pub roles: Vec<String>,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub timestamp: chrono::DateTime<chrono::Utc>,
        pub metadata: std::collections::HashMap<String, serde_json::Value>,
    }

    impl Default for SecurityContext {
        fn default() -> Self {
            Self {
                user_id: None,
                session_id: None,
                permissions: Vec::new(),
                roles: Vec::new(),
                ip_address: None,
                user_agent: None,
                timestamp: chrono::Utc::now(),
                metadata: std::collections::HashMap::new(),
            }
        }
    }
}

/// Security error types
pub mod errors {
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum SecurityError {
        #[error("Authentication failed: {reason}")]
        AuthenticationFailed { reason: String },

        #[error("Authorization denied: {reason}")]
        AuthorizationDenied { reason: String },

        #[error("Invalid credentials: {reason}")]
        InvalidCredentials { reason: String },

        #[error("Token expired: {token_id}")]
        TokenExpired { token_id: String },

        #[error("Access forbidden: {resource}")]
        AccessForbidden { resource: String },

        #[error("Security violation: {violation}")]
        SecurityViolation { violation: String },

        #[error("Encryption failed: {reason}")]
        EncryptionFailed { reason: String },

        #[error("Decryption failed: {reason}")]
        DecryptionFailed { reason: String },

        #[error("Key management error: {reason}")]
        KeyManagementError { reason: String },

        #[error("Input validation failed: {field} - {reason}")]
        ValidationFailed { field: String, reason: String },

        #[error("Audit logging failed: {reason}")]
        AuditFailed { reason: String },

        #[error("Security monitoring error: {reason}")]
        MonitoringError { reason: String },

        #[error("Compliance check failed: {framework} - {reason}")]
        ComplianceFailed { framework: String, reason: String },

        #[error("Configuration error: {reason}")]
        ConfigError { reason: String },

        #[error("Rate limit exceeded: {limit_type}")]
        RateLimitExceeded { limit_type: String },
    }

    pub type SecurityResult<T> = Result<T, SecurityError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_context_creation() {
        let context = traits::SecurityContext::default();
        assert!(context.user_id.is_none());
        assert!(context.session_id.is_none());
        assert!(context.permissions.is_empty());
        assert!(context.timestamp <= chrono::Utc::now());
    }
}