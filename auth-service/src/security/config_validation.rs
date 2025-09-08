//! # Security Configuration Validation
//!
//! This module provides comprehensive validation for all security-critical
//! configuration parameters to prevent security misconfigurations in production.
//!
//! ## Validation Categories
//!
//! - **Cryptographic Settings**: Key lengths, algorithm choices, entropy requirements
//! - **Authentication Configuration**: JWT settings, session management, MFA requirements
//! - **Network Security**: Rate limiting, IP filtering, TLS configuration
//! - **Application Security**: CSP policies, security headers, CORS settings
//! - **Infrastructure Security**: Database connections, Redis configuration, logging
//!
//! ## Usage
//!
//! ```rust
//! use auth_service::security::config_validation::SecurityConfigValidator;
//!
//! let validator = SecurityConfigValidator::new();
//! let result = validator.validate_all_configurations().await;
//!
//! match result {
//!     Ok(_) => println!("All security configurations are valid"),
//!     Err(issues) => {
//!         eprintln!("Security configuration issues found:");
//!         for issue in issues {
//!             eprintln!("  - {}: {}", issue.severity, issue.message);
//!         }
//!     }
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn, error, info};

/// Configuration validation errors
#[derive(Debug, Error)]
pub enum ConfigValidationError {
    #[error("Critical security misconfiguration: {message}")]
    Critical { message: String },
    
    #[error("Security warning: {message}")]
    Warning { message: String },
    
    #[error("Invalid parameter: {parameter} - {reason}")]
    InvalidParameter { parameter: String, reason: String },
    
    #[error("Missing required configuration: {config}")]
    MissingRequired { config: String },
    
    #[error("Insecure default detected: {config} - {recommendation}")]
    InsecureDefault { config: String, recommendation: String },
    
    #[error("Environment validation failed: {reason}")]
    EnvironmentError { reason: String },
}

/// Validation severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ValidationSeverity {
    Critical,   // Must be fixed before production deployment
    High,       // Should be fixed for security
    Medium,     // Recommended for security
    Low,        // Best practice suggestions
    Info,       // Informational notices
}

impl std::fmt::Display for ValidationSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationSeverity::Info => write!(f, "INFO"),
            ValidationSeverity::Low => write!(f, "LOW"),
            ValidationSeverity::Medium => write!(f, "MEDIUM"),
            ValidationSeverity::High => write!(f, "HIGH"),
            ValidationSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Configuration validation issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub severity: ValidationSeverity,
    pub category: String,
    pub parameter: String,
    pub message: String,
    pub recommendation: String,
    pub current_value: Option<String>,
    pub recommended_value: Option<String>,
}

/// Configuration validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub issues: Vec<ValidationIssue>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub passed: bool,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            issues: Vec::new(),
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            passed: true,
        }
    }

    pub fn add_issue(&mut self, issue: ValidationIssue) {
        match issue.severity {
            ValidationSeverity::Critical => {
                self.critical_count += 1;
                self.passed = false;
            }
            ValidationSeverity::High => self.high_count += 1,
            ValidationSeverity::Medium => self.medium_count += 1,
            ValidationSeverity::Low => self.low_count += 1,
            ValidationSeverity::Info => {}
        }
        
        self.issues.push(issue);
    }

    pub fn has_critical_issues(&self) -> bool {
        self.critical_count > 0
    }

    pub fn has_blocking_issues(&self) -> bool {
        self.critical_count > 0 || self.high_count > 0
    }
}

/// Main security configuration validator
#[derive(Debug)]
pub struct SecurityConfigValidator {
    production_mode: bool,
    strict_mode: bool,
    environment_checks: bool,
}

impl Default for SecurityConfigValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityConfigValidator {
    /// Create new validator with default settings
    pub fn new() -> Self {
        let production_mode = std::env::var("PRODUCTION_MODE")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
            
        let strict_mode = std::env::var("STRICT_CONFIG_VALIDATION")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(production_mode);

        Self {
            production_mode,
            strict_mode,
            environment_checks: true,
        }
    }

    /// Create validator for production environment (strict validation)
    pub fn production() -> Self {
        Self {
            production_mode: true,
            strict_mode: true,
            environment_checks: true,
        }
    }

    /// Create validator for development environment (lenient validation)
    pub fn development() -> Self {
        Self {
            production_mode: false,
            strict_mode: false,
            environment_checks: false,
        }
    }

    /// Validate all security configurations
    pub async fn validate_all_configurations(&self) -> ValidationResult {
        let mut result = ValidationResult::new();

        info!("Starting comprehensive security configuration validation");

        // Validate cryptographic configurations
        self.validate_cryptographic_config(&mut result);

        // Validate JWT and authentication settings
        self.validate_jwt_config(&mut result);

        // Validate rate limiting configuration
        self.validate_rate_limiting_config(&mut result);

        // Validate security headers configuration
        self.validate_security_headers_config(&mut result);

        // Validate network and infrastructure settings
        self.validate_network_config(&mut result);

        // Validate database and Redis configuration
        self.validate_database_config(&mut result);

        // Validate environment-specific settings
        if self.environment_checks {
            self.validate_environment_config(&mut result);
        }

        // Validate production readiness
        if self.production_mode {
            self.validate_production_readiness(&mut result);
        }

        info!("Configuration validation completed: {} critical, {} high, {} medium, {} low issues",
              result.critical_count, result.high_count, result.medium_count, result.low_count);

        result
    }

    /// Validate cryptographic configuration parameters
    fn validate_cryptographic_config(&self, result: &mut ValidationResult) {
        debug!("Validating cryptographic configuration");

        // Check JWT secret strength
        if let Ok(jwt_secret) = std::env::var("JWT_SECRET") {
            if jwt_secret.len() < 32 {
                result.add_issue(ValidationIssue {
                    severity: ValidationSeverity::Critical,
                    category: "Cryptography".to_string(),
                    parameter: "JWT_SECRET".to_string(),
                    message: "JWT secret is too short and vulnerable to brute force attacks".to_string(),
                    recommendation: "Use a JWT secret with at least 32 characters (256 bits)".to_string(),
                    current_value: Some(format!("{} characters", jwt_secret.len())),
                    recommended_value: Some("≥32 characters".to_string()),
                });
            }

            if jwt_secret.chars().all(|c| c.is_ascii_alphabetic()) {
                result.add_issue(ValidationIssue {
                    severity: ValidationSeverity::High,
                    category: "Cryptography".to_string(),
                    parameter: "JWT_SECRET".to_string(),
                    message: "JWT secret lacks character diversity and is predictable".to_string(),
                    recommendation: "Use a JWT secret with mixed alphanumeric and special characters".to_string(),
                    current_value: Some("Alphabetic only".to_string()),
                    recommended_value: Some("Mixed characters with symbols".to_string()),
                });
            }
        } else if self.production_mode {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::Critical,
                category: "Cryptography".to_string(),
                parameter: "JWT_SECRET".to_string(),
                message: "JWT secret is not configured".to_string(),
                recommendation: "Set JWT_SECRET environment variable with a strong random value".to_string(),
                current_value: None,
                recommended_value: Some("32+ character random string".to_string()),
            });
        }

        // Check encryption key configuration
        if let Ok(encryption_key) = std::env::var("ENCRYPTION_KEY") {
            if encryption_key.len() != 32 && encryption_key.len() != 64 {
                result.add_issue(ValidationIssue {
                    severity: ValidationSeverity::Critical,
                    category: "Cryptography".to_string(),
                    parameter: "ENCRYPTION_KEY".to_string(),
                    message: "Encryption key length is not suitable for AES-256".to_string(),
                    recommendation: "Use a 32-byte (64 hex chars) key for AES-256".to_string(),
                    current_value: Some(format!("{} characters", encryption_key.len())),
                    recommended_value: Some("64 hex characters (32 bytes)".to_string()),
                });
            }
        }

        // Check password hashing configuration
        let argon2_memory = std::env::var("ARGON2_MEMORY_COST")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(65536);

        if argon2_memory < 32768 {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::High,
                category: "Cryptography".to_string(),
                parameter: "ARGON2_MEMORY_COST".to_string(),
                message: "Argon2 memory cost is too low, vulnerable to GPU attacks".to_string(),
                recommendation: "Use at least 64MB (65536 KB) for production".to_string(),
                current_value: Some(format!("{} KB", argon2_memory)),
                recommended_value: Some("≥65536 KB".to_string()),
            });
        }

        let argon2_time = std::env::var("ARGON2_TIME_COST")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3);

        if argon2_time < 3 {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::Medium,
                category: "Cryptography".to_string(),
                parameter: "ARGON2_TIME_COST".to_string(),
                message: "Argon2 time cost is low".to_string(),
                recommendation: "Use at least 3 iterations for better security".to_string(),
                current_value: Some(argon2_time.to_string()),
                recommended_value: Some("≥3".to_string()),
            });
        }
    }

    /// Validate JWT and authentication configuration
    fn validate_jwt_config(&self, result: &mut ValidationResult) {
        debug!("Validating JWT configuration");

        // Check JWT expiration times
        let access_token_exp = std::env::var("JWT_ACCESS_TOKEN_EXPIRATION")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(900); // 15 minutes default

        if access_token_exp > 3600 {
            let severity = if self.strict_mode {
                ValidationSeverity::High
            } else {
                ValidationSeverity::Medium
            };

            result.add_issue(ValidationIssue {
                severity,
                category: "Authentication".to_string(),
                parameter: "JWT_ACCESS_TOKEN_EXPIRATION".to_string(),
                message: "Access token expiration is too long, increasing security risk".to_string(),
                recommendation: "Use access token expiration ≤1 hour for production".to_string(),
                current_value: Some(format!("{} seconds", access_token_exp)),
                recommended_value: Some("≤3600 seconds (1 hour)".to_string()),
            });
        }

        let refresh_token_exp = std::env::var("JWT_REFRESH_TOKEN_EXPIRATION")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(604800); // 7 days default

        if refresh_token_exp > 2592000 { // 30 days
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::Medium,
                category: "Authentication".to_string(),
                parameter: "JWT_REFRESH_TOKEN_EXPIRATION".to_string(),
                message: "Refresh token expiration is very long".to_string(),
                recommendation: "Consider using refresh token expiration ≤30 days".to_string(),
                current_value: Some(format!("{} seconds", refresh_token_exp)),
                recommended_value: Some("≤2592000 seconds (30 days)".to_string()),
            });
        }

        // Check JWT algorithm configuration
        let jwt_algorithm = std::env::var("JWT_ALGORITHM").unwrap_or_else(|_| "HS256".to_string());
        
        if jwt_algorithm == "none" {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::Critical,
                category: "Authentication".to_string(),
                parameter: "JWT_ALGORITHM".to_string(),
                message: "JWT algorithm 'none' is extremely insecure".to_string(),
                recommendation: "Use RS256, ES256, or HS256 algorithms".to_string(),
                current_value: Some(jwt_algorithm),
                recommended_value: Some("RS256 or ES256".to_string()),
            });
        } else if jwt_algorithm == "HS256" && self.strict_mode {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::Medium,
                category: "Authentication".to_string(),
                parameter: "JWT_ALGORITHM".to_string(),
                message: "HS256 uses shared secrets, RS256/ES256 preferred for production".to_string(),
                recommendation: "Consider using RS256 or ES256 for better key management".to_string(),
                current_value: Some(jwt_algorithm),
                recommended_value: Some("RS256 or ES256".to_string()),
            });
        }
    }

    /// Validate rate limiting configuration
    fn validate_rate_limiting_config(&self, result: &mut ValidationResult) {
        debug!("Validating rate limiting configuration");

        let per_ip_limit = std::env::var("RATE_LIMIT_PER_IP_PER_MINUTE")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(100);

        if per_ip_limit > 1000 {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::Medium,
                category: "Rate Limiting".to_string(),
                parameter: "RATE_LIMIT_PER_IP_PER_MINUTE".to_string(),
                message: "Per-IP rate limit is very high, may not prevent abuse".to_string(),
                recommendation: "Consider using per-IP limit ≤500 requests/minute".to_string(),
                current_value: Some(per_ip_limit.to_string()),
                recommended_value: Some("≤500".to_string()),
            });
        }

        if per_ip_limit < 10 && !self.production_mode {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::Low,
                category: "Rate Limiting".to_string(),
                parameter: "RATE_LIMIT_PER_IP_PER_MINUTE".to_string(),
                message: "Per-IP rate limit is very restrictive for development".to_string(),
                recommendation: "Consider increasing limit for development/testing".to_string(),
                current_value: Some(per_ip_limit.to_string()),
                recommended_value: Some("≥50 for development".to_string()),
            });
        }

        // Check distributed rate limiting configuration
        if std::env::var("RATE_LIMIT_ENABLE_DISTRIBUTED").map(|v| v == "true").unwrap_or(false) {
            if std::env::var("REDIS_URL").is_err() {
                result.add_issue(ValidationIssue {
                    severity: ValidationSeverity::High,
                    category: "Rate Limiting".to_string(),
                    parameter: "REDIS_URL".to_string(),
                    message: "Distributed rate limiting enabled but Redis URL not configured".to_string(),
                    recommendation: "Configure REDIS_URL or disable distributed rate limiting".to_string(),
                    current_value: None,
                    recommended_value: Some("redis://localhost:6379".to_string()),
                });
            }
        }
    }

    /// Validate security headers configuration
    fn validate_security_headers_config(&self, result: &mut ValidationResult) {
        debug!("Validating security headers configuration");

        // Check HSTS configuration
        let hsts_enabled = std::env::var("ENABLE_HSTS")
            .map(|v| v == "true")
            .unwrap_or(true);

        if !hsts_enabled && self.production_mode {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::High,
                category: "Security Headers".to_string(),
                parameter: "ENABLE_HSTS".to_string(),
                message: "HSTS is disabled in production environment".to_string(),
                recommendation: "Enable HSTS for production HTTPS deployments".to_string(),
                current_value: Some("false".to_string()),
                recommended_value: Some("true".to_string()),
            });
        }

        let hsts_max_age = std::env::var("HSTS_MAX_AGE")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(31536000);

        if hsts_enabled && hsts_max_age < 86400 {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::Medium,
                category: "Security Headers".to_string(),
                parameter: "HSTS_MAX_AGE".to_string(),
                message: "HSTS max-age is too short".to_string(),
                recommendation: "Use HSTS max-age of at least 1 year (31536000 seconds)".to_string(),
                current_value: Some(hsts_max_age.to_string()),
                recommended_value: Some("31536000 (1 year)".to_string()),
            });
        }

        // Check CSP configuration
        if std::env::var("CSP_POLICY").is_err() && self.production_mode {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::Medium,
                category: "Security Headers".to_string(),
                parameter: "CSP_POLICY".to_string(),
                message: "Content Security Policy not configured".to_string(),
                recommendation: "Configure CSP to prevent XSS attacks".to_string(),
                current_value: None,
                recommended_value: Some("default-src 'self'; script-src 'self'".to_string()),
            });
        }
    }

    /// Validate network configuration
    fn validate_network_config(&self, result: &mut ValidationResult) {
        debug!("Validating network configuration");

        // Check allowed origins for CORS
        if let Ok(cors_origins) = std::env::var("CORS_ALLOWED_ORIGINS") {
            if cors_origins == "*" && self.production_mode {
                result.add_issue(ValidationIssue {
                    severity: ValidationSeverity::High,
                    category: "Network Security".to_string(),
                    parameter: "CORS_ALLOWED_ORIGINS".to_string(),
                    message: "CORS allows all origins (*) in production".to_string(),
                    recommendation: "Specify explicit allowed origins for production".to_string(),
                    current_value: Some(cors_origins),
                    recommended_value: Some("https://yourdomain.com,https://app.yourdomain.com".to_string()),
                });
            }
        }

        // Check TLS configuration
        let tls_enabled = std::env::var("ENABLE_TLS")
            .map(|v| v == "true")
            .unwrap_or(!self.production_mode);

        if !tls_enabled && self.production_mode {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::Critical,
                category: "Network Security".to_string(),
                parameter: "ENABLE_TLS".to_string(),
                message: "TLS is disabled in production environment".to_string(),
                recommendation: "Enable TLS for all production deployments".to_string(),
                current_value: Some("false".to_string()),
                recommended_value: Some("true".to_string()),
            });
        }
    }

    /// Validate database configuration
    fn validate_database_config(&self, result: &mut ValidationResult) {
        debug!("Validating database configuration");

        // Check database connection security
        if let Ok(db_url) = std::env::var("DATABASE_URL") {
            if db_url.starts_with("postgres://") && !db_url.contains("sslmode=require") {
                result.add_issue(ValidationIssue {
                    severity: if self.production_mode { ValidationSeverity::High } else { ValidationSeverity::Medium },
                    category: "Database Security".to_string(),
                    parameter: "DATABASE_URL".to_string(),
                    message: "Database connection does not enforce SSL".to_string(),
                    recommendation: "Add sslmode=require to database connection string".to_string(),
                    current_value: Some("SSL not enforced".to_string()),
                    recommended_value: Some("sslmode=require".to_string()),
                });
            }

            if db_url.contains("password=") && db_url.contains("localhost") && self.production_mode {
                result.add_issue(ValidationIssue {
                    severity: ValidationSeverity::Medium,
                    category: "Database Security".to_string(),
                    parameter: "DATABASE_URL".to_string(),
                    message: "Database password visible in connection string".to_string(),
                    recommendation: "Use environment variables or secret management for DB credentials".to_string(),
                    current_value: Some("Embedded credentials".to_string()),
                    recommended_value: Some("External credential management".to_string()),
                });
            }
        }

        // Check Redis configuration security
        if let Ok(redis_url) = std::env::var("REDIS_URL") {
            if redis_url.starts_with("redis://") && !redis_url.contains("tls") && self.production_mode {
                result.add_issue(ValidationIssue {
                    severity: ValidationSeverity::Medium,
                    category: "Database Security".to_string(),
                    parameter: "REDIS_URL".to_string(),
                    message: "Redis connection is not encrypted".to_string(),
                    recommendation: "Use rediss:// or configure TLS for Redis in production".to_string(),
                    current_value: Some("Unencrypted connection".to_string()),
                    recommended_value: Some("rediss:// (TLS encrypted)".to_string()),
                });
            }
        }
    }

    /// Validate environment-specific configuration
    fn validate_environment_config(&self, result: &mut ValidationResult) {
        debug!("Validating environment configuration");

        // Check for debug mode in production
        if std::env::var("DEBUG").map(|v| v == "true").unwrap_or(false) && self.production_mode {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::High,
                category: "Environment".to_string(),
                parameter: "DEBUG".to_string(),
                message: "Debug mode is enabled in production".to_string(),
                recommendation: "Disable debug mode for production deployments".to_string(),
                current_value: Some("true".to_string()),
                recommended_value: Some("false".to_string()),
            });
        }

        // Check logging configuration
        let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
        
        if (log_level.contains("debug") || log_level.contains("trace")) && self.production_mode {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::Medium,
                category: "Environment".to_string(),
                parameter: "RUST_LOG".to_string(),
                message: "Verbose logging enabled in production".to_string(),
                recommendation: "Use 'info' or 'warn' log level for production".to_string(),
                current_value: Some(log_level),
                recommended_value: Some("info".to_string()),
            });
        }

        // Check for test mode
        if std::env::var("TEST_MODE").map(|v| v == "true").unwrap_or(false) && self.production_mode {
            result.add_issue(ValidationIssue {
                severity: ValidationSeverity::Critical,
                category: "Environment".to_string(),
                parameter: "TEST_MODE".to_string(),
                message: "Test mode is enabled in production environment".to_string(),
                recommendation: "Disable test mode for production deployments".to_string(),
                current_value: Some("true".to_string()),
                recommended_value: Some("false".to_string()),
            });
        }
    }

    /// Validate production readiness
    fn validate_production_readiness(&self, result: &mut ValidationResult) {
        debug!("Validating production readiness");

        // Check required production environment variables
        let required_vars = [
            "JWT_SECRET",
            "DATABASE_URL",
            "ENCRYPTION_KEY",
        ];

        for var in &required_vars {
            if std::env::var(var).is_err() {
                result.add_issue(ValidationIssue {
                    severity: ValidationSeverity::Critical,
                    category: "Production Readiness".to_string(),
                    parameter: var.to_string(),
                    message: format!("Required production environment variable {} is not set", var),
                    recommendation: format!("Set {} environment variable before production deployment", var),
                    current_value: None,
                    recommended_value: Some("Required value".to_string()),
                });
            }
        }

        // Check for default/insecure values
        let insecure_defaults = [
            ("JWT_SECRET", "your-secret-key"),
            ("JWT_SECRET", "secret"),
            ("JWT_SECRET", "default"),
            ("ENCRYPTION_KEY", "your-encryption-key"),
            ("DATABASE_URL", "postgres://user:pass@localhost/db"),
        ];

        for (var, insecure_value) in &insecure_defaults {
            if let Ok(value) = std::env::var(var) {
                if value == *insecure_value {
                    result.add_issue(ValidationIssue {
                        severity: ValidationSeverity::Critical,
                        category: "Production Readiness".to_string(),
                        parameter: var.to_string(),
                        message: format!("{} is using an insecure default value", var),
                        recommendation: format!("Set a secure, random value for {}", var),
                        current_value: Some("Insecure default".to_string()),
                        recommended_value: Some("Secure random value".to_string()),
                    });
                }
            }
        }
    }

    /// Generate security configuration report
    pub fn generate_report(&self, result: &ValidationResult) -> String {
        let mut report = String::new();
        
        report.push_str("# Security Configuration Validation Report\n\n");
        report.push_str(&format!("**Validation Mode**: {}\n", if self.production_mode { "Production" } else { "Development" }));
        report.push_str(&format!("**Strict Mode**: {}\n\n", self.strict_mode));
        
        report.push_str("## Summary\n\n");
        report.push_str(&format!("- 🔴 Critical Issues: {}\n", result.critical_count));
        report.push_str(&format!("- 🟡 High Priority: {}\n", result.high_count));
        report.push_str(&format!("- 🔵 Medium Priority: {}\n", result.medium_count));
        report.push_str(&format!("- ⚪ Low Priority: {}\n", result.low_count));
        report.push_str(&format!("- **Overall Status**: {}\n\n", if result.passed { "✅ PASSED" } else { "❌ FAILED" }));

        if result.has_critical_issues() {
            report.push_str("⚠️  **CRITICAL**: This configuration has critical security issues that must be resolved before production deployment.\n\n");
        }

        report.push_str("## Issues by Category\n\n");
        
        let mut categories: HashMap<String, Vec<&ValidationIssue>> = HashMap::new();
        for issue in &result.issues {
            categories.entry(issue.category.clone()).or_default().push(issue);
        }

        for (category, issues) in categories {
            report.push_str(&format!("### {}\n\n", category));
            
            for issue in issues {
                let severity_icon = match issue.severity {
                    ValidationSeverity::Critical => "🔴",
                    ValidationSeverity::High => "🟡",
                    ValidationSeverity::Medium => "🔵",
                    ValidationSeverity::Low => "⚪",
                    ValidationSeverity::Info => "ℹ️",
                };
                
                report.push_str(&format!("{} **{}** - `{}`\n", severity_icon, issue.severity.to_string(), issue.parameter));
                report.push_str(&format!("  - **Issue**: {}\n", issue.message));
                report.push_str(&format!("  - **Recommendation**: {}\n", issue.recommendation));
                
                if let Some(ref current) = issue.current_value {
                    report.push_str(&format!("  - **Current**: {}\n", current));
                }
                
                if let Some(ref recommended) = issue.recommended_value {
                    report.push_str(&format!("  - **Recommended**: {}\n", recommended));
                }
                
                report.push_str("\n");
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[tokio::test]
    async fn test_jwt_secret_validation() {
        let validator = SecurityConfigValidator::production();
        
        // Test short JWT secret
        env::set_var("JWT_SECRET", "short");
        let result = validator.validate_all_configurations().await;
        assert!(result.has_critical_issues());
        assert!(result.issues.iter().any(|i| i.parameter == "JWT_SECRET" && i.severity == ValidationSeverity::Critical));
    }

    #[tokio::test] 
    async fn test_production_readiness() {
        let validator = SecurityConfigValidator::production();
        
        // Remove required environment variables
        env::remove_var("JWT_SECRET");
        env::remove_var("DATABASE_URL");
        env::remove_var("ENCRYPTION_KEY");
        
        let result = validator.validate_all_configurations().await;
        assert!(result.has_critical_issues());
        assert_eq!(result.critical_count, 3); // Three missing required vars
    }

    #[test]
    fn test_validation_result() {
        let mut result = ValidationResult::new();
        assert!(result.passed);
        assert_eq!(result.critical_count, 0);
        
        result.add_issue(ValidationIssue {
            severity: ValidationSeverity::Critical,
            category: "Test".to_string(),
            parameter: "TEST_PARAM".to_string(),
            message: "Test message".to_string(),
            recommendation: "Test recommendation".to_string(),
            current_value: None,
            recommended_value: None,
        });
        
        assert!(!result.passed);
        assert_eq!(result.critical_count, 1);
        assert!(result.has_critical_issues());
    }

    #[test]
    fn test_development_vs_production_validation() {
        let dev_validator = SecurityConfigValidator::development();
        let prod_validator = SecurityConfigValidator::production();
        
        assert!(!dev_validator.production_mode);
        assert!(!dev_validator.strict_mode);
        
        assert!(prod_validator.production_mode);
        assert!(prod_validator.strict_mode);
    }
}