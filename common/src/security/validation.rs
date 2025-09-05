//! Security configuration validation
//!
//! This module provides comprehensive validation for security configurations
//! to ensure they meet security requirements and best practices.

use super::*;
use std::collections::HashSet;
use tracing::warn;

/// Extended validation errors with security context
#[derive(Debug, thiserror::Error)]
pub enum SecurityValidationError {
    #[error("Validation failed: {0}")]
    ValidationFailed(#[from] validator::ValidationErrors),

    #[error("Security policy violation: {0}")]
    SecurityPolicyViolation(String),

    #[error("Configuration inconsistency: {0}")]
    ConfigurationInconsistency(String),

    #[error("Environment-specific requirement not met: {0}")]
    EnvironmentRequirement(String),
}

impl UnifiedSecurityConfig {
    /// Comprehensive validation of the security configuration
    ///
    /// This method performs both structural validation (using the validator crate)
    /// and logical/security validation to ensure the configuration is secure
    /// and internally consistent.
    ///
    /// # Validation Checks
    /// 1. **Structural Validation**: Field-level validation using validator attributes
    /// 2. **Security Policy Validation**: Ensures security policies are followed
    /// 3. **Consistency Validation**: Checks for logical consistency between fields
    /// 4. **Environment Validation**: Validates environment-specific requirements
    ///
    /// # Errors
    /// Returns a `SecurityValidationError` if any validation fails
    pub fn validate(&self) -> Result<(), SecurityValidationError> {
        // Basic structural validation using validator crate
        validator::Validate::validate(self)?;

        // Additional security-specific validation
        self.validate_security_policies()?;
        self.validate_consistency()?;
        self.validate_token_security()?;
        self.validate_rate_limiting_logic()?;
        self.validate_cors_security()?;
        self.validate_password_strength()?;

        Ok(())
    }

    /// Validate security policies are properly enforced
    fn validate_security_policies(&self) -> Result<(), SecurityValidationError> {
        // JWT secret validation
        if self.jwt.secret.len() < 32 {
            return Err(SecurityValidationError::SecurityPolicyViolation(
                "JWT secret must be at least 32 characters".to_string(),
            ));
        }

        // Request signing secret validation
        if self.request_signing.enabled && self.request_signing.secret.len() < 32 {
            return Err(SecurityValidationError::SecurityPolicyViolation(
                "Request signing secret must be at least 32 characters when enabled".to_string(),
            ));
        }

        // Encryption key validation
        if self.encryption.key.len() < 32 {
            return Err(SecurityValidationError::SecurityPolicyViolation(
                "Encryption key must be at least 32 characters".to_string(),
            ));
        }

        // Check for insecure development defaults in production-like configs
        self.validate_no_dev_secrets()?;

        Ok(())
    }

    /// Validate configuration consistency
    fn validate_consistency(&self) -> Result<(), SecurityValidationError> {
        // Session TTL should be longer than JWT access token TTL
        if self.session.ttl_seconds < self.jwt.access_token_ttl_seconds {
            return Err(SecurityValidationError::ConfigurationInconsistency(
                "Session TTL should be >= JWT access token TTL".to_string(),
            ));
        }

        // Session rotation should be less than session TTL
        if self.session.rotation_interval_seconds >= self.session.ttl_seconds {
            return Err(SecurityValidationError::ConfigurationInconsistency(
                "Session rotation interval must be < session TTL".to_string(),
            ));
        }

        // JWT refresh token should be longer than access token
        if self.jwt.refresh_token_ttl_seconds <= self.jwt.access_token_ttl_seconds {
            return Err(SecurityValidationError::ConfigurationInconsistency(
                "Refresh token TTL must be > access token TTL".to_string(),
            ));
        }

        // CORS credentials require specific origins (not wildcard)
        if self.cors.allow_credentials && self.cors.allowed_origins.contains(&"*".to_string()) {
            return Err(SecurityValidationError::SecurityPolicyViolation(
                "CORS credentials cannot be used with wildcard origin".to_string(),
            ));
        }

        // TLS validation
        if self.tls.enabled
            && (self.tls.cert_path.is_none() || self.tls.key_path.is_none()) {
                warn!("TLS enabled but cert_path or key_path not configured");
            }

        Ok(())
    }

    /// Validate token security settings
    fn validate_token_security(&self) -> Result<(), SecurityValidationError> {
        // Access tokens should not be too long-lived
        if self.jwt.access_token_ttl_seconds > 3600 {
            warn!("Access token TTL > 1 hour may pose security risks");
        }

        // Refresh tokens should not be too long-lived
        if self.jwt.refresh_token_ttl_seconds > 86400 * 7 {
            warn!("Refresh token TTL > 7 days may pose security risks");
        }

        // Very short access tokens may impact usability
        if self.jwt.access_token_ttl_seconds < 300 {
            warn!("Access token TTL < 5 minutes may impact user experience");
        }

        // Validate JWT algorithm security
        match self.jwt.algorithm {
            JwtAlgorithm::HS256 | JwtAlgorithm::HS384 | JwtAlgorithm::HS512 => {
                // HMAC algorithms require strong secrets
                if self.jwt.secret.len() < 32 {
                    return Err(SecurityValidationError::SecurityPolicyViolation(
                        "HMAC JWT algorithms require secrets >= 32 characters".to_string(),
                    ));
                }
            }
            _ => {
                // RSA/ECDSA algorithms are generally secure with proper key management
            }
        }

        Ok(())
    }

    /// Validate rate limiting logic
    fn validate_rate_limiting_logic(&self) -> Result<(), SecurityValidationError> {
        if !self.rate_limiting.enabled {
            warn!("Rate limiting is disabled - this may allow abuse");
            return Ok(());
        }

        // OAuth rate limits should be lower than general limits
        if self.rate_limiting.oauth_requests_per_minute
            > self.rate_limiting.requests_per_minute_per_ip
        {
            return Err(SecurityValidationError::ConfigurationInconsistency(
                "OAuth rate limit should be <= general rate limit".to_string(),
            ));
        }

        // Admin rate limits should be very restrictive
        if self.rate_limiting.admin_requests_per_minute
            > self.rate_limiting.oauth_requests_per_minute
        {
            return Err(SecurityValidationError::ConfigurationInconsistency(
                "Admin rate limit should be <= OAuth rate limit".to_string(),
            ));
        }

        // Burst size should be reasonable
        if self.rate_limiting.burst_size > self.rate_limiting.requests_per_minute_per_ip {
            warn!("Burst size > rate limit may allow abuse");
        }

        // Ban duration should be meaningful
        if self.rate_limiting.ban_duration_seconds < 60 {
            warn!("Very short ban duration may not deter abuse");
        }

        Ok(())
    }

    /// Validate CORS security settings
    fn validate_cors_security(&self) -> Result<(), SecurityValidationError> {
        // Check for insecure CORS settings
        if self.cors.allowed_origins.contains(&"*".to_string()) {
            if self.cors.allow_credentials {
                return Err(SecurityValidationError::SecurityPolicyViolation(
                    "Cannot use wildcard CORS origin with credentials".to_string(),
                ));
            }
            warn!("Wildcard CORS origin allows any website to make requests");
        }

        // Validate allowed origins are proper URLs
        for origin in &self.cors.allowed_origins {
            if origin != "*" && !origin.starts_with("http://") && !origin.starts_with("https://") {
                return Err(SecurityValidationError::ConfigurationInconsistency(
                    format!("Invalid CORS origin format: {}", origin),
                ));
            }
        }

        // Check for potentially dangerous methods
        let dangerous_methods: HashSet<&str> = ["PATCH", "DELETE", "PUT"].iter().cloned().collect();
        let allowed_methods: HashSet<&str> = self
            .cors
            .allowed_methods
            .iter()
            .map(|s| s.as_str())
            .collect();
        let has_dangerous = dangerous_methods.intersection(&allowed_methods).count() > 0;

        if has_dangerous && self.cors.allowed_origins.contains(&"*".to_string()) {
            warn!("Allowing dangerous HTTP methods with wildcard CORS origin");
        }

        Ok(())
    }

    /// Validate password policy strength
    fn validate_password_strength(&self) -> Result<(), SecurityValidationError> {
        let policy = &self.password_policy;

        // Minimum length should be reasonable
        if policy.min_length < 8 {
            return Err(SecurityValidationError::SecurityPolicyViolation(
                "Password minimum length should be at least 8 characters".to_string(),
            ));
        }

        // Recommend stronger policies for production
        if policy.min_length < 12 {
            warn!("Password minimum length < 12 characters is not ideal for security");
        }

        // Validate Argon2 configuration
        let argon2 = &policy.argon2;

        // Memory cost validation
        if argon2.memory_cost < 32768 {
            // 32MB minimum
            return Err(SecurityValidationError::SecurityPolicyViolation(
                "Argon2 memory cost should be at least 32MB (32768)".to_string(),
            ));
        }

        // Time cost validation
        if argon2.time_cost < 2 {
            return Err(SecurityValidationError::SecurityPolicyViolation(
                "Argon2 time cost should be at least 2".to_string(),
            ));
        }

        // Parallelism validation
        if argon2.parallelism < 1 {
            return Err(SecurityValidationError::SecurityPolicyViolation(
                "Argon2 parallelism should be at least 1".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate that no development secrets are present
    fn validate_no_dev_secrets(&self) -> Result<(), SecurityValidationError> {
        let dev_patterns = [
            "INSECURE_DEV_SECRET",
            "test_secret",
            "changeme",
            "development",
            "dev",
            "test",
            "REPLACE_IN_PRODUCTION",
        ];

        // Check JWT secret
        for pattern in &dev_patterns {
            if self.jwt.secret.contains(pattern) {
                return Err(SecurityValidationError::SecurityPolicyViolation(format!(
                    "JWT secret contains development pattern: {}",
                    pattern
                )));
            }
        }

        // Check request signing secret
        if self.request_signing.enabled {
            for pattern in &dev_patterns {
                if self.request_signing.secret.contains(pattern) {
                    return Err(SecurityValidationError::SecurityPolicyViolation(format!(
                        "Request signing secret contains development pattern: {}",
                        pattern
                    )));
                }
            }
        }

        // Check encryption key
        for pattern in &dev_patterns {
            if self.encryption.key.contains(pattern) {
                return Err(SecurityValidationError::SecurityPolicyViolation(format!(
                    "Encryption key contains development pattern: {}",
                    pattern
                )));
            }
        }

        Ok(())
    }

    /// Validate configuration for specific deployment environment
    pub fn validate_for_environment(
        &self,
        environment: &str,
    ) -> Result<(), SecurityValidationError> {
        match environment.to_lowercase().as_str() {
            "production" => self.validate_production_environment(),
            "staging" => self.validate_staging_environment(),
            "development" => self.validate_development_environment(),
            "test" => self.validate_test_environment(),
            _ => {
                warn!("Unknown environment: {}", environment);
                self.validate_production_environment() // Default to strictest validation
            }
        }
    }

    /// Validate production environment requirements
    fn validate_production_environment(&self) -> Result<(), SecurityValidationError> {
        // TLS must be enabled
        if !self.tls.enabled {
            return Err(SecurityValidationError::EnvironmentRequirement(
                "TLS must be enabled in production".to_string(),
            ));
        }

        // Secure cookies must be enabled
        if !self.session.secure_cookies {
            return Err(SecurityValidationError::EnvironmentRequirement(
                "Secure cookies must be enabled in production".to_string(),
            ));
        }

        // Rate limiting should be enabled
        if !self.rate_limiting.enabled {
            warn!("Rate limiting disabled in production - this may allow abuse");
        }

        // Request signing should be enabled
        if !self.request_signing.enabled {
            warn!("Request signing disabled in production - admin endpoints may be vulnerable");
        }

        // CORS should not use wildcards
        if self.cors.allowed_origins.contains(&"*".to_string()) {
            warn!("Wildcard CORS origin not recommended in production");
        }

        // Security headers should be enabled
        if !self.headers.enabled {
            warn!("Security headers disabled in production");
        }

        // Strong password policy required
        if self.password_policy.min_length < 12 {
            warn!("Password minimum length < 12 characters not ideal for production");
        }

        // Access tokens should be short-lived
        if self.jwt.access_token_ttl_seconds > 3600 {
            warn!("Access token TTL > 1 hour not recommended for production");
        }

        Ok(())
    }

    /// Validate staging environment requirements
    fn validate_staging_environment(&self) -> Result<(), SecurityValidationError> {
        // Staging should be similar to production but can be slightly relaxed
        if !self.tls.enabled {
            warn!("TLS should be enabled in staging to match production");
        }

        if !self.session.secure_cookies {
            warn!("Secure cookies should be enabled in staging to match production");
        }

        Ok(())
    }

    /// Validate development environment requirements
    fn validate_development_environment(&self) -> Result<(), SecurityValidationError> {
        // Development can have relaxed security but warn about potential issues
        if self.rate_limiting.enabled && self.rate_limiting.requests_per_minute_per_ip < 1000 {
            warn!("Low rate limits in development may impact testing");
        }

        if self.jwt.access_token_ttl_seconds < 3600 {
            warn!("Short access tokens in development may impact development workflow");
        }

        Ok(())
    }

    /// Validate test environment requirements
    fn validate_test_environment(&self) -> Result<(), SecurityValidationError> {
        // Test environment should have fast settings for test performance
        if self.password_policy.argon2.memory_cost > 65536 {
            // 64MB
            warn!("High Argon2 memory cost may slow down tests");
        }

        if self.jwt.access_token_ttl_seconds > 300 {
            // 5 minutes
            warn!("Long token TTL may slow down token expiration tests");
        }

        Ok(())
    }
}

/// Validation result with warnings
#[derive(Debug)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<SecurityValidationError>,
    pub warnings: Vec<String>,
}

impl UnifiedSecurityConfig {
    /// Comprehensive validation with detailed results
    ///
    /// Returns a detailed validation result including both errors and warnings.
    /// This is useful for configuration review and security auditing.
    pub fn validate_detailed(&self) -> ValidationResult {
        let mut result = ValidationResult {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        // Capture validation errors
        if let Err(e) = self.validate() {
            result.is_valid = false;
            result.errors.push(e);
        }

        // Additional warning checks (not failures)
        self.collect_warnings(&mut result.warnings);

        result
    }

    /// Collect configuration warnings
    fn collect_warnings(&self, warnings: &mut Vec<String>) {
        // Token TTL warnings
        if self.jwt.access_token_ttl_seconds > 3600 {
            warnings.push("Access token TTL > 1 hour may pose security risks".to_string());
        }

        if self.jwt.access_token_ttl_seconds < 300 {
            warnings.push("Access token TTL < 5 minutes may impact user experience".to_string());
        }

        // Rate limiting warnings
        if !self.rate_limiting.enabled {
            warnings.push("Rate limiting is disabled - this may allow abuse".to_string());
        }

        // CORS warnings
        if self.cors.allowed_origins.contains(&"*".to_string()) {
            warnings.push("Wildcard CORS origin allows any website to make requests".to_string());
        }

        // TLS warnings
        if !self.tls.enabled {
            warnings.push("TLS is disabled - communications are not encrypted".to_string());
        }

        // Password policy warnings
        if self.password_policy.min_length < 12 {
            warnings.push(
                "Password minimum length < 12 characters is not ideal for security".to_string(),
            );
        }

        // Session security warnings
        if !self.session.secure_cookies {
            warnings.push(
                "Secure cookies disabled - sessions may be transmitted over HTTP".to_string(),
            );
        }

        // Request signing warnings
        if !self.request_signing.enabled {
            warnings.push(
                "Request signing disabled - admin endpoints may be vulnerable to replay attacks"
                    .to_string(),
            );
        }
    }
}
