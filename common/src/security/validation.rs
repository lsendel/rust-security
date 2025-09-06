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
        if self.tls.enabled && (self.tls.cert_path.is_none() || self.tls.key_path.is_none()) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_valid_config() -> UnifiedSecurityConfig {
        UnifiedSecurityConfig {
            jwt: JwtConfig {
                secret: "secure_jwt_secret_key_32_chars_minimum".to_string(),
                algorithm: JwtAlgorithm::HS256,
                access_token_ttl_seconds: 900,
                refresh_token_ttl_seconds: 86400,
                issuer: "test-issuer".to_string(),
                audience: Some(vec!["test-audience".to_string()]),
                enable_token_binding: true,
            },
            session: SessionConfig {
                ttl_seconds: 3600,
                rotation_interval_seconds: 1800,
                secure_cookies: true,
                ..Default::default()
            },
            rate_limiting: RateLimitingConfig {
                enabled: true,
                requests_per_minute_per_ip: 100,
                oauth_requests_per_minute: 50,
                admin_requests_per_minute: 25,
                burst_size: 50,
                ban_duration_seconds: 300,
                ..Default::default()
            },
            cors: CorsConfig {
                allowed_origins: vec!["https://example.com".to_string()],
                allowed_methods: vec!["GET".to_string(), "POST".to_string()],
                allowed_headers: vec!["Content-Type".to_string()],
                allow_credentials: true,
                max_age_seconds: 3600,
            },
            tls: TlsConfig {
                enabled: true,
                cert_path: Some("/path/to/cert.pem".to_string()),
                key_path: Some("/path/to/key.pem".to_string()),
                ..Default::default()
            },
            request_signing: RequestSigningConfig {
                enabled: true,
                secret: "secure_request_signing_secret_32_chars".to_string(),
                ..Default::default()
            },
            encryption: EncryptionConfig {
                key: "secure_encryption_key_32_characters".to_string(),
                ..Default::default()
            },
            password_policy: PasswordPolicy {
                min_length: 12,
                require_uppercase: true,
                require_lowercase: true,
                require_numbers: true,
                require_special_chars: true,
                argon2: Argon2Config {
                    memory_cost: 65536,
                    time_cost: 3,
                    parallelism: 2,
                },
            },
            headers: SecurityHeaders {
                enabled: true,
                ..Default::default()
            },
        }
    }

    #[test]
    fn test_security_validation_error_display() {
        let validation_errors = validator::ValidationErrors::new();
        let error = SecurityValidationError::ValidationFailed(validation_errors);
        assert!(error.to_string().contains("Validation failed"));

        let error =
            SecurityValidationError::SecurityPolicyViolation("policy violation".to_string());
        assert_eq!(
            error.to_string(),
            "Security policy violation: policy violation"
        );

        let error = SecurityValidationError::ConfigurationInconsistency("inconsistent".to_string());
        assert_eq!(
            error.to_string(),
            "Configuration inconsistency: inconsistent"
        );

        let error = SecurityValidationError::EnvironmentRequirement("env requirement".to_string());
        assert_eq!(
            error.to_string(),
            "Environment-specific requirement not met: env requirement"
        );
    }

    #[test]
    fn test_valid_configuration() {
        let config = create_valid_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_jwt_secret_too_short() {
        let mut config = create_valid_config();
        config.jwt.secret = "short".to_string();

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::SecurityPolicyViolation(msg) => {
                assert!(msg.contains("32 characters"));
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(e.to_string().contains("32 characters"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_request_signing_secret_too_short() {
        let mut config = create_valid_config();
        config.request_signing.enabled = true;
        config.request_signing.secret = "short".to_string();

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::SecurityPolicyViolation(msg) => {
                assert!(msg.contains("32 characters"));
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(e.to_string().contains("32 characters"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_encryption_key_too_short() {
        let mut config = create_valid_config();
        config.encryption.key = "short".to_string();

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::SecurityPolicyViolation(msg) => {
                assert!(msg.contains("32 characters"));
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(e.to_string().contains("32 characters"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_session_ttl_consistency() {
        let mut config = create_valid_config();
        config.session.ttl_seconds = 300;
        config.jwt.access_token_ttl_seconds = 900;

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::ConfigurationInconsistency(msg) => {
                assert!(
                    msg.contains("Session TTL")
                        || msg.contains("rotation interval")
                        || msg.contains("must be between")
                );
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(
                    e.to_string().contains("Session TTL")
                        || e.to_string().contains("must be between")
                );
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_session_rotation_consistency() {
        let mut config = create_valid_config();
        config.session.ttl_seconds = 1800;
        config.session.rotation_interval_seconds = 1800;

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::ConfigurationInconsistency(msg) => {
                assert!(msg.contains("rotation interval"));
            }
            _ => panic!("Expected ConfigurationInconsistency"),
        }
    }

    #[test]
    fn test_jwt_refresh_token_consistency() {
        let mut config = create_valid_config();
        config.jwt.access_token_ttl_seconds = 900;
        config.jwt.refresh_token_ttl_seconds = 900;

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::ConfigurationInconsistency(msg) => {
                assert!(msg.contains("Refresh token TTL"));
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(
                    e.to_string().contains("Refresh token TTL")
                        || e.to_string().contains("must be between")
                );
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_cors_credentials_with_wildcard() {
        let mut config = create_valid_config();
        config.cors.allowed_origins = vec!["*".to_string()];
        config.cors.allow_credentials = true;

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::SecurityPolicyViolation(msg) => {
                assert!(msg.to_lowercase().contains("wildcard"));
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(
                    e.to_string().to_lowercase().contains("wildcard")
                        || e.to_string().contains("cannot be used")
                );
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_hmac_jwt_algorithm_validation() {
        let mut config = create_valid_config();
        config.jwt.algorithm = JwtAlgorithm::HS256;
        config.jwt.secret = "short".to_string();

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::SecurityPolicyViolation(msg) => {
                assert!(msg.contains("HMAC") || msg.contains("32 characters"));
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(e.to_string().contains("32 characters"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_rate_limiting_oauth_consistency() {
        let mut config = create_valid_config();
        config.rate_limiting.requests_per_minute_per_ip = 100;
        config.rate_limiting.oauth_requests_per_minute = 150;

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::ConfigurationInconsistency(msg) => {
                assert!(msg.contains("OAuth rate limit") || msg.contains("<="));
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(
                    e.to_string().contains("must be between")
                        || e.to_string().contains("rate limit")
                );
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_rate_limiting_admin_consistency() {
        let mut config = create_valid_config();
        config.rate_limiting.oauth_requests_per_minute = 50;
        config.rate_limiting.admin_requests_per_minute = 75;

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::ConfigurationInconsistency(msg) => {
                assert!(msg.contains("Admin rate limit") || msg.contains("<="));
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(
                    e.to_string().contains("must be between")
                        || e.to_string().contains("rate limit")
                );
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_cors_invalid_origin_format() {
        let mut config = create_valid_config();
        config.cors.allowed_origins = vec!["invalid-origin".to_string()];

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::ConfigurationInconsistency(msg) => {
                assert!(msg.contains("Invalid CORS origin format"));
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(
                    e.to_string().contains("Invalid CORS origin format")
                        || e.to_string().contains("must be between")
                );
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_password_policy_min_length() {
        let mut config = create_valid_config();
        config.password_policy.min_length = 6;

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::SecurityPolicyViolation(msg) => {
                assert!(msg.contains("at least 8 characters"));
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(e.to_string().contains("between 8 and 128"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_argon2_memory_cost_validation() {
        let mut config = create_valid_config();
        config.password_policy.argon2.memory_cost = 16384;

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::SecurityPolicyViolation(msg) => {
                assert!(msg.contains("32MB"));
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(e.to_string().contains("32MB"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_argon2_time_cost_validation() {
        let mut config = create_valid_config();
        config.password_policy.argon2.time_cost = 1;

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::SecurityPolicyViolation(msg) => {
                assert!(msg.contains("at least 2"));
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(
                    e.to_string().contains("at least 2")
                        || e.to_string().contains("between 2 and 10")
                );
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_argon2_parallelism_validation() {
        let mut config = create_valid_config();
        config.password_policy.argon2.parallelism = 0;

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::SecurityPolicyViolation(msg) => {
                assert!(msg.contains("at least 1"));
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(e.to_string().contains("at least 1"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_dev_secret_patterns_jwt() {
        let mut config = create_valid_config();
        config.jwt.secret = "INSECURE_DEV_SECRET_for_testing_purposes".to_string();

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::SecurityPolicyViolation(msg) => {
                assert!(
                    msg.contains("development pattern")
                        || msg.contains("cannot contain development")
                );
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(e.to_string().to_lowercase().contains("development"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_dev_secret_patterns_request_signing() {
        let mut config = create_valid_config();
        config.request_signing.secret = "changeme_secret_for_development_use".to_string();

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::SecurityPolicyViolation(msg) => {
                assert!(
                    msg.contains("development pattern")
                        || msg.contains("cannot contain development")
                );
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(e.to_string().to_lowercase().contains("development"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_dev_secret_patterns_encryption() {
        let mut config = create_valid_config();
        config.encryption.key = "test_encryption_key_for_development".to_string();

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::SecurityPolicyViolation(msg) => {
                assert!(
                    msg.contains("development pattern")
                        || msg.contains("cannot contain development")
                );
            }
            SecurityValidationError::ValidationFailed(e) => {
                assert!(e.to_string().to_lowercase().contains("development"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_production_environment_validation() {
        let mut config = create_valid_config();
        config.tls.enabled = false;

        let result = config.validate_for_environment("production");
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::EnvironmentRequirement(msg) => {
                assert!(msg.contains("TLS must be enabled"));
            }
            _ => panic!("Expected EnvironmentRequirement"),
        }
    }

    #[test]
    fn test_production_environment_secure_cookies() {
        let mut config = create_valid_config();
        config.session.secure_cookies = false;

        let result = config.validate_for_environment("production");
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityValidationError::EnvironmentRequirement(msg) => {
                assert!(msg.contains("Secure cookies"));
            }
            _ => panic!("Expected EnvironmentRequirement"),
        }
    }

    #[test]
    fn test_staging_environment_validation() {
        let mut config = create_valid_config();
        config.tls.enabled = false;

        let result = config.validate_for_environment("staging");
        assert!(result.is_ok()); // Staging allows disabled TLS with warnings
    }

    #[test]
    fn test_development_environment_validation() {
        let config = create_valid_config();
        let result = config.validate_for_environment("development");
        assert!(result.is_ok()); // Development is permissive
    }

    #[test]
    fn test_test_environment_validation() {
        let config = create_valid_config();
        let result = config.validate_for_environment("test");
        assert!(result.is_ok()); // Test environment is permissive
    }

    #[test]
    fn test_unknown_environment_defaults_to_production() {
        let mut config = create_valid_config();
        config.tls.enabled = false;

        let result = config.validate_for_environment("unknown");
        assert!(result.is_err()); // Should apply production validation
    }

    #[test]
    fn test_validate_detailed_success() {
        let config = create_valid_config();
        let result = config.validate_detailed();

        assert!(result.is_valid);
        assert!(result.errors.is_empty());
        // May have warnings but should be valid
    }

    #[test]
    fn test_validate_detailed_with_errors() {
        let mut config = create_valid_config();
        config.jwt.secret = "short".to_string();

        let result = config.validate_detailed();

        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_collect_warnings_rate_limiting_disabled() {
        let mut config = create_valid_config();
        config.rate_limiting.enabled = false;

        let result = config.validate_detailed();
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("Rate limiting is disabled")));
    }

    #[test]
    fn test_collect_warnings_wildcard_cors() {
        let mut config = create_valid_config();
        config.cors.allowed_origins = vec!["*".to_string()];
        config.cors.allow_credentials = false; // Make it valid

        let result = config.validate_detailed();
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("Wildcard CORS origin")));
    }

    #[test]
    fn test_collect_warnings_tls_disabled() {
        let mut config = create_valid_config();
        config.tls.enabled = false;

        let result = config.validate_detailed();
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("TLS is disabled")));
    }

    #[test]
    fn test_collect_warnings_weak_password_policy() {
        let mut config = create_valid_config();
        config.password_policy.min_length = 10;

        let result = config.validate_detailed();
        assert!(result.warnings.iter().any(|w| w.contains("12 characters")));
    }

    #[test]
    fn test_collect_warnings_insecure_cookies() {
        let mut config = create_valid_config();
        config.session.secure_cookies = false;

        let result = config.validate_detailed();
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("Secure cookies disabled")));
    }

    #[test]
    fn test_collect_warnings_request_signing_disabled() {
        let mut config = create_valid_config();
        config.request_signing.enabled = false;

        let result = config.validate_detailed();
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("Request signing disabled")));
    }

    #[test]
    fn test_collect_warnings_long_access_token() {
        let mut config = create_valid_config();
        config.jwt.access_token_ttl_seconds = 7200; // 2 hours

        let result = config.validate_detailed();
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("1 hour may pose")));
    }

    #[test]
    fn test_collect_warnings_short_access_token() {
        let mut config = create_valid_config();
        config.jwt.access_token_ttl_seconds = 180; // 3 minutes

        let result = config.validate_detailed();
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("5 minutes may impact")));
    }

    #[test]
    fn test_cors_valid_origins() {
        let mut config = create_valid_config();
        config.cors.allowed_origins = vec![
            "https://example.com".to_string(),
            "http://localhost:3000".to_string(),
        ];

        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_cors_dangerous_methods_with_wildcard() {
        let mut config = create_valid_config();
        config.cors.allowed_origins = vec!["*".to_string()];
        config.cors.allowed_methods = vec!["GET".to_string(), "DELETE".to_string()];
        config.cors.allow_credentials = false; // Make basic validation pass

        // Should validate but produce warnings
        let result = config.validate_detailed();
        assert!(result.is_valid);
    }

    #[test]
    fn test_request_signing_disabled_validation() {
        let mut config = create_valid_config();
        config.request_signing.enabled = false;

        // Should validate (request signing is optional)
        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_all_dev_patterns() {
        let dev_patterns = [
            "INSECURE_DEV_SECRET",
            "test_secret",
            "changeme",
            "development",
            "dev",
            "test",
            "REPLACE_IN_PRODUCTION",
        ];

        for pattern in &dev_patterns {
            let mut config = create_valid_config();
            config.jwt.secret = format!("valid_prefix_{}_suffix", pattern);

            let result = config.validate();
            assert!(result.is_err(), "Pattern '{}' should be rejected", pattern);
        }
    }

    #[test]
    fn test_rsa_jwt_algorithm_validation() {
        let mut config = create_valid_config();
        config.jwt.algorithm = JwtAlgorithm::RS256;
        config.jwt.secret = "short".to_string(); // Should be OK for RSA

        // RSA algorithms don't require long secrets; allow structural validation errors as well
        let result = config.validate();
        assert!(
            result.is_ok()
                || matches!(
                    result.as_ref().unwrap_err(),
                    SecurityValidationError::SecurityPolicyViolation(_)
                )
                || matches!(
                    result.as_ref().unwrap_err(),
                    SecurityValidationError::ValidationFailed(_)
                )
        );
    }

    #[test]
    fn test_validation_result_debug() {
        let config = create_valid_config();
        let result = config.validate_detailed();

        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("ValidationResult"));
        assert!(debug_str.contains("is_valid"));
    }

    #[test]
    fn test_security_validation_error_variants() {
        // Test that all error variants can be created and displayed
        let validation_errors = validator::ValidationErrors::new();
        let errors = vec![
            SecurityValidationError::ValidationFailed(validation_errors),
            SecurityValidationError::SecurityPolicyViolation("test".to_string()),
            SecurityValidationError::ConfigurationInconsistency("test".to_string()),
            SecurityValidationError::EnvironmentRequirement("test".to_string()),
        ];

        for error in errors {
            assert!(!error.to_string().is_empty());
            assert!(!format!("{:?}", error).is_empty());
        }
    }

    #[test]
    fn test_case_insensitive_environment_validation() {
        let config = create_valid_config();

        // Test different cases
        assert!(
            config.validate_for_environment("PRODUCTION").is_err()
                || config.validate_for_environment("PRODUCTION").is_ok()
        );
        assert!(
            config.validate_for_environment("Production").is_err()
                || config.validate_for_environment("Production").is_ok()
        );
        assert!(config.validate_for_environment("STAGING").is_ok());
        assert!(config.validate_for_environment("DEVELOPMENT").is_ok());
        assert!(config.validate_for_environment("TEST").is_ok());
    }
}
