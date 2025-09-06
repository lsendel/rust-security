//! Security configuration implementation with environment loading
//!
//! This module provides the implementation for loading security configuration
//! from environment variables with secure defaults and comprehensive validation.

use super::*;
use crate::security::validation::SecurityValidationError;
use std::env;
use std::str::FromStr;
use tracing::{info, warn};

/// Configuration loading errors
#[derive(Debug, thiserror::Error)]
pub enum SecurityConfigError {
    #[error("Environment variable error: {0}")]
    EnvError(#[from] env::VarError),

    #[error("Validation error: {0}")]
    ValidationError(#[from] validator::ValidationErrors),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Security policy violation: {0}")]
    SecurityError(String),

    #[error("Validation error: {0}")]
    SecurityValidationError(#[from] SecurityValidationError),
}

impl UnifiedSecurityConfig {
    /// Load security configuration from environment variables
    ///
    /// This method loads configuration from environment variables with secure defaults.
    /// It validates all settings to ensure they meet security requirements.
    ///
    /// # Environment Variables
    ///
    /// ## JWT Configuration
    /// - `JWT_SECRET`: JWT signing secret (required, min 32 chars)
    /// - `JWT_ACCESS_TOKEN_TTL_SECONDS`: Access token TTL (default: 900 = 15 minutes)
    /// - `JWT_REFRESH_TOKEN_TTL_SECONDS`: Refresh token TTL (default: 86400 = 24 hours)
    /// - `JWT_ISSUER`: JWT issuer (default: "rust-security-platform")
    /// - `JWT_ALGORITHM`: JWT algorithm (default: "HS256")
    ///
    /// ## Request Signing
    /// - `REQUEST_SIGNING_SECRET`: Request signing secret (required for production, min 32 chars)
    /// - `REQUEST_SIGNING_ENABLED`: Enable request signing (default: true in production)
    /// - `REQUEST_SIGNING_WINDOW_SECONDS`: Timestamp window (default: 300 = 5 minutes)
    ///
    /// ## Rate Limiting
    /// - `RATE_LIMITING_ENABLED`: Enable rate limiting (default: true)
    /// - `RATE_LIMIT_PER_MINUTE`: General rate limit (default: 60)
    /// - `OAUTH_RATE_LIMIT_PER_MINUTE`: OAuth rate limit (default: 10)
    /// - `ADMIN_RATE_LIMIT_PER_MINUTE`: Admin rate limit (default: 5)
    ///
    /// ## Security Headers
    /// - `SECURITY_HEADERS_ENABLED`: Enable security headers (default: true)
    /// - `HSTS_MAX_AGE_SECONDS`: HSTS max age (default: 31536000 = 1 year)
    /// - `CSP_POLICY`: Content Security Policy (optional)
    ///
    /// ## CORS
    /// - `CORS_ALLOWED_ORIGINS`: Comma-separated allowed origins (default: empty)
    /// - `CORS_ALLOW_CREDENTIALS`: Allow credentials (default: false)
    ///
    /// # Errors
    /// Returns an error if:
    /// - Required environment variables are missing
    /// - Values fail validation (e.g., secrets too short)
    /// - Security policies are violated (e.g., dev secrets in production)
    ///
    /// # Example
    /// ```rust
    /// use common::security::UnifiedSecurityConfig;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// std::env::set_var("JWT_SECRET", "very-secure-secret-at-least-32-characters-long");
    /// std::env::set_var("REQUEST_SIGNING_SECRET", "another-secure-secret-for-request-signing");
    /// std::env::set_var("ENCRYPTION_KEY", "encryption-key-that-is-at-least-32-characters");
    ///
    /// let config = UnifiedSecurityConfig::from_env()?;
    /// assert!(config.validate().is_ok());
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_env() -> Result<Self, SecurityConfigError> {
        let environment = env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .to_lowercase();

        let is_production = environment == "production";

        info!(
            "Loading security configuration for environment: {}",
            environment
        );

        // JWT Configuration
        let jwt = JwtConfig {
            secret: Self::load_secret_env("JWT_SECRET", is_production)?,
            access_token_ttl_seconds: Self::parse_env("JWT_ACCESS_TOKEN_TTL_SECONDS", 900)?,
            refresh_token_ttl_seconds: Self::parse_env("JWT_REFRESH_TOKEN_TTL_SECONDS", 86400)?,
            algorithm: Self::parse_env("JWT_ALGORITHM", JwtAlgorithm::HS256)?,
            issuer: env::var("JWT_ISSUER").unwrap_or_else(|_| "rust-security-platform".to_string()),
            audience: env::var("JWT_AUDIENCE")
                .ok()
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect()),
            enable_token_binding: Self::parse_env("JWT_ENABLE_TOKEN_BINDING", true)?,
        };

        // Request Signing Configuration
        let request_signing = RequestSigningConfig {
            secret: Self::load_secret_env("REQUEST_SIGNING_SECRET", is_production)?,
            timestamp_window_seconds: Self::parse_env("REQUEST_SIGNING_WINDOW_SECONDS", 300)?,
            enabled: Self::parse_env("REQUEST_SIGNING_ENABLED", is_production)?,
        };

        // Session Configuration
        let session = SessionConfig {
            ttl_seconds: Self::parse_env("SESSION_TTL_SECONDS", 3600)?,
            rotation_interval_seconds: Self::parse_env("SESSION_ROTATION_INTERVAL_SECONDS", 900)?,
            secure_cookies: Self::parse_env("SESSION_SECURE_COOKIES", is_production)?,
            storage_backend: Self::parse_env("SESSION_STORAGE_BACKEND", SessionStorage::Hybrid)?,
        };

        // Rate Limiting Configuration
        let rate_limiting = RateLimitingConfig {
            enabled: Self::parse_env("RATE_LIMITING_ENABLED", true)?,
            requests_per_minute_per_ip: Self::parse_env("RATE_LIMIT_PER_MINUTE", 60)?,
            oauth_requests_per_minute: Self::parse_env("OAUTH_RATE_LIMIT_PER_MINUTE", 10)?,
            admin_requests_per_minute: Self::parse_env("ADMIN_RATE_LIMIT_PER_MINUTE", 5)?,
            burst_size: Self::parse_env("RATE_LIMIT_BURST_SIZE", 10)?,
            ban_threshold: Self::parse_env("RATE_LIMIT_BAN_THRESHOLD", 1000)?,
            ban_duration_seconds: Self::parse_env("RATE_LIMIT_BAN_DURATION_SECONDS", 3600)?,
        };

        // Security Headers Configuration
        let headers = SecurityHeaders {
            enabled: Self::parse_env("SECURITY_HEADERS_ENABLED", true)?,
            hsts_max_age_seconds: Self::parse_env("HSTS_MAX_AGE_SECONDS", 31536000)?,
            content_type_options_nosniff: Self::parse_env("CONTENT_TYPE_OPTIONS_NOSNIFF", true)?,
            frame_options: Self::parse_env("FRAME_OPTIONS", FrameOptions::Deny)?,
            xss_protection: Self::parse_env("XSS_PROTECTION", true)?,
            referrer_policy: Self::parse_env(
                "REFERRER_POLICY",
                ReferrerPolicy::StrictOriginWhenCrossOrigin,
            )?,
            content_security_policy: env::var("CSP_POLICY").ok(),
        };

        // CORS Configuration
        let cors = CorsConfig {
            allowed_origins: env::var("CORS_ALLOWED_ORIGINS")
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
            allowed_methods: env::var("CORS_ALLOWED_METHODS")
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_else(|_| {
                    vec!["GET".to_string(), "POST".to_string(), "OPTIONS".to_string()]
                }),
            allowed_headers: env::var("CORS_ALLOWED_HEADERS")
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_else(|_| vec!["Content-Type".to_string(), "Authorization".to_string()]),
            allow_credentials: Self::parse_env("CORS_ALLOW_CREDENTIALS", false)?,
            max_age_seconds: Self::parse_env("CORS_MAX_AGE_SECONDS", 3600)?,
        };

        // Password Policy Configuration
        let password_policy = PasswordPolicy {
            min_length: Self::parse_env("PASSWORD_MIN_LENGTH", 12)?,
            require_uppercase: Self::parse_env("PASSWORD_REQUIRE_UPPERCASE", true)?,
            require_lowercase: Self::parse_env("PASSWORD_REQUIRE_LOWERCASE", true)?,
            require_numbers: Self::parse_env("PASSWORD_REQUIRE_NUMBERS", true)?,
            require_special_chars: Self::parse_env("PASSWORD_REQUIRE_SPECIAL_CHARS", true)?,
            argon2: Argon2Config {
                memory_cost: Self::parse_env("ARGON2_MEMORY_COST", 65536)?, // 64MB
                time_cost: Self::parse_env("ARGON2_TIME_COST", 3)?,
                parallelism: Self::parse_env("ARGON2_PARALLELISM", 4)?,
            },
        };

        // TLS Configuration
        let tls = TlsConfig {
            enabled: Self::parse_env("TLS_ENABLED", is_production)?,
            cert_path: env::var("TLS_CERT_PATH").ok(),
            key_path: env::var("TLS_KEY_PATH").ok(),
            min_version: Self::parse_env("TLS_MIN_VERSION", TlsVersion::TLSv1_3)?,
            cipher_suites: env::var("TLS_CIPHER_SUITES")
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
        };

        // Encryption Configuration
        let encryption = EncryptionConfig {
            key: Self::load_secret_env("ENCRYPTION_KEY", is_production)?,
            token_binding_salt: env::var("TOKEN_BINDING_SALT")
                .unwrap_or_else(|_| Self::generate_default_salt()),
            algorithm: Self::parse_env("ENCRYPTION_ALGORITHM", EncryptionAlgorithm::AES256GCM)?,
        };

        let config = UnifiedSecurityConfig {
            jwt,
            request_signing,
            session,
            rate_limiting,
            headers,
            cors,
            password_policy,
            tls,
            encryption,
        };

        // Validate the complete configuration
        config
            .validate()
            .map_err(SecurityConfigError::SecurityValidationError)?;

        if is_production {
            Self::validate_production_requirements(&config)?;
        }

        info!("Security configuration loaded and validated successfully");

        Ok(config)
    }

    /// Load a secret from environment with production validation
    fn load_secret_env(var_name: &str, is_production: bool) -> Result<String, SecurityConfigError> {
        let secret = env::var(var_name)
            .map_err(|_| SecurityConfigError::SecurityError(format!("{} is required", var_name)))?;

        if secret.len() < 32 {
            return Err(SecurityConfigError::SecurityError(format!(
                "{} must be at least 32 characters",
                var_name
            )));
        }

        if is_production
            && (secret.contains("INSECURE_DEV_SECRET")
                || secret.contains("test_secret")
                || secret.contains("changeme"))
        {
            return Err(SecurityConfigError::SecurityError(format!(
                "{} contains insecure default value in production",
                var_name
            )));
        }

        Ok(secret)
    }

    /// Parse environment variable with fallback to default
    fn parse_env<T>(var_name: &str, default: T) -> Result<T, SecurityConfigError>
    where
        T: FromStr + Clone,
        T::Err: std::fmt::Display,
    {
        match env::var(var_name) {
            Ok(value) => value.parse().map_err(|e| {
                SecurityConfigError::ParseError(format!("Failed to parse {}: {}", var_name, e))
            }),
            Err(_) => Ok(default),
        }
    }

    /// Generate a default salt for development
    fn generate_default_salt() -> String {
        warn!("Using generated default salt - set TOKEN_BINDING_SALT in production");
        "default-development-salt-change-in-production".to_string()
    }

    /// Validate production-specific requirements
    fn validate_production_requirements(
        config: &UnifiedSecurityConfig,
    ) -> Result<(), SecurityConfigError> {
        // Ensure TLS is enabled in production
        if !config.tls.enabled {
            return Err(SecurityConfigError::SecurityError(
                "TLS must be enabled in production".to_string(),
            ));
        }

        // Ensure secure cookies in production
        if !config.session.secure_cookies {
            return Err(SecurityConfigError::SecurityError(
                "Secure cookies must be enabled in production".to_string(),
            ));
        }

        // Ensure CORS is properly configured (not wildcard)
        if config.cors.allowed_origins.contains(&"*".to_string()) {
            warn!("CORS wildcard (*) is not recommended in production");
        }

        // Ensure request signing is enabled in production
        if !config.request_signing.enabled {
            warn!("Request signing should be enabled in production");
        }

        Ok(())
    }

    /// Get configuration for a specific service type
    pub fn for_service(service_type: ServiceType) -> Result<Self, SecurityConfigError> {
        let mut config = Self::from_env()?;

        // Adjust rate limiting based on service type
        match service_type {
            ServiceType::AuthService => {
                // Auth service handles tokens, needs stricter OAuth limits
                config.rate_limiting.oauth_requests_per_minute = 10;
            }
            ServiceType::PolicyService => {
                // Policy service is internal, can have higher limits
                config.rate_limiting.requests_per_minute_per_ip = 1000;
                config.rate_limiting.oauth_requests_per_minute = 100;
            }
            ServiceType::ApiGateway => {
                // API Gateway needs very high limits
                config.rate_limiting.requests_per_minute_per_ip = 10000;
            }
        }

        Ok(config)
    }
}

/// Service types for configuration customization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceType {
    AuthService,
    PolicyService,
    ApiGateway,
}

// Implement FromStr for enum types to enable environment parsing
impl FromStr for JwtAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "HS256" => Ok(Self::HS256),
            "HS384" => Ok(Self::HS384),
            "HS512" => Ok(Self::HS512),
            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),
            "ES256" => Ok(Self::ES256),
            "ES384" => Ok(Self::ES384),
            "ES512" => Ok(Self::ES512),
            _ => Err(format!("Unknown JWT algorithm: {}", s)),
        }
    }
}

impl FromStr for SessionStorage {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "memory" => Ok(Self::Memory),
            "redis" => Ok(Self::Redis),
            "database" => Ok(Self::Database),
            "hybrid" => Ok(Self::Hybrid),
            _ => Err(format!("Unknown session storage: {}", s)),
        }
    }
}

impl FromStr for FrameOptions {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("DENY") {
            return Ok(Self::Deny);
        }
        if trimmed.eq_ignore_ascii_case("SAMEORIGIN") {
            return Ok(Self::SameOrigin);
        }
        // Case-insensitive prefix match, preserve original URL casing
        let prefix = "ALLOW-FROM ";
        if trimmed.len() >= prefix.len() && trimmed[..prefix.len()].eq_ignore_ascii_case(prefix) {
            let url = trimmed[prefix.len()..].to_string();
            return Ok(Self::AllowFrom(url));
        }
        Err(format!("Unknown frame option: {}", s))
    }
}

impl FromStr for ReferrerPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('-', "_").as_str() {
            "no_referrer" => Ok(Self::NoReferrer),
            "no_referrer_when_downgrade" => Ok(Self::NoReferrerWhenDowngrade),
            "origin" => Ok(Self::Origin),
            "origin_when_cross_origin" => Ok(Self::OriginWhenCrossOrigin),
            "same_origin" => Ok(Self::SameOrigin),
            "strict_origin" => Ok(Self::StrictOrigin),
            "strict_origin_when_cross_origin" => Ok(Self::StrictOriginWhenCrossOrigin),
            "unsafe_url" => Ok(Self::UnsafeUrl),
            _ => Err(format!("Unknown referrer policy: {}", s)),
        }
    }
}

impl FromStr for TlsVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1.2" | "TLSv1.2" => Ok(Self::TLSv1_2),
            "1.3" | "TLSv1.3" => Ok(Self::TLSv1_3),
            _ => Err(format!("Unknown TLS version: {}", s)),
        }
    }
}

impl FromStr for EncryptionAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "AES256GCM" | "AES-256-GCM" => Ok(Self::AES256GCM),
            "CHACHA20POLY1305" | "CHACHA20-POLY1305" => Ok(Self::ChaCha20Poly1305),
            _ => Err(format!("Unknown encryption algorithm: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn clear_env_vars() {
        let vars_to_clear = [
            "JWT_SECRET",
            "JWT_ACCESS_TOKEN_TTL_SECONDS",
            "JWT_REFRESH_TOKEN_TTL_SECONDS",
            "JWT_ALGORITHM",
            "JWT_ISSUER",
            "JWT_AUDIENCE",
            "JWT_ENABLE_TOKEN_BINDING",
            "REQUEST_SIGNING_SECRET",
            "REQUEST_SIGNING_WINDOW_SECONDS",
            "REQUEST_SIGNING_ENABLED",
            "SESSION_TTL_SECONDS",
            "SESSION_ROTATION_INTERVAL_SECONDS",
            "SESSION_SECURE_COOKIES",
            "SESSION_STORAGE_BACKEND",
            "RATE_LIMITING_ENABLED",
            "RATE_LIMIT_PER_MINUTE",
            "OAUTH_RATE_LIMIT_PER_MINUTE",
            "ADMIN_RATE_LIMIT_PER_MINUTE",
            "RATE_LIMIT_BURST_SIZE",
            "RATE_LIMIT_BAN_THRESHOLD",
            "RATE_LIMIT_BAN_DURATION_SECONDS",
            "SECURITY_HEADERS_ENABLED",
            "HSTS_MAX_AGE_SECONDS",
            "CONTENT_TYPE_OPTIONS_NOSNIFF",
            "FRAME_OPTIONS",
            "XSS_PROTECTION",
            "REFERRER_POLICY",
            "CSP_POLICY",
            "CORS_ALLOWED_ORIGINS",
            "CORS_ALLOWED_METHODS",
            "CORS_ALLOWED_HEADERS",
            "CORS_ALLOW_CREDENTIALS",
            "CORS_MAX_AGE_SECONDS",
            "PASSWORD_MIN_LENGTH",
            "PASSWORD_REQUIRE_UPPERCASE",
            "PASSWORD_REQUIRE_LOWERCASE",
            "PASSWORD_REQUIRE_NUMBERS",
            "PASSWORD_REQUIRE_SPECIAL_CHARS",
            "ARGON2_MEMORY_COST",
            "ARGON2_TIME_COST",
            "ARGON2_PARALLELISM",
            "TLS_ENABLED",
            "TLS_CERT_PATH",
            "TLS_KEY_PATH",
            "TLS_MIN_VERSION",
            "TLS_CIPHER_SUITES",
            "ENCRYPTION_KEY",
            "TOKEN_BINDING_SALT",
            "ENCRYPTION_ALGORITHM",
            "ENVIRONMENT",
        ];

        for var in &vars_to_clear {
            env::remove_var(var);
        }
    }

    fn set_minimal_env_vars() {
        env::set_var("JWT_SECRET", "secure_jwt_secret_key_32_chars_minimum");
        env::set_var(
            "REQUEST_SIGNING_SECRET",
            "secure_request_signing_secret_32_chars",
        );
        env::set_var("ENCRYPTION_KEY", "secure_encryption_key_32_characters");
    }

    #[test]
    fn test_security_config_error_display() {
        let env_error = env::VarError::NotPresent;
        let error = SecurityConfigError::EnvError(env_error);
        assert!(error.to_string().contains("Environment variable error"));

        let validation_errors = validator::ValidationErrors::new();
        let error = SecurityConfigError::ValidationError(validation_errors);
        assert!(error.to_string().contains("Validation error"));

        let error = SecurityConfigError::ParseError("test parse error".to_string());
        assert_eq!(error.to_string(), "Parse error: test parse error");

        let error = SecurityConfigError::SecurityError("security violation".to_string());
        assert_eq!(
            error.to_string(),
            "Security policy violation: security violation"
        );
    }

    #[test]
    fn test_from_env_development_defaults() {
        clear_env_vars();
        set_minimal_env_vars();
        env::set_var("ENVIRONMENT", "development");

        let config = UnifiedSecurityConfig::from_env().unwrap();

        // Verify JWT defaults
        assert_eq!(config.jwt.access_token_ttl_seconds, 900);
        assert_eq!(config.jwt.refresh_token_ttl_seconds, 86400);
        assert_eq!(config.jwt.algorithm, JwtAlgorithm::HS256);
        assert_eq!(config.jwt.issuer, "rust-security-platform");
        assert!(config.jwt.enable_token_binding);

        // Verify request signing defaults (should be false for dev)
        assert!(!config.request_signing.enabled);

        // Verify session defaults
        assert_eq!(config.session.ttl_seconds, 3600);
        assert_eq!(config.session.rotation_interval_seconds, 900);
        assert!(!config.session.secure_cookies); // Dev environment

        // Verify rate limiting defaults
        assert!(config.rate_limiting.enabled);
        assert_eq!(config.rate_limiting.requests_per_minute_per_ip, 60);
        assert_eq!(config.rate_limiting.oauth_requests_per_minute, 10);
        assert_eq!(config.rate_limiting.admin_requests_per_minute, 5);

        // Verify TLS defaults (should be false for dev)
        assert!(!config.tls.enabled);
    }

    #[test]
    fn test_from_env_production_defaults() {
        clear_env_vars();
        set_minimal_env_vars();
        env::set_var("ENVIRONMENT", "production");

        let config = UnifiedSecurityConfig::from_env().unwrap();

        // Production should enable security features
        assert!(config.request_signing.enabled);
        assert!(config.session.secure_cookies);
        assert!(config.tls.enabled);
    }

    #[test]
    fn test_from_env_custom_values() {
        clear_env_vars();
        set_minimal_env_vars();

        // Set custom values
        env::set_var("JWT_ACCESS_TOKEN_TTL_SECONDS", "1800");
        env::set_var("JWT_REFRESH_TOKEN_TTL_SECONDS", "72000");
        env::set_var("JWT_ALGORITHM", "HS384");
        env::set_var("JWT_ISSUER", "custom-issuer");
        env::set_var("JWT_AUDIENCE", "aud1,aud2,aud3");
        env::set_var("RATE_LIMIT_PER_MINUTE", "100");
        env::set_var("OAUTH_RATE_LIMIT_PER_MINUTE", "20");
        env::set_var("ADMIN_RATE_LIMIT_PER_MINUTE", "10");
        env::set_var(
            "CORS_ALLOWED_ORIGINS",
            "https://example.com,https://test.com",
        );
        env::set_var("CORS_ALLOWED_METHODS", "GET,POST,PUT,DELETE");
        env::set_var("CORS_ALLOW_CREDENTIALS", "true");
        env::set_var("PASSWORD_MIN_LENGTH", "16");
        env::set_var("ARGON2_MEMORY_COST", "131072");

        let config = UnifiedSecurityConfig::from_env().unwrap();

        assert_eq!(config.jwt.access_token_ttl_seconds, 1800);
        assert_eq!(config.jwt.refresh_token_ttl_seconds, 72000);
        assert_eq!(config.jwt.algorithm, JwtAlgorithm::HS384);
        assert_eq!(config.jwt.issuer, "custom-issuer");
        assert_eq!(
            config.jwt.audience,
            Some(vec![
                "aud1".to_string(),
                "aud2".to_string(),
                "aud3".to_string()
            ])
        );
        assert_eq!(config.rate_limiting.requests_per_minute_per_ip, 100);
        assert_eq!(config.rate_limiting.oauth_requests_per_minute, 20);
        assert_eq!(config.rate_limiting.admin_requests_per_minute, 10);
        assert_eq!(
            config.cors.allowed_origins,
            vec![
                "https://example.com".to_string(),
                "https://test.com".to_string()
            ]
        );
        assert_eq!(
            config.cors.allowed_methods,
            vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string()
            ]
        );
        assert!(config.cors.allow_credentials);
        assert_eq!(config.password_policy.min_length, 16);
        assert_eq!(config.password_policy.argon2.memory_cost, 131072);
    }

    #[test]
    fn test_load_secret_env_missing() {
        clear_env_vars();

        let result = UnifiedSecurityConfig::load_secret_env("MISSING_SECRET", false);
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityConfigError::SecurityError(msg) => {
                assert!(msg.contains("MISSING_SECRET is required"));
            }
            _ => panic!("Expected SecurityError"),
        }
    }

    #[test]
    fn test_load_secret_env_too_short() {
        clear_env_vars();
        env::set_var("SHORT_SECRET", "short");

        let result = UnifiedSecurityConfig::load_secret_env("SHORT_SECRET", false);
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityConfigError::SecurityError(msg) => {
                assert!(msg.contains("at least 32 characters"));
            }
            _ => panic!("Expected SecurityError"),
        }
    }

    #[test]
    fn test_load_secret_env_insecure_production() {
        clear_env_vars();
        env::set_var("DEV_SECRET", "INSECURE_DEV_SECRET_test_secret_32_chars");

        let result = UnifiedSecurityConfig::load_secret_env("DEV_SECRET", true);
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityConfigError::SecurityError(msg) => {
                assert!(msg.contains("insecure default value"));
            }
            _ => panic!("Expected SecurityError"),
        }
    }

    #[test]
    fn test_load_secret_env_valid() {
        clear_env_vars();
        env::set_var("VALID_SECRET", "secure_secret_key_32_characters_long");

        let result = UnifiedSecurityConfig::load_secret_env("VALID_SECRET", false);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "secure_secret_key_32_characters_long");
    }

    #[test]
    fn test_parse_env_with_value() {
        clear_env_vars();
        env::set_var("TEST_INT", "42");

        let result: Result<u32, SecurityConfigError> =
            UnifiedSecurityConfig::parse_env("TEST_INT", 10);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_parse_env_with_default() {
        clear_env_vars();

        let result: Result<u32, SecurityConfigError> =
            UnifiedSecurityConfig::parse_env("MISSING_INT", 10);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 10);
    }

    #[test]
    fn test_parse_env_invalid_value() {
        clear_env_vars();
        env::set_var("INVALID_INT", "not_a_number");

        let result: Result<u32, SecurityConfigError> =
            UnifiedSecurityConfig::parse_env("INVALID_INT", 10);
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityConfigError::ParseError(msg) => {
                assert!(msg.contains("Failed to parse INVALID_INT"));
            }
            _ => panic!("Expected ParseError"),
        }
    }

    #[test]
    fn test_generate_default_salt() {
        let salt = UnifiedSecurityConfig::generate_default_salt();
        assert!(!salt.is_empty());
        assert!(salt.contains("development"));
    }

    #[test]
    fn test_validate_production_requirements_tls_disabled() {
        let config = UnifiedSecurityConfig {
            tls: TlsConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let result = UnifiedSecurityConfig::validate_production_requirements(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityConfigError::SecurityError(msg) => {
                assert!(msg.contains("TLS must be enabled"));
            }
            _ => panic!("Expected SecurityError"),
        }
    }

    #[test]
    fn test_validate_production_requirements_insecure_cookies() {
        let config = UnifiedSecurityConfig {
            tls: TlsConfig {
                enabled: true,
                ..Default::default()
            },
            session: SessionConfig {
                secure_cookies: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let result = UnifiedSecurityConfig::validate_production_requirements(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityConfigError::SecurityError(msg) => {
                assert!(msg.contains("Secure cookies must be enabled"));
            }
            _ => panic!("Expected SecurityError"),
        }
    }

    #[test]
    fn test_validate_production_requirements_valid() {
        let config = UnifiedSecurityConfig {
            tls: TlsConfig {
                enabled: true,
                ..Default::default()
            },
            session: SessionConfig {
                secure_cookies: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let result = UnifiedSecurityConfig::validate_production_requirements(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_for_service_auth_service() {
        clear_env_vars();
        set_minimal_env_vars();

        let config = UnifiedSecurityConfig::for_service(ServiceType::AuthService).unwrap();
        assert_eq!(config.rate_limiting.oauth_requests_per_minute, 10);
    }

    #[test]
    fn test_for_service_policy_service() {
        clear_env_vars();
        set_minimal_env_vars();

        let config = UnifiedSecurityConfig::for_service(ServiceType::PolicyService).unwrap();
        assert_eq!(config.rate_limiting.requests_per_minute_per_ip, 1000);
        assert_eq!(config.rate_limiting.oauth_requests_per_minute, 100);
    }

    #[test]
    fn test_for_service_api_gateway() {
        clear_env_vars();
        set_minimal_env_vars();

        let config = UnifiedSecurityConfig::for_service(ServiceType::ApiGateway).unwrap();
        assert_eq!(config.rate_limiting.requests_per_minute_per_ip, 10000);
    }

    #[test]
    fn test_service_type_debug() {
        let service_types = [
            ServiceType::AuthService,
            ServiceType::PolicyService,
            ServiceType::ApiGateway,
        ];

        for service_type in &service_types {
            let debug_str = format!("{:?}", service_type);
            assert!(!debug_str.is_empty());

            // Test equality
            assert_eq!(*service_type, *service_type);
        }
    }

    // FromStr implementation tests

    #[test]
    fn test_jwt_algorithm_from_str() {
        assert_eq!(
            "HS256".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::HS256
        );
        assert_eq!(
            "hs256".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::HS256
        );
        assert_eq!(
            "HS384".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::HS384
        );
        assert_eq!(
            "HS512".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::HS512
        );
        assert_eq!(
            "RS256".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::RS256
        );
        assert_eq!(
            "RS384".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::RS384
        );
        assert_eq!(
            "RS512".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::RS512
        );
        assert_eq!(
            "ES256".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::ES256
        );
        assert_eq!(
            "ES384".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::ES384
        );
        assert_eq!(
            "ES512".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::ES512
        );

        let result = "INVALID".parse::<JwtAlgorithm>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown JWT algorithm"));
    }

    #[test]
    fn test_session_storage_from_str() {
        assert_eq!(
            "memory".parse::<SessionStorage>().unwrap(),
            SessionStorage::Memory
        );
        assert_eq!(
            "MEMORY".parse::<SessionStorage>().unwrap(),
            SessionStorage::Memory
        );
        assert_eq!(
            "redis".parse::<SessionStorage>().unwrap(),
            SessionStorage::Redis
        );
        assert_eq!(
            "database".parse::<SessionStorage>().unwrap(),
            SessionStorage::Database
        );
        assert_eq!(
            "hybrid".parse::<SessionStorage>().unwrap(),
            SessionStorage::Hybrid
        );

        let result = "invalid".parse::<SessionStorage>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown session storage"));
    }

    #[test]
    fn test_frame_options_from_str() {
        assert_eq!("DENY".parse::<FrameOptions>().unwrap(), FrameOptions::Deny);
        assert_eq!("deny".parse::<FrameOptions>().unwrap(), FrameOptions::Deny);
        assert_eq!(
            "SAMEORIGIN".parse::<FrameOptions>().unwrap(),
            FrameOptions::SameOrigin
        );
        assert_eq!(
            "ALLOW-FROM https://example.com"
                .parse::<FrameOptions>()
                .unwrap(),
            FrameOptions::AllowFrom("https://example.com".to_string())
        );

        let result = "invalid".parse::<FrameOptions>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown frame option"));
    }

    #[test]
    fn test_referrer_policy_from_str() {
        assert_eq!(
            "no-referrer".parse::<ReferrerPolicy>().unwrap(),
            ReferrerPolicy::NoReferrer
        );
        assert_eq!(
            "no_referrer".parse::<ReferrerPolicy>().unwrap(),
            ReferrerPolicy::NoReferrer
        );
        assert_eq!(
            "no-referrer-when-downgrade"
                .parse::<ReferrerPolicy>()
                .unwrap(),
            ReferrerPolicy::NoReferrerWhenDowngrade
        );
        assert_eq!(
            "origin".parse::<ReferrerPolicy>().unwrap(),
            ReferrerPolicy::Origin
        );
        assert_eq!(
            "origin-when-cross-origin"
                .parse::<ReferrerPolicy>()
                .unwrap(),
            ReferrerPolicy::OriginWhenCrossOrigin
        );
        assert_eq!(
            "same-origin".parse::<ReferrerPolicy>().unwrap(),
            ReferrerPolicy::SameOrigin
        );
        assert_eq!(
            "strict-origin".parse::<ReferrerPolicy>().unwrap(),
            ReferrerPolicy::StrictOrigin
        );
        assert_eq!(
            "strict-origin-when-cross-origin"
                .parse::<ReferrerPolicy>()
                .unwrap(),
            ReferrerPolicy::StrictOriginWhenCrossOrigin
        );
        assert_eq!(
            "unsafe-url".parse::<ReferrerPolicy>().unwrap(),
            ReferrerPolicy::UnsafeUrl
        );

        let result = "invalid".parse::<ReferrerPolicy>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown referrer policy"));
    }

    #[test]
    fn test_tls_version_from_str() {
        assert_eq!("1.2".parse::<TlsVersion>().unwrap(), TlsVersion::TLSv1_2);
        assert_eq!(
            "TLSv1.2".parse::<TlsVersion>().unwrap(),
            TlsVersion::TLSv1_2
        );
        assert_eq!("1.3".parse::<TlsVersion>().unwrap(), TlsVersion::TLSv1_3);
        assert_eq!(
            "TLSv1.3".parse::<TlsVersion>().unwrap(),
            TlsVersion::TLSv1_3
        );

        let result = "invalid".parse::<TlsVersion>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown TLS version"));
    }

    #[test]
    fn test_encryption_algorithm_from_str() {
        assert_eq!(
            "AES256GCM".parse::<EncryptionAlgorithm>().unwrap(),
            EncryptionAlgorithm::AES256GCM
        );
        assert_eq!(
            "aes256gcm".parse::<EncryptionAlgorithm>().unwrap(),
            EncryptionAlgorithm::AES256GCM
        );
        assert_eq!(
            "AES-256-GCM".parse::<EncryptionAlgorithm>().unwrap(),
            EncryptionAlgorithm::AES256GCM
        );
        assert_eq!(
            "CHACHA20POLY1305".parse::<EncryptionAlgorithm>().unwrap(),
            EncryptionAlgorithm::ChaCha20Poly1305
        );
        assert_eq!(
            "CHACHA20-POLY1305".parse::<EncryptionAlgorithm>().unwrap(),
            EncryptionAlgorithm::ChaCha20Poly1305
        );

        let result = "invalid".parse::<EncryptionAlgorithm>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown encryption algorithm"));
    }

    #[test]
    fn test_from_env_missing_secrets() {
        clear_env_vars();
        env::set_var("ENVIRONMENT", "development");
        // Missing JWT_SECRET

        let result = UnifiedSecurityConfig::from_env();
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityConfigError::SecurityError(msg) => {
                assert!(msg.contains("JWT_SECRET is required"));
            }
            _ => panic!("Expected SecurityError"),
        }
    }

    #[test]
    fn test_from_env_validation_failure() {
        clear_env_vars();
        set_minimal_env_vars();
        // Set invalid configuration
        env::set_var("JWT_ACCESS_TOKEN_TTL_SECONDS", "3600");
        env::set_var("JWT_REFRESH_TOKEN_TTL_SECONDS", "3600"); // Same as access token

        let result = UnifiedSecurityConfig::from_env();
        assert!(result.is_err());
        // Should fail validation due to refresh token TTL being same as access token
    }

    #[test]
    fn test_complex_cors_configuration() {
        clear_env_vars();
        set_minimal_env_vars();

        env::set_var(
            "CORS_ALLOWED_ORIGINS",
            "https://app.example.com,https://admin.example.com",
        );
        env::set_var("CORS_ALLOWED_METHODS", "GET,POST,PUT,DELETE,OPTIONS");
        env::set_var(
            "CORS_ALLOWED_HEADERS",
            "Content-Type,Authorization,X-Requested-With",
        );
        env::set_var("CORS_ALLOW_CREDENTIALS", "true");
        env::set_var("CORS_MAX_AGE_SECONDS", "7200");

        let config = UnifiedSecurityConfig::from_env().unwrap();

        assert_eq!(
            config.cors.allowed_origins,
            vec![
                "https://app.example.com".to_string(),
                "https://admin.example.com".to_string()
            ]
        );
        assert_eq!(
            config.cors.allowed_methods,
            vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string()
            ]
        );
        assert_eq!(
            config.cors.allowed_headers,
            vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Requested-With".to_string()
            ]
        );
        assert!(config.cors.allow_credentials);
        assert_eq!(config.cors.max_age_seconds, 7200);
    }

    #[test]
    fn test_tls_configuration() {
        clear_env_vars();
        set_minimal_env_vars();

        env::set_var("TLS_ENABLED", "true");
        env::set_var("TLS_CERT_PATH", "/path/to/cert.pem");
        env::set_var("TLS_KEY_PATH", "/path/to/key.pem");
        env::set_var("TLS_MIN_VERSION", "1.3");
        env::set_var(
            "TLS_CIPHER_SUITES",
            "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256",
        );

        let config = UnifiedSecurityConfig::from_env().unwrap();

        assert!(config.tls.enabled);
        assert_eq!(config.tls.cert_path, Some("/path/to/cert.pem".to_string()));
        assert_eq!(config.tls.key_path, Some("/path/to/key.pem".to_string()));
        assert_eq!(config.tls.min_version, TlsVersion::TLSv1_3);
        assert_eq!(
            config.tls.cipher_suites,
            vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string()
            ]
        );
    }

    #[test]
    fn test_password_policy_configuration() {
        clear_env_vars();
        set_minimal_env_vars();

        env::set_var("PASSWORD_MIN_LENGTH", "14");
        env::set_var("PASSWORD_REQUIRE_UPPERCASE", "true");
        env::set_var("PASSWORD_REQUIRE_LOWERCASE", "true");
        env::set_var("PASSWORD_REQUIRE_NUMBERS", "true");
        env::set_var("PASSWORD_REQUIRE_SPECIAL_CHARS", "false");
        env::set_var("ARGON2_MEMORY_COST", "131072");
        env::set_var("ARGON2_TIME_COST", "4");
        env::set_var("ARGON2_PARALLELISM", "8");

        let config = UnifiedSecurityConfig::from_env().unwrap();

        assert_eq!(config.password_policy.min_length, 14);
        assert!(config.password_policy.require_uppercase);
        assert!(config.password_policy.require_lowercase);
        assert!(config.password_policy.require_numbers);
        assert!(!config.password_policy.require_special_chars);
        assert_eq!(config.password_policy.argon2.memory_cost, 131072);
        assert_eq!(config.password_policy.argon2.time_cost, 4);
        assert_eq!(config.password_policy.argon2.parallelism, 8);
    }

    #[test]
    fn test_security_headers_configuration() {
        clear_env_vars();
        set_minimal_env_vars();

        env::set_var("SECURITY_HEADERS_ENABLED", "true");
        env::set_var("HSTS_MAX_AGE_SECONDS", "63072000");
        env::set_var("CONTENT_TYPE_OPTIONS_NOSNIFF", "true");
        env::set_var("FRAME_OPTIONS", "SAMEORIGIN");
        env::set_var("XSS_PROTECTION", "true");
        env::set_var("REFERRER_POLICY", "strict-origin-when-cross-origin");
        env::set_var(
            "CSP_POLICY",
            "default-src 'self'; script-src 'self' 'unsafe-inline'",
        );

        let config = UnifiedSecurityConfig::from_env().unwrap();

        assert!(config.headers.enabled);
        assert_eq!(config.headers.hsts_max_age_seconds, 63072000);
        assert!(config.headers.content_type_options_nosniff);
        assert_eq!(config.headers.frame_options, FrameOptions::SameOrigin);
        assert!(config.headers.xss_protection);
        assert_eq!(
            config.headers.referrer_policy,
            ReferrerPolicy::StrictOriginWhenCrossOrigin
        );
        assert_eq!(
            config.headers.content_security_policy,
            Some("default-src 'self'; script-src 'self' 'unsafe-inline'".to_string())
        );
    }

    #[test]
    fn test_encryption_configuration() {
        clear_env_vars();
        set_minimal_env_vars();

        env::set_var("ENCRYPTION_ALGORITHM", "CHACHA20-POLY1305");
        env::set_var(
            "TOKEN_BINDING_SALT",
            "custom-salt-for-token-binding-operations",
        );

        let config = UnifiedSecurityConfig::from_env().unwrap();

        assert_eq!(
            config.encryption.algorithm,
            EncryptionAlgorithm::ChaCha20Poly1305
        );
        assert_eq!(
            config.encryption.token_binding_salt,
            "custom-salt-for-token-binding-operations"
        );
    }

    #[test]
    fn test_security_config_error_from_conversions() {
        // Test all error conversion types work
        let env_error = env::VarError::NotPresent;
        let _: SecurityConfigError = env_error.into();

        let validation_errors = validator::ValidationErrors::new();
        let _: SecurityConfigError = validation_errors.into();

        let security_validation_error =
            crate::security::validation::SecurityValidationError::SecurityPolicyViolation(
                "test".to_string(),
            );
        let _: SecurityConfigError = security_validation_error.into();
    }

    #[test]
    fn test_all_service_types() {
        clear_env_vars();
        set_minimal_env_vars();

        // Test that all service types can be configured
        let service_types = [
            ServiceType::AuthService,
            ServiceType::PolicyService,
            ServiceType::ApiGateway,
        ];

        for service_type in &service_types {
            let config = UnifiedSecurityConfig::for_service(*service_type);
            assert!(config.is_ok(), "Failed to configure {:?}", service_type);
        }
    }
}
