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
    /// std::env::set_var("JWT_SECRET", "very-secure-secret-at-least-32-characters-long");
    /// std::env::set_var("REQUEST_SIGNING_SECRET", "another-secure-secret-for-request-signing");
    ///
    /// let config = UnifiedSecurityConfig::from_env()?;
    /// assert!(config.validate().is_ok());
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
        match s.to_uppercase().as_str() {
            "DENY" => Ok(Self::Deny),
            "SAMEORIGIN" => Ok(Self::SameOrigin),
            other if other.starts_with("ALLOW-FROM ") => {
                Ok(Self::AllowFrom(other[11..].to_string()))
            }
            _ => Err(format!("Unknown frame option: {}", s)),
        }
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
