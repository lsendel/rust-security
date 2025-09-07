//! Unified Security Configuration Module
//!
//! This module consolidates security configuration across all services in the rust-security project,
//! eliminating duplication and ensuring consistent security defaults.
//!
//! ## Key Features
//! - **Unified Configuration**: Single source of truth for all security settings
//! - **Validation**: Comprehensive validation for security-critical settings  
//! - **Environment Integration**: Seamless environment variable loading
//! - **Secure Defaults**: Hardened defaults based on security best practices

pub mod config;
pub mod defaults; 
pub mod validation;
pub mod hardening;
pub mod monitoring;

pub use config::*;
pub use defaults::*;
pub use validation::*;

use serde::{Deserialize, Serialize};
use std::time::Duration;
use validator::Validate;

/// Unified security configuration for all rust-security services
///
/// This configuration structure consolidates security settings from:
/// - `auth-service/src/config_production.rs::SecurityConfig`
/// - `auth-service/src/config_secure.rs::SecureSecurityConfig`
/// - `auth-service/src/app/mvp_config.rs::AuthConfig`
/// - `common/src/config.rs::SecurityConfig`
///
/// # Security Guarantees
/// - JWT tokens expire within secure timeframes (15min-1hr access, 1-24hr refresh)
/// - Secrets must be at least 32 characters and cannot contain dev defaults
/// - Rate limiting prevents abuse (configurable per service needs)
/// - Request signing prevents replay attacks
/// - Password policies enforce strong authentication
///
/// # Example
/// ```rust
/// use common::security::UnifiedSecurityConfig;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # std::env::set_var("JWT_SECRET", "very-secure-secret-at-least-32-characters-long");
/// # std::env::set_var("REQUEST_SIGNING_SECRET", "another-secure-secret-for-request-signing");
/// # std::env::set_var("ENCRYPTION_KEY", "encryption-key-that-is-at-least-32-characters");
/// let config = UnifiedSecurityConfig::from_env()?;
/// assert!(config.validate().is_ok());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UnifiedSecurityConfig {
    /// JWT configuration with secure defaults
    #[validate(nested)]
    pub jwt: JwtConfig,

    /// Request signing configuration for admin endpoints
    #[validate(nested)]
    pub request_signing: RequestSigningConfig,

    /// Session management configuration
    #[validate(nested)]
    pub session: SessionConfig,

    /// Rate limiting configuration
    #[validate(nested)]
    pub rate_limiting: RateLimitingConfig,

    /// Security headers configuration
    #[validate(nested)]
    pub headers: SecurityHeaders,

    /// CORS configuration
    #[validate(nested)]
    pub cors: CorsConfig,

    /// Password policy configuration
    #[validate(nested)]
    pub password_policy: PasswordPolicy,

    /// TLS configuration
    #[validate(nested)]
    pub tls: TlsConfig,

    /// Encryption configuration for sensitive data
    #[validate(nested)]
    pub encryption: EncryptionConfig,
}

/// JWT token configuration with secure validation
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct JwtConfig {
    /// JWT signing secret (must be at least 32 characters)
    #[validate(length(min = 32, message = "JWT secret must be at least 32 characters"))]
    #[validate(custom(
        function = "validate_no_dev_secret",
        message = "JWT secret cannot contain development defaults"
    ))]
    pub secret: String,

    /// Access token expiration (15 minutes to 1 hour - secure default)
    #[validate(range(
        min = 900,
        max = 3600,
        message = "Access token TTL must be between 15 minutes and 1 hour"
    ))]
    pub access_token_ttl_seconds: u64,

    /// Refresh token expiration (1 hour to 24 hours)
    #[validate(range(
        min = 3600,
        max = 86400,
        message = "Refresh token TTL must be between 1 hour and 24 hours"
    ))]
    pub refresh_token_ttl_seconds: u64,

    /// JWT algorithm (default: HS256)
    pub algorithm: JwtAlgorithm,

    /// JWT issuer
    #[validate(length(min = 1, message = "JWT issuer cannot be empty"))]
    pub issuer: String,

    /// JWT audience
    pub audience: Option<Vec<String>>,

    /// Enable token binding for additional security
    pub enable_token_binding: bool,
}

/// Request signing configuration for securing admin endpoints
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RequestSigningConfig {
    /// Request signing secret (must be at least 32 characters)  
    #[validate(length(
        min = 32,
        message = "Request signing secret must be at least 32 characters"
    ))]
    #[validate(custom(
        function = "validate_no_dev_secret",
        message = "Request signing secret cannot contain development defaults"
    ))]
    pub secret: String,

    /// Timestamp window for request validation (1-10 minutes)
    #[validate(range(
        min = 60,
        max = 600,
        message = "Timestamp window must be between 1 and 10 minutes"
    ))]
    pub timestamp_window_seconds: u64,

    /// Enable request signing validation
    pub enabled: bool,
}

/// Session management configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SessionConfig {
    /// Session TTL (15 minutes to 2 hours)
    #[validate(range(
        min = 900,
        max = 7200,
        message = "Session TTL must be between 15 minutes and 2 hours"
    ))]
    pub ttl_seconds: u64,

    /// Session rotation interval (5 minutes to 1 hour)
    #[validate(range(
        min = 300,
        max = 3600,
        message = "Session rotation interval must be between 5 minutes and 1 hour"
    ))]
    pub rotation_interval_seconds: u64,

    /// Enable secure session cookies
    pub secure_cookies: bool,

    /// Session storage backend
    pub storage_backend: SessionStorage,
}

/// Rate limiting configuration with flexible policies
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RateLimitingConfig {
    /// Enable rate limiting
    pub enabled: bool,

    /// Requests per minute per IP
    #[validate(range(
        min = 1,
        max = 10000,
        message = "Rate limit must be between 1 and 10,000 requests per minute"
    ))]
    pub requests_per_minute_per_ip: u32,

    /// OAuth requests per minute (lower limit for token endpoints)
    #[validate(range(
        min = 1,
        max = 1000,
        message = "OAuth rate limit must be between 1 and 1,000 requests per minute"
    ))]
    pub oauth_requests_per_minute: u32,

    /// Admin requests per minute (very restrictive)
    #[validate(range(
        min = 1,
        max = 100,
        message = "Admin rate limit must be between 1 and 100 requests per minute"
    ))]
    pub admin_requests_per_minute: u32,

    /// Burst allowance
    #[validate(range(
        min = 1,
        max = 1000,
        message = "Burst size must be between 1 and 1,000"
    ))]
    pub burst_size: u32,

    /// Ban threshold (requests that trigger temporary ban)
    #[validate(range(
        min = 10,
        max = 10000,
        message = "Ban threshold must be between 10 and 10,000"
    ))]
    pub ban_threshold: u32,

    /// Ban duration in seconds
    #[validate(range(
        min = 60,
        max = 86400,
        message = "Ban duration must be between 1 minute and 24 hours"
    ))]
    pub ban_duration_seconds: u64,
}

/// Security headers configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SecurityHeaders {
    /// HSTS max age (minimum 1 year for production)
    #[validate(range(
        min = 31536000,
        max = 63072000,
        message = "HSTS max age should be at least 1 year"
    ))]
    pub hsts_max_age_seconds: u32,

    /// Enable X-Content-Type-Options: nosniff
    pub content_type_options_nosniff: bool,

    /// X-Frame-Options setting
    pub frame_options: FrameOptions,

    /// Enable XSS protection
    pub xss_protection: bool,

    /// Referrer policy
    pub referrer_policy: ReferrerPolicy,

    /// Content Security Policy
    pub content_security_policy: Option<String>,

    /// Enable security headers globally
    pub enabled: bool,
}

/// CORS configuration with secure defaults
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CorsConfig {
    /// Allowed origins (empty = no CORS, ["*"] = allow all - not recommended for production)
    pub allowed_origins: Vec<String>,

    /// Allowed methods
    pub allowed_methods: Vec<String>,

    /// Allowed headers
    pub allowed_headers: Vec<String>,

    /// Enable credentials in CORS requests
    pub allow_credentials: bool,

    /// Max age for preflight cache
    #[validate(range(max = 86400, message = "CORS max age should not exceed 24 hours"))]
    pub max_age_seconds: u32,
}

/// Password policy configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PasswordPolicy {
    /// Minimum password length
    #[validate(range(
        min = 8,
        max = 128,
        message = "Password length must be between 8 and 128 characters"
    ))]
    pub min_length: u32,

    /// Require uppercase letters
    pub require_uppercase: bool,

    /// Require lowercase letters  
    pub require_lowercase: bool,

    /// Require numbers
    pub require_numbers: bool,

    /// Require special characters
    pub require_special_chars: bool,

    /// Argon2 configuration
    pub argon2: Argon2Config,
}

/// Argon2 password hashing configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct Argon2Config {
    /// Memory cost (KB)
    #[validate(range(
        min = 32768,
        max = 1048576,
        message = "Argon2 memory cost must be between 32MB and 1GB"
    ))]
    pub memory_cost: u32,

    /// Time cost (iterations)
    #[validate(range(
        min = 2,
        max = 10,
        message = "Argon2 time cost must be between 2 and 10 iterations"
    ))]
    pub time_cost: u32,

    /// Parallelism (threads)
    #[validate(range(
        min = 1,
        max = 16,
        message = "Argon2 parallelism must be between 1 and 16 threads"
    ))]
    pub parallelism: u32,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct TlsConfig {
    /// Enable TLS
    pub enabled: bool,

    /// TLS certificate path
    pub cert_path: Option<String>,

    /// TLS private key path  
    pub key_path: Option<String>,

    /// Minimum TLS version
    pub min_version: TlsVersion,

    /// Cipher suites (empty = use secure defaults)
    pub cipher_suites: Vec<String>,
}

/// Encryption configuration for sensitive data
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct EncryptionConfig {
    /// Encryption key for sensitive data (must be 32 bytes)
    #[validate(length(min = 32, message = "Encryption key must be at least 32 characters"))]
    #[validate(custom(
        function = "validate_no_dev_secret",
        message = "Encryption key cannot contain development defaults"
    ))]
    pub key: String,

    /// Token binding salt
    #[validate(length(
        min = 16,
        message = "Token binding salt must be at least 16 characters"
    ))]
    pub token_binding_salt: String,

    /// Encryption algorithm
    pub algorithm: EncryptionAlgorithm,
}

// Enums for configuration options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum JwtAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionStorage {
    Memory,
    Redis,
    Database,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FrameOptions {
    Deny,
    SameOrigin,
    AllowFrom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReferrerPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TlsVersion {
    TLSv1_2,
    TLSv1_3,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
}

// Custom validation functions
pub fn validate_no_dev_secret(secret: &str) -> Result<(), validator::ValidationError> {
    if secret.contains("INSECURE_DEV_SECRET")
        || secret.contains("test_secret")
        || secret.contains("changeme")
        || secret == "dev"
    {
        return Err(validator::ValidationError::new("contains_dev_default"));
    }
    Ok(())
}

impl Default for JwtAlgorithm {
    fn default() -> Self {
        Self::HS256
    }
}

impl Default for SessionStorage {
    fn default() -> Self {
        Self::Hybrid
    }
}

impl Default for FrameOptions {
    fn default() -> Self {
        Self::Deny
    }
}

impl Default for ReferrerPolicy {
    fn default() -> Self {
        Self::StrictOriginWhenCrossOrigin
    }
}

impl Default for TlsVersion {
    fn default() -> Self {
        Self::TLSv1_3
    }
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        Self::AES256GCM
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test default implementations for all configuration structs

    #[test]
    fn test_unified_security_config_default() {
        let config = UnifiedSecurityConfig::default();

        assert_eq!(
            config.jwt.secret,
            "REPLACE_IN_PRODUCTION_MIN_32_CHARS_REQUIRED"
        );
        assert_eq!(config.jwt.access_token_ttl_seconds, 900);
        assert_eq!(config.jwt.refresh_token_ttl_seconds, 86400);
        assert_eq!(config.jwt.algorithm, JwtAlgorithm::HS256);
        assert_eq!(config.jwt.issuer, "rust-security-platform");
        assert!(config.jwt.enable_token_binding);
    }

    #[test]
    fn test_jwt_config_default() {
        let config = JwtConfig::default();

        assert_eq!(config.secret, "REPLACE_IN_PRODUCTION_MIN_32_CHARS_REQUIRED");
        assert_eq!(config.access_token_ttl_seconds, 900); // 15 minutes
        assert_eq!(config.refresh_token_ttl_seconds, 86400); // 24 hours
        assert_eq!(config.algorithm, JwtAlgorithm::HS256);
        assert_eq!(config.issuer, "rust-security-platform");
        assert!(config.audience.is_none());
        assert!(config.enable_token_binding);
    }

    #[test]
    fn test_request_signing_config_default() {
        let config = RequestSigningConfig::default();

        assert_eq!(config.secret, "REPLACE_IN_PRODUCTION_MIN_32_CHARS_REQUIRED");
        assert_eq!(config.timestamp_window_seconds, 300); // 5 minutes
        assert!(config.enabled);
    }

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();

        assert_eq!(config.ttl_seconds, 3600); // 1 hour
        assert_eq!(config.rotation_interval_seconds, 900); // 15 minutes
        assert!(config.secure_cookies);
        assert_eq!(config.storage_backend, SessionStorage::Hybrid);
    }

    #[test]
    fn test_rate_limiting_config_default() {
        let config = RateLimitingConfig::default();

        assert!(config.enabled);
        assert_eq!(config.requests_per_minute_per_ip, 60);
        assert_eq!(config.oauth_requests_per_minute, 10);
        assert_eq!(config.admin_requests_per_minute, 5);
        assert_eq!(config.burst_size, 10);
        assert_eq!(config.ban_threshold, 1000);
        assert_eq!(config.ban_duration_seconds, 3600); // 1 hour
    }

    #[test]
    fn test_security_headers_default() {
        let config = SecurityHeaders::default();

        assert!(config.enabled);
        assert_eq!(config.hsts_max_age_seconds, 31536000); // 1 year
        assert!(config.content_type_options_nosniff);
        assert_eq!(config.frame_options, FrameOptions::Deny);
        assert!(config.xss_protection);
        assert_eq!(
            config.referrer_policy,
            ReferrerPolicy::StrictOriginWhenCrossOrigin
        );
        assert!(config.content_security_policy.is_none());
    }

    #[test]
    fn test_cors_config_default() {
        let config = CorsConfig::default();

        assert!(config.allowed_origins.is_empty());
        assert_eq!(config.allowed_methods, vec!["GET", "POST", "OPTIONS"]);
        assert_eq!(
            config.allowed_headers,
            vec!["Content-Type", "Authorization"]
        );
        assert!(!config.allow_credentials);
        assert_eq!(config.max_age_seconds, 3600); // 1 hour
    }

    #[test]
    fn test_password_policy_default() {
        let config = PasswordPolicy::default();

        assert_eq!(config.min_length, 12);
        assert!(config.require_uppercase);
        assert!(config.require_lowercase);
        assert!(config.require_numbers);
        assert!(config.require_special_chars);
    }

    #[test]
    fn test_argon2_config_default() {
        let config = Argon2Config::default();

        assert_eq!(config.memory_cost, 65536); // 64MB
        assert_eq!(config.time_cost, 3);
        assert_eq!(config.parallelism, 4);
    }

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();

        assert!(config.enabled);
        assert!(config.cert_path.is_none());
        assert!(config.key_path.is_none());
        assert_eq!(config.min_version, TlsVersion::TLSv1_3);
        assert!(config.cipher_suites.is_empty());
    }

    #[test]
    fn test_encryption_config_default() {
        let config = EncryptionConfig::default();

        assert_eq!(config.key, "REPLACE_IN_PRODUCTION_MIN_32_CHARS_REQUIRED");
        assert_eq!(
            config.token_binding_salt,
            "default-salt-change-in-production"
        );
        assert_eq!(config.algorithm, EncryptionAlgorithm::AES256GCM);
    }

    // Test enum defaults

    #[test]
    fn test_jwt_algorithm_default() {
        assert_eq!(JwtAlgorithm::default(), JwtAlgorithm::HS256);
    }

    #[test]
    fn test_session_storage_default() {
        assert_eq!(SessionStorage::default(), SessionStorage::Hybrid);
    }

    #[test]
    fn test_frame_options_default() {
        assert_eq!(FrameOptions::default(), FrameOptions::Deny);
    }

    #[test]
    fn test_referrer_policy_default() {
        assert_eq!(
            ReferrerPolicy::default(),
            ReferrerPolicy::StrictOriginWhenCrossOrigin
        );
    }

    #[test]
    fn test_tls_version_default() {
        assert_eq!(TlsVersion::default(), TlsVersion::TLSv1_3);
    }

    #[test]
    fn test_encryption_algorithm_default() {
        assert_eq!(
            EncryptionAlgorithm::default(),
            EncryptionAlgorithm::AES256GCM
        );
    }

    // Test validation functions

    #[test]
    fn test_validate_no_dev_secret_valid() {
        assert!(validate_no_dev_secret("secure-production-secret-32-chars").is_ok());
        assert!(validate_no_dev_secret("another-valid-secret-key-for-production").is_ok());
    }

    #[test]
    fn test_validate_no_dev_secret_invalid() {
        assert!(validate_no_dev_secret("INSECURE_DEV_SECRET").is_err());
        assert!(validate_no_dev_secret("test_secret").is_err());
        assert!(validate_no_dev_secret("changeme").is_err());
        assert!(validate_no_dev_secret("dev").is_err());
        assert!(validate_no_dev_secret("contains_test_secret_here").is_err());
        assert!(validate_no_dev_secret("INSECURE_DEV_SECRET_example").is_err());
    }

    // Test special configuration methods

    #[test]
    fn test_development_config() {
        let config = UnifiedSecurityConfig::development();

        assert_eq!(config.jwt.secret, "development-jwt-secret-32-chars-min");
        assert_eq!(config.jwt.access_token_ttl_seconds, 3600); // 1 hour for dev
        assert_eq!(
            config.request_signing.secret,
            "development-request-signing-secret-32-chars"
        );
        assert!(!config.request_signing.enabled); // Disabled in dev
        assert!(!config.session.secure_cookies); // Allow non-HTTPS
        assert!(!config.rate_limiting.enabled); // Disabled for dev
        assert!(!config.tls.enabled); // Allow HTTP
        assert_eq!(
            config.encryption.key,
            "development-encryption-key-32-chars-minimum"
        );
        assert_eq!(config.cors.allowed_origins, vec!["http://localhost:3000"]);
        assert!(config.cors.allow_credentials);
    }

    #[test]
    fn test_testing_config() {
        let config = UnifiedSecurityConfig::testing();

        assert_eq!(
            config.jwt.secret,
            "test-jwt-secret-32-characters-minimum-length"
        );
        assert_eq!(config.jwt.access_token_ttl_seconds, 60); // 1 minute for tests
        assert_eq!(config.jwt.refresh_token_ttl_seconds, 300); // 5 minutes
        assert_eq!(config.request_signing.timestamp_window_seconds, 60);
        assert!(config.request_signing.enabled); // Test security features
        assert_eq!(config.session.ttl_seconds, 300); // 5 minutes
        assert_eq!(config.session.storage_backend, SessionStorage::Memory);
        assert!(!config.session.secure_cookies); // Allow HTTP in tests
        assert!(config.rate_limiting.enabled); // Test rate limiting
        assert_eq!(config.rate_limiting.requests_per_minute_per_ip, 1000);
        assert_eq!(config.password_policy.argon2.memory_cost, 32768); // Faster
        assert_eq!(config.password_policy.argon2.time_cost, 2);
        assert!(!config.tls.enabled); // Allow HTTP in tests
        assert_eq!(config.cors.allowed_origins, vec!["*"]); // Allow all for tests
        assert_eq!(config.headers.hsts_max_age_seconds, 3600); // 1 hour
    }

    // Test enum variants

    #[test]
    fn test_jwt_algorithm_variants() {
        let algorithms = [
            JwtAlgorithm::HS256,
            JwtAlgorithm::HS384,
            JwtAlgorithm::HS512,
            JwtAlgorithm::RS256,
            JwtAlgorithm::RS384,
            JwtAlgorithm::RS512,
            JwtAlgorithm::ES256,
            JwtAlgorithm::ES384,
            JwtAlgorithm::ES512,
        ];

        for algorithm in &algorithms {
            // Just test that they can be created and compared
            assert_eq!(*algorithm, algorithm.clone());
        }
    }

    #[test]
    fn test_session_storage_variants() {
        let storages = [
            SessionStorage::Memory,
            SessionStorage::Redis,
            SessionStorage::Database,
            SessionStorage::Hybrid,
        ];

        for storage in &storages {
            assert_eq!(*storage, storage.clone());
        }
    }

    #[test]
    fn test_frame_options_variants() {
        let options = [
            FrameOptions::Deny,
            FrameOptions::SameOrigin,
            FrameOptions::AllowFrom("https://example.com".to_string()),
        ];

        for option in &options {
            assert_eq!(*option, option.clone());
        }
    }

    #[test]
    fn test_tls_version_variants() {
        let versions = [TlsVersion::TLSv1_2, TlsVersion::TLSv1_3];

        for version in &versions {
            assert_eq!(*version, version.clone());
        }
    }

    #[test]
    fn test_encryption_algorithm_variants() {
        let algorithms = [
            EncryptionAlgorithm::AES256GCM,
            EncryptionAlgorithm::ChaCha20Poly1305,
        ];

        for algorithm in &algorithms {
            assert_eq!(*algorithm, algorithm.clone());
        }
    }

    // Test struct creation and basic functionality

    #[test]
    fn test_jwt_config_creation() {
        let config = JwtConfig {
            secret: "test-secret-32-characters-minimum".to_string(),
            access_token_ttl_seconds: 1800,
            refresh_token_ttl_seconds: 7200,
            algorithm: JwtAlgorithm::HS512,
            issuer: "test-issuer".to_string(),
            audience: Some(vec!["test-audience".to_string()]),
            enable_token_binding: false,
        };

        assert_eq!(config.secret, "test-secret-32-characters-minimum");
        assert_eq!(config.access_token_ttl_seconds, 1800);
        assert_eq!(config.algorithm, JwtAlgorithm::HS512);
        assert!(!config.enable_token_binding);
    }

    #[test]
    fn test_security_headers_creation() {
        let headers = SecurityHeaders {
            enabled: false,
            hsts_max_age_seconds: 63072000,
            content_type_options_nosniff: false,
            frame_options: FrameOptions::SameOrigin,
            xss_protection: false,
            referrer_policy: ReferrerPolicy::NoReferrer,
            content_security_policy: Some("default-src 'self'".to_string()),
        };

        assert!(!headers.enabled);
        assert_eq!(headers.hsts_max_age_seconds, 63072000);
        assert_eq!(headers.frame_options, FrameOptions::SameOrigin);
        assert_eq!(headers.referrer_policy, ReferrerPolicy::NoReferrer);
        assert_eq!(
            headers.content_security_policy,
            Some("default-src 'self'".to_string())
        );
    }

    #[test]
    fn test_cors_config_creation() {
        let cors = CorsConfig {
            allowed_origins: vec![
                "https://api.example.com".to_string(),
                "https://app.example.com".to_string(),
            ],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
            ],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-API-Key".to_string(),
            ],
            allow_credentials: true,
            max_age_seconds: 7200,
        };

        assert_eq!(cors.allowed_origins.len(), 2);
        assert!(cors
            .allowed_origins
            .contains(&"https://api.example.com".to_string()));
        assert_eq!(cors.allowed_methods.len(), 4);
        assert!(cors.allow_credentials);
        assert_eq!(cors.max_age_seconds, 7200);
    }
}
