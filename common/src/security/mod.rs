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
//! - **Backward Compatibility**: Compatible with existing service configurations

pub mod config;
pub mod defaults;
pub mod validation;

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
///
/// let config = UnifiedSecurityConfig::from_env()?;
/// assert!(config.validate().is_ok());
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
fn validate_no_dev_secret(secret: &str) -> Result<(), validator::ValidationError> {
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
