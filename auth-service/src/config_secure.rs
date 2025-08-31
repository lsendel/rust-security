use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::env;
use validator::Validate;

/// Secure configuration with hardened defaults
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SecureAppConfig {
    // Server configuration
    #[validate(length(min = 1))]
    pub bind_addr: String,

    // External dependencies
    pub redis_url: Option<String>,
    pub database_url: Option<String>,

    // Security settings
    #[validate(nested)]
    pub security: SecureSecurityConfig,

    // Rate limiting
    #[validate(nested)]
    pub rate_limiting: SecureRateLimitConfig,

    // Monitoring
    #[validate(nested)]
    pub monitoring: SecureMonitoringConfig,

    // Feature flags
    pub features: SecureFeatureFlags,

    // OAuth configuration
    #[validate(nested)]
    pub oauth: SecureOAuthConfig,

    // OIDC providers
    pub oidc_providers: SecureOidcProviders,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[allow(clippy::struct_excessive_bools)]
pub struct SecureSecurityConfig {
    // JWT settings with secure defaults
    #[validate(range(min = 300, max = 3600))] // 5 minutes to 1 hour
    pub jwt_access_token_ttl_seconds: u64,

    #[validate(range(min = 3600, max = 86400))] // 1 hour to 24 hours
    pub jwt_refresh_token_ttl_seconds: u64,

    #[validate(range(min = 2048, max = 8192))] // RSA key size
    pub rsa_key_size: u32,

    // Request signing (required in production)
    pub request_signing_secret: Option<String>,

    #[validate(range(min = 60, max = 600))] // 1 minute to 10 minutes
    pub request_timestamp_window_seconds: i64,

    // Session management
    #[validate(range(min = 900, max = 7200))] // 15 minutes to 2 hours
    pub session_ttl_seconds: u64,

    #[validate(range(min = 300, max = 3600))] // 5 minutes to 1 hour
    pub session_rotation_interval_seconds: u64,

    // CORS settings (empty by default - must be explicitly configured)
    pub allowed_origins: Vec<String>,

    // Content security
    #[validate(range(min = 1_024, max = 10_485_760))] // 1KB to 10MB
    pub max_request_body_size: usize,

    // Security headers
    pub security_headers: SecurityHeaders,

    // TLS settings
    pub tls_config: TlsConfig,

    // Password policy
    pub password_policy: PasswordPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[allow(clippy::struct_excessive_bools)]
pub struct SecurityHeaders {
    pub hsts_max_age: u32,
    pub content_type_options: bool,
    pub frame_options: FrameOptions,
    pub xss_protection: bool,
    pub referrer_policy: ReferrerPolicy,
    pub csp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FrameOptions {
    Deny,
    SameOrigin,
    AllowFrom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[allow(clippy::struct_excessive_bools)]
pub struct TlsConfig {
    pub min_version: String, // "1.2" or "1.3"
    pub cipher_suites: Vec<String>,
    pub require_client_cert: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[allow(clippy::struct_excessive_bools)]
pub struct PasswordPolicy {
    #[validate(range(min = 8, max = 128))]
    pub min_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digits: bool,
    pub require_special_chars: bool,
    pub min_character_classes: u32,
    pub prevent_common_passwords: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[allow(clippy::struct_excessive_bools)]
pub struct SecureRateLimitConfig {
    #[validate(range(min = 1, max = 10000))]
    pub requests_per_minute_global: u32,

    #[validate(range(min = 1, max = 1000))]
    pub requests_per_minute_per_ip: u32,

    #[validate(range(min = 1, max = 100))]
    pub oauth_requests_per_minute: u32,

    #[validate(range(min = 1, max = 50))]
    pub admin_requests_per_minute: u32,

    #[validate(range(min = 1, max = 100))]
    pub burst_size: u32,

    #[validate(range(min = 1, max = 20))]
    pub ban_threshold: u32,

    #[validate(range(min = 5, max = 1440))] // 5 minutes to 24 hours
    pub ban_duration_minutes: u32,

    pub enable_adaptive_limiting: bool,
    pub suspicious_activity_threshold: u32,

    // IP allowlist/blocklist
    pub allowlist_ips: Vec<String>,
    pub blocklist_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[allow(clippy::struct_excessive_bools)]
pub struct SecureMonitoringConfig {
    pub prometheus_metrics_enabled: bool,
    pub opentelemetry_enabled: bool,
    pub jaeger_endpoint: Option<String>,

    #[validate(range(min = 10, max = 3600))]
    pub metrics_scrape_interval_seconds: u64,

    pub security_monitoring_enabled: bool,
    pub audit_logging_enabled: bool,
    pub performance_monitoring_enabled: bool,

    // Log levels
    pub log_level: String,
    pub security_log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct SecureFeatureFlags {
    pub mfa_enabled: bool,
    pub webauthn_enabled: bool,
    pub oauth_dynamic_registration: bool,
    pub admin_api_enabled: bool,
    pub debug_endpoints_enabled: bool,
    pub experimental_features_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[allow(clippy::struct_excessive_bools)]
pub struct SecureOAuthConfig {
    #[validate(range(min = 300, max = 3600))] // 5 minutes to 1 hour
    pub authorization_code_ttl_seconds: u64,

    #[validate(range(min = 8, max = 128))]
    pub client_id_min_length: u32,

    #[validate(range(min = 16, max = 256))]
    pub client_secret_min_length: u32,

    pub require_pkce: bool,
    pub require_state: bool,
    pub require_nonce_for_id_tokens: bool,

    // Allowed grant types
    pub allowed_grant_types: Vec<String>,

    // Allowed response types
    pub allowed_response_types: Vec<String>,

    // Allowed scopes
    pub allowed_scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate, Default)]
pub struct SecureOidcProviders {
    pub google: Option<SecureOidcProvider>,
    pub microsoft: Option<SecureOidcProvider>,
    pub github: Option<SecureOidcProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SecureOidcProvider {
    #[validate(length(min = 1))]
    pub client_id: String,

    #[validate(length(min = 16))] // Minimum 16 characters for security
    pub client_secret: String,

    #[validate(url)]
    pub redirect_uri: String,

    #[validate(url)]
    pub discovery_url: Option<String>,

    pub scopes: Vec<String>,
    pub enabled: bool,
}

/// Configuration errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required field: {0}")]
    MissingRequiredField(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Insecure configuration: {0}")]
    InsecureConfiguration(String),
    #[error("Weak secret: {0}")]
    WeakSecret(String),
    #[error("Weak cryptography: {0}")]
    WeakCrypto(String),
    #[error("Environment error: {0}")]
    EnvironmentError(String),
}

impl Default for SecureSecurityConfig {
    fn default() -> Self {
        Self {
            // Secure JWT defaults - shorter expiration times
            jwt_access_token_ttl_seconds: 900,  // 15 minutes
            jwt_refresh_token_ttl_seconds: 86400, // 24 hours
            rsa_key_size: 4096, // Increased from 2048 for better security

            // Request signing required in production
            request_signing_secret: None, // Must be set via environment
            request_timestamp_window_seconds: 300, // 5 minutes

            // Secure session defaults
            session_ttl_seconds: 1800, // 30 minutes
            session_rotation_interval_seconds: 900, // 15 minutes

            // Secure CORS defaults - empty by default, must be explicitly configured
            allowed_origins: vec![], // No origins allowed by default

            // Secure request size limits
            max_request_body_size: 1024 * 1024, // 1MB

            // Security headers with secure defaults
            security_headers: SecurityHeaders {
                hsts_max_age: 31_536_000, // 1 year
                content_type_options: true,
                frame_options: FrameOptions::Deny,
                xss_protection: true,
                referrer_policy: ReferrerPolicy::StrictOriginWhenCrossOrigin,
                csp: Some("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'none';".to_string()),
            },

            // TLS configuration
            tls_config: TlsConfig {
                min_version: "1.3".to_string(), // Require TLS 1.3
                cipher_suites: vec![
                    "TLS_AES_256_GCM_SHA384".to_string(),
                    "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                    "TLS_AES_128_GCM_SHA256".to_string(),
                ],
                require_client_cert: false,
                cert_path: None,
                key_path: None,
            },

            // Strong password policy
            password_policy: PasswordPolicy {
                min_length: 12, // Increased from 8
                require_uppercase: true,
                require_lowercase: true,
                require_digits: true,
                require_special_chars: true,
                min_character_classes: 3,
                prevent_common_passwords: true,
            },
        }
    }
}

impl Default for SecureRateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute_global: 1000,
            requests_per_minute_per_ip: 60,
            oauth_requests_per_minute: 10, // Strict OAuth limits
            admin_requests_per_minute: 5,  // Very strict admin limits
            burst_size: 10,
            ban_threshold: 5,
            ban_duration_minutes: 15,
            enable_adaptive_limiting: true,
            suspicious_activity_threshold: 3,
            allowlist_ips: vec![],
            blocklist_ips: vec![],
        }
    }
}

impl Default for SecureMonitoringConfig {
    fn default() -> Self {
        Self {
            prometheus_metrics_enabled: true,
            opentelemetry_enabled: true,
            jaeger_endpoint: None,
            metrics_scrape_interval_seconds: 30,
            security_monitoring_enabled: true,
            audit_logging_enabled: true,
            performance_monitoring_enabled: true,
            log_level: "info".to_string(),
            security_log_level: "warn".to_string(),
        }
    }
}

impl Default for SecureFeatureFlags {
    fn default() -> Self {
        Self {
            mfa_enabled: true,
            webauthn_enabled: false, // Disabled by default until fully implemented
            oauth_dynamic_registration: false, // Disabled by default for security
            admin_api_enabled: false, // Disabled by default
            debug_endpoints_enabled: false, // Never enabled by default
            experimental_features_enabled: false, // Never enabled by default
        }
    }
}

impl Default for SecureOAuthConfig {
    fn default() -> Self {
        Self {
            authorization_code_ttl_seconds: 600, // 10 minutes
            client_id_min_length: 16,
            client_secret_min_length: 32,
            require_pkce: true,                // Always require PKCE for security
            require_state: true,               // Always require state for CSRF protection
            require_nonce_for_id_tokens: true, // Always require nonce for ID tokens
            allowed_grant_types: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
                "refresh_token".to_string(),
            ],
            allowed_response_types: vec!["code".to_string()],
            allowed_scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "read".to_string(),
                "write".to_string(),
            ],
        }
    }
}

/// Load secure configuration with environment-based hardening
pub fn load_secure_config() -> Result<SecureAppConfig, ConfigError> {
    let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

    let mut config = SecureAppConfig {
        bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
        redis_url: env::var("REDIS_URL").ok(),
        database_url: env::var("DATABASE_URL").ok(),
        security: SecureSecurityConfig::default(),
        rate_limiting: SecureRateLimitConfig::default(),
        monitoring: SecureMonitoringConfig::default(),
        features: SecureFeatureFlags::default(),
        oauth: SecureOAuthConfig::default(),
        oidc_providers: SecureOidcProviders::default(),
    };

    // Environment-specific security hardening
    match environment.as_str() {
        "production" => {
            apply_production_security(&mut config)?;
        }
        "staging" => {
            apply_staging_security(&mut config);
        }
        _ => {
            apply_development_security(&mut config);
        }
    }

    // Validate configuration
    config
        .validate()
        .map_err(|e| ConfigError::InvalidConfiguration(format!("Validation failed: {e}")))?;

    // Additional security validations
    validate_security_requirements(&config)?;

    Ok(config)
}

fn apply_production_security(config: &mut SecureAppConfig) -> Result<(), ConfigError> {
    apply_production_timeouts(config);
    validate_production_secrets(config)?;
    enforce_https_requirement()?;
    configure_production_cors(config)?;
    disable_debug_features(config);
    apply_strict_rate_limits(config);
    Ok(())
}

fn apply_production_timeouts(config: &mut SecureAppConfig) {
    config.security.jwt_access_token_ttl_seconds = 600; // 10 minutes
    config.security.session_ttl_seconds = 1800; // 30 minutes
    config.security.session_rotation_interval_seconds = 600; // 10 minutes
}

fn validate_production_secrets(config: &mut SecureAppConfig) -> Result<(), ConfigError> {
    let secret = env::var("REQUEST_SIGNING_SECRET").map_err(|_| {
        ConfigError::MissingRequiredField("REQUEST_SIGNING_SECRET".to_string())
    })?;
    
    if secret.len() < 32 {
        return Err(ConfigError::WeakSecret(
            "REQUEST_SIGNING_SECRET must be at least 32 characters".to_string(),
        ));
    }
    
    config.security.request_signing_secret = Some(secret);
    Ok(())
}

fn enforce_https_requirement() -> Result<(), ConfigError> {
    if env::var("FORCE_HTTPS").unwrap_or_default() != "true" {
        return Err(ConfigError::InsecureConfiguration(
            "HTTPS must be enabled in production (set FORCE_HTTPS=true)".to_string(),
        ));
    }
    Ok(())
}

fn configure_production_cors(config: &mut SecureAppConfig) -> Result<(), ConfigError> {
    let cors_origins = env::var("ALLOWED_ORIGINS").unwrap_or_default();
    if cors_origins.is_empty() {
        return Err(ConfigError::InsecureConfiguration(
            "ALLOWED_ORIGINS must be explicitly set in production".to_string(),
        ));
    }
    
    config.security.allowed_origins = cors_origins
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    
    Ok(())
}

fn disable_debug_features(config: &mut SecureAppConfig) {
    config.features.debug_endpoints_enabled = false;
    config.features.experimental_features_enabled = false;
}

fn apply_strict_rate_limits(config: &mut SecureAppConfig) {
    config.rate_limiting.oauth_requests_per_minute = 5;
    config.rate_limiting.admin_requests_per_minute = 2;
}

fn apply_staging_security(config: &mut SecureAppConfig) {
    // Staging security (slightly relaxed but still secure)
    config.security.jwt_access_token_ttl_seconds = 1800; // 30 minutes
    config.security.session_ttl_seconds = 3600; // 1 hour

    // Allow some development origins in staging
    config.security.allowed_origins = vec![
        "https://staging.example.com".to_string(),
        "http://localhost:3000".to_string(),
    ];

    // Disable experimental features in staging
    config.features.experimental_features_enabled = false;
}

fn apply_development_security(config: &mut SecureAppConfig) {
    // Development (relaxed for testing but still reasonably secure)
    config.security.jwt_access_token_ttl_seconds = 3600; // 1 hour
    config.security.session_ttl_seconds = 7200; // 2 hours

    config.security.allowed_origins = vec![
        "http://localhost:3000".to_string(),
        "http://localhost:8080".to_string(),
        "http://127.0.0.1:3000".to_string(),
    ];

    // Allow debug endpoints in development
    config.features.debug_endpoints_enabled = true;

    // More relaxed rate limiting for development
    config.rate_limiting.requests_per_minute_per_ip = 120;
    config.rate_limiting.oauth_requests_per_minute = 30;
}

#[allow(clippy::too_many_lines)]
fn validate_security_requirements(config: &SecureAppConfig) -> Result<(), ConfigError> {
    // Validate RSA key size
    if config.security.rsa_key_size < 2048 {
        return Err(ConfigError::WeakCrypto(
            "RSA key size must be at least 2048 bits".to_string(),
        ));
    }

    // Validate TTL values
    if config.security.jwt_access_token_ttl_seconds < 300 {
        return Err(ConfigError::InvalidConfiguration(
            "Access token TTL too short (minimum 5 minutes)".to_string(),
        ));
    }

    if config.security.jwt_access_token_ttl_seconds > 86400 {
        return Err(ConfigError::InvalidConfiguration(
            "Access token TTL too long (maximum 24 hours)".to_string(),
        ));
    }

    if config.security.session_ttl_seconds < 900 {
        return Err(ConfigError::InvalidConfiguration(
            "Session TTL too short (minimum 15 minutes)".to_string(),
        ));
    }

    // Validate password policy
    if config.security.password_policy.min_length < 8 {
        return Err(ConfigError::WeakCrypto(
            "Password minimum length must be at least 8".to_string(),
        ));
    }

    // Validate rate limiting
    if config.rate_limiting.requests_per_minute_per_ip > 1000 {
        return Err(ConfigError::InvalidConfiguration(
            "Per-IP rate limit too high (maximum 1000)".to_string(),
        ));
    }

    // Validate CORS origins format
    for origin in &config.security.allowed_origins {
        if origin == "*" {
            return Err(ConfigError::InsecureConfiguration(
                "Wildcard CORS origin (*) is not allowed".to_string(),
            ));
        }

        if !origin.starts_with("http://") && !origin.starts_with("https://") {
            return Err(ConfigError::InvalidConfiguration(format!(
                "Invalid CORS origin format: {origin}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_defaults() {
        let config = SecureSecurityConfig::default();

        // Verify secure defaults
        assert_eq!(config.jwt_access_token_ttl_seconds, 900); // 15 minutes
        assert_eq!(config.rsa_key_size, 4096); // Strong key size
        assert!(config.allowed_origins.is_empty()); // No default origins
        assert_eq!(config.security_headers.frame_options, FrameOptions::Deny);
    }

    #[test]
    fn test_production_security_validation() {
        env::set_var("ENVIRONMENT", "production");
        env::set_var("FORCE_HTTPS", "true");
        env::set_var("REQUEST_SIGNING_SECRET", "a".repeat(32));
        env::set_var("ALLOWED_ORIGINS", "https://example.com");

        let result = load_secure_config();
        assert!(result.is_ok());
    }

    #[test]
    fn test_weak_secret_rejection() {
        env::set_var("ENVIRONMENT", "production");
        env::set_var("REQUEST_SIGNING_SECRET", "weak"); // Too short

        let result = load_secure_config();
        assert!(matches!(result, Err(ConfigError::WeakSecret(_))));
    }
}
