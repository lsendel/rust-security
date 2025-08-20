use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::time::Duration;
use url::Url;
use validator::Validate;

// Raw configuration structure for legacy env loading
#[derive(Debug, Deserialize)]
struct RawConfig {
    bind_addr: Option<String>,
    redis_url: Option<String>,
    client_credentials: Option<String>,
    allowed_scopes: Option<String>,
    jwt_secret: Option<String>,
    token_expiry_seconds: Option<u64>,
    rate_limit_requests_per_minute: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AppConfig {
    // Server configuration
    pub bind_addr: String,

    // External dependencies
    pub redis_url: Option<String>,

    // Authentication providers
    pub oidc_providers: OidcProviders,

    // Security settings
    pub security: SecurityConfig,

    // Rate limiting
    pub rate_limiting: RateLimitConfig,

    // Monitoring
    pub monitoring: MonitoringConfig,

    // Feature flags
    pub features: FeatureFlags,

    // OAuth configuration
    pub oauth: OAuthConfig,

    // SCIM configuration
    pub scim: ScimConfig,

    // Store configuration
    pub store: StoreConfig,

    // Client credentials
    pub client_credentials: HashMap<String, String>,

    // Allowed scopes
    #[validate(length(min = 1))]
    pub allowed_scopes: Vec<String>,

    // Legacy fields for backward compatibility
    #[allow(dead_code)]
    pub jwt_secret: String,
    pub token_expiry_seconds: u64,
    pub rate_limit_requests_per_minute: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct OidcProviders {
    pub google: Option<OidcProvider>,
    pub microsoft: Option<OidcProvider>,
    pub github: Option<OidcProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct OidcProvider {
    #[validate(length(min = 1))]
    pub client_id: String,

    #[validate(length(min = 1))]
    pub client_secret: String,

    #[validate(url)]
    pub redirect_uri: String,

    #[validate(url)]
    pub discovery_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SecurityConfig {
    // JWT settings
    #[validate(range(min = 300, max = 86400))] // 5 minutes to 24 hours
    pub jwt_access_token_ttl_seconds: u64,

    #[validate(range(min = 3600, max = 2592000))] // 1 hour to 30 days
    pub jwt_refresh_token_ttl_seconds: u64,

    #[validate(range(min = 2048, max = 8192))] // RSA key size
    pub rsa_key_size: u32,

    // Request signing
    pub request_signing_secret: Option<String>,

    #[validate(range(min = 60, max = 3600))] // 1 minute to 1 hour
    pub request_timestamp_window_seconds: i64,

    // Session management
    #[validate(range(min = 1800, max = 86400))] // 30 minutes to 24 hours
    pub session_ttl_seconds: u64,

    // CORS settings
    pub allowed_origins: Vec<String>,

    // Content security
    #[validate(range(min = 1024, max = 104857600))] // 1KB to 100MB
    pub max_request_body_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RateLimitConfig {
    #[validate(range(min = 1, max = 10000))]
    pub requests_per_minute_global: u32,

    #[validate(range(min = 1, max = 1000))]
    pub requests_per_minute_per_ip: u32,

    #[validate(range(min = 1, max = 100))]
    pub oauth_requests_per_minute: u32,

    #[validate(range(min = 1, max = 500))]
    pub admin_requests_per_minute: u32,

    pub enable_banlist: bool,
    pub enable_allowlist: bool,

    pub banlist_ips: Vec<String>,
    pub allowlist_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct MonitoringConfig {
    pub prometheus_metrics_enabled: bool,
    pub opentelemetry_enabled: bool,
    pub jaeger_endpoint: Option<String>,

    #[validate(range(min = 10, max = 3600))]
    pub metrics_scrape_interval_seconds: u64,

    pub security_monitoring_enabled: bool,
    pub audit_logging_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureFlags {
    pub soar_integration: bool,
    pub google_oidc: bool,
    pub microsoft_oidc: bool,
    pub github_oidc: bool,
    pub webauthn: bool,
    pub scim_v2: bool,
    pub advanced_mfa: bool,
    pub threat_detection: bool,
    pub policy_engine: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct OAuthConfig {
    #[validate(range(min = 60, max = 3600))] // 1 minute to 1 hour
    pub authorization_code_ttl_seconds: u64,

    #[validate(range(min = 1, max = 100))]
    pub max_authorization_codes_per_client: usize,

    pub enforce_pkce: bool,
    pub require_state_parameter: bool,

    // Redirect URI validation
    pub strict_redirect_validation: bool,
    pub allowed_redirect_schemes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ScimConfig {
    pub enabled: bool,

    #[validate(range(min = 1, max = 10000))]
    pub max_filter_length: usize,

    #[validate(range(min = 1, max = 1000))]
    pub max_results_per_page: usize,

    #[validate(range(min = 1, max = 100))]
    pub default_results_per_page: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".to_string(),
            redis_url: None,
            oidc_providers: OidcProviders::default(),
            security: SecurityConfig::default(),
            rate_limiting: RateLimitConfig::default(),
            monitoring: MonitoringConfig::default(),
            features: FeatureFlags::default(),
            oauth: OAuthConfig::default(),
            scim: ScimConfig::default(),
            store: StoreConfig::default(),
            client_credentials: HashMap::new(),
            allowed_scopes: vec!["read".to_string(), "write".to_string()],
            // Legacy fields
            jwt_secret: "legacy".to_string(),
            token_expiry_seconds: 3600,
            rate_limit_requests_per_minute: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StoreBackend {
    Hybrid,
    Sql,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct StoreConfig {
    pub backend: StoreBackend,
    #[validate(url)]
    pub database_url: Option<String>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self { backend: StoreBackend::Hybrid, database_url: None }
    }
}

impl Default for OidcProviders {
    fn default() -> Self {
        Self { google: None, microsoft: None, github: None }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            jwt_access_token_ttl_seconds: 3600,   // 1 hour
            jwt_refresh_token_ttl_seconds: 86400, // 24 hours
            rsa_key_size: 2048,
            request_signing_secret: None,
            request_timestamp_window_seconds: 300, // 5 minutes
            session_ttl_seconds: 7200,             // 2 hours
            allowed_origins: Vec::new(),
            max_request_body_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute_global: 1000,
            requests_per_minute_per_ip: 60,
            oauth_requests_per_minute: 20,
            admin_requests_per_minute: 10,
            enable_banlist: true,
            enable_allowlist: false,
            banlist_ips: Vec::new(),
            allowlist_ips: Vec::new(),
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            prometheus_metrics_enabled: true,
            opentelemetry_enabled: false,
            jaeger_endpoint: None,
            metrics_scrape_interval_seconds: 15,
            security_monitoring_enabled: true,
            audit_logging_enabled: true,
        }
    }
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            soar_integration: false,
            google_oidc: true,
            microsoft_oidc: true,
            github_oidc: true,
            webauthn: true,
            scim_v2: true,
            advanced_mfa: true,
            threat_detection: true,
            policy_engine: true,
        }
    }
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            authorization_code_ttl_seconds: 600, // 10 minutes
            max_authorization_codes_per_client: 10,
            enforce_pkce: true,
            require_state_parameter: true,
            strict_redirect_validation: true,
            allowed_redirect_schemes: vec![
                "https".to_string(),
                "http".to_string(), // Only for development
            ],
        }
    }
}

impl Default for ScimConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_filter_length: 1000,
            max_results_per_page: 100,
            default_results_per_page: 20,
        }
    }
}

impl StoreConfig {
    pub fn from_env() -> Self {
        let backend_str = env::var("STORE_BACKEND").unwrap_or_else(|_| "hybrid".to_string());
        let backend = match backend_str.to_lowercase().as_str() {
            "sql" => StoreBackend::Sql,
            _ => StoreBackend::Hybrid,
        };
        let database_url = env::var("DATABASE_URL").ok();

        if backend == StoreBackend::Sql && database_url.is_none() {
            // This is a critical configuration error, so we panic.
            panic!("FATAL: `STORE_BACKEND` is set to `sql`, but `DATABASE_URL` is not set.");
        }

        Self { backend, database_url }
    }
}

impl AppConfig {
    /// Load configuration from environment variables with validation
    pub fn from_env() -> Result<Self, anyhow::Error> {
        let mut config = Self::default();

        // Server configuration
        if let Ok(bind_addr) = env::var("BIND_ADDR") {
            config.bind_addr = bind_addr;
        }

        // Redis configuration
        config.redis_url = env::var("REDIS_URL").ok();

        // Legacy environment loading (backward compatibility)
        if config.redis_url.is_none() {
            config.redis_url = env::var("redis_url").ok();
        }

        // OIDC Providers
        config.oidc_providers = OidcProviders::default();

        // Security settings
        config.security = SecurityConfig::default();

        // Rate limiting
        config.rate_limiting = RateLimitConfig::default();

        // Monitoring
        config.monitoring = MonitoringConfig::default();

        // Feature flags
        config.features = FeatureFlags::default();

        // OAuth configuration
        config.oauth = OAuthConfig::default();

        // SCIM configuration
        config.scim = ScimConfig::default();

        // Store Configuration
        config.store = StoreConfig::from_env();

        // Client credentials (required)
        config.client_credentials = if let Ok(creds) = env::var("CLIENT_CREDENTIALS") {
            parse_client_credentials(&creds)?
        } else {
            HashMap::new()
        };

        // Allowed scopes
        if let Ok(scopes) = env::var("ALLOWED_SCOPES") {
            config.allowed_scopes = scopes.split(',').map(|s| s.trim().to_string()).collect();
        } else if let Ok(scopes) = env::var("allowed_scopes") {
            config.allowed_scopes = scopes.split(',').map(|s| s.trim().to_string()).collect();
        }

        // Legacy fields for backward compatibility
        config.jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "legacy".to_string());
        config.token_expiry_seconds =
            env::var("TOKEN_EXPIRY_SECONDS").ok().and_then(|s| s.parse().ok()).unwrap_or(3600);
        config.rate_limit_requests_per_minute = env::var("RATE_LIMIT_REQUESTS_PER_MINUTE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);

        // Configuration loaded successfully

        Ok(config)
    }

    /// Legacy method for backward compatibility
    pub fn from_env_legacy() -> Result<Self> {
        dotenvy::dotenv().ok(); // Load .env file if present

        let raw = envy::from_env::<RawConfig>()
            .context("Failed to parse configuration from environment")?;

        let bind_addr = raw.bind_addr.unwrap_or_else(|| "127.0.0.1:8080".to_string());

        // Validate bind address format
        if bind_addr.parse::<std::net::SocketAddr>().is_err() {
            anyhow::bail!("Invalid bind address format: {}", bind_addr);
        }

        let client_credentials = parse_client_credentials(
            raw.client_credentials.as_deref().unwrap_or("test_client:test_secret"),
        )?;

        // Validate client credentials
        for (client_id, client_secret) in &client_credentials {
            if client_id.is_empty() || client_secret.is_empty() {
                anyhow::bail!("Client credentials cannot be empty");
            }
            if client_id.len() < 3 || client_secret.len() < 8 {
                anyhow::bail!("Client credentials too short (min 3 chars for ID, 8 for secret)");
            }
        }

        let allowed_scopes: Vec<String> = raw
            .allowed_scopes
            .as_deref()
            .unwrap_or("read,write")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>();

        // Validate scopes
        if allowed_scopes.is_empty() {
            anyhow::bail!("At least one scope must be configured");
        }

        for scope in &allowed_scopes {
            if !scope.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                anyhow::bail!("Invalid scope format: {}", scope);
            }
        }

        let jwt_secret = raw.jwt_secret.unwrap_or_else(generate_default_secret);

        let token_expiry_seconds = raw.token_expiry_seconds.unwrap_or(3600);
        if !(60..=86400).contains(&token_expiry_seconds) {
            anyhow::bail!("Token expiry must be between 60 seconds and 24 hours");
        }

        let rate_limit_requests_per_minute = raw.rate_limit_requests_per_minute.unwrap_or(60);
        if rate_limit_requests_per_minute == 0 || rate_limit_requests_per_minute > 10000 {
            anyhow::bail!("Rate limit must be between 1 and 10000 requests per minute");
        }

        // Validate Redis URL if provided
        if let Some(redis_url) = &raw.redis_url {
            if !redis_url.starts_with("redis://") && !redis_url.starts_with("rediss://") {
                anyhow::bail!("Invalid Redis URL format");
            }
        }

        Ok(AppConfig {
            bind_addr,
            redis_url: raw.redis_url,
            client_credentials,
            allowed_scopes,
            jwt_secret,
            token_expiry_seconds,
            rate_limit_requests_per_minute,
            // Add missing fields with defaults
            oidc_providers: OidcProviders::default(),
            security: SecurityConfig::default(),
            rate_limiting: RateLimitConfig::default(),
            monitoring: MonitoringConfig::default(),
            features: FeatureFlags::default(),
            oauth: OAuthConfig::default(),
            scim: ScimConfig::default(),
        })
    }
}

fn parse_client_credentials(creds_str: &str) -> Result<HashMap<String, String>> {
    let mut credentials = HashMap::new();

    for pair in creds_str.split(';') {
        let parts: Vec<&str> = pair.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid client credentials format. Expected 'client_id:client_secret'");
        }
        credentials.insert(parts[0].trim().to_string(), parts[1].trim().to_string());
    }

    Ok(credentials)
}

fn generate_default_secret() -> String {
    use std::env;

    // Check if we're in production environment
    let is_production =
        env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()).to_lowercase()
            == "production";

    match env::var("JWT_SECRET") {
        Ok(secret) => {
            // Validate secret strength in production
            if is_production {
                if let Err(e) = validate_secret_strength(&secret, "JWT_SECRET") {
                    tracing::error!("JWT_SECRET validation failed: {}", e);
                    std::process::exit(1);
                }
            }
            secret
        }
        Err(_) => {
            if is_production {
                tracing::error!("JWT_SECRET environment variable is required in production");
                std::process::exit(1);
            }

            tracing::warn!(
                "Using default JWT secret. Set JWT_SECRET environment variable in production!"
            );

            // Generate a random secret for development
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
            base64::engine::general_purpose::STANDARD.encode(random_bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_client_credentials() {
        let result = parse_client_credentials("client1:secret1;client2:secret2").unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains_key("client1"));
        assert!(result.contains_key("client2"));
    }

    #[test]
    fn test_parse_invalid_client_credentials() {
        let result = parse_client_credentials("invalid_format");
        assert!(result.is_err());
    }
}

/// Validates secret strength for production environments
fn validate_secret_strength(secret: &str, secret_name: &str) -> Result<()> {
    // Check minimum length
    if secret.len() < 32 {
        return Err(anyhow::anyhow!(
            "{} must be at least 32 characters long in production",
            secret_name
        ));
    }

    // Check for weak patterns
    let weak_patterns = [
        "default", "change", "test", "dev", "admin", "password", "secret", "key", "123456",
        "qwerty", "abc",
    ];

    let lower_secret = secret.to_lowercase();
    for pattern in &weak_patterns {
        if lower_secret.contains(pattern) {
            return Err(anyhow::anyhow!("{} contains weak pattern '{}' in production. Use a cryptographically strong secret.", secret_name, pattern));
        }
    }

    // Check character diversity (must have at least 3 different character types)
    let has_lower = secret.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = secret.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = secret.chars().any(|c| c.is_ascii_digit());
    let has_special = secret.chars().any(|c| !c.is_ascii_alphanumeric());

    let char_types = [has_lower, has_upper, has_digit, has_special].iter().filter(|&&x| x).count();

    if char_types < 3 {
        return Err(anyhow::anyhow!("{} must contain at least 3 different character types (lowercase, uppercase, digits, special characters) in production", secret_name));
    }

    // Check for repeated patterns (simple check for repeating substrings)
    if secret.len() >= 8 {
        for window_size in 2..=4 {
            if secret.len() >= window_size * 3 {
                for i in 0..=(secret.len() - window_size * 3) {
                    let pattern = &secret[i..i + window_size];
                    let remaining = &secret[i + window_size..];
                    if remaining.starts_with(pattern)
                        && remaining[window_size..].starts_with(pattern)
                    {
                        return Err(anyhow::anyhow!("{} contains repeated patterns in production. Use a more random secret.", secret_name));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Validates all secrets at startup
pub fn validate_production_secrets() -> Result<()> {
    let is_production =
        env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()).to_lowercase()
            == "production";

    if !is_production {
        return Ok(());
    }

    // Validate REQUEST_SIGNING_SECRET
    match env::var("REQUEST_SIGNING_SECRET") {
        Ok(secret) => {
            validate_secret_strength(&secret, "REQUEST_SIGNING_SECRET")?;
        }
        Err(_) => {
            return Err(anyhow::anyhow!(
                "REQUEST_SIGNING_SECRET environment variable is required in production"
            ));
        }
    }

    // JWT_SECRET is already validated in get_jwt_secret()

    tracing::info!("All production secrets validated successfully");
    Ok(())
}
