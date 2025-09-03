use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use tracing::{info, warn};

/// Static configuration that replaces .env variables
/// This provides a compile-time configuration approach instead of runtime env vars
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticConfig {
    pub server: ServerConfig,
    pub security: StaticSecurityConfig,
    pub clients: StaticClientConfig,
    pub features: StaticFeatureConfig,
    pub monitoring: StaticMonitoringConfig,
    pub oauth: StaticOAuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub cors_allowed_origins: Vec<String>,
    pub request_body_limit_mb: usize,
    pub health_check_timeout_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticSecurityConfig {
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub token_expiry_seconds: u64,
    pub allowed_scopes: Vec<String>,
    pub rate_limit_requests_per_minute: u32,
    pub session_timeout_minutes: u32,
    pub max_login_attempts: u32,
    pub lockout_duration_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticClientConfig {
    pub default_clients: HashMap<String, ClientInfo>,
    pub allow_dynamic_registration: bool,
    pub require_client_authentication: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub secret_hash: String, // bcrypt hash of the secret
    pub scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticFeatureConfig {
    pub enable_oidc_google: bool,
    pub enable_oidc_microsoft: bool,
    pub enable_oidc_github: bool,
    pub enable_webauthn: bool,
    pub enable_mfa: bool,
    pub enable_scim: bool,
    pub enable_advanced_logging: bool,
    pub enable_metrics: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMonitoringConfig {
    pub prometheus_enabled: bool,
    pub metrics_port: u16,
    pub jaeger_enabled: bool,
    pub log_level: String,
    pub audit_log_retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticOAuthConfig {
    pub authorization_code_ttl_seconds: u64,
    pub refresh_token_ttl_seconds: u64,
    pub enforce_pkce: bool,
    pub require_state_parameter: bool,
    pub allowed_redirect_schemes: Vec<String>,
}

/// Environment-specific configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Testing,
    Staging,
    Production,
}

impl Environment {
    #[must_use]
    pub fn from_env() -> Self {
        match env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .to_lowercase()
            .as_str()
        {
            "production" | "prod" => Self::Production,
            "staging" | "stage" => Self::Staging,
            "testing" | "test" => Self::Testing,
            _ => Self::Development,
        }
    }

    #[must_use]
    pub const fn is_production(&self) -> bool {
        matches!(self, Self::Production)
    }

    #[must_use]
    pub const fn is_development(&self) -> bool {
        matches!(self, Self::Development)
    }
}

/// Static configuration instance - loaded once at startup
pub static CONFIG: Lazy<StaticConfig> = Lazy::new(|| {
    let env = Environment::from_env();
    match env {
        Environment::Production => production_config(),
        Environment::Staging => staging_config(),
        Environment::Testing => testing_config(),
        Environment::Development => development_config(),
    }
});

/// Production configuration with hardcoded secure defaults
#[must_use]
pub fn production_config() -> StaticConfig {
    StaticConfig {
        server: ServerConfig {
            bind_addr: "0.0.0.0:8080".to_string(),
            cors_allowed_origins: vec![
                "https://api.company.com".to_string(),
                "https://app.company.com".to_string(),
            ],
            request_body_limit_mb: 1,
            health_check_timeout_seconds: 30,
        },
        security: StaticSecurityConfig {
            jwt_issuer: "rust-security-auth".to_string(),
            jwt_audience: "api-clients".to_string(),
            token_expiry_seconds: 3600,
            allowed_scopes: vec![
                "read".to_string(),
                "write".to_string(),
                "admin".to_string(),
                "user:profile".to_string(),
                "user:email".to_string(),
            ],
            rate_limit_requests_per_minute: 100,
            session_timeout_minutes: 60,
            max_login_attempts: 3,
            lockout_duration_minutes: 15,
        },
        clients: StaticClientConfig {
            default_clients: get_production_clients(),
            allow_dynamic_registration: false,
            require_client_authentication: true,
        },
        features: StaticFeatureConfig {
            enable_oidc_google: true,
            enable_oidc_microsoft: true,
            enable_oidc_github: false, // Disabled in production
            enable_webauthn: true,
            enable_mfa: true,
            enable_scim: true,
            enable_advanced_logging: true,
            enable_metrics: true,
        },
        monitoring: StaticMonitoringConfig {
            prometheus_enabled: true,
            metrics_port: 9090,
            jaeger_enabled: true,
            log_level: "info".to_string(),
            audit_log_retention_days: 90,
        },
        oauth: StaticOAuthConfig {
            authorization_code_ttl_seconds: 600,
            refresh_token_ttl_seconds: 86400 * 7, // 7 days
            enforce_pkce: true,
            require_state_parameter: true,
            allowed_redirect_schemes: vec!["https".to_string()],
        },
    }
}

/// Staging configuration - similar to production but with relaxed security
#[must_use]
pub fn staging_config() -> StaticConfig {
    let mut config = production_config();

    // Allow HTTP for staging
    config
        .oauth
        .allowed_redirect_schemes
        .push("http".to_string());
    config.server.cors_allowed_origins = vec![
        "https://staging-api.company.com".to_string(),
        "https://staging-app.company.com".to_string(),
        "http://localhost:3000".to_string(),
    ];

    // Enable GitHub OAuth for testing
    config.features.enable_oidc_github = true;

    // More permissive rate limits
    config.security.rate_limit_requests_per_minute = 200;

    config
}

/// Testing configuration - optimized for automated tests
#[must_use]
pub fn testing_config() -> StaticConfig {
    StaticConfig {
        server: ServerConfig {
            bind_addr: "127.0.0.1:0".to_string(), // Random port
            cors_allowed_origins: vec!["*".to_string()],
            request_body_limit_mb: 10,
            health_check_timeout_seconds: 5,
        },
        security: StaticSecurityConfig {
            jwt_issuer: "test-auth".to_string(),
            jwt_audience: "test-clients".to_string(),
            token_expiry_seconds: 300, // Short expiry for tests
            allowed_scopes: vec![
                "read".to_string(),
                "write".to_string(),
                "admin".to_string(),
                "test".to_string(),
            ],
            rate_limit_requests_per_minute: 1000, // High for tests
            session_timeout_minutes: 10,
            max_login_attempts: 10, // Permissive for tests
            lockout_duration_minutes: 1,
        },
        clients: StaticClientConfig {
            default_clients: get_test_clients(),
            allow_dynamic_registration: true,
            require_client_authentication: false, // Simplified for tests
        },
        features: StaticFeatureConfig {
            enable_oidc_google: false,
            enable_oidc_microsoft: false,
            enable_oidc_github: false,
            enable_webauthn: false,
            enable_mfa: false,
            enable_scim: true,
            enable_advanced_logging: false,
            enable_metrics: false,
        },
        monitoring: StaticMonitoringConfig {
            prometheus_enabled: false,
            metrics_port: 9091,
            jaeger_enabled: false,
            log_level: "debug".to_string(),
            audit_log_retention_days: 1,
        },
        oauth: StaticOAuthConfig {
            authorization_code_ttl_seconds: 60,
            refresh_token_ttl_seconds: 3600,
            enforce_pkce: false,
            require_state_parameter: false,
            allowed_redirect_schemes: vec!["http".to_string(), "https".to_string()],
        },
    }
}

/// Development configuration - developer-friendly settings
#[must_use]
pub fn development_config() -> StaticConfig {
    StaticConfig {
        server: ServerConfig {
            bind_addr: "127.0.0.1:8080".to_string(),
            cors_allowed_origins: vec![
                "http://localhost:3000".to_string(),
                "http://localhost:3001".to_string(),
                "http://127.0.0.1:3000".to_string(),
            ],
            request_body_limit_mb: 10,
            health_check_timeout_seconds: 30,
        },
        security: StaticSecurityConfig {
            jwt_issuer: "dev-auth-service".to_string(),
            jwt_audience: "dev-api-clients".to_string(),
            token_expiry_seconds: 7200, // 2 hours for dev convenience
            allowed_scopes: vec![
                "read".to_string(),
                "write".to_string(),
                "admin".to_string(),
                "dev".to_string(),
                "user:profile".to_string(),
                "user:email".to_string(),
            ],
            rate_limit_requests_per_minute: 300, // Permissive for development
            session_timeout_minutes: 120,
            max_login_attempts: 10,
            lockout_duration_minutes: 1,
        },
        clients: StaticClientConfig {
            default_clients: get_development_clients(),
            allow_dynamic_registration: true,
            require_client_authentication: true,
        },
        features: StaticFeatureConfig {
            enable_oidc_google: true,
            enable_oidc_microsoft: true,
            enable_oidc_github: true,
            enable_webauthn: true,
            enable_mfa: true,
            enable_scim: true,
            enable_advanced_logging: true,
            enable_metrics: true,
        },
        monitoring: StaticMonitoringConfig {
            prometheus_enabled: true,
            metrics_port: 9090,
            jaeger_enabled: false, // Usually off in dev
            log_level: "debug".to_string(),
            audit_log_retention_days: 7,
        },
        oauth: StaticOAuthConfig {
            authorization_code_ttl_seconds: 600,
            refresh_token_ttl_seconds: 86400 * 30, // 30 days for dev convenience
            enforce_pkce: true,
            require_state_parameter: true,
            allowed_redirect_schemes: vec!["http".to_string(), "https".to_string()],
        },
    }
}

/// Production client configurations with secure defaults
fn get_production_clients() -> HashMap<String, ClientInfo> {
    let mut clients = HashMap::new();

    // API Gateway client
    clients.insert(
        "api-gateway".to_string(),
        ClientInfo {
            name: "API Gateway".to_string(),
            secret_hash: "$2b$12$placeholder_for_production_hash".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
            redirect_uris: vec!["https://api.company.com/oauth/callback".to_string()],
            grant_types: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
            ],
        },
    );

    // Web Application client
    clients.insert(
        "web-app".to_string(),
        ClientInfo {
            name: "Web Application".to_string(),
            secret_hash: "$2b$12$placeholder_for_production_hash".to_string(),
            scopes: vec![
                "read".to_string(),
                "user:profile".to_string(),
                "user:email".to_string(),
            ],
            redirect_uris: vec!["https://app.company.com/auth/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
        },
    );

    // Admin Dashboard client
    clients.insert(
        "admin-dashboard".to_string(),
        ClientInfo {
            name: "Admin Dashboard".to_string(),
            secret_hash: "$2b$12$placeholder_for_production_hash".to_string(),
            scopes: vec!["read".to_string(), "write".to_string(), "admin".to_string()],
            redirect_uris: vec!["https://admin.company.com/auth/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
        },
    );

    clients
}

/// Development client configurations for local testing
fn get_development_clients() -> HashMap<String, ClientInfo> {
    let mut clients = HashMap::new();

    // Development test client
    clients.insert(
        "dev-client".to_string(),
        ClientInfo {
            name: "Development Client".to_string(),
            secret_hash: "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW".to_string(), // "dev-secret"
            scopes: vec![
                "read".to_string(),
                "write".to_string(),
                "admin".to_string(),
                "dev".to_string(),
            ],
            redirect_uris: vec![
                "http://localhost:3000/auth/callback".to_string(),
                "http://localhost:3001/auth/callback".to_string(),
            ],
            grant_types: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
            ],
        },
    );

    // Postman/API testing client
    clients.insert(
        "api-test".to_string(),
        ClientInfo {
            name: "API Testing Client".to_string(),
            secret_hash: "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW".to_string(), // "test-secret"
            scopes: vec!["read".to_string(), "write".to_string()],
            redirect_uris: vec!["http://localhost:8080/oauth/callback".to_string()],
            grant_types: vec!["client_credentials".to_string()],
        },
    );

    clients
}

/// Test client configurations for automated testing
fn get_test_clients() -> HashMap<String, ClientInfo> {
    let mut clients = HashMap::new();

    clients.insert(
        "test-client".to_string(),
        ClientInfo {
            name: "Test Client".to_string(),
            secret_hash: "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW".to_string(), // "test"
            scopes: vec![
                "read".to_string(),
                "write".to_string(),
                "admin".to_string(),
                "test".to_string(),
            ],
            redirect_uris: vec!["http://localhost/callback".to_string()],
            grant_types: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
            ],
        },
    );

    clients
}

/// Runtime secrets that must still be provided via environment (for security)
#[derive(Debug)]
pub struct RuntimeSecrets {
    pub jwt_signing_key: String,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    pub oidc_google_client_secret: Option<String>,
    pub oidc_microsoft_client_secret: Option<String>,
    pub oidc_github_client_secret: Option<String>,
    pub webhook_signing_secret: Option<String>,
}

impl RuntimeSecrets {
    /// Load runtime secrets from environment variables
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - JWT_SIGNING_KEY is missing in production environment
    /// - JWT key validation fails in production
    /// - Required environment variables are malformed
    pub fn from_env() -> Result<Self> {
        let env = Environment::from_env();

        // JWT signing key is always required
        let jwt_signing_key = if let Ok(key) = env::var("JWT_SIGNING_KEY") {
            if env.is_production() {
                validate_jwt_key_strength(&key)?;
            }
            key
        } else {
            if env.is_production() {
                return Err(anyhow::anyhow!("JWT_SIGNING_KEY is required in production"));
            }
            warn!("JWT_SIGNING_KEY not set, generating random key for development");
            generate_development_jwt_key()
        };

        Ok(Self {
            jwt_signing_key,
            database_url: env::var("DATABASE_URL").ok(),
            redis_url: env::var("REDIS_URL").ok(),
            oidc_google_client_secret: env::var("OIDC_GOOGLE_CLIENT_SECRET").ok(),
            oidc_microsoft_client_secret: env::var("OIDC_MICROSOFT_CLIENT_SECRET").ok(),
            oidc_github_client_secret: env::var("OIDC_GITHUB_CLIENT_SECRET").ok(),
            webhook_signing_secret: env::var("WEBHOOK_SIGNING_SECRET").ok(),
        })
    }
}

/// Validate JWT key strength for production
///
/// # Errors
///
/// Returns an error if:
/// - Key is shorter than 32 characters
/// - Key contains weak patterns like 'test', 'dev', etc.
fn validate_jwt_key_strength(key: &str) -> Result<()> {
    if key.len() < 32 {
        return Err(anyhow::anyhow!(
            "JWT signing key must be at least 32 characters"
        ));
    }

    // Check for obvious weak patterns
    let weak_patterns = ["test", "dev", "demo", "example", "changeme"];
    let key_lower = key.to_lowercase();
    for pattern in &weak_patterns {
        if key_lower.contains(pattern) {
            return Err(anyhow::anyhow!(
                "JWT signing key contains weak pattern: {}",
                pattern
            ));
        }
    }

    Ok(())
}

/// Generate a secure JWT key for development
fn generate_development_jwt_key() -> String {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut key_bytes = vec![0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key_bytes)
}

/// Configuration manager that combines static and runtime configuration
#[derive(Debug)]
pub struct ConfigManager {
    pub static_config: &'static StaticConfig,
    pub runtime_secrets: RuntimeSecrets,
    pub environment: Environment,
}

impl ConfigManager {
    /// Create a new configuration manager
    ///
    /// # Errors
    ///
    /// Returns an error if runtime secrets loading fails
    pub fn new() -> Result<Self> {
        let environment = Environment::from_env();
        let runtime_secrets = RuntimeSecrets::from_env()?;

        info!("Loaded configuration for environment: {:?}", environment);
        info!("Static configuration loaded successfully");

        Ok(Self {
            static_config: &CONFIG,
            runtime_secrets,
            environment,
        })
    }

    /// Get client info by client ID
    #[must_use]
    pub fn get_client_info(&self, client_id: &str) -> Option<&ClientInfo> {
        self.static_config.clients.default_clients.get(client_id)
    }

    /// Check if a feature is enabled
    #[must_use]
    pub fn is_feature_enabled(&self, feature: &str) -> bool {
        match feature {
            "oidc_google" => self.static_config.features.enable_oidc_google,
            "oidc_microsoft" => self.static_config.features.enable_oidc_microsoft,
            "oidc_github" => self.static_config.features.enable_oidc_github,
            "webauthn" => self.static_config.features.enable_webauthn,
            "mfa" => self.static_config.features.enable_mfa,
            "scim" => self.static_config.features.enable_scim,
            "advanced_logging" => self.static_config.features.enable_advanced_logging,
            "metrics" => self.static_config.features.enable_metrics,
            _ => false,
        }
    }

    /// Validate client credentials
    #[must_use]
    pub fn validate_client_credentials(&self, client_id: &str, client_secret: &str) -> bool {
        if let Some(client_info) = self.get_client_info(client_id) {
            bcrypt::verify(client_secret, &client_info.secret_hash).unwrap_or(false)
        } else {
            false
        }
    }

    /// Get JWT signing key
    #[must_use]
    pub fn jwt_signing_key(&self) -> &str {
        &self.runtime_secrets.jwt_signing_key
    }

    /// Get database URL if configured
    #[must_use]
    pub fn database_url(&self) -> Option<&str> {
        self.runtime_secrets.database_url.as_deref()
    }

    /// Get Redis URL if configured
    #[must_use]
    pub fn redis_url(&self) -> Option<&str> {
        self.runtime_secrets.redis_url.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_detection() {
        std::env::set_var("ENVIRONMENT", "production");
        assert_eq!(Environment::from_env(), Environment::Production);

        std::env::set_var("ENVIRONMENT", "development");
        assert_eq!(Environment::from_env(), Environment::Development);
    }

    #[test]
    fn test_config_loading() {
        let config = development_config();
        assert!(!config.server.bind_addr.is_empty());
        assert!(!config.security.allowed_scopes.is_empty());
        assert!(!config.clients.default_clients.is_empty());
    }

    #[test]
    fn test_client_validation() {
        let config = development_config();
        let clients = &config.clients.default_clients;

        for (client_id, client_info) in clients {
            assert!(!client_id.is_empty());
            assert!(!client_info.name.is_empty());
            assert!(!client_info.secret_hash.is_empty());
            assert!(!client_info.scopes.is_empty());
        }
    }
}
