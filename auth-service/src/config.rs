use anyhow::{Context, Result};
use common::{constants, UnifiedRedisConfig};
use crate::config::{Config as ConfigBuilder, Environment, File};
use serde::{Deserialize, Serialize};
use std::env;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: UnifiedRedisConfig,
    pub security: SecurityConfig,
    pub jwt: JwtConfig,
    pub oauth: OAuthConfig,
    pub rate_limiting: RateLimitConfig,
    pub session: SessionConfig,
    pub monitoring: MonitoringConfig,
    pub features: FeatureFlags,
    #[cfg(feature = "soar")]
    pub soar: Option<SoarConfig>,
    #[cfg(feature = "threat-hunting")]
    pub threat_hunting: Option<ThreatHuntingConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub bind_addr: SocketAddr,
    pub workers: Option<usize>,
    pub max_connections: usize,
    pub request_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_cert_path: Option<String>,
    pub client_auth_required: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: Duration,
    pub acquire_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
    pub test_before_acquire: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub bcrypt_cost: u32,
    pub argon2_params: Argon2Config,
    pub password_min_length: usize,
    pub password_require_uppercase: bool,
    pub password_require_lowercase: bool,
    pub password_require_digit: bool,
    pub password_require_special: bool,
    pub max_login_attempts: u32,
    pub lockout_duration: Duration,
    pub secure_cookies: bool,
    pub csrf_protection: bool,
    pub cors: CorsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Argon2Config {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub salt_length: usize,
    pub hash_length: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub exposed_headers: Vec<String>,
    pub max_age: u64,
    pub allow_credentials: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtConfig {
    pub secret: String,
    pub issuer: String,
    pub audience: Vec<String>,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    pub algorithm: String,
    pub key_rotation_interval: Duration,
    pub leeway: Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OAuthConfig {
    pub providers: Vec<OAuthProvider>,
    pub redirect_base_url: String,
    pub state_ttl: Duration,
    pub pkce_required: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OAuthProvider {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub scopes: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    pub global_limit: u32,
    pub global_window: Duration,
    pub per_ip_limit: u32,
    pub per_ip_window: Duration,
    pub per_user_limit: u32,
    pub per_user_window: Duration,
    pub burst_size: u32,
    pub cleanup_interval: Duration,
    pub whitelist: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionConfig {
    pub ttl: Duration,
    pub cookie_name: String,
    pub cookie_secure: bool,
    pub cookie_http_only: bool,
    pub cookie_same_site: String,
    pub cleanup_interval: Duration,
    pub max_sessions_per_user: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MonitoringConfig {
    pub metrics_enabled: bool,
    pub metrics_path: String,
    pub health_check_path: String,
    pub tracing_enabled: bool,
    pub tracing_level: String,
    pub jaeger_endpoint: Option<String>,
    pub prometheus_enabled: bool,
    pub log_format: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct FeatureFlags {
    pub mfa_enabled: bool,
    pub webauthn_enabled: bool,
    pub api_keys_enabled: bool,
    pub oauth_enabled: bool,
    pub scim_enabled: bool,
    pub audit_logging_enabled: bool,
    pub enhanced_security: bool,
    pub post_quantum_crypto: bool,
}

#[cfg(feature = "soar")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SoarConfig {
    pub enabled: bool,
    pub database_url: String,
    pub workflow_engine: String,
    pub max_concurrent_cases: u32,
    pub auto_escalation_enabled: bool,
    pub integration_timeout: Duration,
}

#[cfg(feature = "threat-hunting")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ThreatHuntingConfig {
    pub enabled: bool,
    pub ml_model_path: String,
    pub anomaly_threshold: f64,
    pub correlation_window: Duration,
    pub max_events_per_analysis: u32,
    pub behavioral_analysis_enabled: bool,
}

impl Config {
    pub fn load() -> Result<Self> {
        let environment = env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
        let config_dir = env::var("CONFIG_DIR").unwrap_or_else(|_| "config".to_string());

        let mut builder = ConfigBuilder::builder();

        // Load base configuration
        let base_config = Path::new(&config_dir).join("base.toml");
        if base_config.exists() {
            builder = builder.add_source(File::from(base_config));
        }

        // Load environment-specific configuration
        let env_config = Path::new(&config_dir).join(format!("{}.toml", environment));
        if env_config.exists() {
            builder = builder.add_source(File::from(env_config));
        }

        // Load local configuration (not committed to git)
        let local_config = Path::new(&config_dir).join("local.toml");
        if local_config.exists() {
            builder = builder.add_source(File::from(local_config));
        }

        // Override with environment variables
        builder = builder.add_source(
            Environment::with_prefix("AUTH")
                .separator("__")
                .try_parsing(true),
        );

        let config = builder
            .build()
            .context("Failed to build configuration")?
            .try_deserialize()
            .context("Failed to deserialize configuration")?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        // Validate server configuration
        if self.server.port == 0 {
            anyhow::bail!("Server port must be greater than 0");
        }

        // Validate security configuration
        if self.security.bcrypt_cost < 10 {
            anyhow::bail!("BCrypt cost must be at least 10 for security");
        }

        if self.security.password_min_length < 8 {
            anyhow::bail!("Password minimum length must be at least 8");
        }

        // Validate JWT configuration
        if self.jwt.secret.len() < 32 {
            anyhow::bail!("JWT secret must be at least 32 characters");
        }

        // Validate database configuration
        if self.database.max_connections < self.database.min_connections {
            anyhow::bail!("Database max_connections must be >= min_connections");
        }

        // Validate rate limiting
        if self.rate_limiting.global_limit == 0 {
            anyhow::bail!("Rate limit must be greater than 0");
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                bind_addr: "127.0.0.1:8080"
                    .parse()
                    .expect("Failed to parse default bind address"),
                workers: None,
                max_connections: 10000,
                request_timeout: Duration::from_secs(30),
                shutdown_timeout: Duration::from_secs(30),
                tls: None,
            },
            database: DatabaseConfig {
                url: "postgres://localhost/auth_service".to_string(),
                max_connections: 32,
                min_connections: 5,
                connect_timeout: Duration::from_secs(30),
                acquire_timeout: Duration::from_secs(30),
                idle_timeout: Duration::from_secs(600),
                max_lifetime: Duration::from_secs(1800),
                test_before_acquire: true,
            },
            redis: UnifiedRedisConfig::for_sessions("redis://localhost:6379"),
            security: SecurityConfig {
                bcrypt_cost: 12,
                argon2_params: Argon2Config {
                    memory_cost: constants::crypto::ARGON2_MEMORY_COST,
                    time_cost: constants::crypto::ARGON2_TIME_COST,
                    parallelism: constants::crypto::ARGON2_PARALLELISM,
                    salt_length: constants::crypto::DEFAULT_SALT_LENGTH,
                    hash_length: 32,
                },
                password_min_length: constants::security::MIN_PASSWORD_LENGTH,
                password_require_uppercase: true,
                password_require_lowercase: true,
                password_require_digit: true,
                password_require_special: true,
                max_login_attempts: constants::security::MAX_LOGIN_ATTEMPTS,
                lockout_duration: Duration::from_secs(
                    constants::security::ACCOUNT_LOCKOUT_DURATION,
                ),
                secure_cookies: true,
                csrf_protection: true,
                cors: CorsConfig {
                    allowed_origins: vec!["http://localhost:3000".to_string()],
                    allowed_methods: vec!["GET".to_string(), "POST".to_string()],
                    allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
                    exposed_headers: vec![],
                    max_age: 86400,
                    allow_credentials: true,
                },
            },
            jwt: JwtConfig {
                secret: "change-me-in-production".to_string(),
                issuer: "auth-service".to_string(),
                audience: vec!["api".to_string()],
                access_token_ttl: Duration::from_secs(constants::security::JWT_TOKEN_EXPIRY as u64),
                refresh_token_ttl: Duration::from_secs(
                    constants::security::REFRESH_TOKEN_EXPIRY as u64,
                ),
                algorithm: "HS256".to_string(),
                key_rotation_interval: Duration::from_secs(86400 * 30),
                leeway: Duration::from_secs(60),
            },
            oauth: OAuthConfig {
                providers: vec![],
                redirect_base_url: "http://localhost:8080/auth/callback".to_string(),
                state_ttl: Duration::from_secs(600),
                pkce_required: true,
            },
            rate_limiting: RateLimitConfig {
                global_limit: 10000,
                global_window: Duration::from_secs(60),
                per_ip_limit: 100,
                per_ip_window: Duration::from_secs(60),
                per_user_limit: 1000,
                per_user_window: Duration::from_secs(60),
                burst_size: 10,
                cleanup_interval: Duration::from_secs(300),
                whitelist: vec![],
            },
            session: SessionConfig {
                ttl: Duration::from_secs(3600),
                cookie_name: "auth_session".to_string(),
                cookie_secure: true,
                cookie_http_only: true,
                cookie_same_site: "Strict".to_string(),
                cleanup_interval: Duration::from_secs(3600),
                max_sessions_per_user: 5,
            },
            monitoring: MonitoringConfig {
                metrics_enabled: true,
                metrics_path: "/metrics".to_string(),
                health_check_path: "/health".to_string(),
                tracing_enabled: true,
                tracing_level: "info".to_string(),
                jaeger_endpoint: None,
                prometheus_enabled: true,
                log_format: "json".to_string(),
            },
            features: FeatureFlags {
                mfa_enabled: true,
                webauthn_enabled: false,
                api_keys_enabled: true,
                oauth_enabled: true,
                scim_enabled: false,
                audit_logging_enabled: true,
                enhanced_security: true,
                post_quantum_crypto: false,
            },
            #[cfg(feature = "soar")]
            soar: None,
            #[cfg(feature = "threat-hunting")]
            threat_hunting: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.security.bcrypt_cost, 12);
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());

        config.server.port = 0;
        assert!(config.validate().is_err());

        config.server.port = 8080;
        config.security.bcrypt_cost = 5;
        assert!(config.validate().is_err());
    }
}
