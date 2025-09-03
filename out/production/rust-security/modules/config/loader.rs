//! Configuration Loader
//!
//! Loads configuration from TOML files and environment variables with validation.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use config::{Config, ConfigError, File, FileFormat};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::shared::error::AppError;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub security: SecurityConfig,
    pub jwt: JwtConfig,
    pub oauth: OAuthConfig,
    pub rate_limiting: RateLimitingConfig,
    pub session: SessionConfig,
    pub monitoring: MonitoringConfig,
    pub features: FeaturesConfig,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub bind_addr: String,
    pub max_connections: u32,
    pub request_timeout: String,
    pub shutdown_timeout: String,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: Option<u32>,
    pub min_connections: Option<u32>,
    pub connect_timeout: Option<String>,
    pub acquire_timeout: Option<String>,
    pub idle_timeout: Option<String>,
    pub max_lifetime: Option<String>,
    pub test_before_acquire: Option<bool>,
}

/// Redis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
    pub connection_timeout: String,
    pub command_timeout: String,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub bcrypt_cost: Option<u32>,
    pub password_min_length: Option<usize>,
    pub password_require_uppercase: Option<bool>,
    pub password_require_lowercase: Option<bool>,
    pub password_require_digit: Option<bool>,
    pub password_require_special: Option<bool>,
    pub max_login_attempts: Option<u32>,
    pub lockout_duration: Option<String>,
    pub secure_cookies: Option<bool>,
    pub csrf_protection: Option<bool>,

    #[serde(flatten)]
    pub argon2_params: Option<Argon2Params>,

    #[serde(flatten)]
    pub cors: Option<CorsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub salt_length: usize,
    pub hash_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub exposed_headers: Vec<String>,
    pub max_age: u32,
    pub allow_credentials: bool,
}

/// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub secret: Option<String>,
    pub issuer: Option<String>,
    pub audience: Option<Vec<String>>,
    pub access_token_ttl: String,
    pub refresh_token_ttl: String,
    pub algorithm: String,
    pub key_rotation_interval: Option<String>,
    pub leeway: Option<String>,
}

/// OAuth configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub providers: Option<HashMap<String, OAuthProvider>>,
    pub redirect_base_url: Option<String>,
    pub state_ttl: Option<String>,
    pub pkce_required: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProvider {
    pub client_id: String,
    pub client_secret: String,
    pub authorization_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub scopes: Vec<String>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    pub global_limit: u32,
    pub global_window: String,
    pub per_ip_limit: u32,
    pub per_ip_window: String,
    pub per_user_limit: u32,
    pub per_user_window: String,
    pub burst_size: u32,
    pub cleanup_interval: String,
    pub whitelist: Vec<String>,
}

/// Session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub ttl: String,
    pub cookie_name: String,
    pub cookie_secure: bool,
    pub cookie_http_only: bool,
    pub cookie_same_site: String,
    pub cleanup_interval: String,
    pub max_sessions_per_user: u32,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Features configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturesConfig {
    pub mfa_enabled: bool,
    pub webauthn_enabled: bool,
    pub api_keys_enabled: bool,
    pub oauth_enabled: bool,
    pub scim_enabled: bool,
    pub audit_logging_enabled: bool,
    pub enhanced_security: bool,
    pub post_quantum_crypto: bool,
}

/// Configuration loader with hot-reload capability
#[derive(Clone)]
pub struct ConfigLoader {
    config: Arc<RwLock<ServiceConfig>>,
    config_path: String,
}

impl ConfigLoader {
    /// Create a new configuration loader
    pub fn new(config_path: impl Into<String>) -> Self {
        Self {
            config: Arc::new(RwLock::new(ServiceConfig::default())),
            config_path: config_path.into(),
        }
    }

    /// Load configuration from file and environment
    pub async fn load(&self) -> Result<(), AppError> {
        let mut builder = Config::builder()
            .add_source(File::with_name(&self.config_path).format(FileFormat::Toml))
            .add_source(config::Environment::with_prefix("AUTH").separator("_"));

        // Add environment-specific configuration
        let env = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
        let env_config_path = format!("config/{}.toml", env);
        if Path::new(&env_config_path).exists() {
            builder = builder.add_source(File::with_name(&env_config_path).format(FileFormat::Toml).required(false));
        }

        let config = builder.build().map_err(|e| AppError::Config(e.to_string()))?;
        let service_config: ServiceConfig = config.try_deserialize().map_err(|e| AppError::Config(e.to_string()))?;

        // Validate configuration
        self.validate_config(&service_config)?;

        // Store configuration
        *self.config.write().await = service_config;

        info!("Configuration loaded successfully from {}", self.config_path);
        Ok(())
    }

    /// Get current configuration
    pub async fn get_config(&self) -> ServiceConfig {
        self.config.read().await.clone()
    }

    /// Reload configuration (for hot-reload)
    pub async fn reload(&self) -> Result<(), AppError> {
        self.load().await
    }

    /// Validate configuration
    fn validate_config(&self, config: &ServiceConfig) -> Result<(), AppError> {
        // Validate server configuration
        if config.server.port == 0 {
            return Err(AppError::Config("Server port cannot be 0".to_string()));
        }

        // Validate database URL
        if config.database.url.is_empty() {
            return Err(AppError::Config("Database URL cannot be empty".to_string()));
        }

        // Validate Redis URL
        if !config.redis.url.starts_with("redis://") && !config.redis.url.starts_with("rediss://") {
            return Err(AppError::Config("Redis URL must start with redis:// or rediss://".to_string()));
        }

        // Validate JWT configuration
        if let Some(ref secret) = config.jwt.secret {
            if secret.len() < 32 {
                return Err(AppError::Config("JWT secret must be at least 32 characters".to_string()));
            }
        }

        // Validate security configuration
        if let Some(min_length) = config.security.password_min_length {
            if min_length < 8 {
                return Err(AppError::Config("Minimum password length must be at least 8".to_string()));
            }
        }

        Ok(())
    }

    /// Get specific configuration section
    pub async fn get_server_config(&self) -> ServerConfig {
        self.config.read().await.server.clone()
    }

    pub async fn get_database_config(&self) -> DatabaseConfig {
        self.config.read().await.database.clone()
    }

    pub async fn get_redis_config(&self) -> RedisConfig {
        self.config.read().await.redis.clone()
    }

    pub async fn get_security_config(&self) -> SecurityConfig {
        self.config.read().await.security.clone()
    }

    pub async fn get_jwt_config(&self) -> JwtConfig {
        self.config.read().await.jwt.clone()
    }

    pub async fn get_oauth_config(&self) -> OAuthConfig {
        self.config.read().await.oauth.clone()
    }

    pub async fn get_rate_limiting_config(&self) -> RateLimitingConfig {
        self.config.read().await.rate_limiting.clone()
    }

    pub async fn get_session_config(&self) -> SessionConfig {
        self.config.read().await.session.clone()
    }

    pub async fn get_monitoring_config(&self) -> MonitoringConfig {
        self.config.read().await.monitoring.clone()
    }

    pub async fn get_features_config(&self) -> FeaturesConfig {
        self.config.read().await.features.clone()
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                bind_addr: "127.0.0.1:8080".to_string(),
                max_connections: 1000,
                request_timeout: "30s".to_string(),
                shutdown_timeout: "30s".to_string(),
            },
            database: DatabaseConfig {
                url: "sqlite::memory:".to_string(),
                max_connections: Some(32),
                min_connections: Some(5),
                connect_timeout: Some("30s".to_string()),
                acquire_timeout: Some("30s".to_string()),
                idle_timeout: Some("600s".to_string()),
                max_lifetime: Some("1800s".to_string()),
                test_before_acquire: Some(true),
            },
            redis: RedisConfig {
                url: "redis://localhost:6379".to_string(),
                pool_size: 10,
                connection_timeout: "5s".to_string(),
                command_timeout: "1s".to_string(),
            },
            security: SecurityConfig {
                bcrypt_cost: Some(12),
                password_min_length: Some(12),
                password_require_uppercase: Some(true),
                password_require_lowercase: Some(true),
                password_require_digit: Some(true),
                password_require_special: Some(true),
                max_login_attempts: Some(5),
                lockout_duration: Some("15m".to_string()),
                secure_cookies: Some(false),
                csrf_protection: Some(true),
                argon2_params: Some(Argon2Params {
                    memory_cost: 4096,
                    time_cost: 3,
                    parallelism: 1,
                    salt_length: 32,
                    hash_length: 32,
                }),
                cors: Some(CorsConfig {
                    allowed_origins: vec!["http://localhost:3000".to_string()],
                    allowed_methods: vec!["GET".to_string(), "POST".to_string(), "PUT".to_string(), "DELETE".to_string()],
                    allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
                    exposed_headers: vec![],
                    max_age: 86400,
                    allow_credentials: true,
                }),
            },
            jwt: JwtConfig {
                secret: Some("development-jwt-secret-key-minimum-32-characters-long-for-security".to_string()),
                issuer: Some("http://localhost:8080".to_string()),
                audience: Some(vec!["api".to_string(), "web-client".to_string()]),
                access_token_ttl: "1h".to_string(),
                refresh_token_ttl: "7d".to_string(),
                algorithm: "HS256".to_string(),
                key_rotation_interval: Some("30d".to_string()),
                leeway: Some("60s".to_string()),
            },
            oauth: OAuthConfig {
                providers: None,
                redirect_base_url: Some("http://localhost:8080/auth/callback".to_string()),
                state_ttl: Some("10m".to_string()),
                pkce_required: Some(true),
            },
            rate_limiting: RateLimitingConfig {
                global_limit: 10000,
                global_window: "60s".to_string(),
                per_ip_limit: 100,
                per_ip_window: "60s".to_string(),
                per_user_limit: 1000,
                per_user_window: "60s".to_string(),
                burst_size: 10,
                cleanup_interval: "5m".to_string(),
                whitelist: vec![],
            },
            session: SessionConfig {
                ttl: "1h".to_string(),
                cookie_name: "auth_session".to_string(),
                cookie_secure: false,
                cookie_http_only: true,
                cookie_same_site: "Lax".to_string(),
                cleanup_interval: "1h".to_string(),
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
            features: FeaturesConfig {
                mfa_enabled: true,
                webauthn_enabled: false,
                api_keys_enabled: true,
                oauth_enabled: true,
                scim_enabled: false,
                audit_logging_enabled: true,
                enhanced_security: true,
                post_quantum_crypto: false,
            },
        }
    }
}
