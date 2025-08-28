use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::Path;
use tracing::{info, warn};

/// Production configuration management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionConfig {
    /// Server configuration
    pub server: ServerConfig,
    /// Database configuration
    pub database: DatabaseConfig,
    /// Redis configuration
    pub redis: RedisConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Observability configuration
    pub observability: ObservabilityConfig,
    /// Feature flags
    pub features: FeatureFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Number of worker threads
    pub workers: Option<usize>,
    /// Request timeout in seconds
    pub request_timeout: u64,
    /// Keep-alive timeout in seconds
    pub keep_alive: u64,
    /// Maximum request size in bytes
    pub max_request_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL
    pub url: String,
    /// Maximum connections in pool
    pub max_connections: u32,
    /// Minimum connections in pool
    pub min_connections: u32,
    /// Connection timeout in seconds
    pub connect_timeout: u64,
    /// Query timeout in seconds
    pub query_timeout: u64,
    /// Enable SSL
    pub ssl_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Redis URL
    pub url: String,
    /// Maximum connections in pool
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connect_timeout: u64,
    /// Command timeout in seconds
    pub command_timeout: u64,
    /// Enable cluster mode
    pub cluster_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// JWT signing secret
    pub jwt_secret: String,
    /// JWT expiration time in seconds
    pub jwt_expiration: u64,
    /// Refresh token expiration in seconds
    pub refresh_token_expiration: u64,
    /// Request signing secret
    pub request_signing_secret: String,
    /// Token binding salt
    pub token_binding_salt: String,
    /// Encryption key for sensitive data
    pub encryption_key: String,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    /// Requests per minute per IP
    pub requests_per_minute: u32,
    /// Burst allowance
    pub burst_size: u32,
    /// Ban threshold
    pub ban_threshold: u32,
    /// Ban duration in seconds
    pub ban_duration: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Log level
    pub log_level: String,
    /// Enable metrics
    pub metrics_enabled: bool,
    /// Metrics endpoint
    pub metrics_endpoint: String,
    /// Enable tracing
    pub tracing_enabled: bool,
    /// Tracing endpoint
    pub tracing_endpoint: Option<String>,
    /// Health check endpoint
    pub health_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlags {
    /// Enable multi-factor authentication
    pub mfa_enabled: bool,
    /// Enable SAML authentication
    pub saml_enabled: bool,
    /// Enable OIDC authentication
    pub oidc_enabled: bool,
    /// Enable advanced security features
    pub advanced_security: bool,
    /// Enable AI threat detection
    pub ai_threat_detection: bool,
    /// Enable quantum-safe cryptography
    pub quantum_safe: bool,
}

impl Default for ProductionConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            redis: RedisConfig::default(),
            security: SecurityConfig::default(),
            observability: ObservabilityConfig::default(),
            features: FeatureFlags::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            workers: None, // Use system default
            request_timeout: 30,
            keep_alive: 60,
            max_request_size: 1024 * 1024, // 1MB
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgresql://localhost/auth".to_string(),
            max_connections: 10,
            min_connections: 1,
            connect_timeout: 30,
            query_timeout: 30,
            ssl_mode: "prefer".to_string(),
        }
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            max_connections: 10,
            connect_timeout: 5,
            command_timeout: 5,
            cluster_mode: false,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "change-me-in-production".to_string(),
            jwt_expiration: 3600,                // 1 hour
            refresh_token_expiration: 86400 * 7, // 7 days
            request_signing_secret: "change-me-in-production".to_string(),
            token_binding_salt: "change-me-in-production".to_string(),
            encryption_key: "change-me-in-production".to_string(),
            rate_limiting: RateLimitingConfig::default(),
        }
    }
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            burst_size: 10,
            ban_threshold: 5,
            ban_duration: 300, // 5 minutes
        }
    }
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            metrics_enabled: true,
            metrics_endpoint: "/metrics".to_string(),
            tracing_enabled: true,
            tracing_endpoint: None,
            health_endpoint: "/health".to_string(),
        }
    }
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            mfa_enabled: true,
            saml_enabled: false,
            oidc_enabled: true,
            advanced_security: true,
            ai_threat_detection: false,
            quantum_safe: false,
        }
    }
}

/// Configuration loader with environment variable support
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load configuration from environment variables and files
    pub fn load() -> Result<ProductionConfig> {
        let mut config = ProductionConfig::default();

        // Load from environment variables
        Self::load_from_env(&mut config)?;

        // Load from configuration file if specified
        if let Ok(config_file) = env::var("CONFIG_FILE") {
            Self::load_from_file(&mut config, &config_file)?;
        }

        // Validate configuration
        Self::validate_config(&config)?;

        info!("Configuration loaded successfully");
        Ok(config)
    }

    /// Load configuration from environment variables
    fn load_from_env(config: &mut ProductionConfig) -> Result<()> {
        // Server configuration
        if let Ok(host) = env::var("SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = env::var("SERVER_PORT") {
            config.server.port = port.parse().context("Invalid SERVER_PORT")?;
        }
        if let Ok(workers) = env::var("SERVER_WORKERS") {
            config.server.workers = Some(workers.parse().context("Invalid SERVER_WORKERS")?);
        }

        // Database configuration
        if let Ok(url) = env::var("DATABASE_URL") {
            config.database.url = url;
        }
        if let Ok(max_conn) = env::var("DATABASE_MAX_CONNECTIONS") {
            config.database.max_connections = max_conn
                .parse()
                .context("Invalid DATABASE_MAX_CONNECTIONS")?;
        }

        // Redis configuration
        if let Ok(url) = env::var("REDIS_URL") {
            config.redis.url = url;
        }
        if let Ok(max_conn) = env::var("REDIS_MAX_CONNECTIONS") {
            config.redis.max_connections =
                max_conn.parse().context("Invalid REDIS_MAX_CONNECTIONS")?;
        }

        // Security configuration
        if let Ok(secret) = env::var("JWT_SECRET") {
            config.security.jwt_secret = secret;
        }
        if let Ok(secret) = env::var("REQUEST_SIGNING_SECRET") {
            config.security.request_signing_secret = secret;
        }
        if let Ok(salt) = env::var("TOKEN_BINDING_SALT") {
            config.security.token_binding_salt = salt;
        }
        if let Ok(key) = env::var("ENCRYPTION_KEY") {
            config.security.encryption_key = key;
        }

        // Observability configuration
        if let Ok(level) = env::var("LOG_LEVEL") {
            config.observability.log_level = level;
        }
        if let Ok(endpoint) = env::var("TRACING_ENDPOINT") {
            config.observability.tracing_endpoint = Some(endpoint);
        }

        // Feature flags
        if let Ok(enabled) = env::var("MFA_ENABLED") {
            config.features.mfa_enabled = enabled.parse().unwrap_or(false);
        }
        if let Ok(enabled) = env::var("SAML_ENABLED") {
            config.features.saml_enabled = enabled.parse().unwrap_or(false);
        }
        if let Ok(enabled) = env::var("OIDC_ENABLED") {
            config.features.oidc_enabled = enabled.parse().unwrap_or(true);
        }
        if let Ok(enabled) = env::var("ADVANCED_SECURITY") {
            config.features.advanced_security = enabled.parse().unwrap_or(true);
        }
        if let Ok(enabled) = env::var("AI_THREAT_DETECTION") {
            config.features.ai_threat_detection = enabled.parse().unwrap_or(false);
        }
        if let Ok(enabled) = env::var("QUANTUM_SAFE") {
            config.features.quantum_safe = enabled.parse().unwrap_or(false);
        }

        Ok(())
    }

    /// Load configuration from file
    fn load_from_file(config: &mut ProductionConfig, file_path: &str) -> Result<()> {
        if !Path::new(file_path).exists() {
            warn!("Configuration file {} not found, using defaults", file_path);
            return Ok(());
        }

        let content = std::fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read config file: {}", file_path))?;

        let file_config: ProductionConfig =
            if file_path.ends_with(".yaml") || file_path.ends_with(".yml") {
                serde_yaml::from_str(&content)
                    .with_context(|| format!("Failed to parse YAML config: {}", file_path))?
            } else if file_path.ends_with(".json") {
                serde_json::from_str(&content)
                    .with_context(|| format!("Failed to parse JSON config: {}", file_path))?
            } else {
                return Err(anyhow::anyhow!(
                    "Unsupported config file format: {}",
                    file_path
                ));
            };

        // Merge file config with current config (environment variables take precedence)
        Self::merge_configs(config, file_config);

        info!("Configuration loaded from file: {}", file_path);
        Ok(())
    }

    /// Merge two configurations (first takes precedence)
    fn merge_configs(base: &mut ProductionConfig, other: ProductionConfig) {
        // Only update fields that are still at default values
        // This allows environment variables to override file config

        if base.server.host == ServerConfig::default().host {
            base.server.host = other.server.host;
        }
        if base.server.port == ServerConfig::default().port {
            base.server.port = other.server.port;
        }

        if base.database.url == DatabaseConfig::default().url {
            base.database.url = other.database.url;
        }

        if base.redis.url == RedisConfig::default().url {
            base.redis.url = other.redis.url;
        }

        // Continue for other fields as needed...
    }

    /// Validate configuration
    fn validate_config(config: &ProductionConfig) -> Result<()> {
        // Validate server configuration
        if config.server.port == 0 {
            return Err(anyhow::anyhow!("Server port cannot be 0"));
        }

        // Validate database configuration
        if config.database.url.is_empty() {
            return Err(anyhow::anyhow!("Database URL cannot be empty"));
        }
        if config.database.max_connections == 0 {
            return Err(anyhow::anyhow!("Database max connections must be > 0"));
        }

        // Validate security configuration
        if config.security.jwt_secret == "change-me-in-production" {
            warn!("JWT secret is using default value - change in production!");
        }
        if config.security.jwt_secret.len() < 32 {
            return Err(anyhow::anyhow!("JWT secret must be at least 32 characters"));
        }

        if config.security.request_signing_secret == "change-me-in-production" {
            warn!("Request signing secret is using default value - change in production!");
        }
        if config.security.request_signing_secret.len() < 32 {
            return Err(anyhow::anyhow!(
                "Request signing secret must be at least 32 characters"
            ));
        }

        // Validate observability configuration
        let valid_log_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_log_levels.contains(&config.observability.log_level.as_str()) {
            return Err(anyhow::anyhow!(
                "Invalid log level: {}",
                config.observability.log_level
            ));
        }

        info!("Configuration validation passed");
        Ok(())
    }

    /// Get configuration summary for logging (without secrets)
    pub fn get_config_summary(config: &ProductionConfig) -> HashMap<String, String> {
        let mut summary = HashMap::new();

        summary.insert("server_host".to_string(), config.server.host.clone());
        summary.insert("server_port".to_string(), config.server.port.to_string());
        summary.insert(
            "database_max_connections".to_string(),
            config.database.max_connections.to_string(),
        );
        summary.insert(
            "redis_max_connections".to_string(),
            config.redis.max_connections.to_string(),
        );
        summary.insert(
            "log_level".to_string(),
            config.observability.log_level.clone(),
        );
        summary.insert(
            "metrics_enabled".to_string(),
            config.observability.metrics_enabled.to_string(),
        );
        summary.insert(
            "tracing_enabled".to_string(),
            config.observability.tracing_enabled.to_string(),
        );

        // Feature flags
        summary.insert(
            "mfa_enabled".to_string(),
            config.features.mfa_enabled.to_string(),
        );
        summary.insert(
            "saml_enabled".to_string(),
            config.features.saml_enabled.to_string(),
        );
        summary.insert(
            "oidc_enabled".to_string(),
            config.features.oidc_enabled.to_string(),
        );
        summary.insert(
            "advanced_security".to_string(),
            config.features.advanced_security.to_string(),
        );
        summary.insert(
            "ai_threat_detection".to_string(),
            config.features.ai_threat_detection.to_string(),
        );
        summary.insert(
            "quantum_safe".to_string(),
            config.features.quantum_safe.to_string(),
        );

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_config() {
        let config = ProductionConfig::default();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);
        assert!(config.features.mfa_enabled);
        assert!(config.features.oidc_enabled);
    }

    #[test]
    fn test_config_validation() {
        let mut config = ProductionConfig::default();

        // Valid config should pass
        config.security.jwt_secret = "a".repeat(32);
        config.security.request_signing_secret = "b".repeat(32);
        assert!(ConfigLoader::validate_config(&config).is_ok());

        // Invalid JWT secret should fail
        config.security.jwt_secret = "too_short".to_string();
        assert!(ConfigLoader::validate_config(&config).is_err());
    }

    #[test]
    fn test_env_var_loading() {
        env::set_var("SERVER_PORT", "9090");
        env::set_var("LOG_LEVEL", "debug");
        env::set_var("MFA_ENABLED", "false");

        let mut config = ProductionConfig::default();
        ConfigLoader::load_from_env(&mut config).unwrap();

        assert_eq!(config.server.port, 9090);
        assert_eq!(config.observability.log_level, "debug");
        assert!(!config.features.mfa_enabled);

        // Clean up
        env::remove_var("SERVER_PORT");
        env::remove_var("LOG_LEVEL");
        env::remove_var("MFA_ENABLED");
    }

    #[test]
    fn test_config_summary() {
        let config = ProductionConfig::default();
        let summary = ConfigLoader::get_config_summary(&config);

        assert!(summary.contains_key("server_host"));
        assert!(summary.contains_key("server_port"));
        assert!(summary.contains_key("mfa_enabled"));

        // Should not contain secrets
        assert!(!summary
            .values()
            .any(|v| v.contains("change-me-in-production")));
    }
}
