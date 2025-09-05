//! MVP Configuration Structure
//!
//! Single config struct for environment-based configuration as specified
//! in the MVP implementation plan.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// MVP-focused configuration struct
/// 
/// This single configuration struct handles all MVP settings through environment variables,
/// simplifying deployment and configuration management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Database configuration
    pub database_url: String,           // PostgreSQL or SQLite
    pub redis_url: Option<String>,      // Optional Redis for sessions
    
    /// Security configuration
    pub jwt_secret: String,             // JWT signing secret
    pub token_ttl: Duration,            // Default 1 hour
    pub request_signing_secret: Option<String>, // For admin endpoints
    
    /// Server configuration
    pub bind_address: String,           // Default 0.0.0.0:8080
    pub cors_origins: Vec<String>,      // CORS configuration
    
    /// Feature flags
    pub enable_redis_sessions: bool,    // Enable Redis sessions
    pub enable_postgres: bool,          // Enable PostgreSQL storage
    pub enable_metrics: bool,           // Enable Prometheus metrics
    pub enable_api_keys: bool,          // Enable API key support
    
    /// Rate limiting
    pub rate_limit_enabled: bool,       // Enable rate limiting
    pub rate_limit_per_minute: u32,     // Requests per minute per IP
    
    /// Operational settings
    pub log_level: String,              // Logging level
    pub external_base_url: String,      // External base URL for JWKS etc
}

impl AuthConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            // Database
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite::memory:".to_string()),
            redis_url: std::env::var("REDIS_URL").ok(),
            
            // Security
            jwt_secret: std::env::var("JWT_SECRET")
                .map_err(|_| ConfigError::MissingRequiredVar("JWT_SECRET".to_string()))?,
            token_ttl: Duration::from_secs(
                std::env::var("TOKEN_TTL_SECONDS")
                    .unwrap_or_else(|_| "3600".to_string())
                    .parse()
                    .unwrap_or(3600)
            ),
            request_signing_secret: std::env::var("REQUEST_SIGNING_SECRET").ok(),
            
            // Server
            bind_address: std::env::var("BIND_ADDRESS")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            cors_origins: std::env::var("CORS_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .collect(),
            
            // Feature flags
            enable_redis_sessions: env_bool("ENABLE_REDIS_SESSIONS", false),
            enable_postgres: env_bool("ENABLE_POSTGRES", false),
            enable_metrics: env_bool("ENABLE_METRICS", true),
            enable_api_keys: env_bool("ENABLE_API_KEYS", true),
            
            // Rate limiting
            rate_limit_enabled: env_bool("RATE_LIMIT_ENABLED", true),
            rate_limit_per_minute: std::env::var("RATE_LIMIT_PER_MINUTE")
                .unwrap_or_else(|_| "100".to_string())
                .parse()
                .unwrap_or(100),
            
            // Operational
            log_level: std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "info".to_string()),
            external_base_url: std::env::var("EXTERNAL_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
        })
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.jwt_secret.len() < 32 {
            return Err(ConfigError::InvalidValue("JWT_SECRET must be at least 32 characters".to_string()));
        }
        
        if self.token_ttl.as_secs() == 0 {
            return Err(ConfigError::InvalidValue("TOKEN_TTL_SECONDS must be greater than 0".to_string()));
        }
        
        if !self.bind_address.contains(':') {
            return Err(ConfigError::InvalidValue("BIND_ADDRESS must include port (e.g., 0.0.0.0:8080)".to_string()));
        }
        
        Ok(())
    }
    
    /// Get database URL based on enabled features
    pub fn get_database_url(&self) -> &str {
        if self.enable_postgres {
            &self.database_url
        } else {
            "sqlite::memory:"
        }
    }
    
    /// Get Redis URL if Redis sessions are enabled
    pub fn get_redis_url(&self) -> Option<&String> {
        if self.enable_redis_sessions {
            self.redis_url.as_ref()
        } else {
            None
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            database_url: "sqlite::memory:".to_string(),
            redis_url: None,
            jwt_secret: "your-256-bit-secret-key-change-in-production-minimum-32-chars".to_string(),
            token_ttl: Duration::from_secs(3600),
            request_signing_secret: None,
            bind_address: "0.0.0.0:8080".to_string(),
            cors_origins: vec![],
            enable_redis_sessions: false,
            enable_postgres: false,
            enable_metrics: true,
            enable_api_keys: true,
            rate_limit_enabled: true,
            rate_limit_per_minute: 100,
            log_level: "info".to_string(),
            external_base_url: "http://localhost:8080".to_string(),
        }
    }
}

/// Configuration error types
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    MissingRequiredVar(String),
    
    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),
}

/// Helper function to parse boolean environment variables
fn env_bool(var_name: &str, default: bool) -> bool {
    std::env::var(var_name)
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AuthConfig::default();
        assert_eq!(config.bind_address, "0.0.0.0:8080");
        assert_eq!(config.token_ttl, Duration::from_secs(3600));
        assert!(config.enable_metrics);
        assert!(config.enable_api_keys);
    }

    #[test]
    fn test_env_bool_parsing() {
        assert!(env_bool("NONEXISTENT_VAR", true));
        assert!(!env_bool("NONEXISTENT_VAR", false));
    }

    #[test]
    fn test_config_validation() {
        let mut config = AuthConfig::default();
        
        // Test valid config
        assert!(config.validate().is_ok());
        
        // Test short JWT secret
        config.jwt_secret = "short".to_string();
        assert!(config.validate().is_err());
        
        // Test zero TTL
        config.jwt_secret = "valid-32-character-secret-key-here".to_string();
        config.token_ttl = Duration::from_secs(0);
        assert!(config.validate().is_err());
    }
}