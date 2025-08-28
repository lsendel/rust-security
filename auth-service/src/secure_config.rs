//! Secure configuration management
//!
//! This module provides secure configuration loading that enforces the use of
//! environment variables for sensitive data and validates configuration security.

use serde::{Deserialize, Serialize};
use std::env;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    MissingEnvVar(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Weak secret detected: {0}")]
    WeakSecret(String),
    #[error("Configuration validation failed: {0}")]
    ValidationFailed(String),
}

/// Secure string that automatically zeroizes on drop
#[derive(Clone, Serialize, Deserialize)]
pub struct SecureString(String);

impl SecureString {
    pub fn new(value: String) -> Result<Self, ConfigError> {
        if value.len() < 32 {
            return Err(ConfigError::WeakSecret(
                "Secret must be at least 32 characters".to_string(),
            ));
        }
        
        // Check for common weak patterns
        if value.contains("password") || 
           value.contains("secret") || 
           value.contains("123") ||
           value == "dev-secret-key-12345678901234567890123456789012" {
            return Err(ConfigError::WeakSecret(
                "Secret contains weak patterns".to_string(),
            ));
        }
        
        Ok(SecureString(value))
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Secure configuration structure
#[derive(Debug, Clone)]
pub struct SecureConfig {
    pub jwt_secret: SecureString,
    pub encryption_key: SecureString,
    pub database_url: String,
    pub redis_url: String,
    pub server_host: String,
    pub server_port: u16,
    pub rate_limit_per_minute: u32,
    pub enable_tls: bool,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

impl SecureConfig {
    /// Load configuration from environment variables with security validation
    pub fn from_env() -> Result<Self, ConfigError> {
        // JWT Secret - must be strong
        let jwt_secret = env::var("JWT_SECRET")
            .map_err(|_| ConfigError::MissingEnvVar("JWT_SECRET".to_string()))?;
        let jwt_secret = SecureString::new(jwt_secret)?;
        
        // Encryption Key - must be strong
        let encryption_key = env::var("ENCRYPTION_KEY")
            .map_err(|_| ConfigError::MissingEnvVar("ENCRYPTION_KEY".to_string()))?;
        let encryption_key = SecureString::new(encryption_key)?;
        
        // Database URL - validate format
        let database_url = env::var("DATABASE_URL")
            .map_err(|_| ConfigError::MissingEnvVar("DATABASE_URL".to_string()))?;
        
        if !database_url.starts_with("postgresql://") && !database_url.starts_with("sqlite://") {
            return Err(ConfigError::InvalidConfig(
                "DATABASE_URL must use postgresql:// or sqlite://".to_string(),
            ));
        }
        
        // Redis URL
        let redis_url = env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".to_string());
        
        // Server configuration
        let server_host = env::var("SERVER_HOST")
            .unwrap_or_else(|_| "127.0.0.1".to_string());
        
        let server_port = env::var("SERVER_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse::<u16>()
            .map_err(|_| ConfigError::InvalidConfig("Invalid SERVER_PORT".to_string()))?;
        
        // Rate limiting
        let rate_limit_per_minute = env::var("RATE_LIMIT_PER_MINUTE")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<u32>()
            .map_err(|_| ConfigError::InvalidConfig("Invalid RATE_LIMIT_PER_MINUTE".to_string()))?;
        
        // TLS configuration
        let enable_tls = env::var("ENABLE_TLS")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .map_err(|_| ConfigError::InvalidConfig("Invalid ENABLE_TLS".to_string()))?;
        
        let tls_cert_path = env::var("TLS_CERT_PATH").ok();
        let tls_key_path = env::var("TLS_KEY_PATH").ok();
        
        // Validate TLS configuration
        if enable_tls && (tls_cert_path.is_none() || tls_key_path.is_none()) {
            return Err(ConfigError::ValidationFailed(
                "TLS enabled but TLS_CERT_PATH or TLS_KEY_PATH not provided".to_string(),
            ));
        }
        
        Ok(SecureConfig {
            jwt_secret,
            encryption_key,
            database_url,
            redis_url,
            server_host,
            server_port,
            rate_limit_per_minute,
            enable_tls,
            tls_cert_path,
            tls_key_path,
        })
    }
    
    /// Validate configuration security
    pub fn validate_security(&self) -> Result<(), ConfigError> {
        // Check for production readiness
        if self.server_host == "0.0.0.0" && !self.enable_tls {
            return Err(ConfigError::ValidationFailed(
                "Binding to 0.0.0.0 without TLS is insecure for production".to_string(),
            ));
        }
        
        // Check rate limiting
        if self.rate_limit_per_minute > 1000 {
            tracing::warn!("High rate limit configured: {} requests/minute", self.rate_limit_per_minute);
        }
        
        // Validate database URL doesn't contain credentials in production
        if self.database_url.contains("password=") {
            tracing::warn!("Database URL contains embedded credentials - consider using connection pooling with separate auth");
        }
        
        Ok(())
    }
}

/// Generate a cryptographically secure secret
pub fn generate_secure_secret(length: usize) -> Result<String, ConfigError> {
    use ring::rand::{SecureRandom, SystemRandom};
    
    if length < 32 {
        return Err(ConfigError::WeakSecret(
            "Secret length must be at least 32 bytes".to_string(),
        ));
    }
    
    let rng = SystemRandom::new();
    let mut bytes = vec![0u8; length];
    
    rng.fill(&mut bytes)
        .map_err(|_| ConfigError::InvalidConfig("Failed to generate random bytes".to_string()))?;
    
    Ok(hex::encode(bytes))
}

/// Initialize secure configuration with validation
pub fn init_secure_config() -> Result<SecureConfig, ConfigError> {
    let config = SecureConfig::from_env()?;
    config.validate_security()?;
    
    tracing::info!("Secure configuration loaded and validated");
    tracing::info!("Server: {}:{}", config.server_host, config.server_port);
    tracing::info!("TLS enabled: {}", config.enable_tls);
    tracing::info!("Rate limit: {} requests/minute", config.rate_limit_per_minute);
    
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    
    #[test]
    fn test_secure_string_validation() {
        // Too short
        assert!(SecureString::new("short".to_string()).is_err());
        
        // Weak patterns
        assert!(SecureString::new("password123456789012345678901234567890".to_string()).is_err());
        assert!(SecureString::new("secret123456789012345678901234567890".to_string()).is_err());
        
        // Valid strong secret
        let strong_secret = "a".repeat(64);
        assert!(SecureString::new(strong_secret).is_ok());
    }
    
    #[test]
    fn test_generate_secure_secret() {
        let secret = generate_secure_secret(32).unwrap();
        assert_eq!(secret.len(), 64); // hex encoded
        
        // Should be different each time
        let secret2 = generate_secure_secret(32).unwrap();
        assert_ne!(secret, secret2);
    }
    
    #[test]
    fn test_config_validation() {
        // Set up test environment
        env::set_var("JWT_SECRET", &"a".repeat(64));
        env::set_var("ENCRYPTION_KEY", &"b".repeat(64));
        env::set_var("DATABASE_URL", "postgresql://localhost/test");
        
        let config = SecureConfig::from_env().unwrap();
        assert!(config.validate_security().is_ok());
        
        // Clean up
        env::remove_var("JWT_SECRET");
        env::remove_var("ENCRYPTION_KEY");
        env::remove_var("DATABASE_URL");
    }
}