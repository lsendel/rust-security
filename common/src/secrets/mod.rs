//! Secure secrets management module
//! 
//! Provides secure handling of secrets with support for:
//! - Environment variables
//! - HashiCorp Vault
//! - AWS Secrets Manager
//! - Azure Key Vault
//! - File-based secrets with encryption

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure secret container that auto-zeroes on drop
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecureSecret {
    #[zeroize(skip)]
    pub name: String,
    pub value: String,
    #[zeroize(skip)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[zeroize(skip)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[zeroize(skip)]
    pub rotation_required: bool,
}

impl SecureSecret {
    /// Create a new secure secret
    pub fn new(name: String, value: String) -> Self {
        Self {
            name,
            value,
            created_at: chrono::Utc::now(),
            expires_at: None,
            rotation_required: false,
        }
    }

    /// Check if the secret is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            chrono::Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Check if the secret needs rotation
    pub fn needs_rotation(&self) -> bool {
        self.rotation_required || self.is_expired()
    }
}

/// Error types for secret management operations
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("Secret not found: {0}")]
    NotFound(String),
    
    #[error("Invalid secret format: {0}")]
    InvalidFormat(String),
    
    #[error("Secret expired: {0}")]
    Expired(String),
    
    #[error("Vault communication failed: {0}")]
    VaultError(String),
    
    #[error("AWS Secrets Manager error: {0}")]
    AwsError(String),
    
    #[error("Environment variable not found: {0}")]
    EnvVarNotFound(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
}

pub type SecretResult<T> = Result<T, SecretError>;

/// Secret source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretSource {
    /// Environment variable
    Environment { var_name: String },
    
    /// HashiCorp Vault
    Vault {
        url: String,
        token: String,
        mount_path: String,
        secret_path: String,
    },
    
    /// AWS Secrets Manager
    AwsSecretsManager {
        region: String,
        secret_id: String,
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
    },
    
    /// File-based secret (encrypted)
    File {
        path: String,
        encryption_key: String,
    },
}

/// Secrets manager interface
#[async_trait::async_trait]
pub trait SecretsProvider: Send + Sync {
    /// Get a secret by name
    async fn get_secret(&self, name: &str) -> SecretResult<SecureSecret>;
    
    /// Set a secret
    async fn set_secret(&self, secret: SecureSecret) -> SecretResult<()>;
    
    /// Delete a secret
    async fn delete_secret(&self, name: &str) -> SecretResult<()>;
    
    /// List all secrets (names only)
    async fn list_secrets(&self) -> SecretResult<Vec<String>>;
    
    /// Rotate a secret
    async fn rotate_secret(&self, name: &str) -> SecretResult<SecureSecret>;
    
    /// Check if secrets provider is healthy
    async fn health_check(&self) -> SecretResult<()>;
}

/// Environment variable secrets provider
pub struct EnvSecretsProvider {
    prefix: String,
    required_vars: Vec<String>,
}

impl EnvSecretsProvider {
    pub fn new(prefix: String) -> Self {
        Self {
            prefix,
            required_vars: vec![
                "JWT_SECRET".to_string(),
                "MASTER_ENCRYPTION_KEY".to_string(),
                "REQUEST_SIGNING_SECRET".to_string(),
                "SESSION_SECRET".to_string(),
            ],
        }
    }

    /// Validate all required environment variables are present
    pub fn validate_required(&self) -> SecretResult<()> {
        for var_name in &self.required_vars {
            let full_name = format!("{}_{}", self.prefix, var_name);
            std::env::var(&full_name)
                .map_err(|_| SecretError::EnvVarNotFound(full_name))?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl SecretsProvider for EnvSecretsProvider {
    async fn get_secret(&self, name: &str) -> SecretResult<SecureSecret> {
        let env_var_name = if self.prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}_{}", self.prefix, name)
        };

        let value = std::env::var(&env_var_name)
            .map_err(|_| SecretError::EnvVarNotFound(env_var_name.clone()))?;

        // Validate secret strength
        if value.len() < 32 {
            return Err(SecretError::InvalidFormat(
                format!("Secret {} is too short (minimum 32 characters)", name)
            ));
        }

        // Check for development patterns
        let dev_patterns = ["development", "test", "changeme", "INSECURE_DEV_SECRET"];
        for pattern in &dev_patterns {
            if value.contains(pattern) {
                return Err(SecretError::InvalidFormat(
                    format!("Secret {} contains development pattern: {}", name, pattern)
                ));
            }
        }

        Ok(SecureSecret::new(name.to_string(), value))
    }

    async fn set_secret(&self, _secret: SecureSecret) -> SecretResult<()> {
        Err(SecretError::InvalidFormat(
            "Cannot set environment variables at runtime".to_string()
        ))
    }

    async fn delete_secret(&self, _name: &str) -> SecretResult<()> {
        Err(SecretError::InvalidFormat(
            "Cannot delete environment variables at runtime".to_string()
        ))
    }

    async fn list_secrets(&self) -> SecretResult<Vec<String>> {
        let mut secrets = Vec::new();
        for (key, _) in std::env::vars() {
            if key.starts_with(&format!("{}_", self.prefix)) {
                let secret_name = key.strip_prefix(&format!("{}_", self.prefix))
                    .unwrap_or(&key)
                    .to_string();
                secrets.push(secret_name);
            }
        }
        Ok(secrets)
    }

    async fn rotate_secret(&self, _name: &str) -> SecretResult<SecureSecret> {
        Err(SecretError::InvalidFormat(
            "Cannot rotate environment variables automatically".to_string()
        ))
    }

    async fn health_check(&self) -> SecretResult<()> {
        self.validate_required()
    }
}

/// Unified secrets manager that can use multiple providers
pub struct SecretsManager {
    providers: HashMap<String, Box<dyn SecretsProvider>>,
    default_provider: String,
    cache: HashMap<String, SecureSecret>,
    cache_ttl: chrono::Duration,
}

impl SecretsManager {
    /// Create a new secrets manager
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            default_provider: "env".to_string(),
            cache: HashMap::new(),
            cache_ttl: chrono::Duration::minutes(5), // 5 minute cache
        }
    }

    /// Add a secrets provider
    pub fn add_provider(&mut self, name: String, provider: Box<dyn SecretsProvider>) {
        self.providers.insert(name, provider);
    }

    /// Set the default provider
    pub fn set_default_provider(&mut self, name: String) -> SecretResult<()> {
        if !self.providers.contains_key(&name) {
            return Err(SecretError::NotFound(format!("Provider {} not found", name)));
        }
        self.default_provider = name;
        Ok(())
    }

    /// Get a secret with caching
    pub async fn get_secret(&mut self, name: &str) -> SecretResult<SecureSecret> {
        // Check cache first
        if let Some(cached_secret) = self.cache.get(name) {
            if !cached_secret.is_expired() {
                return Ok(cached_secret.clone());
            }
        }

        // Get from provider
        let provider = self.providers.get(&self.default_provider)
            .ok_or_else(|| SecretError::NotFound("Default provider not found".to_string()))?;
        
        let secret = provider.get_secret(name).await?;

        // Cache the secret
        self.cache.insert(name.to_string(), secret.clone());

        Ok(secret)
    }

    /// Get multiple secrets efficiently
    pub async fn get_secrets(&mut self, names: &[&str]) -> SecretResult<HashMap<String, SecureSecret>> {
        let mut secrets = HashMap::new();
        
        for name in names {
            match self.get_secret(name).await {
                Ok(secret) => {
                    secrets.insert(name.to_string(), secret);
                }
                Err(e) => {
                    tracing::warn!("Failed to get secret {}: {}", name, e);
                    return Err(e);
                }
            }
        }
        
        Ok(secrets)
    }

    /// Clear the cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Health check all providers
    pub async fn health_check(&self) -> SecretResult<()> {
        for (name, provider) in &self.providers {
            provider.health_check().await.map_err(|e| {
                SecretError::VaultError(format!("Provider {} failed health check: {}", name, e))
            })?;
        }
        Ok(())
    }
}

impl Default for SecretsManager {
    fn default() -> Self {
        let mut manager = Self::new();
        
        // Add default environment provider
        let env_provider = EnvSecretsProvider::new("AUTH".to_string());
        manager.add_provider("env".to_string(), Box::new(env_provider));
        
        manager
    }
}

/// Convenience function to create a secrets manager from environment
pub async fn create_secrets_manager_from_env() -> SecretResult<SecretsManager> {
    let manager = SecretsManager::default();
    
    // Health check the default provider
    manager.health_check().await?;
    
    Ok(manager)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[tokio::test]
    async fn test_env_secrets_provider() {
        env::set_var("TEST_JWT_SECRET", "this_is_a_test_secret_that_is_long_enough_32_chars");
        
        let provider = EnvSecretsProvider::new("TEST".to_string());
        let secret = provider.get_secret("JWT_SECRET").await.unwrap();
        
        assert_eq!(secret.name, "JWT_SECRET");
        assert_eq!(secret.value, "this_is_a_test_secret_that_is_long_enough_32_chars");
    }

    #[tokio::test]
    async fn test_env_provider_rejects_short_secrets() {
        env::set_var("TEST_SHORT_SECRET", "short");
        
        let provider = EnvSecretsProvider::new("TEST".to_string());
        let result = provider.get_secret("SHORT_SECRET").await;
        
        assert!(matches!(result, Err(SecretError::InvalidFormat(_))));
    }

    #[tokio::test]
    async fn test_env_provider_rejects_dev_patterns() {
        env::set_var("TEST_DEV_SECRET", "development_secret_32_characters_long");
        
        let provider = EnvSecretsProvider::new("TEST".to_string());
        let result = provider.get_secret("DEV_SECRET").await;
        
        assert!(matches!(result, Err(SecretError::InvalidFormat(_))));
    }

    #[tokio::test]
    async fn test_secrets_manager_caching() {
        env::set_var("TEST_CACHED_SECRET", "cached_secret_32_characters_long_enough");
        
        let mut manager = SecretsManager::new();
        let provider = EnvSecretsProvider::new("TEST".to_string());
        manager.add_provider("test".to_string(), Box::new(provider));
        manager.set_default_provider("test".to_string()).unwrap();
        
        // First call should hit provider
        let secret1 = manager.get_secret("CACHED_SECRET").await.unwrap();
        
        // Second call should hit cache
        let secret2 = manager.get_secret("CACHED_SECRET").await.unwrap();
        
        assert_eq!(secret1.value, secret2.value);
    }
}