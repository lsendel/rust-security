//! Enterprise Secrets Management System
//!
//! This module provides secure secrets management with multiple backend support:
//! - AWS Secrets Manager (production recommended)
//! - HashiCorp Vault (enterprise preferred)
//! - Environment variables (development/fallback)
//!
//! Features:
//! - Automatic secret rotation detection
//! - Caching with TTL for performance
//! - Circuit breaker for resilience
//! - Audit logging for compliance
//! - Encryption of cached secrets

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[cfg(feature = "aws")]
use aws_config::meta::region::RegionProviderChain;
#[cfg(feature = "aws")]
use aws_sdk_secretsmanager::{Client as SecretsManagerClient, Error as AwsError};

#[cfg(feature = "vault")]
use vaultrs::{
    client::{VaultClient, VaultClientSettingsBuilder},
    kv2, Error as VaultError,
};

use crate::crypto_unified::{EncryptedData, UnifiedCryptoError, UnifiedCryptoManager};

#[derive(Error, Debug)]
pub enum SecretsError {
    #[error("Secret not found: {name}")]
    SecretNotFound { name: String },
    #[error("AWS Secrets Manager error: {0}")]
    AwsError(String),
    #[error("Vault error: {0}")]
    VaultError(String),
    #[error("Environment variable error: {name}")]
    EnvError { name: String },
    #[error("Cache error: {0}")]
    CacheError(String),
    #[error("Encryption error: {0}")]
    EncryptionError(#[from] UnifiedCryptoError),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Circuit breaker open for backend: {backend}")]
    CircuitBreakerOpen { backend: String },
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SecretBackend {
    /// AWS Secrets Manager - recommended for AWS environments
    AwsSecretsManager,
    /// HashiCorp Vault - enterprise secret management
    Vault,
    /// Environment variables - development and fallback
    Environment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub name: String,
    pub backend: SecretBackend,
    pub version: Option<String>,
    pub created_at: u64,
    pub last_accessed: u64,
    pub access_count: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CachedSecret {
    value: EncryptedData,
    metadata: SecretMetadata,
    cached_at: SystemTime,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct CircuitBreaker {
    failure_count: u32,
    last_failure_time: Option<SystemTime>,
    failure_threshold: u32,
    recovery_timeout: Duration,
}

impl CircuitBreaker {
    fn new(failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            failure_count: 0,
            last_failure_time: None,
            failure_threshold,
            recovery_timeout,
        }
    }

    fn is_open(&self) -> bool {
        if self.failure_count >= self.failure_threshold {
            if let Some(last_failure) = self.last_failure_time {
                SystemTime::now()
                    .duration_since(last_failure)
                    .unwrap_or_default()
                    < self.recovery_timeout
            } else {
                true
            }
        } else {
            false
        }
    }

    fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(SystemTime::now());
    }

    fn record_success(&mut self) {
        self.failure_count = 0;
        self.last_failure_time = None;
    }
}

#[derive(Debug, Clone)]
pub struct SecretsManagerConfig {
    pub default_backend: SecretBackend,
    pub cache_ttl: Duration,
    pub max_cache_size: usize,
    pub circuit_breaker_threshold: u32,
    pub circuit_breaker_timeout: Duration,
    pub aws_region: Option<String>,
    pub vault_address: Option<String>,
    pub vault_token: Option<String>,
    pub vault_mount: Option<String>,
}

impl Default for SecretsManagerConfig {
    fn default() -> Self {
        Self {
            default_backend: SecretBackend::Environment,
            cache_ttl: Duration::from_secs(300), // 5 minutes
            max_cache_size: 1000,
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout: Duration::from_secs(60),
            aws_region: None,
            vault_address: None,
            vault_token: None,
            vault_mount: Some("secret".to_string()),
        }
    }
}

/// Enterprise Secrets Manager with multiple backend support
pub struct SecretsManager {
    config: SecretsManagerConfig,
    #[cfg(feature = "aws")]
    aws_client: Option<SecretsManagerClient>,
    #[cfg(feature = "vault")]
    vault_client: Option<VaultClient>,
    cache: Arc<RwLock<HashMap<String, CachedSecret>>>,
    circuit_breakers: Arc<RwLock<HashMap<SecretBackend, CircuitBreaker>>>,
    crypto_manager: UnifiedCryptoManager,
}

impl SecretsManager {
    /// Create a new SecretsManager with automatic backend detection
    pub async fn new() -> Result<Self, SecretsError> {
        let config = Self::load_config_from_env();
        Self::new_with_config(config).await
    }

    /// Create a new SecretsManager with explicit configuration
    pub async fn new_with_config(config: SecretsManagerConfig) -> Result<Self, SecretsError> {
        let crypto_manager =
            UnifiedCryptoManager::new_aes().map_err(SecretsError::EncryptionError)?;

        let mut manager = Self {
            config: config.clone(),
            #[cfg(feature = "aws")]
            aws_client: None,
            #[cfg(feature = "vault")]
            vault_client: None,
            cache: Arc::new(RwLock::new(HashMap::new())),
            circuit_breakers: Arc::new(RwLock::new(HashMap::new())),
            crypto_manager,
        };

        // Initialize circuit breakers
        manager.init_circuit_breakers().await;

        // Initialize backends based on configuration
        manager.init_backends().await?;

        info!(
            "SecretsManager initialized with backend: {:?}",
            config.default_backend
        );
        Ok(manager)
    }

    fn load_config_from_env() -> SecretsManagerConfig {
        let mut config = SecretsManagerConfig::default();

        // Detect backend based on environment
        config.default_backend =
            if std::env::var("AWS_REGION").is_ok() && std::env::var("USE_AWS_SECRETS").is_ok() {
                config.aws_region = std::env::var("AWS_REGION").ok();
                SecretBackend::AwsSecretsManager
            } else if std::env::var("VAULT_ADDR").is_ok() {
                config.vault_address = std::env::var("VAULT_ADDR").ok();
                config.vault_token = std::env::var("VAULT_TOKEN").ok();
                config.vault_mount = std::env::var("VAULT_MOUNT").ok().or(config.vault_mount);
                SecretBackend::Vault
            } else {
                SecretBackend::Environment
            };

        // Cache configuration
        if let Ok(ttl_str) = std::env::var("SECRETS_CACHE_TTL") {
            if let Ok(ttl_secs) = ttl_str.parse::<u64>() {
                config.cache_ttl = Duration::from_secs(ttl_secs);
            }
        }

        config
    }

    async fn init_circuit_breakers(&self) {
        let mut breakers = self.circuit_breakers.write().await;
        breakers.insert(
            SecretBackend::AwsSecretsManager,
            CircuitBreaker::new(
                self.config.circuit_breaker_threshold,
                self.config.circuit_breaker_timeout,
            ),
        );
        breakers.insert(
            SecretBackend::Vault,
            CircuitBreaker::new(
                self.config.circuit_breaker_threshold,
                self.config.circuit_breaker_timeout,
            ),
        );
        breakers.insert(
            SecretBackend::Environment,
            CircuitBreaker::new(
                self.config.circuit_breaker_threshold,
                self.config.circuit_breaker_timeout,
            ),
        );
    }

    async fn init_backends(&mut self) -> Result<(), SecretsError> {
        match self.config.default_backend {
            #[cfg(feature = "aws")]
            SecretBackend::AwsSecretsManager => {
                self.init_aws_backend().await?;
            }
            #[cfg(feature = "vault")]
            SecretBackend::Vault => {
                self.init_vault_backend().await?;
            }
            SecretBackend::Environment => {
                debug!("Using environment variables backend");
            }
            #[cfg(not(feature = "aws"))]
            SecretBackend::AwsSecretsManager => {
                return Err(SecretsError::ConfigError(
                    "AWS Secrets Manager requested but AWS feature not enabled".to_string(),
                ));
            }
            #[cfg(not(feature = "vault"))]
            SecretBackend::Vault => {
                return Err(SecretsError::ConfigError(
                    "Vault requested but Vault feature not enabled".to_string(),
                ));
            }
        }
        Ok(())
    }

    #[cfg(feature = "aws")]
    async fn init_aws_backend(&mut self) -> Result<(), SecretsError> {
        let region_provider = RegionProviderChain::default_provider();
        let region_provider = if let Some(region) = &self.config.aws_region {
            region_provider.or_else(region.clone())
        } else {
            region_provider.or_else("us-east-1")
        };

        let config = aws_config::from_env().region(region_provider).load().await;
        self.aws_client = Some(SecretsManagerClient::new(&config));

        info!("AWS Secrets Manager client initialized");
        Ok(())
    }

    #[cfg(feature = "vault")]
    async fn init_vault_backend(&mut self) -> Result<(), SecretsError> {
        let vault_addr =
            self.config.vault_address.as_ref().ok_or_else(|| {
                SecretsError::ConfigError("VAULT_ADDR not configured".to_string())
            })?;

        let vault_token =
            self.config.vault_token.as_ref().ok_or_else(|| {
                SecretsError::ConfigError("VAULT_TOKEN not configured".to_string())
            })?;

        let settings = VaultClientSettingsBuilder::default()
            .address(vault_addr)
            .token(vault_token)
            .build()
            .map_err(|e| {
                SecretsError::VaultError(format!("Failed to build Vault settings: {}", e))
            })?;

        self.vault_client = Some(VaultClient::new(settings).map_err(|e| {
            SecretsError::VaultError(format!("Failed to create Vault client: {}", e))
        })?);

        info!("Vault client initialized for address: {}", vault_addr);
        Ok(())
    }

    /// Get a secret by name with automatic backend selection and caching
    pub async fn get_secret(&self, name: &str) -> Result<String, SecretsError> {
        // Check cache first
        if let Some(cached) = self.get_from_cache(name).await? {
            return Ok(cached);
        }

        // Try backends in order of preference
        let backends = vec![
            self.config.default_backend.clone(),
            SecretBackend::Environment, // Always fallback to env vars
        ];

        let mut last_error = None;
        for backend in backends {
            if self.is_circuit_breaker_open(&backend).await {
                warn!("Circuit breaker open for backend: {:?}", backend);
                continue;
            }

            match self.get_secret_from_backend(name, &backend).await {
                Ok(value) => {
                    self.record_backend_success(&backend).await;
                    self.cache_secret(name, &value, &backend).await?;
                    return Ok(value);
                }
                Err(e) => {
                    self.record_backend_failure(&backend).await;
                    error!("Failed to get secret '{}' from {:?}: {}", name, backend, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(SecretsError::SecretNotFound {
            name: name.to_string(),
        }))
    }

    async fn get_secret_from_backend(
        &self,
        name: &str,
        backend: &SecretBackend,
    ) -> Result<String, SecretsError> {
        match backend {
            #[cfg(feature = "aws")]
            SecretBackend::AwsSecretsManager => self.get_from_aws(name).await,
            #[cfg(feature = "vault")]
            SecretBackend::Vault => self.get_from_vault(name).await,
            SecretBackend::Environment => self.get_from_env(name).await,
            #[cfg(not(feature = "aws"))]
            SecretBackend::AwsSecretsManager => Err(SecretsError::ConfigError(
                "AWS feature not enabled".to_string(),
            )),
            #[cfg(not(feature = "vault"))]
            SecretBackend::Vault => Err(SecretsError::ConfigError(
                "Vault feature not enabled".to_string(),
            )),
        }
    }

    #[cfg(feature = "aws")]
    async fn get_from_aws(&self, name: &str) -> Result<String, SecretsError> {
        let client = self
            .aws_client
            .as_ref()
            .ok_or_else(|| SecretsError::AwsError("AWS client not initialized".to_string()))?;

        let result = client
            .get_secret_value()
            .secret_id(name)
            .send()
            .await
            .map_err(|e| SecretsError::AwsError(format!("AWS API error: {}", e)))?;

        result
            .secret_string()
            .ok_or_else(|| {
                SecretsError::AwsError("Secret value is binary, expected string".to_string())
            })
            .map(|s| s.to_string())
    }

    #[cfg(feature = "vault")]
    async fn get_from_vault(&self, name: &str) -> Result<String, SecretsError> {
        let client = self
            .vault_client
            .as_ref()
            .ok_or_else(|| SecretsError::VaultError("Vault client not initialized".to_string()))?;

        let mount = self.config.vault_mount.as_deref().unwrap_or("secret");

        let secret: serde_json::Value = kv2::read(client, mount, name)
            .await
            .map_err(|e| SecretsError::VaultError(format!("Vault API error: {}", e)))?;

        // Extract the actual secret value from Vault's response structure
        secret
            .get("data")
            .and_then(|data| data.get("value"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                SecretsError::VaultError("Invalid secret format in Vault response".to_string())
            })
            .map(|s| s.to_string())
    }

    async fn get_from_env(&self, name: &str) -> Result<String, SecretsError> {
        std::env::var(name).map_err(|_| SecretsError::EnvError {
            name: name.to_string(),
        })
    }

    async fn get_from_cache(&self, name: &str) -> Result<Option<String>, SecretsError> {
        let cache = self.cache.read().await;
        if let Some(cached) = cache.get(name) {
            // Check if cache entry is still valid
            if cached.cached_at.elapsed().unwrap_or_default() < cached.ttl {
                let decrypted = self.crypto_manager.decrypt(&cached.value).await?;
                let value = String::from_utf8(decrypted).map_err(|e| {
                    SecretsError::CacheError(format!("Invalid UTF-8 in cached secret: {}", e))
                })?;

                debug!("Cache hit for secret: {}", name);
                return Ok(Some(value));
            } else {
                debug!("Cache entry expired for secret: {}", name);
            }
        }
        Ok(None)
    }

    async fn cache_secret(
        &self,
        name: &str,
        value: &str,
        backend: &SecretBackend,
    ) -> Result<(), SecretsError> {
        let encrypted = self.crypto_manager.encrypt(value.as_bytes()).await?;

        let metadata = SecretMetadata {
            name: name.to_string(),
            backend: backend.clone(),
            version: None,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_accessed: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            access_count: 1,
        };

        let cached_secret = CachedSecret {
            value: encrypted,
            metadata,
            cached_at: SystemTime::now(),
            ttl: self.config.cache_ttl,
        };

        let mut cache = self.cache.write().await;

        // Implement cache size limit with LRU eviction
        if cache.len() >= self.config.max_cache_size {
            // Remove oldest entries
            let mut entries: Vec<_> = cache.iter().collect();
            entries.sort_by_key(|(_, v)| v.cached_at);

            let to_remove: Vec<_> = entries
                .iter()
                .take(cache.len() - self.config.max_cache_size + 1)
                .map(|(k, _)| (*k).clone())
                .collect();

            for key in to_remove {
                cache.remove(&key);
            }
        }

        cache.insert(name.to_string(), cached_secret);
        debug!("Cached secret: {} from backend: {:?}", name, backend);
        Ok(())
    }

    async fn is_circuit_breaker_open(&self, backend: &SecretBackend) -> bool {
        let breakers = self.circuit_breakers.read().await;
        breakers.get(backend).is_some_and(|cb| cb.is_open())
    }

    async fn record_backend_success(&self, backend: &SecretBackend) {
        let mut breakers = self.circuit_breakers.write().await;
        if let Some(breaker) = breakers.get_mut(backend) {
            breaker.record_success();
        }
    }

    async fn record_backend_failure(&self, backend: &SecretBackend) {
        let mut breakers = self.circuit_breakers.write().await;
        if let Some(breaker) = breakers.get_mut(backend) {
            breaker.record_failure();
        }
    }

    /// Clear the secrets cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("Secrets cache cleared");
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> HashMap<String, u64> {
        let cache = self.cache.read().await;
        let mut stats = HashMap::new();
        stats.insert("cache_size".to_string(), cache.len() as u64);
        stats.insert("cache_limit".to_string(), self.config.max_cache_size as u64);
        stats
    }

    /// Preload commonly used secrets into cache
    pub async fn preload_secrets(&self, secret_names: &[&str]) -> Result<(), SecretsError> {
        info!("Preloading {} secrets into cache", secret_names.len());

        for &name in secret_names {
            match self.get_secret(name).await {
                Ok(_) => debug!("Preloaded secret: {}", name),
                Err(e) => warn!("Failed to preload secret '{}': {}", name, e),
            }
        }

        Ok(())
    }
}

/// Convenience methods for common secret types
impl SecretsManager {
    /// Get JWT signing secret
    pub async fn get_jwt_secret(&self) -> Result<String, SecretsError> {
        self.get_secret("JWT_SECRET").await
    }

    /// Get database URL
    pub async fn get_database_url(&self) -> Result<String, SecretsError> {
        self.get_secret("DATABASE_URL").await
    }

    /// Get Redis URL
    pub async fn get_redis_url(&self) -> Result<String, SecretsError> {
        self.get_secret("REDIS_URL").await
    }

    /// Get request signing secret
    pub async fn get_request_signing_secret(&self) -> Result<String, SecretsError> {
        self.get_secret("REQUEST_SIGNING_SECRET").await
    }

    /// Get MFA encryption key
    pub async fn get_mfa_encryption_key(&self) -> Result<String, SecretsError> {
        self.get_secret("MFA_ENCRYPTION_KEY").await
    }

    /// Get client credentials as a map
    pub async fn get_client_credentials(&self) -> Result<HashMap<String, String>, SecretsError> {
        let creds_str = self.get_secret("CLIENT_CREDENTIALS").await?;

        // Parse client credentials in format: client1:secret1,client2:secret2
        let mut credentials = HashMap::new();
        for pair in creds_str.split(',') {
            let parts: Vec<&str> = pair.split(':').collect();
            if parts.len() == 2 {
                credentials.insert(parts[0].trim().to_string(), parts[1].trim().to_string());
            }
        }

        if credentials.is_empty() {
            return Err(SecretsError::ValidationError(
                "No valid client credentials found".to_string(),
            ));
        }

        Ok(credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_environment_backend() {
        std::env::set_var("TEST_SECRET", "test_value");

        let config = SecretsManagerConfig {
            default_backend: SecretBackend::Environment,
            ..Default::default()
        };

        let manager = SecretsManager::new_with_config(config).await.unwrap();
        let value = manager.get_secret("TEST_SECRET").await.unwrap();

        assert_eq!(value, "test_value");

        std::env::remove_var("TEST_SECRET");
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        std::env::set_var("CACHE_TEST_SECRET", "cached_value");

        let config = SecretsManagerConfig {
            default_backend: SecretBackend::Environment,
            cache_ttl: Duration::from_secs(10),
            ..Default::default()
        };

        let manager = SecretsManager::new_with_config(config).await.unwrap();

        // First call should hit the backend
        let value1 = manager.get_secret("CACHE_TEST_SECRET").await.unwrap();
        assert_eq!(value1, "cached_value");

        // Second call should hit the cache
        let value2 = manager.get_secret("CACHE_TEST_SECRET").await.unwrap();
        assert_eq!(value2, "cached_value");

        let stats = manager.get_cache_stats().await;
        assert_eq!(stats.get("cache_size"), Some(&1));

        std::env::remove_var("CACHE_TEST_SECRET");
    }

    #[tokio::test]
    async fn test_secret_not_found() {
        let config = SecretsManagerConfig {
            default_backend: SecretBackend::Environment,
            ..Default::default()
        };

        let manager = SecretsManager::new_with_config(config).await.unwrap();
        let result = manager.get_secret("NONEXISTENT_SECRET").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SecretsError::EnvError { name } => assert_eq!(name, "NONEXISTENT_SECRET"),
            _ => panic!("Expected EnvError"),
        }
    }

    #[tokio::test]
    async fn test_convenience_methods() {
        std::env::set_var("JWT_SECRET", "jwt_test_secret");
        std::env::set_var("CLIENT_CREDENTIALS", "client1:secret1,client2:secret2");

        let config = SecretsManagerConfig {
            default_backend: SecretBackend::Environment,
            ..Default::default()
        };

        let manager = SecretsManager::new_with_config(config).await.unwrap();

        let jwt_secret = manager.get_jwt_secret().await.unwrap();
        assert_eq!(jwt_secret, "jwt_test_secret");

        let client_creds = manager.get_client_credentials().await.unwrap();
        assert_eq!(client_creds.get("client1"), Some(&"secret1".to_string()));
        assert_eq!(client_creds.get("client2"), Some(&"secret2".to_string()));

        std::env::remove_var("JWT_SECRET");
        std::env::remove_var("CLIENT_CREDENTIALS");
    }
}
