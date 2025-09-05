//! Unified Key Management Operations
//!
//! Consolidates key management from:
//! - auth-service/src/infrastructure/crypto/keys.rs
//! - auth-service/src/infrastructure/crypto/key_management.rs
//! - auth-service/src/infrastructure/crypto/keys_*.rs variants

use super::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Key management errors
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    
    #[error("Key generation failed: {0}")]
    GenerationFailed(String),
    
    #[error("Key rotation failed: {0}")]
    RotationFailed(String),
    
    #[error("Invalid key format: {0}")]
    InvalidFormat(String),
}

/// Key management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManagementConfig {
    /// Key rotation interval in seconds
    pub rotation_interval: u64,
    
    /// Maximum key age in seconds
    pub max_key_age: u64,
    
    /// Maximum number of keys to keep
    pub max_keys: usize,
    
    /// Enable automatic rotation
    pub auto_rotation: bool,
}

impl Default for KeyManagementConfig {
    fn default() -> Self {
        Self {
            rotation_interval: 3600,  // 1 hour
            max_key_age: 7200,        // 2 hours
            max_keys: 3,
            auto_rotation: true,
        }
    }
}

impl FromEnvironment for KeyManagementConfig {
    fn from_env() -> CryptoResult<Self> {
        Ok(Self::default()) // Simplified for now
    }
}

impl CryptoValidation for KeyManagementConfig {
    fn validate(&self) -> CryptoResult<()> {
        if self.max_keys == 0 {
            return Err(CryptoError::ValidationFailed("Max keys must be > 0".to_string()));
        }
        Ok(())
    }
}

/// Key material
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    pub id: String,
    pub key_data: Vec<u8>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub algorithm: String,
}

/// Unified key manager
pub struct KeyManager {
    config: KeyManagementConfig,
    keys: Arc<RwLock<HashMap<String, KeyMaterial>>>,
    current_key_id: Arc<RwLock<Option<String>>>,
    rng: ring::rand::SystemRandom,
}

impl KeyManager {
    /// Create new key manager
    pub async fn new(config: KeyManagementConfig) -> CryptoResult<Self> {
        config.validate()?;
        
        let manager = Self {
            config,
            keys: Arc::new(RwLock::new(HashMap::new())),
            current_key_id: Arc::new(RwLock::new(None)),
            rng: ring::rand::SystemRandom::new(),
        };
        
        // Generate initial key
        manager.rotate_keys().await?;
        
        Ok(manager)
    }
    
    /// Rotate keys
    pub async fn rotate_keys(&self) -> CryptoResult<()> {
        let new_key = self.generate_key().await?;
        let key_id = new_key.id.clone();
        
        let mut keys = self.keys.write().await;
        let mut current_id = self.current_key_id.write().await;
        
        // Add new key
        keys.insert(key_id.clone(), new_key);
        *current_id = Some(key_id);
        
        // Remove expired keys
        let now = SystemTime::now();
        keys.retain(|_, key| key.expires_at > now);
        
        Ok(())
    }
    
    /// Get current key
    pub async fn get_current_key(&self) -> CryptoResult<KeyMaterial> {
        let current_id = self.current_key_id.read().await;
        let keys = self.keys.read().await;
        
        match &*current_id {
            Some(id) => keys.get(id)
                .cloned()
                .ok_or_else(|| KeyError::KeyNotFound(id.clone()).into()),
            None => Err(KeyError::KeyNotFound("No current key".to_string()).into()),
        }
    }
    
    /// Get key by ID
    pub async fn get_key(&self, key_id: &str) -> CryptoResult<KeyMaterial> {
        let keys = self.keys.read().await;
        keys.get(key_id)
            .cloned()
            .ok_or_else(|| KeyError::KeyNotFound(key_id.to_string()).into())
    }
    
    async fn generate_key(&self) -> CryptoResult<KeyMaterial> {
        let id = Uuid::new_v4().to_string();
        let mut key_data = vec![0u8; 32];
        
        ring::rand::SecureRandom::fill(&self.rng, &mut key_data)
            .map_err(|_| KeyError::GenerationFailed("Random key generation failed".to_string()))?;
        
        let now = SystemTime::now();
        let expires_at = now + Duration::from_secs(self.config.max_key_age);
        
        Ok(KeyMaterial {
            id,
            key_data,
            created_at: now,
            expires_at,
            algorithm: "AES256".to_string(),
        })
    }
}