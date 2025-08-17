use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key not found: version {0}")]
    KeyNotFound(u32),
    #[error("Invalid key format")]
    InvalidKeyFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_version: u32,
}

#[derive(Clone)]
struct EncryptionKey {
    key: ChaCha20Poly1305,
    version: u32,
    created_at: chrono::DateTime<chrono::Utc>,
}

pub struct SecretManager {
    current_key: Arc<RwLock<EncryptionKey>>,
    old_keys: Arc<RwLock<HashMap<u32, EncryptionKey>>>,
    key_rotation_interval: chrono::Duration,
}

impl SecretManager {
    pub fn new() -> Result<Self, CryptoError> {
        let key = Self::generate_key(1)?;
        Ok(Self {
            current_key: Arc::new(RwLock::new(key)),
            old_keys: Arc::new(RwLock::new(HashMap::new())),
            key_rotation_interval: chrono::Duration::days(30),
        })
    }

    pub fn from_env() -> Result<Self, CryptoError> {
        if let Ok(key_hex) = std::env::var("MFA_ENCRYPTION_KEY") {
            let key_bytes = hex::decode(key_hex)
                .map_err(|_| CryptoError::InvalidKeyFormat)?;
            if key_bytes.len() != 32 {
                return Err(CryptoError::InvalidKeyFormat);
            }
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&key_bytes);
            let cipher = ChaCha20Poly1305::new(&key_array.into());
            let key = EncryptionKey {
                key: cipher,
                version: 1,
                created_at: chrono::Utc::now(),
            };
            Ok(Self {
                current_key: Arc::new(RwLock::new(key)),
                old_keys: Arc::new(RwLock::new(HashMap::new())),
                key_rotation_interval: chrono::Duration::days(30),
            })
        } else {
            Self::new()
        }
    }

    fn generate_key(version: u32) -> Result<EncryptionKey, CryptoError> {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        Ok(EncryptionKey {
            key: ChaCha20Poly1305::new(&key),
            version,
            created_at: chrono::Utc::now(),
        })
    }

    pub async fn encrypt_secret(&self, secret: &[u8]) -> Result<EncryptedSecret, CryptoError> {
        let current_key = self.current_key.read().await;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        let ciphertext = current_key.key
            .encrypt(&nonce, secret)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        Ok(EncryptedSecret {
            ciphertext,
            nonce: nonce.to_vec(),
            key_version: current_key.version,
        })
    }

    pub async fn decrypt_secret(&self, encrypted: &EncryptedSecret) -> Result<Vec<u8>, CryptoError> {
        let key = if encrypted.key_version == self.current_key.read().await.version {
            self.current_key.read().await.key.clone()
        } else {
            self.old_keys.read().await
                .get(&encrypted.key_version)
                .ok_or(CryptoError::KeyNotFound(encrypted.key_version))?
                .key.clone()
        };

        let nonce = Nonce::from_slice(&encrypted.nonce);
        key.decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }

    pub async fn current_key_version(&self) -> u32 {
        self.current_key.read().await.version
    }

    pub async fn rotate_key(&self) -> Result<(), CryptoError> {
        let mut current_key = self.current_key.write().await;
        let mut old_keys = self.old_keys.write().await;
        
        // Move current key to old keys
        let old_key = current_key.clone();
        old_keys.insert(old_key.version, old_key);
        
        // Generate new key
        let new_version = current_key.version + 1;
        *current_key = Self::generate_key(new_version)?;
        
        tracing::info!(
            "Rotated MFA encryption key from version {} to {}",
            new_version - 1,
            new_version
        );
        
        Ok(())
    }

    pub async fn should_rotate_key(&self) -> bool {
        let current_key = self.current_key.read().await;
        let age = chrono::Utc::now() - current_key.created_at;
        age > self.key_rotation_interval
    }

    pub async fn cleanup_old_keys(&self, max_age: chrono::Duration) {
        let mut old_keys = self.old_keys.write().await;
        let cutoff = chrono::Utc::now() - max_age;
        
        old_keys.retain(|_, key| key.created_at > cutoff);
    }
}

impl Default for SecretManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default SecretManager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let manager = SecretManager::new().unwrap();
        let secret = b"test_secret_data_123";
        
        let encrypted = manager.encrypt_secret(secret).await.unwrap();
        let decrypted = manager.decrypt_secret(&encrypted).await.unwrap();
        
        assert_eq!(secret, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let manager = SecretManager::new().unwrap();
        let secret = b"test_secret";
        
        // Encrypt with initial key
        let encrypted_v1 = manager.encrypt_secret(secret).await.unwrap();
        assert_eq!(encrypted_v1.key_version, 1);
        
        // Rotate key
        manager.rotate_key().await.unwrap();
        
        // Encrypt with new key
        let encrypted_v2 = manager.encrypt_secret(secret).await.unwrap();
        assert_eq!(encrypted_v2.key_version, 2);
        
        // Should be able to decrypt both
        let decrypted_v1 = manager.decrypt_secret(&encrypted_v1).await.unwrap();
        let decrypted_v2 = manager.decrypt_secret(&encrypted_v2).await.unwrap();
        
        assert_eq!(secret, decrypted_v1.as_slice());
        assert_eq!(secret, decrypted_v2.as_slice());
    }

    #[tokio::test]
    async fn test_different_secrets_different_ciphertext() {
        let manager = SecretManager::new().unwrap();
        let secret1 = b"secret1";
        let secret2 = b"secret2";
        
        let encrypted1 = manager.encrypt_secret(secret1).await.unwrap();
        let encrypted2 = manager.encrypt_secret(secret2).await.unwrap();
        
        // Same secret encrypted twice should have different ciphertext (due to random nonce)
        let encrypted1_again = manager.encrypt_secret(secret1).await.unwrap();
        
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        assert_ne!(encrypted1.ciphertext, encrypted1_again.ciphertext);
        assert_ne!(encrypted1.nonce, encrypted1_again.nonce);
    }
}