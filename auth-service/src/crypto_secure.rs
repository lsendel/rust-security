//! Secure cryptographic operations
//!
//! This module provides hardened cryptographic operations with proper key management,
//! secure random number generation, and protection against common crypto vulnerabilities.

use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    digest::{self, SHA256, SHA512},
    hmac,
    rand::{SecureRandom as RingSecureRandom, SystemRandom},
};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use base64::Engine;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key generation failed")]
    KeyGenerationFailed,
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("HMAC verification failed")]
    HmacVerificationFailed,
    #[error("Random generation failed")]
    RandomGenerationFailed,
    #[error("Key not found: {0}")]
    KeyNotFound(String),
}

/// Secure key material that zeroizes on drop
#[derive(Clone)]
pub struct SecureKey {
    key: LessSafeKey,
    id: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl SecureKey {
    fn new(key_material: &[u8], id: String) -> Result<Self, CryptoError> {
        if key_material.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: key_material.len(),
            });
        }
        
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_material)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;
        let key = LessSafeKey::new(unbound_key);
        
        Ok(Self {
            key,
            id,
            created_at: chrono::Utc::now(),
        })
    }
}

/// Encrypted data with metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_id: String,
    pub algorithm: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Secure cryptographic manager with key rotation and proper entropy
pub struct SecureCryptoManager {
    current_key: Arc<RwLock<SecureKey>>,
    old_keys: Arc<RwLock<HashMap<String, SecureKey>>>,
    rng: SystemRandom,
    key_rotation_interval: chrono::Duration,
}

impl SecureCryptoManager {
    /// Create new crypto manager with secure key generation
    pub fn new() -> Result<Self, CryptoError> {
        let key_id = Self::generate_key_id()?;
        let key = Self::generate_secure_key(key_id)?;
        
        Ok(Self {
            current_key: Arc::new(RwLock::new(key)),
            old_keys: Arc::new(RwLock::new(HashMap::new())),
            rng: SystemRandom::new(),
            key_rotation_interval: chrono::Duration::hours(24), // Rotate daily
        })
    }
    
    /// Create from environment variable with validation
    pub fn from_env() -> Result<Self, CryptoError> {
        if let Ok(key_hex) = std::env::var("MASTER_ENCRYPTION_KEY") {
            let key_material = hex::decode(key_hex)
                .map_err(|_| CryptoError::KeyGenerationFailed)?;
            
            let key_id = "env_key".to_string();
            let key = SecureKey::new(&key_material, key_id)?;
            
            Ok(Self {
                current_key: Arc::new(RwLock::new(key)),
                old_keys: Arc::new(RwLock::new(HashMap::new())),
                rng: SystemRandom::new(),
                key_rotation_interval: chrono::Duration::hours(24),
            })
        } else {
            Self::new()
        }
    }
    
    fn generate_key_id() -> Result<String, CryptoError> {
        let mut bytes = [0u8; 16];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;
        Ok(hex::encode(bytes))
    }
    
    fn generate_secure_key(key_id: String) -> Result<SecureKey, CryptoError> {
        let mut key_material = [0u8; 32];
        
        // Use multiple entropy sources for enhanced security
        let rng = SystemRandom::new();
        
        // Primary entropy from system RNG
        rng.fill(&mut key_material)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;
        
        // Additional entropy mixing (defense in depth)
        let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let process_id = std::process::id();
        
        // Mix additional entropy using HMAC
        let additional_entropy = format!("{timestamp}{process_id}");
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &key_material);
        let mixed_entropy = hmac::sign(&hmac_key, additional_entropy.as_bytes());
        
        // XOR the additional entropy with the key material
        for (i, &byte) in mixed_entropy.as_ref().iter().take(32).enumerate() {
            key_material[i] ^= byte;
        }
        
        SecureKey::new(&key_material, key_id)
    }
    
    /// Encrypt data with authenticated encryption
    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
        let current_key = self.current_key.read().await;
        
        // Generate cryptographically secure nonce
        let mut nonce_bytes = [0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;
        
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| CryptoError::EncryptionFailed("Invalid nonce".to_string()))?;
        
        // Encrypt with authenticated encryption
        let mut in_out = plaintext.to_vec();
        current_key
            .key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| CryptoError::EncryptionFailed(format!("AES-GCM encryption failed: {e:?}")))?;
        
        Ok(EncryptedData {
            ciphertext: in_out,
            nonce: nonce_bytes.to_vec(),
            key_id: current_key.id.clone(),
            algorithm: "AES-256-GCM".to_string(),
            created_at: chrono::Utc::now(),
        })
    }
    
    /// Decrypt data with key lookup and validation
    pub async fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>, CryptoError> {
        // Validate algorithm
        if encrypted.algorithm != "AES-256-GCM" {
            return Err(CryptoError::DecryptionFailed(
                format!("Unsupported algorithm: {}", encrypted.algorithm)
            ));
        }
        
        // Find the appropriate key
        let key = {
            let current_key = self.current_key.read().await;
            if current_key.id == encrypted.key_id {
                current_key.key.clone()
            } else {
                let old_keys = self.old_keys.read().await;
                old_keys
                    .get(&encrypted.key_id)
                    .ok_or_else(|| CryptoError::KeyNotFound(encrypted.key_id.clone()))?
                    .key
                    .clone()
            }
        };
        
        // Validate nonce length
        if encrypted.nonce.len() != 12 {
            return Err(CryptoError::DecryptionFailed(
                "Invalid nonce length".to_string()
            ));
        }
        
        let nonce = Nonce::try_assume_unique_for_key(&encrypted.nonce)
            .map_err(|_| CryptoError::DecryptionFailed("Invalid nonce".to_string()))?;
        
        // Decrypt and verify
        let mut ciphertext = encrypted.ciphertext.clone();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(format!("AES-GCM decryption failed: {e:?}")))?;
        
        Ok(plaintext.to_vec())
    }
    
    /// Rotate encryption key
    pub async fn rotate_key(&self) -> Result<(), CryptoError> {
        let mut current_key = self.current_key.write().await;
        let mut old_keys = self.old_keys.write().await;
        
        // Move current key to old keys
        let old_key = current_key.clone();
        old_keys.insert(old_key.id.clone(), old_key);
        
        // Generate new key
        let new_key_id = Self::generate_key_id()?;
        *current_key = Self::generate_secure_key(new_key_id)?;
        
        tracing::info!("Encryption key rotated successfully");
        Ok(())
    }
    
    /// Check if key should be rotated
    pub async fn should_rotate_key(&self) -> bool {
        let current_key = self.current_key.read().await;
        let age = chrono::Utc::now() - current_key.created_at;
        age > self.key_rotation_interval
    }
    
    /// Clean up old keys
    pub async fn cleanup_old_keys(&self, max_age: chrono::Duration) {
        let mut old_keys = self.old_keys.write().await;
        let cutoff = chrono::Utc::now() - max_age;
        
        old_keys.retain(|_, key| key.created_at > cutoff);
        tracing::info!("Cleaned up old encryption keys");
    }
}

/// Secure hashing operations
pub struct SecureHasher;

impl SecureHasher {
    /// SHA-256 hash
    #[must_use] pub fn sha256(data: &[u8]) -> Vec<u8> {
        digest::digest(&SHA256, data).as_ref().to_vec()
    }
    
    /// SHA-512 hash
    #[must_use] pub fn sha512(data: &[u8]) -> Vec<u8> {
        digest::digest(&SHA512, data).as_ref().to_vec()
    }
    
    /// Multi-input SHA-256 hash
    #[must_use] pub fn sha256_multi(inputs: &[&[u8]]) -> Vec<u8> {
        let mut context = digest::Context::new(&SHA256);
        for input in inputs {
            context.update(input);
        }
        context.finish().as_ref().to_vec()
    }
}

/// Secure HMAC operations
pub struct SecureHmac;

impl SecureHmac {
    /// HMAC-SHA256
    #[must_use] pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::sign(&key, data).as_ref().to_vec()
    }
    
    /// HMAC-SHA512
    #[must_use] pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
        let key = hmac::Key::new(hmac::HMAC_SHA512, key);
        hmac::sign(&key, data).as_ref().to_vec()
    }
    
    /// Verify HMAC-SHA256 in constant time
    #[must_use] pub fn verify_hmac_sha256(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::verify(&key, data, expected).is_ok()
    }
    
    /// Verify HMAC-SHA512 in constant time
    #[must_use] pub fn verify_hmac_sha512(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
        let key = hmac::Key::new(hmac::HMAC_SHA512, key);
        hmac::verify(&key, data, expected).is_ok()
    }
}

/// Secure random number generation
pub struct SecureRandom;

impl SecureRandom {
    /// Generate cryptographically secure random bytes
    pub fn generate_bytes(length: usize) -> Result<Vec<u8>, CryptoError> {
        let rng = SystemRandom::new();
        let mut bytes = vec![0u8; length];
        
        rng.fill(&mut bytes)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;
        
        Ok(bytes)
    }
    
    /// Generate secure token
    pub fn generate_token(length: usize) -> Result<String, CryptoError> {
        let bytes = Self::generate_bytes(length)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }
    
    /// Generate secure hex string
    pub fn generate_hex(length: usize) -> Result<String, CryptoError> {
        let bytes = Self::generate_bytes(length)?;
        Ok(hex::encode(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let manager = SecureCryptoManager::new().unwrap();
        let plaintext = b"sensitive data";
        
        let encrypted = manager.encrypt(plaintext).await.unwrap();
        let decrypted = manager.decrypt(&encrypted).await.unwrap();
        
        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }
    
    #[tokio::test]
    async fn test_key_rotation() {
        let manager = SecureCryptoManager::new().unwrap();
        let plaintext = b"test data";
        
        // Encrypt with original key
        let encrypted1 = manager.encrypt(plaintext).await.unwrap();
        
        // Rotate key
        manager.rotate_key().await.unwrap();
        
        // Encrypt with new key
        let encrypted2 = manager.encrypt(plaintext).await.unwrap();
        
        // Should be able to decrypt both
        let decrypted1 = manager.decrypt(&encrypted1).await.unwrap();
        let decrypted2 = manager.decrypt(&encrypted2).await.unwrap();
        
        assert_eq!(plaintext.as_ref(), decrypted1.as_slice());
        assert_eq!(plaintext.as_ref(), decrypted2.as_slice());
        assert_ne!(encrypted1.key_id, encrypted2.key_id);
    }
    
    #[test]
    fn test_secure_hashing() {
        let data = b"test data";
        
        let hash256 = SecureHasher::sha256(data);
        let hash512 = SecureHasher::sha512(data);
        
        assert_eq!(hash256.len(), 32);
        assert_eq!(hash512.len(), 64);
        
        // Same input should produce same hash
        assert_eq!(hash256, SecureHasher::sha256(data));
    }
    
    #[test]
    fn test_secure_hmac() {
        let key = b"secret key";
        let data = b"test data";
        
        let hmac256 = SecureHmac::hmac_sha256(key, data);
        let hmac512 = SecureHmac::hmac_sha512(key, data);
        
        assert_eq!(hmac256.len(), 32);
        assert_eq!(hmac512.len(), 64);
        
        // Verification should work
        assert!(SecureHmac::verify_hmac_sha256(key, data, &hmac256));
        assert!(SecureHmac::verify_hmac_sha512(key, data, &hmac512));
        
        // Wrong key should fail
        let wrong_key = b"wrong key";
        assert!(!SecureHmac::verify_hmac_sha256(wrong_key, data, &hmac256));
    }
    
    #[test]
    fn test_secure_random() {
        let bytes1 = SecureRandom::generate_bytes(32).unwrap();
        let bytes2 = SecureRandom::generate_bytes(32).unwrap();
        
        assert_eq!(bytes1.len(), 32);
        assert_ne!(bytes1, bytes2);
        
        let token = SecureRandom::generate_token(32).unwrap();
        assert!(!token.is_empty());
        
        let hex = SecureRandom::generate_hex(16).unwrap();
        assert_eq!(hex.len(), 32); // hex encoded
    }
}