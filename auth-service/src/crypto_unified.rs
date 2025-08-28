//! Unified cryptographic operations using the `ring` library
//!
//! This module consolidates all symmetric encryption, hashing, and HMAC operations
//! to use the `ring` cryptographic library for consistent security guarantees,
//! hardware acceleration, and reduced attack surface.

use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305},
    digest::{self, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA512},
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum UnifiedCryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key not found: version {0}")]
    KeyNotFound(u32),
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Key generation failed")]
    KeyGenerationFailed,
    #[error("HMAC verification failed")]
    HmacVerificationFailed,
    #[error("Random number generation failed")]
    RandomGenerationFailed,
}

/// Supported symmetric encryption algorithms
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum SymmetricAlgorithm {
    /// AES-256-GCM - Hardware accelerated where available
    #[default]
    Aes256Gcm,
    /// ChaCha20-Poly1305 - Pure software implementation, good for environments without AES-NI
    ChaCha20Poly1305,
}

impl SymmetricAlgorithm {
    const fn key_length(&self) -> usize {
        match self {
            Self::Aes256Gcm => 32,        // 256 bits
            Self::ChaCha20Poly1305 => 32, // 256 bits
        }
    }

    const fn nonce_length(&self) -> usize {
        match self {
            Self::Aes256Gcm => 12,        // 96 bits
            Self::ChaCha20Poly1305 => 12, // 96 bits
        }
    }

    fn algorithm(&self) -> &'static aead::Algorithm {
        match self {
            Self::Aes256Gcm => &AES_256_GCM,
            Self::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub algorithm: SymmetricAlgorithm,
    pub key_version: u32,
}

#[derive(Clone)]
struct CryptoKey {
    key: LessSafeKey,
    algorithm: SymmetricAlgorithm,
    version: u32,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Unified cryptographic manager using ring for all operations
pub struct UnifiedCryptoManager {
    current_key: Arc<RwLock<CryptoKey>>,
    old_keys: Arc<RwLock<HashMap<u32, CryptoKey>>>,
    rng: SystemRandom,
    _default_algorithm: SymmetricAlgorithm,
    key_rotation_interval: chrono::Duration,
}

impl UnifiedCryptoManager {
    /// Create a new crypto manager with the specified algorithm
    pub fn new(algorithm: SymmetricAlgorithm) -> Result<Self, UnifiedCryptoError> {
        let key = Self::generate_key(algorithm, 1)?;
        Ok(Self {
            current_key: Arc::new(RwLock::new(key)),
            old_keys: Arc::new(RwLock::new(HashMap::new())),
            rng: SystemRandom::new(),
            _default_algorithm: algorithm,
            key_rotation_interval: chrono::Duration::days(30),
        })
    }

    /// Create a new crypto manager with AES-256-GCM (hardware accelerated)
    pub fn new_aes() -> Result<Self, UnifiedCryptoError> {
        Self::new(SymmetricAlgorithm::Aes256Gcm)
    }

    /// Create a new crypto manager with ChaCha20-Poly1305 (software only)
    pub fn new_chacha() -> Result<Self, UnifiedCryptoError> {
        Self::new(SymmetricAlgorithm::ChaCha20Poly1305)
    }

    /// Create manager from environment variable key
    pub fn from_env(algorithm: SymmetricAlgorithm) -> Result<Self, UnifiedCryptoError> {
        if let Ok(key_hex) = std::env::var("UNIFIED_ENCRYPTION_KEY") {
            let key_bytes =
                hex::decode(key_hex).map_err(|_| UnifiedCryptoError::InvalidKeyFormat)?;

            if key_bytes.len() != algorithm.key_length() {
                return Err(UnifiedCryptoError::InvalidKeyFormat);
            }

            let unbound_key = UnboundKey::new(algorithm.algorithm(), &key_bytes)
                .map_err(|_| UnifiedCryptoError::InvalidKeyFormat)?;
            let less_safe_key = LessSafeKey::new(unbound_key);

            let key = CryptoKey {
                key: less_safe_key,
                algorithm,
                version: 1,
                created_at: chrono::Utc::now(),
            };

            Ok(Self {
                current_key: Arc::new(RwLock::new(key)),
                old_keys: Arc::new(RwLock::new(HashMap::new())),
                rng: SystemRandom::new(),
                _default_algorithm: algorithm,
                key_rotation_interval: chrono::Duration::days(30),
            })
        } else {
            Self::new(algorithm)
        }
    }

    fn generate_key(
        algorithm: SymmetricAlgorithm,
        version: u32,
    ) -> Result<CryptoKey, UnifiedCryptoError> {
        let rng = SystemRandom::new();
        let mut key_bytes = vec![0u8; algorithm.key_length()];
        rng.fill(&mut key_bytes)
            .map_err(|_| UnifiedCryptoError::KeyGenerationFailed)?;

        let unbound_key = UnboundKey::new(algorithm.algorithm(), &key_bytes)
            .map_err(|_| UnifiedCryptoError::KeyGenerationFailed)?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        Ok(CryptoKey {
            key: less_safe_key,
            algorithm,
            version,
            created_at: chrono::Utc::now(),
        })
    }

    /// Encrypt data using the current key
    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData, UnifiedCryptoError> {
        let current_key = self.current_key.read().await;
        let algorithm = current_key.algorithm;

        // Generate random nonce
        let mut nonce_bytes = vec![0u8; algorithm.nonce_length()];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| UnifiedCryptoError::RandomGenerationFailed)?;

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| UnifiedCryptoError::EncryptionFailed("Invalid nonce".to_string()))?;

        // Create mutable copy for in-place encryption
        let mut in_out = plaintext.to_vec();

        current_key
            .key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| {
                UnifiedCryptoError::EncryptionFailed(format!("Ring encryption failed: {e:?}"))
            })?;

        Ok(EncryptedData {
            ciphertext: in_out,
            nonce: nonce_bytes,
            algorithm,
            key_version: current_key.version,
        })
    }

    /// Decrypt data using the appropriate key version
    pub async fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>, UnifiedCryptoError> {
        let key = if encrypted.key_version == self.current_key.read().await.version {
            self.current_key.read().await.key.clone()
        } else {
            let old_keys = self.old_keys.read().await;
            old_keys
                .get(&encrypted.key_version)
                .ok_or(UnifiedCryptoError::KeyNotFound(encrypted.key_version))?
                .key
                .clone()
        };

        let nonce = Nonce::try_assume_unique_for_key(&encrypted.nonce)
            .map_err(|_| UnifiedCryptoError::DecryptionFailed("Invalid nonce".to_string()))?;

        // Create mutable copy for in-place decryption
        let mut ciphertext = encrypted.ciphertext.clone();

        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut ciphertext)
            .map_err(|e| {
                UnifiedCryptoError::DecryptionFailed(format!("Ring decryption failed: {e:?}"))
            })?;

        Ok(plaintext.to_vec())
    }

    /// Get the current key version
    pub async fn current_key_version(&self) -> u32 {
        self.current_key.read().await.version
    }

    /// Rotate to a new encryption key
    pub async fn rotate_key(&self) -> Result<(), UnifiedCryptoError> {
        let mut current_key = self.current_key.write().await;
        let mut old_keys = self.old_keys.write().await;

        // Move current key to old keys
        let old_key = current_key.clone();
        old_keys.insert(old_key.version, old_key);

        // Generate new key with same algorithm
        let new_version = current_key.version + 1;
        *current_key = Self::generate_key(current_key.algorithm, new_version)?;

        tracing::info!(
            "Rotated encryption key from version {} to {} using {:?}",
            new_version - 1,
            new_version,
            current_key.algorithm
        );

        Ok(())
    }

    /// Check if key should be rotated based on age
    pub async fn should_rotate_key(&self) -> bool {
        let current_key = self.current_key.read().await;
        let age = chrono::Utc::now() - current_key.created_at;
        age > self.key_rotation_interval
    }

    /// Clean up old keys beyond the specified age
    pub async fn cleanup_old_keys(&self, max_age: chrono::Duration) {
        let mut old_keys = self.old_keys.write().await;
        let cutoff = chrono::Utc::now() - max_age;

        old_keys.retain(|_, key| key.created_at > cutoff);

        tracing::info!(
            "Cleaned up old encryption keys, {} keys remain",
            old_keys.len()
        );
    }
}

/// Unified hashing operations using ring
pub struct UnifiedHasher;

impl UnifiedHasher {
    /// SHA-1 hash (for legacy use only - TOTP compatibility)
    ///
    /// ⚠️  WARNING: SHA-1 is cryptographically broken for general use.
    /// This should only be used for TOTP compatibility where required by RFC 6238.
    #[must_use] pub fn sha1_legacy(data: &[u8]) -> Vec<u8> {
        digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, data)
            .as_ref()
            .to_vec()
    }

    /// SHA-256 hash
    #[must_use] pub fn sha256(data: &[u8]) -> Vec<u8> {
        digest::digest(&SHA256, data).as_ref().to_vec()
    }

    /// SHA-512 hash
    #[must_use] pub fn sha512(data: &[u8]) -> Vec<u8> {
        digest::digest(&SHA512, data).as_ref().to_vec()
    }

    /// SHA-256 hash of multiple inputs
    #[must_use] pub fn sha256_multi(inputs: &[&[u8]]) -> Vec<u8> {
        let mut context = digest::Context::new(&SHA256);
        for input in inputs {
            context.update(input);
        }
        context.finish().as_ref().to_vec()
    }
}

/// Unified HMAC operations using ring
pub struct UnifiedHmac;

impl UnifiedHmac {
    /// HMAC-SHA1 (for legacy use only - TOTP compatibility)
    ///
    /// ⚠️  WARNING: SHA-1 is cryptographically broken for general use.
    /// This should only be used for TOTP compatibility where required by RFC 6238.
    #[must_use] pub fn hmac_sha1_legacy(key: &[u8], data: &[u8]) -> Vec<u8> {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
        hmac::sign(&key, data).as_ref().to_vec()
    }

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

    /// Verify HMAC-SHA1 in constant time (for legacy use only)
    #[must_use] pub fn verify_hmac_sha1_legacy(key: &[u8], data: &[u8], expected_hmac: &[u8]) -> bool {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
        hmac::verify(&key, data, expected_hmac).is_ok()
    }

    /// Verify HMAC-SHA256 in constant time
    #[must_use] pub fn verify_hmac_sha256(key: &[u8], data: &[u8], expected_hmac: &[u8]) -> bool {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::verify(&key, data, expected_hmac).is_ok()
    }

    /// Verify HMAC-SHA512 in constant time
    #[must_use] pub fn verify_hmac_sha512(key: &[u8], data: &[u8], expected_hmac: &[u8]) -> bool {
        let key = hmac::Key::new(hmac::HMAC_SHA512, key);
        hmac::verify(&key, data, expected_hmac).is_ok()
    }
}

/// Secure random number generation using ring
pub struct UnifiedRandom;

impl UnifiedRandom {
    /// Generate cryptographically secure random bytes
    pub fn generate_bytes(length: usize) -> Result<Vec<u8>, UnifiedCryptoError> {
        let rng = SystemRandom::new();
        let mut bytes = vec![0u8; length];
        rng.fill(&mut bytes)
            .map_err(|_| UnifiedCryptoError::RandomGenerationFailed)?;
        Ok(bytes)
    }

    /// Generate a random 256-bit key
    pub fn generate_key() -> Result<Vec<u8>, UnifiedCryptoError> {
        Self::generate_bytes(32)
    }

    /// Generate a random nonce of specified length
    pub fn generate_nonce(length: usize) -> Result<Vec<u8>, UnifiedCryptoError> {
        Self::generate_bytes(length)
    }
}

impl Default for UnifiedCryptoManager {
    fn default() -> Self {
        Self::new_aes().expect("Failed to create default UnifiedCryptoManager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_aes_encrypt_decrypt_roundtrip() {
        let manager = UnifiedCryptoManager::new_aes().unwrap();
        let plaintext = b"test_secret_data_123";

        let encrypted = manager.encrypt(plaintext).await.unwrap();
        let decrypted = manager.decrypt(&encrypted).await.unwrap();

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
        assert_eq!(encrypted.algorithm, SymmetricAlgorithm::Aes256Gcm);
    }

    #[tokio::test]
    async fn test_chacha_encrypt_decrypt_roundtrip() {
        let manager = UnifiedCryptoManager::new_chacha().unwrap();
        let plaintext = b"test_secret_data_123";

        let encrypted = manager.encrypt(plaintext).await.unwrap();
        let decrypted = manager.decrypt(&encrypted).await.unwrap();

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
        assert_eq!(encrypted.algorithm, SymmetricAlgorithm::ChaCha20Poly1305);
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let manager = UnifiedCryptoManager::new_aes().unwrap();
        let plaintext = b"test_secret";

        // Encrypt with initial key
        let encrypted_v1 = manager.encrypt(plaintext).await.unwrap();
        assert_eq!(encrypted_v1.key_version, 1);

        // Rotate key
        manager.rotate_key().await.unwrap();

        // Encrypt with new key
        let encrypted_v2 = manager.encrypt(plaintext).await.unwrap();
        assert_eq!(encrypted_v2.key_version, 2);

        // Should be able to decrypt both
        let decrypted_v1 = manager.decrypt(&encrypted_v1).await.unwrap();
        let decrypted_v2 = manager.decrypt(&encrypted_v2).await.unwrap();

        assert_eq!(plaintext.as_ref(), decrypted_v1.as_slice());
        assert_eq!(plaintext.as_ref(), decrypted_v2.as_slice());
    }

    #[test]
    fn test_unified_hashing() {
        let data = b"test data";

        let hash256 = UnifiedHasher::sha256(data);
        let hash512 = UnifiedHasher::sha512(data);

        assert_eq!(hash256.len(), 32); // SHA-256 output length
        assert_eq!(hash512.len(), 64); // SHA-512 output length

        // Same input should produce same hash
        let hash256_again = UnifiedHasher::sha256(data);
        assert_eq!(hash256, hash256_again);
    }

    #[test]
    fn test_unified_hmac() {
        let key = b"secret_key";
        let data = b"test data";

        let hmac1 = UnifiedHmac::hmac_sha1_legacy(key, data);
        let hmac256 = UnifiedHmac::hmac_sha256(key, data);
        let hmac512 = UnifiedHmac::hmac_sha512(key, data);

        assert_eq!(hmac1.len(), 20); // HMAC-SHA1 output length
        assert_eq!(hmac256.len(), 32); // HMAC-SHA256 output length
        assert_eq!(hmac512.len(), 64); // HMAC-SHA512 output length

        // Verification should work
        assert!(UnifiedHmac::verify_hmac_sha1_legacy(key, data, &hmac1));
        assert!(UnifiedHmac::verify_hmac_sha256(key, data, &hmac256));
        assert!(UnifiedHmac::verify_hmac_sha512(key, data, &hmac512));

        // Wrong key should fail verification
        let wrong_key = b"wrong_key";
        assert!(!UnifiedHmac::verify_hmac_sha256(wrong_key, data, &hmac256));
    }

    #[test]
    fn test_unified_random() {
        let bytes1 = UnifiedRandom::generate_bytes(32).unwrap();
        let bytes2 = UnifiedRandom::generate_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different

        let key = UnifiedRandom::generate_key().unwrap();
        assert_eq!(key.len(), 32);
    }

    #[tokio::test]
    async fn test_different_algorithms_compatibility() {
        // Test that we can't decrypt AES data with ChaCha manager and vice versa
        let aes_manager = UnifiedCryptoManager::new_aes().unwrap();
        let chacha_manager = UnifiedCryptoManager::new_chacha().unwrap();

        let plaintext = b"test data";

        let aes_encrypted = aes_manager.encrypt(plaintext).await.unwrap();
        let chacha_encrypted = chacha_manager.encrypt(plaintext).await.unwrap();

        // Each should decrypt its own
        assert!(aes_manager.decrypt(&aes_encrypted).await.is_ok());
        assert!(chacha_manager.decrypt(&chacha_encrypted).await.is_ok());

        // But not the other's (will fail due to key version mismatch)
        assert!(aes_manager.decrypt(&chacha_encrypted).await.is_err());
        assert!(chacha_manager.decrypt(&aes_encrypted).await.is_err());
    }
}
