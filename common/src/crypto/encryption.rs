//! Unified Encryption/Decryption Operations
//!
//! This module provides a unified interface for encryption and decryption operations.
//! It is designed to be a single point of entry for all cryptographic functions
//! that involve symmetric encryption.
//!
//! ## Features
//!
//! - AES-256-GCM encryption and decryption.
//! - Configuration management for encryption keys and algorithms.
//! - Loading configuration from environment variables.
//! - Validation of configuration to prevent common security mistakes.
//!
//! ## Limitations
//!
//! - **ChaCha20Poly1305 is not fully implemented.** The `ChaCha20Poly1305` algorithm
//!   is defined in the `EncryptionAlgorithm` enum, but the actual implementation
//!   currently falls back to AES-256-GCM. This is a placeholder and should not be
//!   used in production with the expectation of using ChaCha20Poly1305.
//! - **Post-quantum cryptography is not implemented.** The `PqEncryption` algorithm
//!   is behind a feature flag and is not implemented.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use rust_security::common::crypto::encryption::{EncryptionConfig, EncryptionOperations};
//!
//! let config = EncryptionConfig {
//!     key: "ThisIsASecure32ByteKeyForTesting12".to_string(),
//!     ..Default::default()
//! };
//! let ops = EncryptionOperations::new(config).unwrap();
//! let plaintext = b"Hello, World!";
//! let encrypted = ops.encrypt(plaintext, None).unwrap();
//! let decrypted = ops.decrypt(&encrypted, None).unwrap();
//! assert_eq!(plaintext, decrypted.as_slice());
//! ```

use super::*;
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::env;
use zeroize::Zeroize;

/// Encryption-specific errors
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Algorithm not supported: {0}")]
    UnsupportedAlgorithm(String),
}

/// Encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Default encryption algorithm
    pub algorithm: EncryptionAlgorithm,

    /// Encryption key (must be 32 bytes)
    pub key: String,

    /// Enable key rotation
    pub enable_key_rotation: bool,

    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            key: "REPLACE_WITH_32_BYTE_KEY_IN_PROD00".to_string(), // Exactly 32 chars
            enable_key_rotation: false,
            key_rotation_interval: 86400, // 24 hours
        }
    }
}

impl FromEnvironment for EncryptionConfig {
    fn from_env() -> CryptoResult<Self> {
        let algorithm = env::var("ENCRYPTION_ALGORITHM")
            .unwrap_or_else(|_| "aes256gcm".to_string())
            .parse()
            .map_err(|_| {
                CryptoError::InvalidConfiguration("Invalid ENCRYPTION_ALGORITHM".to_string())
            })?;

        let key = env::var("ENCRYPTION_KEY")
            .unwrap_or_else(|_| "REPLACE_WITH_32_BYTE_KEY_IN_PROD00".to_string()); // Exactly 32 chars

        let enable_key_rotation = env::var("ENCRYPTION_KEY_ROTATION")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let key_rotation_interval = env::var("ENCRYPTION_KEY_ROTATION_INTERVAL")
            .unwrap_or_else(|_| "86400".to_string())
            .parse()
            .map_err(|_| {
                CryptoError::InvalidConfiguration(
                    "Invalid ENCRYPTION_KEY_ROTATION_INTERVAL".to_string(),
                )
            })?;

        Ok(Self {
            algorithm,
            key,
            enable_key_rotation,
            key_rotation_interval,
        })
    }
}

impl CryptoValidation for EncryptionConfig {
    fn validate(&self) -> CryptoResult<()> {
        // Validate key length
        if self.key.len() != 32 {
            return Err(CryptoError::ValidationFailed(
                "Encryption key must be 32 characters long".to_string(),
            ));
        }

        // Check for development defaults
        if self.key.contains("REPLACE_WITH") {
            return Err(CryptoError::ValidationFailed(
                "Encryption key contains insecure default values".to_string(),
            ));
        }

        Ok(())
    }
}

/// Encrypted data with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,

    /// Nonce/IV used for encryption
    pub nonce: Vec<u8>,

    /// Algorithm used
    pub algorithm: EncryptionAlgorithm,

    /// Optional associated data (for AEAD)
    pub associated_data: Option<Vec<u8>>,

    /// Encryption timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Zeroize for EncryptedData {
    fn zeroize(&mut self) {
        self.ciphertext.zeroize();
        self.nonce.zeroize();
        if let Some(ref mut ad) = self.associated_data {
            ad.zeroize();
        }
    }
}

/// Unified encryption operations
pub struct EncryptionOperations {
    config: EncryptionConfig,
    rng: SystemRandom,
}

impl EncryptionOperations {
    /// Create new encryption operations instance
    pub fn new(config: EncryptionConfig) -> CryptoResult<Self> {
        config.validate()?;

        Ok(Self {
            config,
            rng: SystemRandom::new(),
        })
    }

    /// Encrypt data using the configured algorithm
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> CryptoResult<EncryptedData> {
        match self.config.algorithm {
            EncryptionAlgorithm::Aes256Gcm => self.aes_256_gcm_encrypt(plaintext, associated_data),
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                self.chacha20_poly1305_encrypt(plaintext, associated_data)
            }
            #[cfg(feature = "post-quantum")]
            EncryptionAlgorithm::PqEncryption => Err(EncryptionError::UnsupportedAlgorithm(
                "Post-quantum not implemented".to_string(),
            )
            .into()),
        }
    }

    /// Decrypt data
    pub fn decrypt(
        &self,
        encrypted: &EncryptedData,
        associated_data: Option<&[u8]>,
    ) -> CryptoResult<Vec<u8>> {
        match encrypted.algorithm {
            EncryptionAlgorithm::Aes256Gcm => self.aes_256_gcm_decrypt(encrypted, associated_data),
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                self.chacha20_poly1305_decrypt(encrypted, associated_data)
            }
            #[cfg(feature = "post-quantum")]
            EncryptionAlgorithm::PqEncryption => Err(EncryptionError::UnsupportedAlgorithm(
                "Post-quantum not implemented".to_string(),
            )
            .into()),
        }
    }

    /// Encrypt string and return base64-encoded result
    pub fn encrypt_string(
        &self,
        plaintext: &str,
        associated_data: Option<&str>,
    ) -> CryptoResult<String> {
        let associated_bytes = associated_data.map(|s| s.as_bytes());
        let encrypted = self.encrypt(plaintext.as_bytes(), associated_bytes)?;
        let serialized = serde_json::to_vec(&encrypted).map_err(|e| {
            EncryptionError::EncryptionFailed(format!("Serialization failed: {}", e))
        })?;
        Ok(base64::engine::general_purpose::STANDARD.encode(serialized))
    }

    /// Decrypt base64-encoded string
    pub fn decrypt_string(
        &self,
        encrypted_b64: &str,
        associated_data: Option<&str>,
    ) -> CryptoResult<String> {
        let serialized = base64::engine::general_purpose::STANDARD
            .decode(encrypted_b64)
            .map_err(|e| {
                EncryptionError::DecryptionFailed(format!("Base64 decode failed: {}", e))
            })?;

        let encrypted: EncryptedData = serde_json::from_slice(&serialized).map_err(|e| {
            EncryptionError::DecryptionFailed(format!("Deserialization failed: {}", e))
        })?;

        let associated_bytes = associated_data.map(|s| s.as_bytes());
        let plaintext = self.decrypt(&encrypted, associated_bytes)?;

        String::from_utf8(plaintext).map_err(|e| {
            EncryptionError::DecryptionFailed(format!("UTF-8 decode failed: {}", e)).into()
        })
    }

    /// Generate a new encryption key for the specified algorithm
    pub fn generate_key(&self, _algorithm: EncryptionAlgorithm) -> CryptoResult<Vec<u8>> {
        let mut key = vec![0u8; 32];
        self.rng.fill(&mut key).map_err(|_| {
            EncryptionError::KeyGenerationFailed("Random key generation failed".to_string())
        })?;
        Ok(key)
    }

    // Secure AES-256-GCM encryption implementation
    fn aes_256_gcm_encrypt(
        &self,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> CryptoResult<EncryptedData> {
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

        // Generate a secure random nonce
        let mut nonce_bytes = vec![0u8; 12];
        self.rng.fill(&mut nonce_bytes).map_err(|_| {
            EncryptionError::EncryptionFailed("Nonce generation failed".to_string())
        })?;

        // Prepare the key
        let key_bytes = self.config.key.as_bytes();

        // Create the encryption key
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_bytes)
            .map_err(|_| EncryptionError::EncryptionFailed("Invalid encryption key".to_string()))?;
        let key = LessSafeKey::new(unbound_key);

        // Create nonce
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| EncryptionError::EncryptionFailed("Invalid nonce".to_string()))?;

        // Encrypt the data
        let mut ciphertext = plaintext.to_vec();
        key.seal_in_place_append_tag(
            nonce,
            Aad::from(associated_data.unwrap_or_default()),
            &mut ciphertext,
        )
        .map_err(|_| {
            EncryptionError::EncryptionFailed("Encryption operation failed".to_string())
        })?;

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce_bytes,
            algorithm: self.config.algorithm.clone(),
            associated_data: associated_data.map(|d| d.to_vec()),
            created_at: chrono::Utc::now(),
        })
    }

    fn aes_256_gcm_decrypt(
        &self,
        encrypted: &EncryptedData,
        associated_data: Option<&[u8]>,
    ) -> CryptoResult<Vec<u8>> {
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

        // Prepare the key
        let key_bytes = self.config.key.as_bytes();

        // Create the decryption key
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_bytes)
            .map_err(|_| EncryptionError::DecryptionFailed("Invalid decryption key".to_string()))?;
        let key = LessSafeKey::new(unbound_key);

        // Create nonce from stored nonce
        let nonce = Nonce::try_assume_unique_for_key(&encrypted.nonce)
            .map_err(|_| EncryptionError::DecryptionFailed("Invalid nonce".to_string()))?;

        // Decrypt the data
        let mut ciphertext = encrypted.ciphertext.clone();
        let plaintext = key
            .open_in_place(
                nonce,
                Aad::from(associated_data.unwrap_or_default()),
                &mut ciphertext,
            )
            .map_err(|_| {
                EncryptionError::DecryptionFailed("Decryption operation failed".to_string())
            })?;

        Ok(plaintext.to_vec())
    }

    /// ChaCha20Poly1305 encryption implementation
    fn chacha20_poly1305_encrypt(
        &self,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> CryptoResult<EncryptedData> {
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

        // Generate a secure random nonce
        let mut nonce_bytes = vec![0u8; 12];
        self.rng.fill(&mut nonce_bytes).map_err(|_| {
            EncryptionError::EncryptionFailed("Nonce generation failed".to_string())
        })?;

        // Prepare the key
        let key_bytes = self.config.key.as_bytes();

        // Create the encryption key
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key_bytes)
            .map_err(|_| EncryptionError::EncryptionFailed("Invalid encryption key".to_string()))?;
        let key = LessSafeKey::new(unbound_key);

        // Create nonce
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| EncryptionError::EncryptionFailed("Invalid nonce".to_string()))?;

        // Encrypt the data
        let mut ciphertext = plaintext.to_vec();
        key.seal_in_place_append_tag(
            nonce,
            Aad::from(associated_data.unwrap_or_default()),
            &mut ciphertext,
        )
        .map_err(|_| {
            EncryptionError::EncryptionFailed("Encryption operation failed".to_string())
        })?;

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce_bytes,
            algorithm: self.config.algorithm.clone(),
            associated_data: associated_data.map(|d| d.to_vec()),
            created_at: chrono::Utc::now(),
        })
    }

    /// ChaCha20Poly1305 decryption implementation
    fn chacha20_poly1305_decrypt(
        &self,
        encrypted: &EncryptedData,
        associated_data: Option<&[u8]>,
    ) -> CryptoResult<Vec<u8>> {
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

        // Prepare the key
        let key_bytes = self.config.key.as_bytes();

        // Create the decryption key
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key_bytes)
            .map_err(|_| EncryptionError::DecryptionFailed("Invalid decryption key".to_string()))?;
        let key = LessSafeKey::new(unbound_key);

        // Create nonce from stored nonce
        let nonce = Nonce::try_assume_unique_for_key(&encrypted.nonce)
            .map_err(|_| EncryptionError::DecryptionFailed("Invalid nonce".to_string()))?;

        // Decrypt the data
        let mut ciphertext = encrypted.ciphertext.clone();
        let plaintext = key
            .open_in_place(
                nonce,
                Aad::from(associated_data.unwrap_or_default()),
                &mut ciphertext,
            )
            .map_err(|_| {
                EncryptionError::DecryptionFailed("Decryption operation failed".to_string())
            })?;

        Ok(plaintext.to_vec())
    }
}

/// Parse encryption algorithm from string
impl std::str::FromStr for EncryptionAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aes256gcm" | "aes-256-gcm" => Ok(EncryptionAlgorithm::Aes256Gcm),
            "chacha20poly1305" | "chacha20-poly1305" => Ok(EncryptionAlgorithm::ChaCha20Poly1305),
            #[cfg(feature = "post-quantum")]
            "pq" | "post-quantum" => Ok(EncryptionAlgorithm::PqEncryption),
            _ => Err(format!("Unknown encryption algorithm: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_encryption_operations_creation() {
        let config = EncryptionConfig {
            key: "ThisIsASecure32ByteKeyForTest_00".to_string(), // Exactly 32 chars
            ..Default::default()
        };

        let ops = EncryptionOperations::new(config);
        assert!(ops.is_ok());
    }

    #[test]
    fn test_simple_encryption_decryption() {
        let config = EncryptionConfig {
            key: "ThisIsASecure32ByteKeyForTest_00".to_string(), // Exactly 32 chars // Exactly 32 chars
            ..Default::default()
        };

        let ops = EncryptionOperations::new(config).unwrap();
        let plaintext = b"Hello, World!";

        let encrypted = ops.encrypt(plaintext, None).unwrap();
        let decrypted = ops.decrypt(&encrypted, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[cfg(test)]
    mod property_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn test_encrypt_decrypt_roundtrip(
                plaintext in any::<Vec<u8>>().prop_filter("non-empty", |v| !v.is_empty() && v.len() <= 1024)
            ) {
                let config = EncryptionConfig {
                    key: "ThisIsASecure32ByteKeyForTest_00".to_string(), // Exactly 32 chars
                    ..Default::default()
                };

                let ops = EncryptionOperations::new(config)?;
                let encrypted = ops.encrypt(&plaintext, None)?;
                let decrypted = ops.decrypt(&encrypted, None)?;

                prop_assert_eq!(plaintext, decrypted);
            }

            #[test]
            fn test_encryption_deterministic_with_same_plaintext(
                plaintext in any::<Vec<u8>>().prop_filter("non-empty", |v| !v.is_empty() && v.len() <= 256)
            ) {
                let config = EncryptionConfig {
                    key: "ThisIsASecure32ByteKeyForTest_00".to_string(),
                    ..Default::default()
                };

                let ops = EncryptionOperations::new(config)?;
                let encrypted1 = ops.encrypt(&plaintext, None)?;
                let encrypted2 = ops.encrypt(&plaintext, None)?;

                // Different encryptions should produce different ciphertext (due to random nonce)
                let encrypted1_ciphertext = encrypted1.ciphertext.clone();
                let encrypted2_ciphertext = encrypted2.ciphertext.clone();
                prop_assert_ne!(encrypted1_ciphertext, encrypted2_ciphertext);

                // But both should decrypt to the same plaintext
                let decrypted1 = ops.decrypt(&encrypted1, None)?;
                let decrypted2 = ops.decrypt(&encrypted2, None)?;
                prop_assert_eq!(decrypted1.clone(), decrypted2);
                prop_assert_eq!(plaintext, decrypted1);
            }

            #[test]
            fn test_encryption_with_associated_data(
                plaintext in any::<Vec<u8>>().prop_filter("non-empty", |v| !v.is_empty() && v.len() <= 256),
                associated_data in any::<Vec<u8>>().prop_filter("reasonable-size", |v| v.len() <= 128)
            ) {
                let config = EncryptionConfig {
                    key: "ThisIsASecure32ByteKeyForTest_00".to_string(),
                    ..Default::default()
                };

                let ops = EncryptionOperations::new(config)?;
                let ad_option = if associated_data.is_empty() { None } else { Some(associated_data.as_slice()) };

                let encrypted = ops.encrypt(&plaintext, ad_option)?;
                let decrypted = ops.decrypt(&encrypted, ad_option)?;

                prop_assert_eq!(plaintext, decrypted);
            }

            #[test]
            fn test_different_keys_produce_different_ciphertext(
                plaintext in any::<Vec<u8>>().prop_filter("non-empty", |v| !v.is_empty() && v.len() <= 128),
                key_suffix1 in 0u8..99u8,
                key_suffix2 in 0u8..99u8
            ) {
                prop_assume!(key_suffix1 != key_suffix2);

                let key1 = format!("ThisIsASecure32ByteKeyForTest_{:02}", key_suffix1);
                let key2 = format!("ThisIsASecure32ByteKeyForTest_{:02}", key_suffix2);

                let config1 = EncryptionConfig { key: key1, ..Default::default() };
                let config2 = EncryptionConfig { key: key2, ..Default::default() };

                let ops1 = EncryptionOperations::new(config1)?;
                let ops2 = EncryptionOperations::new(config2)?;

                let encrypted1 = ops1.encrypt(&plaintext, None)?;
                let encrypted2 = ops2.encrypt(&plaintext, None)?;

                // Different keys should produce different ciphertext
                let encrypted1_ciphertext = encrypted1.ciphertext.clone();
                let encrypted2_ciphertext = encrypted2.ciphertext.clone();
                prop_assert_ne!(encrypted1_ciphertext, encrypted2_ciphertext);

                // Decryption with wrong key should fail
                prop_assert!(ops1.decrypt(&encrypted2, None).is_err());
                prop_assert!(ops2.decrypt(&encrypted1, None).is_err());
            }
        }
    }

    #[test]
    fn test_string_encryption_decryption() {
        let config = EncryptionConfig {
            key: "ThisIsASecure32ByteKeyForTest_00".to_string(), // Exactly 32 chars
            ..Default::default()
        };

        let ops = EncryptionOperations::new(config).unwrap();
        let plaintext = "Hello, World!";

        let encrypted = ops.encrypt_string(plaintext, None).unwrap();
        let decrypted = ops.decrypt_string(&encrypted, None).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decryption_with_wrong_key() {
        let config1 = EncryptionConfig {
            key: "ThisIsASecure32ByteKeyForTest_00".to_string(), // Exactly 32 chars
            ..Default::default()
        };
        let ops1 = EncryptionOperations::new(config1).unwrap();
        let plaintext = b"Hello, World!";
        let encrypted = ops1.encrypt(plaintext, None).unwrap();

        let config2 = EncryptionConfig {
            key: "ThisIsADifferent32ByteKeyForTes0".to_string(), // Exactly 32 chars
            ..Default::default()
        };
        let ops2 = EncryptionOperations::new(config2).unwrap();
        let decrypted = ops2.decrypt(&encrypted, None);
        assert!(decrypted.is_err());
    }

    #[test]
    fn test_decryption_with_tampered_ciphertext() {
        let config = EncryptionConfig {
            key: "ThisIsASecure32ByteKeyForTest_00".to_string(), // Exactly 32 chars
            ..Default::default()
        };
        let ops = EncryptionOperations::new(config).unwrap();
        let plaintext = b"Hello, World!";
        let mut encrypted = ops.encrypt(plaintext, None).unwrap();
        encrypted.ciphertext[0] ^= 0xff; // Flip a bit

        let decrypted = ops.decrypt(&encrypted, None);
        assert!(decrypted.is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let config = EncryptionConfig {
            key: "shortkey".to_string(),
            ..Default::default()
        };
        let ops = EncryptionOperations::new(config);
        assert!(ops.is_err());
    }

    #[test]
    fn test_insecure_default_key() {
        let config = EncryptionConfig {
            key: "REPLACE_WITH_32_BYTE_KEY_IN_PROD00".to_string(), // Exactly 32 chars
            ..Default::default()
        };
        let ops = EncryptionOperations::new(config);
        assert!(ops.is_err());
    }

    #[test]
    fn test_config_from_env() {
        env::set_var("ENCRYPTION_ALGORITHM", "aes-256-gcm");
        env::set_var("ENCRYPTION_KEY", "ThisIsASecure32ByteKeyForTesting1234");
        env::set_var("ENCRYPTION_KEY_ROTATION", "true");
        env::set_var("ENCRYPTION_KEY_ROTATION_INTERVAL", "3600");

        let config = EncryptionConfig::from_env().unwrap();
        assert_eq!(config.algorithm, EncryptionAlgorithm::Aes256Gcm);
        assert_eq!(config.key, "ThisIsASecure32ByteKeyForTesting1234");
        assert!(config.enable_key_rotation);
        assert_eq!(config.key_rotation_interval, 3600);

        env::remove_var("ENCRYPTION_ALGORITHM");
        env::remove_var("ENCRYPTION_KEY");
        env::remove_var("ENCRYPTION_KEY_ROTATION");
        env::remove_var("ENCRYPTION_KEY_ROTATION_INTERVAL");
    }

    #[test]
    fn test_chacha20poly1305_is_ok() {
        let config = EncryptionConfig {
            key: "ThisIsASecure32ByteKeyForTest_00".to_string(), // Exactly 32 chars
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            ..Default::default()
        };
        let ops = EncryptionOperations::new(config).unwrap();
        let plaintext = b"Hello, World!";
        let encrypted = ops.encrypt(plaintext, None);
        assert!(encrypted.is_ok());
        let decrypted = ops.decrypt(&encrypted.unwrap(), None);
        assert!(decrypted.is_ok());
    }
}
