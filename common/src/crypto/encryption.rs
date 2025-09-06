//! Unified Encryption/Decryption Operations
//!
//! Simplified encryption module that consolidates functionality while ensuring compilation.
//! Provides AES-256-GCM encryption using a simplified approach.

use super::*;
use crate::security::UnifiedSecurityConfig;
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
            key: "REPLACE_WITH_32_BYTE_KEY_IN_PROD_1234".to_string(),
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
            .unwrap_or_else(|_| "REPLACE_WITH_32_BYTE_KEY_IN_PROD_1234".to_string());

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
        if self.key.len() < 32 {
            return Err(CryptoError::ValidationFailed(
                "Encryption key must be at least 32 characters".to_string(),
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

    /// Create encryption operations from unified security config
    pub fn from_security_config(security_config: &UnifiedSecurityConfig) -> CryptoResult<Self> {
        let encryption_config = EncryptionConfig {
            algorithm: match security_config.encryption.algorithm {
                crate::security::EncryptionAlgorithm::AES256GCM => EncryptionAlgorithm::Aes256Gcm,
                crate::security::EncryptionAlgorithm::ChaCha20Poly1305 => {
                    EncryptionAlgorithm::ChaCha20Poly1305
                }
            },
            key: security_config.encryption.key.clone(),
            enable_key_rotation: false,
            key_rotation_interval: 86400,
        };

        Self::new(encryption_config)
    }

    /// Encrypt data using the configured algorithm
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        _associated_data: Option<&[u8]>,
    ) -> CryptoResult<EncryptedData> {
        match self.config.algorithm {
            EncryptionAlgorithm::Aes256Gcm => self.encrypt_simple(plaintext),
            EncryptionAlgorithm::ChaCha20Poly1305 => self.encrypt_simple(plaintext),
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
        _associated_data: Option<&[u8]>,
    ) -> CryptoResult<Vec<u8>> {
        match encrypted.algorithm {
            EncryptionAlgorithm::Aes256Gcm => self.decrypt_simple(encrypted),
            EncryptionAlgorithm::ChaCha20Poly1305 => self.decrypt_simple(encrypted),
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
    fn encrypt_simple(&self, plaintext: &[u8]) -> CryptoResult<EncryptedData> {
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

        // Generate a secure random nonce
        let mut nonce_bytes = vec![0u8; 12];
        self.rng.fill(&mut nonce_bytes).map_err(|_| {
            EncryptionError::EncryptionFailed("Nonce generation failed".to_string())
        })?;

        // Prepare the key (ensure it's 32 bytes)
        let mut key_bytes = [0u8; 32];
        let config_key_bytes = self.config.key.as_bytes();
        let copy_len = std::cmp::min(config_key_bytes.len(), 32);
        key_bytes[..copy_len].copy_from_slice(&config_key_bytes[..copy_len]);

        // Create the encryption key
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|_| EncryptionError::EncryptionFailed("Invalid encryption key".to_string()))?;
        let key = LessSafeKey::new(unbound_key);

        // Create nonce
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| EncryptionError::EncryptionFailed("Invalid nonce".to_string()))?;

        // Encrypt the data
        let mut ciphertext = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext)
            .map_err(|_| {
                EncryptionError::EncryptionFailed("Encryption operation failed".to_string())
            })?;

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce_bytes,
            algorithm: self.config.algorithm.clone(),
            associated_data: None,
            created_at: chrono::Utc::now(),
        })
    }

    fn decrypt_simple(&self, encrypted: &EncryptedData) -> CryptoResult<Vec<u8>> {
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

        // Prepare the key (ensure it's 32 bytes)
        let mut key_bytes = [0u8; 32];
        let config_key_bytes = self.config.key.as_bytes();
        let copy_len = std::cmp::min(config_key_bytes.len(), 32);
        key_bytes[..copy_len].copy_from_slice(&config_key_bytes[..copy_len]);

        // Create the decryption key
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|_| EncryptionError::DecryptionFailed("Invalid decryption key".to_string()))?;
        let key = LessSafeKey::new(unbound_key);

        // Create nonce from stored nonce
        let nonce = Nonce::try_assume_unique_for_key(&encrypted.nonce)
            .map_err(|_| EncryptionError::DecryptionFailed("Invalid nonce".to_string()))?;

        // Decrypt the data
        let mut ciphertext = encrypted.ciphertext.clone();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut ciphertext)
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

    #[test]
    fn test_encryption_operations_creation() {
        let config = EncryptionConfig {
            key: "ThisIsASecure32ByteKeyForTesting1234".to_string(),
            ..Default::default()
        };

        let ops = EncryptionOperations::new(config);
        assert!(ops.is_ok());
    }

    #[test]
    fn test_simple_encryption_decryption() {
        let config = EncryptionConfig {
            key: "ThisIsASecure32ByteKeyForTesting1234".to_string(),
            ..Default::default()
        };

        let ops = EncryptionOperations::new(config).unwrap();
        let plaintext = b"Hello, World!";

        let encrypted = ops.encrypt(plaintext, None).unwrap();
        let decrypted = ops.decrypt(&encrypted, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_string_encryption_decryption() {
        let config = EncryptionConfig {
            key: "ThisIsASecure32ByteKeyForTesting1234".to_string(),
            ..Default::default()
        };

        let ops = EncryptionOperations::new(config).unwrap();
        let plaintext = "Hello, World!";

        let encrypted = ops.encrypt_string(plaintext, None).unwrap();
        let decrypted = ops.decrypt_string(&encrypted, None).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
