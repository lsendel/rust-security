//! Shared cryptographic utilities
//!
//! This module provides centralized cryptographic functions to eliminate
//! code duplication across the authentication service.

use crate::constants::crypto;
use base64::Engine;
use ring::{digest, hmac, rand::SecureRandom as RingSecureRandom, rand::SystemRandom};
use thiserror::Error;

/// Cryptographic errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Random number generation failed")]
    RandomGenerationFailed,
    #[error("Invalid input length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Hash verification failed")]
    HashVerificationFailed,
}

/// Secure random number generator
pub struct SecureRandom {
    rng: SystemRandom,
}

impl SecureRandom {
    /// Create a new secure random number generator
    #[must_use]
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }

    /// Generate secure random bytes
    ///
    /// # Errors
    /// Returns `CryptoError::RandomGenerationFailed` if the underlying RNG fails
    pub fn generate_bytes(&self, len: usize) -> Result<Vec<u8>, CryptoError> {
        let mut bytes = vec![0u8; len];
        RingSecureRandom::fill(&self.rng, &mut bytes)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;
        Ok(bytes)
    }

    /// Generate secure random string (base64url encoded)
    ///
    /// # Errors
    /// Returns `CryptoError::RandomGenerationFailed` if the underlying RNG fails
    pub fn generate_string(&self, byte_len: usize) -> Result<String, CryptoError> {
        let bytes = self.generate_bytes(byte_len)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Generate secure session ID
    ///
    /// # Errors
    /// Returns `CryptoError::RandomGenerationFailed` if the underlying RNG fails
    pub fn generate_session_id(&self) -> Result<String, CryptoError> {
        self.generate_string(32) // 256 bits of entropy
    }

    /// Generate secure API key
    ///
    /// # Errors
    /// Returns `CryptoError::RandomGenerationFailed` if the underlying RNG fails
    pub fn generate_api_key(&self) -> Result<String, CryptoError> {
        let bytes = self.generate_bytes(32)?;
        Ok(format!("sk_{}", hex::encode(bytes)))
    }
}

impl Default for SecureRandom {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash a token using SHA-256
#[must_use]
pub fn hash_token(token: &str) -> String {
    let digest = digest::digest(&digest::SHA256, token.as_bytes());
    hex::encode(digest.as_ref())
}

/// Hash a password using SHA-256 (for backwards compatibility)
/// Note: This should be replaced with Argon2 for new implementations
#[must_use]
pub fn hash_password_sha256(password: &str) -> String {
    let digest = digest::digest(&digest::SHA256, password.as_bytes());
    hex::encode(digest.as_ref())
}

/// Hash a secret using SHA-256
#[must_use]
pub fn hash_secret(secret: &str) -> String {
    let digest = digest::digest(&digest::SHA256, secret.as_bytes());
    hex::encode(digest.as_ref())
}

/// Hash a backup code using SHA-256
#[must_use]
pub fn hash_backup_code(code: &str) -> String {
    hash_token(code) // Reuse the same implementation
}

/// Hash an OTP using SHA-256
#[must_use]
pub fn hash_otp(otp: &str) -> String {
    hash_token(otp) // Reuse the same implementation
}

/// Hash a user agent string using SHA-256
#[must_use]
pub fn hash_user_agent(user_agent: &str) -> String {
    hash_token(user_agent) // Reuse the same implementation
}

/// Generate HMAC-SHA256 signature
///
/// # Errors
/// Returns `CryptoError::InvalidLength` if the key is too short (less than 32 bytes)
pub fn generate_hmac_signature(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() < crypto::HMAC_KEY_MIN_SIZE {
        return Err(CryptoError::InvalidLength {
            expected: crypto::HMAC_KEY_MIN_SIZE,
            actual: key.len(),
        });
    }

    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let signature = hmac::sign(&hmac_key, data);
    Ok(signature.as_ref().to_vec())
}

/// Verify HMAC-SHA256 signature
///
/// # Errors
/// Returns `CryptoError::InvalidLength` if the key is too short (less than 32 bytes)
pub fn verify_hmac_signature(
    key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    if key.len() < crypto::HMAC_KEY_MIN_SIZE {
        return Err(CryptoError::InvalidLength {
            expected: crypto::HMAC_KEY_MIN_SIZE,
            actual: key.len(),
        });
    }

    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    match hmac::verify(&hmac_key, data, signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generate a secure salt for password hashing
///
/// # Errors
/// Returns `CryptoError::RandomGenerationFailed` if the underlying RNG fails
pub fn generate_salt() -> Result<Vec<u8>, CryptoError> {
    let rng = SecureRandom::new();
    rng.generate_bytes(crypto::DEFAULT_SALT_LENGTH)
}

/// Generate a secure salt as a hex string
///
/// # Errors
/// Returns `CryptoError::RandomGenerationFailed` if the underlying RNG fails
pub fn generate_salt_hex() -> Result<String, CryptoError> {
    let salt = generate_salt()?;
    Ok(hex::encode(salt))
}

/// Constant-time comparison of byte slices
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq::constant_time_eq(a, b)
}

/// Constant-time comparison of strings
#[must_use]
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Hash input data with optional salt
#[must_use]
pub fn hash_with_salt(data: &[u8], salt: Option<&[u8]>) -> String {
    let mut hasher_input = Vec::new();

    if let Some(salt) = salt {
        hasher_input.extend_from_slice(salt);
        hasher_input.push(0xFF); // Separator
    }

    hasher_input.extend_from_slice(data);

    let digest = digest::digest(&digest::SHA256, &hasher_input);
    hex::encode(digest.as_ref())
}

/// Validate hash format (hex string)
#[must_use]
pub fn is_valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Hash utilities for different data types
pub trait Hashable {
    fn hash(&self) -> String;
    fn hash_with_salt(&self, salt: &[u8]) -> String;
}

impl Hashable for str {
    fn hash(&self) -> String {
        hash_token(self)
    }

    fn hash_with_salt(&self, salt: &[u8]) -> String {
        hash_with_salt(self.as_bytes(), Some(salt))
    }
}

impl Hashable for String {
    fn hash(&self) -> String {
        self.as_str().hash()
    }

    fn hash_with_salt(&self, salt: &[u8]) -> String {
        self.as_str().hash_with_salt(salt)
    }
}

impl Hashable for [u8] {
    fn hash(&self) -> String {
        let digest = digest::digest(&digest::SHA256, self);
        hex::encode(digest.as_ref())
    }

    fn hash_with_salt(&self, salt: &[u8]) -> String {
        hash_with_salt(self, Some(salt))
    }
}

impl Hashable for Vec<u8> {
    fn hash(&self) -> String {
        self.as_slice().hash()
    }

    fn hash_with_salt(&self, salt: &[u8]) -> String {
        self.as_slice().hash_with_salt(salt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_token() {
        let token = "test_token";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
        assert!(is_valid_hash(&hash1));
    }

    #[test]
    fn test_secure_random() {
        let rng = SecureRandom::new();

        let bytes1 = rng.generate_bytes(32).unwrap();
        let bytes2 = rng.generate_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }

    #[test]
    fn test_hmac_signature() {
        let key = b"test_key_that_is_long_enough_for_hmac_security";
        let data = b"test_data";

        let signature = generate_hmac_signature(key, data).unwrap();
        assert!(verify_hmac_signature(key, data, &signature).unwrap());

        // Test with wrong data
        let wrong_data = b"wrong_data";
        assert!(!verify_hmac_signature(key, wrong_data, &signature).unwrap());
    }

    #[test]
    fn test_hmac_short_key() {
        let short_key = b"short"; // Less than 32 bytes
        let data = b"test_data";

        let result = generate_hmac_signature(short_key, data);
        assert!(matches!(result, Err(CryptoError::InvalidLength { .. })));
    }

    #[test]
    fn test_constant_time_comparison() {
        let a = "hello";
        let b = "hello";
        let c = "world";

        assert!(constant_time_eq_str(a, b));
        assert!(!constant_time_eq_str(a, c));
    }

    #[test]
    fn test_hashable_trait() {
        let data = "test_data";
        let salt = b"test_salt";

        let hash1 = data.hash();
        let hash2 = data.hash_with_salt(salt);

        assert_ne!(hash1, hash2);
        assert!(is_valid_hash(&hash1));
        assert!(is_valid_hash(&hash2));
    }

    #[test]
    fn test_salt_generation() {
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();

        assert_eq!(salt1.len(), crypto::DEFAULT_SALT_LENGTH);
        assert_eq!(salt2.len(), crypto::DEFAULT_SALT_LENGTH);
        assert_ne!(salt1, salt2);

        let salt_hex = generate_salt_hex().unwrap();
        assert_eq!(salt_hex.len(), crypto::DEFAULT_SALT_LENGTH * 2);
        assert!(salt_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_validation() {
        let valid_hash = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3";
        let invalid_hash = "not_a_hash";
        let short_hash = "abc123";

        assert!(is_valid_hash(valid_hash));
        assert!(!is_valid_hash(invalid_hash));
        assert!(!is_valid_hash(short_hash));
    }
}
