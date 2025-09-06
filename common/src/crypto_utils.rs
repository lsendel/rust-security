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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random_generate_bytes() {
        let rng = SecureRandom::new();
        let bytes = rng.generate_bytes(32).unwrap();

        assert_eq!(bytes.len(), 32);

        // Generate another set to ensure randomness
        let bytes2 = rng.generate_bytes(32).unwrap();
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_secure_random_generate_string() {
        let rng = SecureRandom::new();
        let string1 = rng.generate_string(16).unwrap();
        let string2 = rng.generate_string(16).unwrap();

        assert_ne!(string1, string2);
        assert!(!string1.is_empty());
        assert!(!string2.is_empty());
    }

    #[test]
    fn test_secure_random_generate_session_id() {
        let rng = SecureRandom::new();
        let session_id1 = rng.generate_session_id().unwrap();
        let session_id2 = rng.generate_session_id().unwrap();

        assert_ne!(session_id1, session_id2);
        assert!(!session_id1.is_empty());
        assert!(!session_id2.is_empty());
    }

    #[test]
    fn test_secure_random_generate_api_key() {
        let rng = SecureRandom::new();
        let api_key1 = rng.generate_api_key().unwrap();
        let api_key2 = rng.generate_api_key().unwrap();

        assert_ne!(api_key1, api_key2);
        assert!(api_key1.starts_with("sk_"));
        assert!(api_key2.starts_with("sk_"));
        assert_eq!(api_key1.len(), 67); // "sk_" + 64 hex chars
    }

    #[test]
    fn test_hash_functions() {
        let input = "test_data";

        let hash1 = hash_token(input);
        let hash2 = hash_password_sha256(input);
        let hash3 = hash_secret(input);
        let hash4 = hash_backup_code(input);
        let hash5 = hash_otp(input);
        let hash6 = hash_user_agent(input);

        // All should be the same (they all use SHA-256)
        assert_eq!(hash1, hash2);
        assert_eq!(hash1, hash3);
        assert_eq!(hash1, hash4);
        assert_eq!(hash1, hash5);
        assert_eq!(hash1, hash6);

        // Should be 64 characters (256 bits in hex)
        assert_eq!(hash1.len(), 64);

        // Different inputs should produce different hashes
        let different_hash = hash_token("different_data");
        assert_ne!(hash1, different_hash);
    }

    #[test]
    fn test_hmac_signature_generation_and_verification() {
        let key = b"this_is_a_very_secure_key_that_is_long_enough";
        let data = b"hello world";

        let signature = generate_hmac_signature(key, data).unwrap();
        assert!(!signature.is_empty());

        // Verify signature
        assert!(verify_hmac_signature(key, data, &signature).unwrap());

        // Wrong signature should fail
        let wrong_signature = vec![0u8; signature.len()];
        assert!(!verify_hmac_signature(key, data, &wrong_signature).unwrap());

        // Wrong data should fail
        let wrong_data = b"wrong data";
        assert!(!verify_hmac_signature(key, wrong_data, &signature).unwrap());
    }

    #[test]
    fn test_hmac_with_short_key_fails() {
        let short_key = b"short"; // Less than HMAC_KEY_MIN_SIZE
        let data = b"test data";

        let result = generate_hmac_signature(short_key, data);
        assert!(matches!(result, Err(CryptoError::InvalidLength { .. })));

        let result = verify_hmac_signature(short_key, data, &[]);
        assert!(matches!(result, Err(CryptoError::InvalidLength { .. })));
    }

    #[test]
    fn test_salt_generation() {
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();

        assert_eq!(salt1.len(), crypto::DEFAULT_SALT_LENGTH);
        assert_eq!(salt2.len(), crypto::DEFAULT_SALT_LENGTH);
        assert_ne!(salt1, salt2);

        let salt_hex1 = generate_salt_hex().unwrap();
        let salt_hex2 = generate_salt_hex().unwrap();

        assert_eq!(salt_hex1.len(), crypto::DEFAULT_SALT_LENGTH * 2); // Hex is 2 chars per byte
        assert_ne!(salt_hex1, salt_hex2);
    }

    #[test]
    fn test_constant_time_comparison() {
        let a = b"secret_data";
        let b = b"secret_data";
        let c = b"different_data";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));

        let str1 = "password123";
        let str2 = "password123";
        let str3 = "different_password";

        assert!(constant_time_eq_str(str1, str2));
        assert!(!constant_time_eq_str(str1, str3));
    }

    #[test]
    fn test_secure_random_default() {
        let rng = SecureRandom::default();
        let bytes = rng.generate_bytes(16).unwrap();
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn test_error_display() {
        let error = CryptoError::RandomGenerationFailed;
        assert_eq!(error.to_string(), "Random number generation failed");

        let error = CryptoError::InvalidLength {
            expected: 32,
            actual: 16,
        };
        assert_eq!(
            error.to_string(),
            "Invalid input length: expected 32, got 16"
        );

        let error = CryptoError::EncryptionFailed("key error".to_string());
        assert_eq!(error.to_string(), "Encryption failed: key error");
    }

    #[test]
    fn test_hash_consistency() {
        let input = "consistent_input";

        // Hash should be consistent across multiple calls
        let hash1 = hash_token(input);
        let hash2 = hash_token(input);
        assert_eq!(hash1, hash2);

        // Same for other hash functions
        let pass_hash1 = hash_password_sha256(input);
        let pass_hash2 = hash_password_sha256(input);
        assert_eq!(pass_hash1, pass_hash2);
    }

    #[test]
    fn test_empty_input_handling() {
        let empty = "";
        let hash = hash_token(empty);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 always produces 64 hex chars

        // Empty strings should hash to consistent values
        let hash2 = hash_token(empty);
        assert_eq!(hash, hash2);
    }
}
