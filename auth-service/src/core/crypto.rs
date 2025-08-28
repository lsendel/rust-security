//! Core cryptographic functionality
//!
//! This module provides cryptographic operations for the authentication service,
//! including key management, signing, verification, and secure random generation.

use crate::core::errors::{CoreError, CryptographicError};
use base64::prelude::*;
use ring::{
    digest,
    hmac,
    rand::{SecureRandom, SystemRandom},
    signature::{self, Ed25519KeyPair},
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// Cryptographic key types supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// HMAC SHA-256 key for symmetric operations
    HmacSha256,
    /// Ed25519 key for digital signatures
    Ed25519,
    /// AES-256 key for encryption
    Aes256,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HmacSha256 => write!(f, "HMAC-SHA256"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::Aes256 => write!(f, "AES-256"),
        }
    }
}

/// Secure key material with automatic zeroization
#[derive(Clone)]
pub struct SecureKey {
    key_data: Vec<u8>,
    key_type: KeyType,
    key_id: String,
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        self.key_data.zeroize();
    }
}

impl SecureKey {
    /// Create a new secure key
    pub fn new(key_data: Vec<u8>, key_type: KeyType, key_id: String) -> Self {
        Self {
            key_data,
            key_type,
            key_id,
        }
    }

    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Get the key ID
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the key data (use with caution)
    pub fn key_data(&self) -> &[u8] {
        &self.key_data
    }

    /// Get the key length
    pub fn len(&self) -> usize {
        self.key_data.len()
    }

    /// Check if key is empty
    pub fn is_empty(&self) -> bool {
        self.key_data.is_empty()
    }
}

impl fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureKey")
            .field("key_type", &self.key_type)
            .field("key_id", &self.key_id)
            .field("key_length", &self.key_data.len())
            .finish()
    }
}

/// Cryptographic operations provider
pub struct CryptoProvider {
    rng: SystemRandom,
}

impl CryptoProvider {
    /// Create a new crypto provider
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }

    /// Generate a secure random key
    pub fn generate_key(&self, key_type: KeyType, key_id: String) -> Result<SecureKey, CoreError> {
        let key_size = match key_type {
            KeyType::HmacSha256 => 32, // 256 bits
            KeyType::Ed25519 => 32,    // 256 bits seed
            KeyType::Aes256 => 32,     // 256 bits
        };

        let mut key_data = vec![0u8; key_size];
        self.rng
            .fill(&mut key_data)
            .map_err(|_| CoreError::Cryptographic(CryptographicError::KeyGenerationFailed))?;

        Ok(SecureKey::new(key_data, key_type, key_id))
    }

    /// Generate secure random bytes
    pub fn generate_random(&self, length: usize) -> Result<Vec<u8>, CoreError> {
        let mut random_data = vec![0u8; length];
        self.rng
            .fill(&mut random_data)
            .map_err(|_| CoreError::Cryptographic(CryptographicError::RandomGenerationFailed))?;
        Ok(random_data)
    }

    /// Generate a secure salt for password hashing
    pub fn generate_salt(&self) -> Result<Vec<u8>, CoreError> {
        self.generate_random(32) // 256-bit salt
    }

    /// Hash data using SHA-256
    pub fn hash_sha256(&self, data: &[u8]) -> Vec<u8> {
        digest::digest(&digest::SHA256, data).as_ref().to_vec()
    }

    /// Compute HMAC-SHA256
    pub fn hmac_sha256(&self, key: &SecureKey, data: &[u8]) -> Result<Vec<u8>, CoreError> {
        if key.key_type() != KeyType::HmacSha256 {
            return Err(CoreError::Cryptographic(
                CryptographicError::InvalidKeyFormat,
            ));
        }

        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key.key_data());
        let tag = hmac::sign(&hmac_key, data);
        Ok(tag.as_ref().to_vec())
    }

    /// Verify HMAC-SHA256
    pub fn verify_hmac_sha256(
        &self,
        key: &SecureKey,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CoreError> {
        if key.key_type() != KeyType::HmacSha256 {
            return Err(CoreError::Cryptographic(
                CryptographicError::InvalidKeyFormat,
            ));
        }

        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key.key_data());
        match hmac::verify(&hmac_key, data, signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Create Ed25519 key pair for signing
    pub fn create_ed25519_keypair(&self, _key_id: String) -> Result<Ed25519KeyPair, CoreError> {
        let seed = self.generate_random(32)?;
        Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| CoreError::Cryptographic(CryptographicError::KeyGenerationFailed))
    }

    /// Sign data with Ed25519
    pub fn sign_ed25519(&self, keypair: &Ed25519KeyPair, data: &[u8]) -> Vec<u8> {
        keypair.sign(data).as_ref().to_vec()
    }

    /// Verify Ed25519 signature
    pub fn verify_ed25519_signature(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CoreError> {
        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);
        match public_key.verify(data, signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Derive key using PBKDF2
    pub fn derive_key_pbkdf2(
        &self,
        password: &str,
        salt: &[u8],
        iterations: u32,
        length: usize,
    ) -> Result<Vec<u8>, CoreError> {
        use ring::pbkdf2;
        
        let mut derived_key = vec![0u8; length];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(iterations)
                .ok_or_else(|| CoreError::Cryptographic(CryptographicError::KeyDerivationFailed))?,
            salt,
            password.as_bytes(),
            &mut derived_key,
        );
        
        Ok(derived_key)
    }

    /// Constant-time comparison of byte arrays
    pub fn constant_time_eq(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut result = 0u8;
        for (byte_a, byte_b) in a.iter().zip(b.iter()) {
            result |= byte_a ^ byte_b;
        }
        result == 0
    }
}

impl Default for CryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for encoding/decoding
pub struct CryptoUtils;

impl CryptoUtils {
    /// Encode bytes to base64url (no padding)
    pub fn encode_base64url(data: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(data)
    }

    /// Decode base64url (no padding)
    pub fn decode_base64url(data: &str) -> Result<Vec<u8>, CoreError> {
        BASE64_URL_SAFE_NO_PAD
            .decode(data)
            .map_err(|_| CoreError::Cryptographic(CryptographicError::InvalidKeyFormat))
    }

    /// Encode bytes to base64 (standard)
    pub fn encode_base64(data: &[u8]) -> String {
        BASE64_STANDARD.encode(data)
    }

    /// Decode base64 (standard)
    pub fn decode_base64(data: &str) -> Result<Vec<u8>, CoreError> {
        BASE64_STANDARD
            .decode(data)
            .map_err(|_| CoreError::Cryptographic(CryptographicError::InvalidKeyFormat))
    }

    /// Convert hex string to bytes
    pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, CoreError> {
        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|_| CoreError::Cryptographic(CryptographicError::InvalidKeyFormat))
            })
            .collect()
    }

    /// Convert bytes to hex string
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Secure string that automatically zeroizes its content
#[derive(Clone)]
pub struct SecureString {
    data: String,
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl SecureString {
    /// Create a new secure string
    pub fn new(data: String) -> Self {
        Self { data }
    }

    /// Get the string content (use with caution)
    pub fn expose_secret(&self) -> &str {
        &self.data
    }

    /// Get the length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl From<String> for SecureString {
    fn from(data: String) -> Self {
        Self::new(data)
    }
}

impl From<&str> for SecureString {
    fn from(data: &str) -> Self {
        Self::new(data.to_string())
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureString")
            .field("length", &self.data.len())
            .finish()
    }
}

impl Zeroize for SecureString {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_provider_creation() {
        let provider = CryptoProvider::new();
        assert!(provider.generate_random(32).is_ok());
    }

    #[test]
    fn test_key_generation() {
        let provider = CryptoProvider::new();
        let key = provider
            .generate_key(KeyType::HmacSha256, "test-key".to_string())
            .unwrap();

        assert_eq!(key.key_type(), KeyType::HmacSha256);
        assert_eq!(key.key_id(), "test-key");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hmac_operations() {
        let provider = CryptoProvider::new();
        let key = provider
            .generate_key(KeyType::HmacSha256, "hmac-key".to_string())
            .unwrap();
        let data = b"test data";

        let signature = provider.hmac_sha256(&key, data).unwrap();
        let is_valid = provider.verify_hmac_sha256(&key, data, &signature).unwrap();

        assert!(is_valid);
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_base64_encoding() {
        let data = b"hello world";
        let encoded = CryptoUtils::encode_base64url(data);
        let decoded = CryptoUtils::decode_base64url(&encoded).unwrap();

        assert_eq!(data, decoded.as_slice());
    }

    #[test]
    fn test_hex_encoding() {
        let data = b"test";
        let hex = CryptoUtils::bytes_to_hex(data);
        let decoded = CryptoUtils::hex_to_bytes(&hex).unwrap();

        assert_eq!(data, decoded.as_slice());
        assert_eq!(hex, "74657374");
    }

    #[test]
    fn test_secure_string() {
        let secret = SecureString::new("password123".to_string());
        assert_eq!(secret.expose_secret(), "password123");
        assert_eq!(secret.len(), 11);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_constant_time_comparison() {
        let provider = CryptoProvider::new();
        let data1 = b"same_data";
        let data2 = b"same_data";
        let data3 = b"diff_data";

        assert!(provider.constant_time_eq(data1, data2));
        assert!(!provider.constant_time_eq(data1, data3));
    }
}