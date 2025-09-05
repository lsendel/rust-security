//! Unified Hashing Operations
//!
//! Consolidates hashing functionality from common/src/crypto_utils.rs
//! and other implementations.

use super::*;
use ring::{digest, hmac};

/// Hashing errors
#[derive(Debug, Error)]
pub enum HashingError {
    #[error("Hashing failed: {0}")]
    HashingFailed(String),
    
    #[error("HMAC verification failed")]
    HmacVerificationFailed,
    
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),
}

/// Hashing operations
pub struct HashingOperations {
    rng: ring::rand::SystemRandom,
}

impl HashingOperations {
    /// Create new hashing operations
    pub fn new() -> Self {
        Self {
            rng: ring::rand::SystemRandom::new(),
        }
    }
    
    /// Hash data with SHA-256
    pub fn sha256(&self, data: &[u8]) -> Vec<u8> {
        digest::digest(&digest::SHA256, data).as_ref().to_vec()
    }
    
    /// Hash data with SHA-512
    pub fn sha512(&self, data: &[u8]) -> Vec<u8> {
        digest::digest(&digest::SHA512, data).as_ref().to_vec()
    }
    
    /// Generate HMAC-SHA256
    pub fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        Ok(hmac::sign(&key, data).as_ref().to_vec())
    }
    
    /// Verify HMAC-SHA256
    pub fn verify_hmac_sha256(&self, key: &[u8], data: &[u8], signature: &[u8]) -> CryptoResult<()> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::verify(&key, data, signature)
            .map_err(|_| HashingError::HmacVerificationFailed.into())
    }
    
    /// Constant-time comparison
    pub fn constant_time_eq(&self, a: &[u8], b: &[u8]) -> bool {
        constant_time_eq::constant_time_eq(a, b)
    }
}

impl Default for HashingOperations {
    fn default() -> Self {
        Self::new()
    }
}