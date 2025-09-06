//! Unified Secure Random Generation
//!
//! Consolidates secure random generation from common/src/crypto_utils.rs
//! and other scattered implementations.

use super::*;
use base64::Engine;
use ring::rand::{SecureRandom as RingSecureRandom, SystemRandom};

/// Random generation errors
#[derive(Debug, Error)]
pub enum RandomError {
    #[error("Random generation failed")]
    GenerationFailed,

    #[error("Invalid length: {0}")]
    InvalidLength(usize),
}

/// Unified secure random operations
pub struct SecureRandom {
    rng: SystemRandom,
}

impl SecureRandom {
    /// Create new secure random generator
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }

    /// Generate secure random bytes
    pub fn generate_bytes(&self, len: usize) -> CryptoResult<Vec<u8>> {
        let mut bytes = vec![0u8; len];
        RingSecureRandom::fill(&self.rng, &mut bytes).map_err(|_| RandomError::GenerationFailed)?;
        Ok(bytes)
    }

    /// Generate random base64 string
    pub fn generate_base64(&self, byte_len: usize) -> CryptoResult<String> {
        let bytes = self.generate_bytes(byte_len)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    /// Generate random hex string
    pub fn generate_hex(&self, byte_len: usize) -> CryptoResult<String> {
        let bytes = self.generate_bytes(byte_len)?;
        Ok(hex::encode(bytes))
    }

    /// Generate secure salt for hashing
    pub fn generate_salt(&self) -> CryptoResult<Vec<u8>> {
        self.generate_bytes(32)
    }
}

impl Default for SecureRandom {
    fn default() -> Self {
        Self::new()
    }
}
