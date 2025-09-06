//! Unified Token Operations
//!
//! Consolidates secure token generation and validation functionality.

use super::*;
use base64::Engine;
use std::env;

/// Token errors
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Token generation failed: {0}")]
    GenerationFailed(String),

    #[error("Token validation failed: {0}")]
    ValidationFailed(String),

    #[error("Invalid token format")]
    InvalidFormat,
}

/// Token configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    /// Default token length in bytes
    pub default_length: usize,

    /// Token binding salt
    pub binding_salt: String,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            default_length: 32,
            binding_salt: "REPLACE_WITH_SECURE_SALT_32_BYTES_MIN".to_string(),
        }
    }
}

impl FromEnvironment for TokenConfig {
    fn from_env() -> CryptoResult<Self> {
        let default_length = env::var("TOKEN_DEFAULT_LENGTH")
            .unwrap_or_else(|_| "32".to_string())
            .parse()
            .unwrap_or(32);

        let binding_salt = env::var("TOKEN_BINDING_SALT")
            .unwrap_or_else(|_| "REPLACE_WITH_SECURE_SALT_32_BYTES_MIN".to_string());

        Ok(Self {
            default_length,
            binding_salt,
        })
    }
}

impl CryptoValidation for TokenConfig {
    fn validate(&self) -> CryptoResult<()> {
        if self.binding_salt.len() < 16 {
            return Err(CryptoError::ValidationFailed(
                "Token binding salt must be at least 16 characters".to_string(),
            ));
        }
        Ok(())
    }
}

/// Unified token operations
pub struct TokenOperations {
    config: TokenConfig,
    rng: ring::rand::SystemRandom,
}

impl TokenOperations {
    /// Create new token operations
    pub fn new(config: TokenConfig) -> CryptoResult<Self> {
        config.validate()?;

        Ok(Self {
            config,
            rng: ring::rand::SystemRandom::new(),
        })
    }

    /// Generate secure token
    pub fn generate_token(&self, length: Option<usize>) -> CryptoResult<String> {
        let len = length.unwrap_or(self.config.default_length);
        let mut bytes = vec![0u8; len];

        ring::rand::SecureRandom::fill(&self.rng, &mut bytes)
            .map_err(|_| TokenError::GenerationFailed("Random generation failed".to_string()))?;

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Generate API key
    pub fn generate_api_key(&self) -> CryptoResult<String> {
        let prefix = "rsp_"; // rust-security-platform
        let token = self.generate_token(Some(24))?;
        Ok(format!("{}{}", prefix, token))
    }

    /// Generate session token
    pub fn generate_session_token(&self) -> CryptoResult<String> {
        self.generate_token(Some(48))
    }
}
