//! Unified Cryptographic Operations Module
//!
//! This module consolidates all cryptographic operations across the rust-security platform,
//! eliminating duplication and providing a single, secure, and performant crypto API.
//!
//! ## Consolidates Code From
//! - `auth-service/src/security/jwt.rs` - JWT operations
//! - `auth-service/src/security/cryptography.rs` - General crypto
//! - `auth-service/src/services/password_service.rs` - Password hashing
//! - `auth-service/src/infrastructure/crypto/*` - Various crypto implementations
//! - `common/src/crypto_utils.rs` - Basic crypto utilities
//! - `auth-service/src/shared/crypto.rs` - Service-specific utilities
//!
//! ## Key Features
//! - **JWT Operations**: Unified JWT encoding/decoding with multiple algorithms
//! - **Password Hashing**: Secure Argon2 with configurable parameters
//! - **Key Management**: Automatic rotation, JWKS serving, distributed storage
//! - **Encryption/Decryption**: AES-256-GCM and ChaCha20-Poly1305 support
//! - **Secure Random**: Cryptographically secure random number generation
//! - **Token Operations**: Secure token generation and validation
//! - **Post-Quantum**: Future-ready post-quantum cryptography support

pub mod encryption;
pub mod hashing;
pub mod jwt;
pub mod keys;
pub mod passwords;
pub mod random;
pub mod tokens;

pub use encryption::*;
pub use hashing::*;
pub use jwt::*;
pub use keys::*;
pub use passwords::*;
pub use random::*;
pub use tokens::*;

use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Unified cryptographic errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("JWT error: {0}")]
    Jwt(#[from] JwtError),

    #[error("Password error: {0}")]
    Password(#[from] PasswordError),

    #[error("Key management error: {0}")]
    KeyManagement(#[from] KeyError),

    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptionError),

    #[error("Random generation error: {0}")]
    Random(#[from] RandomError),

    #[error("Token error: {0}")]
    Token(#[from] TokenError),

    #[error("Hashing error: {0}")]
    Hashing(#[from] HashingError),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Validation failed: {0}")]
    ValidationFailed(String),
}

/// Unified cryptographic configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoConfig {
    /// JWT configuration
    pub jwt: JwtConfig,

    /// Password hashing configuration
    pub password: PasswordConfig,

    /// Key management configuration
    pub key_management: KeyManagementConfig,

    /// Encryption configuration
    pub encryption: EncryptionConfig,

    /// Token generation configuration
    pub token: TokenConfig,
}

/// JWT algorithm configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum JwtAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    EdDSA,
    // Future post-quantum algorithms
    #[cfg(feature = "post-quantum")]
    PqJwt,
}

/// Encryption algorithm configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    // Future post-quantum algorithms
    #[cfg(feature = "post-quantum")]
    PqEncryption,
}

impl CryptoConfig {
    /// Load cryptographic configuration from environment variables
    pub fn from_env() -> Result<Self, CryptoError> {
        Ok(Self {
            jwt: JwtConfig::from_env()?,
            password: PasswordConfig::from_env()?,
            key_management: KeyManagementConfig::from_env()?,
            encryption: EncryptionConfig::from_env()?,
            token: TokenConfig::from_env()?,
        })
    }

    /// Validate the cryptographic configuration
    pub fn validate(&self) -> Result<(), CryptoError> {
        self.jwt.validate()?;
        self.password.validate()?;
        self.key_management.validate()?;
        self.encryption.validate()?;
        self.token.validate()?;
        Ok(())
    }
}

/// Unified cryptographic operations facade
pub struct CryptoOperations {
    jwt: JwtOperations,
    password: PasswordOperations,
    key_manager: KeyManager,
    encryption: EncryptionOperations,
    random: SecureRandom,
    token: TokenOperations,
    hashing: HashingOperations,
}

impl CryptoOperations {
    /// Initialize unified cryptographic operations
    pub async fn new(config: CryptoConfig) -> Result<Self, CryptoError> {
        config.validate()?;

        Ok(Self {
            jwt: JwtOperations::new(config.jwt).await?,
            password: PasswordOperations::new(config.password)?,
            key_manager: KeyManager::new(config.key_management).await?,
            encryption: EncryptionOperations::new(config.encryption)?,
            random: SecureRandom::new(),
            token: TokenOperations::new(config.token)?,
            hashing: HashingOperations::new(),
        })
    }

    /// Get JWT operations
    pub fn jwt(&self) -> &JwtOperations {
        &self.jwt
    }

    /// Get password operations
    pub fn password(&self) -> &PasswordOperations {
        &self.password
    }

    /// Get key manager
    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }

    /// Get encryption operations
    pub fn encryption(&self) -> &EncryptionOperations {
        &self.encryption
    }

    /// Get secure random
    pub fn random(&self) -> &SecureRandom {
        &self.random
    }

    /// Get token operations
    pub fn token(&self) -> &TokenOperations {
        &self.token
    }

    /// Get hashing operations
    pub fn hashing(&self) -> &HashingOperations {
        &self.hashing
    }
}

// Common result type for crypto operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Common traits for cryptographic operations
pub trait CryptoValidation {
    fn validate(&self) -> CryptoResult<()>;
}

pub trait FromEnvironment {
    fn from_env() -> CryptoResult<Self>
    where
        Self: Sized;
}
