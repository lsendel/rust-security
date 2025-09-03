//! Cryptographic Infrastructure
//!
//! Provides cryptographic operations and key management for the authentication service.

pub mod crypto_optimized;
pub mod crypto_secure;
#[cfg(feature = "crypto")]
pub mod crypto_unified;
#[cfg(feature = "crypto")]
pub mod jwks_rotation;
#[cfg(feature = "crypto")]
pub mod key_management;
#[cfg(feature = "crypto")]
pub mod key_rotation;
#[cfg(feature = "crypto")]
pub mod keys;
#[cfg(feature = "crypto")]
pub mod keys_optimized;
#[cfg(feature = "crypto")]
pub mod keys_ring;
#[cfg(feature = "crypto")]
pub mod keys_secure;
#[cfg(feature = "crypto")]
pub mod quantum_jwt;

// Re-export commonly used types
// pub use key_management::KeyManager;  // KeyManager not found
#[cfg(feature = "crypto")]
pub use jwks_rotation::JwksManager;
// pub use crypto_unified::CryptoService;  // CryptoService not found
