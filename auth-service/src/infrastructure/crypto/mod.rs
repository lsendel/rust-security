//! Cryptographic Infrastructure
//!
//! Provides cryptographic operations and key management for the authentication service.

pub mod crypto_optimized;
pub mod crypto_secure;
pub mod crypto_unified;
pub mod jwks_rotation;
pub mod key_management;
pub mod key_rotation;
pub mod keys;
pub mod keys_optimized;
pub mod keys_ring;
pub mod keys_secure;
pub mod quantum_jwt;

// Re-export commonly used types
// pub use key_management::KeyManager;  // KeyManager not found
pub use jwks_rotation::JwksManager;
// pub use crypto_unified::CryptoService;  // CryptoService not found
