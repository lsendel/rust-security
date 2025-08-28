//! Core authentication and security modules
//!
//! This module contains the fundamental components for authentication,
//! security, and cryptographic operations.

pub mod auth;
pub mod crypto;
pub mod errors;
pub mod security;
pub mod types;

// Re-export common types for convenience
pub use errors::{CoreError, CoreResult};
pub use auth::{AuthContext, TokenInfo};
pub use security::SecurityContext;