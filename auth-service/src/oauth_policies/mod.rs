//! OAuth Client Registration Policies
//!
//! Modular policy system for OAuth 2.0 dynamic client registration
//! with separate modules for different policy types.

pub mod security;

// Re-export main types
pub use security::*;
