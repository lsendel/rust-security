//! Authentication module
//!
//! This module provides authentication functionality split into submodules
//! based on different authentication features.

#[cfg(feature = "user-auth")]
pub mod user_auth;

#[cfg(feature = "oauth")]
pub mod oauth;

#[cfg(feature = "jwt-auth")]
pub mod jwt;

pub mod types;
pub mod handlers;

// Re-export commonly used types
pub use types::*;

// Re-export handlers based on feature flags
#[cfg(feature = "user-auth")]
pub use handlers::user::{login, me, register, logout};

#[cfg(feature = "oauth")]
pub use handlers::oauth::{authorize, token};

// Re-export the main AuthState for backward compatibility
pub use types::AuthState;