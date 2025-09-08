//! Authentication module
//!
//! This module provides authentication functionality split into submodules
//! based on different authentication features.

pub mod types;

// Re-export commonly used types
pub use types::*;

// Re-export the main AuthState for backward compatibility
pub use types::AuthState;
