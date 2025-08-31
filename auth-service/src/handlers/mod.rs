//! HTTP Handlers
//!
//! Contains HTTP request handlers organized by functionality.

pub mod auth;

// Re-export handlers for convenience
pub use auth::*;
