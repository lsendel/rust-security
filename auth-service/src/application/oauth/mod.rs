//! OAuth Application Services
//!
//! This module provides OAuth-related application services
//! including client registration, token handling, and OAuth flows.

pub mod oauth_client_registration;
pub mod oauth_client_registration_policies;
pub mod oauth_client_secret_rotation;

// Re-export main OAuth types
pub use oauth_client_registration::ClientRegistrationManager;
