//! User Management Module
//!
//! This module handles user lifecycle management including registration,
//! profile updates, and user administration.

pub mod admin;
pub mod profile;
pub mod registration;

// Re-export main types
pub use admin::UserAdminService;
pub use profile::UserProfileManager;
pub use registration::RegistrationHandler;
