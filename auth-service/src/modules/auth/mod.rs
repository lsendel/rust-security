//! Authentication Module
//!
//! This module handles authentication operations including JWT validation,
//! session management, and user authentication flows.

pub mod jwt;
pub mod oauth;
pub mod session;
pub mod token;

// Re-export main types
pub use jwt::JwtHandler;
pub use oauth::OAuthHandler;
pub use session::SessionManager;
pub use token::TokenManager;
