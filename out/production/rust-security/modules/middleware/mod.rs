//! Middleware Module
//!
//! This module handles HTTP middleware including authentication,
//! logging, CORS, and request processing middleware.

pub mod auth;
pub mod logging;
pub mod cors;
pub mod processing;

// Re-export main types
pub use auth::AuthMiddleware;
pub use logging::LoggingMiddleware;
pub use cors::CorsMiddleware;
pub use processing::RequestProcessor;
