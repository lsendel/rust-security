//! Shared utilities and common types
//!
//! Contains shared code used across different layers of the application.

pub mod crypto;
pub mod error;
pub mod error_handler;
pub mod time;

pub use crypto::CryptoService;
pub use error::{AppError, AppResult};
pub use error_handler::{ErrorBoundary, ErrorHandler};
