//! Common error types used across services

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Common error type for all services
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum CommonError {
    #[error("Authentication failed: {message}")]
    Authentication { message: String },

    #[error("Authorization failed: {message}")]
    Authorization { message: String },

    #[error("Configuration error: {message}")]
    Configuration { message: String },

    #[error("Network error: {message}")]
    Network { message: String },

    #[error("Database error: {message}")]
    Database { message: String },

    #[error("Cache error: {message}")]
    Cache { message: String },

    #[error("Rate limit exceeded: {message}")]
    RateLimit { message: String },

    #[error("Security violation: {message}")]
    Security { message: String },

    #[error("Service unavailable: {message}")]
    ServiceUnavailable { message: String },

    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl CommonError {
    /// Convert to HTTP status code
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        match self {
            Self::Authentication { .. } => 401,
            Self::Authorization { .. } => 403,
            Self::NotFound { .. } => 404,
            Self::RateLimit { .. } => 429,
            Self::ServiceUnavailable { .. } => 503,
            Self::InvalidInput { .. } => 400,
            Self::Configuration { .. }
            | Self::Network { .. }
            | Self::Database { .. }
            | Self::Cache { .. }
            | Self::Security { .. }
            | Self::Internal { .. } => 500,
        }
    }
}
