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
    pub fn status_code(&self) -> u16 {
        match self {
            CommonError::Authentication { .. } => 401,
            CommonError::Authorization { .. } => 403,
            CommonError::NotFound { .. } => 404,
            CommonError::RateLimit { .. } => 429,
            CommonError::ServiceUnavailable { .. } => 503,
            CommonError::InvalidInput { .. } => 400,
            CommonError::Configuration { .. } | 
            CommonError::Network { .. } | 
            CommonError::Database { .. } | 
            CommonError::Cache { .. } | 
            CommonError::Security { .. } | 
            CommonError::Internal { .. } => 500,
        }
    }
}