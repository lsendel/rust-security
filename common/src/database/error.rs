//! Database Error Types
//!
//! Unified error handling for all database operations

use thiserror::Error;

/// Database operation errors
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("SQL error: {0}")]
    SqlError(#[from] sqlx::Error),
    
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    
    #[error("Pool error: {0}")]
    PoolError(String),
    
    #[error("Connection error: {0}")]
    ConnectionError(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Migration error: {0}")]
    MigrationError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Timeout error: {0}")]
    TimeoutError(String),
    
    #[error("Transaction error: {0}")]
    TransactionError(String),
    
    #[error("Repository error: {0}")]
    RepositoryError(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Already exists: {0}")]
    AlreadyExists(String),
    
    #[error("Deadpool pool error: {0}")]
    DeadpoolError(String),
    
    #[error("BB8 pool error: {0}")]
    Bb8Error(String),
}

// Conversion from common pool errors
impl From<deadpool_redis::redis::RedisError> for DatabaseError {
    fn from(err: deadpool_redis::redis::RedisError) -> Self {
        DatabaseError::DeadpoolError(err.to_string())
    }
}

impl From<deadpool_redis::PoolError> for DatabaseError {
    fn from(err: deadpool_redis::PoolError) -> Self {
        DatabaseError::DeadpoolError(err.to_string())
    }
}

impl From<bb8::RunError<redis::RedisError>> for DatabaseError {
    fn from(err: bb8::RunError<redis::RedisError>) -> Self {
        DatabaseError::Bb8Error(err.to_string())
    }
}

impl From<serde_json::Error> for DatabaseError {
    fn from(err: serde_json::Error) -> Self {
        DatabaseError::SerializationError(err.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for DatabaseError {
    fn from(err: tokio::time::error::Elapsed) -> Self {
        DatabaseError::TimeoutError(err.to_string())
    }
}

impl From<sqlx::migrate::MigrateError> for DatabaseError {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        DatabaseError::MigrationError(err.to_string())
    }
}

/// Result type for database operations
pub type DatabaseResult<T> = Result<T, DatabaseError>;

/// Error conversion utilities
pub trait DatabaseErrorExt<T> {
    /// Convert error to not found
    fn not_found(self, message: &str) -> DatabaseResult<T>;
    
    /// Convert error to validation error
    fn validation_error(self, message: &str) -> DatabaseResult<T>;
    
    /// Convert error to repository error
    fn repository_error(self, message: &str) -> DatabaseResult<T>;
}

impl<T> DatabaseErrorExt<T> for DatabaseResult<T> {
    fn not_found(self, message: &str) -> DatabaseResult<T> {
        self.map_err(|err| {
            tracing::debug!("Converting database error to NotFound: {}", err);
            DatabaseError::NotFound(format!("{}: {}", message, err))
        })
    }
    
    fn validation_error(self, message: &str) -> DatabaseResult<T> {
        self.map_err(|err| {
            tracing::debug!("Converting database error to ValidationError: {}", err);
            DatabaseError::ValidationError(format!("{}: {}", message, err))
        })
    }
    
    fn repository_error(self, message: &str) -> DatabaseResult<T> {
        self.map_err(|err| {
            tracing::debug!("Converting database error to RepositoryError: {}", err);
            DatabaseError::RepositoryError(format!("{}: {}", message, err))
        })
    }
}