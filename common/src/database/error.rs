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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_database_error_display() {
        let error = DatabaseError::PoolError("connection pool exhausted".to_string());
        assert_eq!(error.to_string(), "Pool error: connection pool exhausted");

        let error = DatabaseError::ConnectionError("failed to connect".to_string());
        assert_eq!(error.to_string(), "Connection error: failed to connect");

        let error = DatabaseError::ConfigurationError("invalid config".to_string());
        assert_eq!(error.to_string(), "Configuration error: invalid config");

        let error = DatabaseError::MigrationError("migration failed".to_string());
        assert_eq!(error.to_string(), "Migration error: migration failed");

        let error = DatabaseError::SerializationError("json parse error".to_string());
        assert_eq!(error.to_string(), "Serialization error: json parse error");

        let error = DatabaseError::TimeoutError("operation timed out".to_string());
        assert_eq!(error.to_string(), "Timeout error: operation timed out");

        let error = DatabaseError::TransactionError("tx rollback".to_string());
        assert_eq!(error.to_string(), "Transaction error: tx rollback");

        let error = DatabaseError::RepositoryError("repo error".to_string());
        assert_eq!(error.to_string(), "Repository error: repo error");

        let error = DatabaseError::ValidationError("invalid data".to_string());
        assert_eq!(error.to_string(), "Validation error: invalid data");

        let error = DatabaseError::NotFound("user not found".to_string());
        assert_eq!(error.to_string(), "Not found: user not found");

        let error = DatabaseError::AlreadyExists("user exists".to_string());
        assert_eq!(error.to_string(), "Already exists: user exists");

        let error = DatabaseError::DeadpoolError("deadpool error".to_string());
        assert_eq!(error.to_string(), "Deadpool pool error: deadpool error");

        let error = DatabaseError::Bb8Error("bb8 error".to_string());
        assert_eq!(error.to_string(), "BB8 pool error: bb8 error");
    }

    #[test]
    fn test_database_error_debug() {
        let error = DatabaseError::PoolError("test error".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("PoolError"));
        assert!(debug_str.contains("test error"));
    }

    #[test]
    fn test_from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let db_err: DatabaseError = json_err.into();

        match db_err {
            DatabaseError::SerializationError(msg) => {
                assert!(msg.contains("expected") || msg.contains("invalid"));
            }
            _ => panic!("Expected SerializationError"),
        }
    }

    #[tokio::test]
    async fn test_from_tokio_timeout_error() {
        use tokio::time::{sleep, timeout, Duration};

        // Create a real timeout error
        let result = timeout(Duration::from_millis(1), sleep(Duration::from_secs(1))).await;
        assert!(result.is_err());

        let timeout_err = result.unwrap_err();
        let db_err: DatabaseError = timeout_err.into();

        match db_err {
            DatabaseError::TimeoutError(msg) => {
                assert!(msg.contains("deadline") || msg.contains("elapsed"));
            }
            _ => panic!("Expected TimeoutError"),
        }
    }

    #[test]
    fn test_database_error_ext_not_found() {
        let original_error = DatabaseError::PoolError("connection failed".to_string());
        let result: DatabaseResult<String> = Err(original_error);

        let converted = result.not_found("User lookup failed");
        assert!(converted.is_err());

        match converted.unwrap_err() {
            DatabaseError::NotFound(msg) => {
                assert!(msg.contains("User lookup failed"));
                assert!(msg.contains("connection failed"));
            }
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_database_error_ext_validation_error() {
        let original_error = DatabaseError::ConnectionError("timeout".to_string());
        let result: DatabaseResult<i32> = Err(original_error);

        let converted = result.validation_error("Invalid input data");
        assert!(converted.is_err());

        match converted.unwrap_err() {
            DatabaseError::ValidationError(msg) => {
                assert!(msg.contains("Invalid input data"));
                assert!(msg.contains("timeout"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_database_error_ext_repository_error() {
        let original_error = DatabaseError::SerializationError("parse error".to_string());
        let result: DatabaseResult<bool> = Err(original_error);

        let converted = result.repository_error("Repository operation failed");
        assert!(converted.is_err());

        match converted.unwrap_err() {
            DatabaseError::RepositoryError(msg) => {
                assert!(msg.contains("Repository operation failed"));
                assert!(msg.contains("parse error"));
            }
            _ => panic!("Expected RepositoryError"),
        }
    }

    #[test]
    fn test_database_error_ext_success_passthrough() {
        let result: DatabaseResult<String> = Ok("success".to_string());

        let converted = result.not_found("This should not be called");
        assert!(converted.is_ok());
        assert_eq!(converted.unwrap(), "success");
    }

    #[test]
    fn test_database_error_variants() {
        // Test that all error variants can be created
        let errors = vec![
            DatabaseError::PoolError("pool".to_string()),
            DatabaseError::ConnectionError("connection".to_string()),
            DatabaseError::ConfigurationError("config".to_string()),
            DatabaseError::MigrationError("migration".to_string()),
            DatabaseError::SerializationError("serialization".to_string()),
            DatabaseError::TimeoutError("timeout".to_string()),
            DatabaseError::TransactionError("transaction".to_string()),
            DatabaseError::RepositoryError("repository".to_string()),
            DatabaseError::ValidationError("validation".to_string()),
            DatabaseError::NotFound("not found".to_string()),
            DatabaseError::AlreadyExists("exists".to_string()),
            DatabaseError::DeadpoolError("deadpool".to_string()),
            DatabaseError::Bb8Error("bb8".to_string()),
        ];

        for error in errors {
            // Test that each error can be displayed and debugged
            assert!(!error.to_string().is_empty());
            assert!(!format!("{:?}", error).is_empty());
        }
    }

    #[test]
    fn test_database_result_type() {
        // Test successful result
        let success: DatabaseResult<i32> = Ok(42);
        assert!(success.is_ok());
        if let Ok(value) = success {
            assert_eq!(value, 42);
        }

        // Test error result
        let error: DatabaseResult<i32> = Err(DatabaseError::NotFound("test".to_string()));
        assert!(error.is_err());

        if let Err(DatabaseError::NotFound(msg)) = error {
            assert_eq!(msg, "test");
        } else {
            panic!("Expected NotFound error");
        }
    }

    #[test]
    fn test_error_chaining() {
        // Test that we can chain error conversions
        let original_error = DatabaseError::PoolError("original".to_string());
        let result: DatabaseResult<String> = Err(original_error);

        let chained: DatabaseResult<String> = result.not_found("First conversion");

        assert!(chained.is_err());
        match chained.unwrap_err() {
            DatabaseError::NotFound(msg) => {
                assert!(msg.contains("First conversion"));
                assert!(msg.contains("original"));
            }
            _ => panic!("Expected NotFound error from first conversion"),
        }
    }

    // Test error conversions that require actual external errors
    #[tokio::test]
    async fn test_timeout_error_conversion() {
        use tokio::time::{sleep, timeout, Duration};

        // This will timeout and create a real Elapsed error
        let result = timeout(Duration::from_millis(1), sleep(Duration::from_millis(100))).await;
        assert!(result.is_err());

        let elapsed_error = result.unwrap_err();
        let db_error: DatabaseError = elapsed_error.into();

        match db_error {
            DatabaseError::TimeoutError(_) => {} // Expected
            _ => panic!("Expected TimeoutError"),
        }
    }

    fn test_all_error_conversions_compile() {
        // This test ensures all From implementations compile correctly

        // Test that we can create errors from various sources
        fn _test_conversions() {
            let _: DatabaseError = serde_json::Error::io(std::io::Error::other("test")).into();
            // Note: Other From implementations require actual external types
        }

        // Test passes if the above function compiles
        _test_conversions();
    }
}
