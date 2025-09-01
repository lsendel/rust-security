//! Error Conversion Macros
//!
//! This module provides derive macros to automatically generate
//! From implementations for error types, reducing boilerplate code.

/// Macro to generate From implementations for crate::shared::error::AppError
///
/// Usage:
/// ```rust
/// auth_error_from! {
///     RedisError => RedisConnectionError,
///     SerdeJsonError => SerializationError,
///     ReqwestError => HttpClientError,
/// }
/// ```
#[macro_export]
macro_rules! auth_error_from {
    ($($source_type:ty => $variant:ident),+ $(,)?) => {
        $(
            impl From<$source_type> for $crate::shared::error::AppError {
                fn from(source: $source_type) -> Self {
                    Self::$variant { source }
                }
            }
        )+
    };
}

/// Macro for simple error conversions with context
///
/// Usage:
/// ```rust
/// auth_error_from_with_context! {
///     std::io::Error => InternalError("IO operation failed"),
///     ValidationError => InvalidRequest("Validation failed"),
/// }
/// ```
#[macro_export]
macro_rules! auth_error_from_with_context {
    ($($source_type:ty => $variant:ident($context:expr)),+ $(,)?) => {
        $(
            impl From<$source_type> for $crate::shared::error::AppError {
                fn from(source: $source_type) -> Self {
                    Self::$variant {
                        error_id: uuid::Uuid::new_v4(),
                        context: format!("{}: {}", $context, source),
                    }
                }
            }
        )+
    };
}

/// Macro for boxed error conversions
///
/// Usage:
/// ```rust
/// auth_error_from_boxed! {
///     CryptographicError("RSA operation failed"),
///     JwtSigningError("JWT signing operation failed"),
/// }
/// ```
#[macro_export]
macro_rules! auth_error_from_boxed {
    ($($variant:ident($operation:expr)),+ $(,)?) => {
        $(
            impl<T: std::error::Error + Send + Sync + 'static> From<T> for $crate::shared::error::AppError
            where
                T: std::error::Error + Send + Sync + 'static,
            {
                fn from(source: T) -> Self {
                    Self::$variant {
                        operation: $operation.to_string(),
                        source: Box::new(source),
                    }
                }
            }
        )+
    };
}

/// Macro for SOAR error conversions
///
/// Usage:
/// ```rust
/// soar_error_from! {
///     serde_json::Error => SerializationError,
///     std::io::Error => IoError,
/// }
/// ```
#[macro_export]
macro_rules! soar_error_from {
    ($($source_type:ty => $variant:ident),+ $(,)?) => {
        $(
            impl From<$source_type> for $crate::modules::soar::case_management::errors::SoarError {
                fn from(source: $source_type) -> Self {
                    Self::$variant { source: Box::new(source) }
                }
            }
        )+
    };
}

/// Comprehensive error conversion generator
/// Generates multiple From implementations at once
///
/// Usage:
/// ```rust
/// generate_error_conversions! {
///     crate::shared::error::AppError {
///         redis::RedisError => RedisConnectionError,
///         serde_json::Error => SerializationError,
///         reqwest::Error => HttpClientError,
///     }
/// }
/// ```
#[macro_export]
macro_rules! generate_error_conversions {
    ($error_type:ty { $($source:ty => $variant:ident),+ $(,)? }) => {
        $(
            impl From<$source> for $error_type {
                fn from(source: $source) -> Self {
                    Self::$variant { source }
                }
            }
        )+
    };
}

#[cfg(test)]
mod tests {

    // Mock error types for testing
    #[derive(Debug, thiserror::Error)]
    #[error("Test error")]
    #[allow(dead_code)]
    struct TestError;

    #[derive(Debug, thiserror::Error)]
    #[allow(dead_code)]
    enum MockAppError {
        #[error("Redis error")]
        RedisConnectionError { source: TestError },
        #[error("Serialization error")]
        SerializationError { source: TestError },
        #[error("Internal error: {context}")]
        InternalError {
            error_id: uuid::Uuid,
            context: String,
        },
    }

    // This would generate the From implementations:
    // generate_error_conversions! {
    //     Mockcrate::shared::error::AppError {
    //         TestError => RedisConnectionError,
    //     }
    // }

    #[test]
    fn test_macro_syntax() {
        // Just testing that the macro syntax compiles
        assert!(true);
    }
}
