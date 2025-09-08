//! Common Configuration Utilities
//!
//! This module provides reusable utilities for loading and validating
//! configuration from environment variables across crypto modules.

use super::*;
use std::env;
use std::str::FromStr;

/// Utility functions for loading configuration from environment variables
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load a required configuration value from environment variable
    pub fn load_required<T>(env_var: &str) -> CryptoResult<T>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        env::var(env_var)
            .map_err(|_| {
                CryptoError::InvalidConfiguration(format!(
                    "Missing required environment variable: {}",
                    env_var
                ))
            })?
            .parse()
            .map_err(|e| {
                CryptoError::InvalidConfiguration(format!("Invalid value for {}: {}", env_var, e))
            })
    }

    /// Load an optional configuration value with a default
    pub fn load_optional_with_default<T>(env_var: &str, default: T) -> CryptoResult<T>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        match env::var(env_var) {
            Ok(value) => value.parse().map_err(|e| {
                CryptoError::InvalidConfiguration(format!("Invalid value for {}: {}", env_var, e))
            }),
            Err(_) => Ok(default),
        }
    }

    /// Load a boolean configuration value
    pub fn load_bool(env_var: &str, default: bool) -> bool {
        env::var(env_var)
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(default)
    }

    /// Load a string configuration value with validation
    pub fn load_validated_string<F>(
        env_var: &str,
        default: String,
        validator: F,
    ) -> CryptoResult<String>
    where
        F: Fn(&str) -> bool,
    {
        let value = env::var(env_var).unwrap_or(default);
        if validator(&value) {
            Ok(value)
        } else {
            Err(CryptoError::InvalidConfiguration(format!(
                "Invalid value for {}: validation failed",
                env_var
            )))
        }
    }

    /// Validate numeric range
    pub fn validate_range<T>(value: T, min: T, max: T, param_name: &str) -> CryptoResult<T>
    where
        T: PartialOrd + std::fmt::Display + Copy,
    {
        if value < min || value > max {
            return Err(CryptoError::ValidationFailed(format!(
                "{} must be between {} and {}, got {}",
                param_name, min, max, value
            )));
        }
        Ok(value)
    }

    /// Validate minimum value
    pub fn validate_minimum<T>(value: T, min: T, param_name: &str) -> CryptoResult<T>
    where
        T: PartialOrd + std::fmt::Display + Copy,
    {
        if value < min {
            return Err(CryptoError::ValidationFailed(format!(
                "{} must be at least {}, got {}",
                param_name, min, value
            )));
        }
        Ok(value)
    }

    /// Validate maximum value  
    pub fn validate_maximum<T>(value: T, max: T, param_name: &str) -> CryptoResult<T>
    where
        T: PartialOrd + std::fmt::Display + Copy,
    {
        if value > max {
            return Err(CryptoError::ValidationFailed(format!(
                "{} must be at most {}, got {}",
                param_name, max, value
            )));
        }
        Ok(value)
    }

    /// Load and validate a string length
    pub fn validate_string_length(
        value: &str,
        min_len: usize,
        max_len: usize,
        param_name: &str,
    ) -> CryptoResult<()> {
        if value.len() < min_len {
            return Err(CryptoError::ValidationFailed(format!(
                "{} must be at least {} characters long",
                param_name, min_len
            )));
        }
        if value.len() > max_len {
            return Err(CryptoError::ValidationFailed(format!(
                "{} must be at most {} characters long",
                param_name, max_len
            )));
        }
        Ok(())
    }

    /// Check if string contains insecure patterns
    pub fn validate_no_insecure_patterns(
        value: &str,
        patterns: &[&str],
        param_name: &str,
    ) -> CryptoResult<()> {
        for pattern in patterns {
            if value.contains(pattern) {
                return Err(CryptoError::ValidationFailed(format!(
                    "{} contains insecure pattern: {}",
                    param_name, pattern
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_load_required_success() {
        env::set_var("TEST_REQUIRED", "42");
        let result: CryptoResult<u32> = ConfigLoader::load_required("TEST_REQUIRED");
        assert_eq!(result.unwrap(), 42);
        env::remove_var("TEST_REQUIRED");
    }

    #[test]
    fn test_load_required_missing() {
        env::remove_var("TEST_MISSING");
        let result: CryptoResult<u32> = ConfigLoader::load_required("TEST_MISSING");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_optional_with_default() {
        env::remove_var("TEST_OPTIONAL");
        let result: CryptoResult<u32> =
            ConfigLoader::load_optional_with_default("TEST_OPTIONAL", 100);
        assert_eq!(result.unwrap(), 100);
    }

    #[test]
    fn test_load_bool() {
        env::set_var("TEST_BOOL_TRUE", "true");
        env::set_var("TEST_BOOL_1", "1");
        env::set_var("TEST_BOOL_FALSE", "false");

        assert!(ConfigLoader::load_bool("TEST_BOOL_TRUE", false));
        assert!(ConfigLoader::load_bool("TEST_BOOL_1", false));
        assert!(!ConfigLoader::load_bool("TEST_BOOL_FALSE", true));
        assert!(!ConfigLoader::load_bool("TEST_BOOL_MISSING", false));

        env::remove_var("TEST_BOOL_TRUE");
        env::remove_var("TEST_BOOL_1");
        env::remove_var("TEST_BOOL_FALSE");
    }

    #[test]
    fn test_validate_range() {
        assert!(ConfigLoader::validate_range(50u32, 0, 100, "test").is_ok());
        assert!(ConfigLoader::validate_range(150u32, 0, 100, "test").is_err());
    }

    #[test]
    fn test_validate_string_length() {
        assert!(ConfigLoader::validate_string_length("hello", 1, 10, "test").is_ok());
        assert!(ConfigLoader::validate_string_length("", 1, 10, "test").is_err());
        assert!(ConfigLoader::validate_string_length("very_long_string", 1, 5, "test").is_err());
    }

    #[test]
    fn test_validate_no_insecure_patterns() {
        let patterns = &["REPLACE_WITH", "DEFAULT", "CHANGEME"];
        assert!(
            ConfigLoader::validate_no_insecure_patterns("secure_key", patterns, "test").is_ok()
        );
        assert!(
            ConfigLoader::validate_no_insecure_patterns("REPLACE_WITH_KEY", patterns, "test")
                .is_err()
        );
    }
}
