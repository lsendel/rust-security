//! Validation utilities for compliance tools

use crate::{ComplianceError, ComplianceResult};

/// Validation utilities
pub struct Validator;

impl Validator {
    /// Validate email address format
    #[must_use]
    pub fn validate_email(email: &str) -> bool {
        // Simple email validation - in production use a proper regex or validation library
        email.contains('@') && email.contains('.') && email.len() > 5
    }

    /// Validate URL format
    ///
    /// # Errors
    /// Returns an error if the URL cannot be parsed.
    pub fn validate_url(url: &str) -> ComplianceResult<()> {
        match url::Url::parse(url) {
            Ok(_) => Ok(()),
            Err(e) => Err(ComplianceError::Validation(format!("Invalid URL: {e}"))),
        }
    }

    /// Validate file path exists
    ///
    /// # Errors
    /// Returns an error if the file does not exist.
    pub fn validate_file_path(path: &str) -> ComplianceResult<()> {
        if std::path::Path::new(path).exists() {
            Ok(())
        } else {
            Err(ComplianceError::Validation(format!(
                "File path does not exist: {path}"
            )))
        }
    }

    /// Validate directory path exists
    ///
    /// # Errors
    /// Returns an error if the directory does not exist or is not a directory.
    pub fn validate_directory_path(path: &str) -> ComplianceResult<()> {
        let path = std::path::Path::new(path);
        if path.exists() && path.is_dir() {
            Ok(())
        } else {
            Err(ComplianceError::Validation(format!(
                "Directory path does not exist: {}",
                path.display()
            )))
        }
    }

    /// Validate positive integer
    ///
    /// # Errors
    /// Returns an error if the value is not positive.
    pub fn validate_positive_integer(value: i64) -> ComplianceResult<()> {
        if value > 0 {
            Ok(())
        } else {
            Err(ComplianceError::Validation(format!(
                "Value must be positive: {value}"
            )))
        }
    }

    /// Validate percentage (0-100)
    ///
    /// # Errors
    /// Returns an error if the percentage is out of range.
    pub fn validate_percentage(value: f64) -> ComplianceResult<()> {
        if (0.0..=100.0).contains(&value) {
            Ok(())
        } else {
            Err(ComplianceError::Validation(format!(
                "Percentage must be between 0 and 100: {value}"
            )))
        }
    }
}
