//! Scope Value Object
//!
//! Represents `OAuth` 2.0 scopes.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// `OAuth` 2.0 scope value object
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Scope(String);

impl Scope {
    /// Create a new scope with validation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The scope is empty (`ScopeError::Empty`)
    /// - The scope is longer than 100 characters (`ScopeError::TooLong`)
    /// - The scope contains invalid characters (only alphanumeric, underscore,
    ///   and hyphen are allowed) (`ScopeError::InvalidFormat`)
    pub fn new(scope: impl Into<String>) -> Result<Self, ScopeError> {
        let scope = scope.into();

        if scope.is_empty() {
            return Err(ScopeError::Empty);
        }

        if scope.len() > 100 {
            return Err(ScopeError::TooLong);
        }

        // Validate scope format (alphanumeric, underscore, hyphen, colon)
        if !scope
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == ':')
        {
            return Err(ScopeError::InvalidFormat);
        }

        Ok(Self(scope))
    }

    /// Get the scope as a string
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the scope as a string (consuming self)
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    /// Check if this scope includes read access
    #[must_use]
    pub fn has_read(&self) -> bool {
        self.0 == "read" || self.0 == "read:write"
    }

    /// Check if this scope includes write access
    #[must_use]
    pub fn has_write(&self) -> bool {
        self.0 == "write" || self.0 == "read:write"
    }
}

/// Scope validation error
#[derive(Debug, thiserror::Error, Clone)]
pub enum ScopeError {
    #[error("Scope cannot be empty")]
    Empty,
    #[error("Scope too long (max 100 characters)")]
    TooLong,
    #[error("Invalid scope format")]
    InvalidFormat,
}

impl FromStr for Scope {
    type Err = ScopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_scope() {
        let scope = Scope::new("read");
        assert!(scope.is_ok());
        assert_eq!(scope.unwrap().as_str(), "read");
    }

    #[test]
    fn test_invalid_scope_format() {
        let scope = Scope::new("read@write");
        assert!(scope.is_err());
        assert!(matches!(scope.unwrap_err(), ScopeError::InvalidFormat));
    }

    #[test]
    fn test_empty_scope() {
        let scope = Scope::new("");
        assert!(scope.is_err());
        assert!(matches!(scope.unwrap_err(), ScopeError::Empty));
    }

    #[test]
    fn test_scope_permissions() {
        let read_scope = Scope::new("read").unwrap();
        assert!(read_scope.has_read());
        assert!(!read_scope.has_write());

        let write_scope = Scope::new("write").unwrap();
        assert!(!write_scope.has_read());
        assert!(write_scope.has_write());

        let read_write_scope = Scope::new("read:write").unwrap();
        assert!(read_write_scope.has_read());
        assert!(read_write_scope.has_write());
    }
}
