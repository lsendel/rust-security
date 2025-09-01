//! Email value object with validation.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Email value object with validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    /// Create a new email with validation
    pub fn new(email: String) -> Result<Self, String> {
        Self::validate(&email)?;
        Ok(Self(email))
    }

    /// Get the email as a string
    #[must_use] pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the email domain
    #[must_use] pub fn domain(&self) -> &str {
        self.0.split('@').nth(1).unwrap_or("")
    }

    /// Get the email username (part before @)
    #[must_use] pub fn username(&self) -> &str {
        self.0.split('@').next().unwrap_or("")
    }

    /// Validate email format using regex
    fn validate(email: &str) -> Result<(), String> {
        if email.is_empty() {
            return Err("Email cannot be empty".to_string());
        }

        if email.len() > 254 {
            return Err("Email is too long (maximum 254 characters)".to_string());
        }

        // RFC 5322 compliant email regex (simplified)
        let email_regex = Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
            .map_err(|_| "Invalid regex pattern".to_string())?;

        if !email_regex.is_match(email) {
            return Err("Invalid email format".to_string());
        }

        Ok(())
    }
}

impl FromStr for Email {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl std::fmt::Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_valid_email_creation() {
        let email = Email::new("test@example.com".to_string());
        assert!(email.is_ok());
        assert_eq!(email.unwrap().as_str(), "test@example.com");
    }

    #[test]
    fn test_email_from_str() {
        let email = Email::from_str("user@domain.org");
        assert!(email.is_ok());
        assert_eq!(email.unwrap().as_str(), "user@domain.org");
    }

    #[test]
    fn test_email_domain_and_username() {
        let email = Email::new("john.doe@example.com".to_string()).unwrap();

        assert_eq!(email.username(), "john.doe");
        assert_eq!(email.domain(), "example.com");
    }

    #[test]
    fn test_email_display() {
        let email = Email::new("test@example.com".to_string()).unwrap();
        assert_eq!(format!("{}", email), "test@example.com");
    }

    #[test]
    fn test_empty_email() {
        let email = Email::new("".to_string());
        assert!(email.is_err());
        assert_eq!(email.unwrap_err(), "Email cannot be empty");
    }

    #[test]
    fn test_email_too_long() {
        let long_email = "a".repeat(255) + "@example.com";
        let email = Email::new(long_email);
        assert!(email.is_err());
        assert!(email.unwrap_err().contains("too long"));
    }

    #[test]
    fn test_invalid_email_formats() {
        let invalid_emails = vec![
            "invalid",
            "@example.com",
            "user@",
            "user@.com",
            "user..double@example.com",
            "user@example..com",
            "user @example.com",
            "user@example.com ",
        ];

        for invalid_email in invalid_emails {
            let email = Email::new(invalid_email.to_string());
            assert!(
                email.is_err(),
                "Email '{}' should be invalid",
                invalid_email
            );
        }
    }

    #[test]
    fn test_valid_email_formats() {
        let valid_emails = vec![
            "test@example.com",
            "user.name@domain.org",
            "user+tag@gmail.com",
            "123@numbers.com",
            "test.email@sub.domain.co.uk",
            "user_name@example-domain.com",
        ];

        for valid_email in valid_emails {
            let email = Email::new(valid_email.to_string());
            assert!(email.is_ok(), "Email '{}' should be valid", valid_email);
        }
    }

    #[test]
    fn test_email_equality() {
        let email1 = Email::new("test@example.com".to_string()).unwrap();
        let email2 = Email::new("test@example.com".to_string()).unwrap();
        let email3 = Email::new("other@example.com".to_string()).unwrap();

        assert_eq!(email1, email2);
        assert_ne!(email1, email3);
    }

    #[test]
    fn test_email_hash() {
        use std::collections::HashMap;

        let mut map = HashMap::new();
        let email1 = Email::new("test@example.com".to_string()).unwrap();
        let email2 = Email::new("test@example.com".to_string()).unwrap();

        map.insert(email1, "value");

        assert_eq!(map.get(&email2), Some(&"value"));
    }
}
