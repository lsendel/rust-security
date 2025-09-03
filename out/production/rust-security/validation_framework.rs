//! Validation Framework - Reusable validation types and macros
//!
//! This module provides common validation patterns to reduce code duplication
//! across SCIM DTOs and other validation structures.

use validator::ValidationError;

/// Common string field lengths
pub const MAX_SHORT_STRING: usize = 50;
pub const MAX_MEDIUM_STRING: usize = 255;
pub const MAX_LONG_STRING: usize = 500;
pub const MAX_EMAIL: usize = 320;
pub const MAX_PHONE: usize = 20;
pub const MAX_CERT: usize = 10000;

/// Type alias for email validation
pub type ValidatedEmail = String;

/// Type alias for short strings (like types, codes)
pub type ValidatedShortString = String;

/// Type alias for medium strings (like names, descriptions)  
pub type ValidatedMediumString = String;

/// Type alias for long strings (like formatted addresses)
pub type ValidatedLongString = String;

/// Type alias for phone numbers
pub type ValidatedPhone = String;

/// Reusable validation constraints trait
pub trait ValidationConstraints {
    fn validate_email(&self) -> Result<(), ValidationError>;
    fn validate_short_string(&self) -> Result<(), ValidationError>;
    fn validate_medium_string(&self) -> Result<(), ValidationError>;
    fn validate_long_string(&self) -> Result<(), ValidationError>;
    fn validate_phone(&self) -> Result<(), ValidationError>;
}

impl ValidationConstraints for Option<String> {
    fn validate_email(&self) -> Result<(), ValidationError> {
        if let Some(email) = self {
            if email.len() > MAX_EMAIL {
                return Err(ValidationError::new("Email too long"));
            }
            // Basic email validation
            if !email.contains('@') || !email.contains('.') {
                return Err(ValidationError::new("Invalid email format"));
            }
        }
        Ok(())
    }

    fn validate_short_string(&self) -> Result<(), ValidationError> {
        if let Some(s) = self {
            if s.len() > MAX_SHORT_STRING {
                return Err(ValidationError::new("String too long"));
            }
        }
        Ok(())
    }

    fn validate_medium_string(&self) -> Result<(), ValidationError> {
        if let Some(s) = self {
            if s.len() > MAX_MEDIUM_STRING {
                return Err(ValidationError::new("String too long"));
            }
        }
        Ok(())
    }

    fn validate_long_string(&self) -> Result<(), ValidationError> {
        if let Some(s) = self {
            if s.len() > MAX_LONG_STRING {
                return Err(ValidationError::new("String too long"));
            }
        }
        Ok(())
    }

    fn validate_phone(&self) -> Result<(), ValidationError> {
        if let Some(phone) = self {
            if phone.len() > MAX_PHONE {
                return Err(ValidationError::new("Phone number too long"));
            }
        }
        Ok(())
    }
}

impl ValidationConstraints for String {
    fn validate_email(&self) -> Result<(), ValidationError> {
        Some(self.clone()).validate_email()
    }

    fn validate_short_string(&self) -> Result<(), ValidationError> {
        Some(self.clone()).validate_short_string()
    }

    fn validate_medium_string(&self) -> Result<(), ValidationError> {
        Some(self.clone()).validate_medium_string()
    }

    fn validate_long_string(&self) -> Result<(), ValidationError> {
        Some(self.clone()).validate_long_string()
    }

    fn validate_phone(&self) -> Result<(), ValidationError> {
        Some(self.clone()).validate_phone()
    }
}

/// Macro to create common validation patterns
#[macro_export]
macro_rules! validated_field {
    (email, $field:expr) => {
        #[validate(email, length(max = 320))]
        $field: String
    };
    (short_string, $field:expr) => {
        #[validate(length(max = 50))]
        $field: Option<String>
    };
    (medium_string, $field:expr) => {
        #[validate(length(max = 255))]
        $field: Option<String>
    };
    (long_string, $field:expr) => {
        #[validate(length(max = 500))]
        $field: Option<String>
    };
    (phone, $field:expr) => {
        #[validate(length(max = 20))]
        $field: String
    };
}

/// Common validation functions
pub fn validate_phone_number(phone: &str) -> Result<(), ValidationError> {
    // Basic phone number validation - digits, spaces, dashes, parentheses, plus
    let allowed_chars = phone
        .chars()
        .all(|c| c.is_ascii_digit() || c == ' ' || c == '-' || c == '(' || c == ')' || c == '+');

    if !allowed_chars {
        return Err(ValidationError::new("Invalid phone number format"));
    }

    let digit_count = phone.chars().filter(char::is_ascii_digit).count();
    if !(10..=15).contains(&digit_count) {
        return Err(ValidationError::new("Phone number must have 10-15 digits"));
    }

    Ok(())
}

pub fn validate_country_code(code: &str) -> Result<(), ValidationError> {
    if code.len() != 2 {
        return Err(ValidationError::new(
            "Country code must be exactly 2 characters",
        ));
    }
    if !code
        .chars()
        .all(|c| c.is_ascii_alphabetic() && c.is_uppercase())
    {
        return Err(ValidationError::new(
            "Country code must be uppercase letters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validation() {
        let valid_email = "user@example.com".to_string();
        assert!(valid_email.validate_email().is_ok());

        let invalid_email = "not-an-email".to_string();
        assert!(invalid_email.validate_email().is_err());
    }

    #[test]
    fn test_phone_validation() {
        assert!(validate_phone_number("+1-555-123-4567").is_ok());
        assert!(validate_phone_number("555.123.4567").is_err()); // dots not allowed
        assert!(validate_phone_number("123").is_err()); // too short
    }

    #[test]
    fn test_country_code_validation() {
        assert!(validate_country_code("US").is_ok());
        assert!(validate_country_code("us").is_err()); // not uppercase
        assert!(validate_country_code("USA").is_err()); // too long
    }
}
