use thiserror::Error;
use regex::Regex;
use std::collections::HashSet;

// SCIM Filter parsing structures, now public for sharing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimOperator {
    Eq, // equals
    Ne, // not equals
    Co, // contains
    Sw, // starts with
    Ew, // ends with
    Pr, // present (has value)
    Gt, // greater than
    Ge, // greater than or equal
    Lt, // less than
    Le, // less than or equal
}

#[derive(Debug, Clone)]
pub struct ScimFilter {
    pub attribute: String,
    pub operator: ScimOperator,
    pub value: Option<String>,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ScimFilterError {
    #[error("Invalid filter syntax")]
    InvalidSyntax,
    #[error("Unsupported operator: {0}")]
    UnsupportedOperator(String),
    #[error("Invalid attribute: {0}")]
    InvalidAttribute(String),
    #[error("Filter too long (max 500 characters)")]
    FilterTooLong,
    #[error("Potential injection attempt detected")]
    InjectionAttempt,
    #[error("Invalid value format")]
    InvalidValue,
}

lazy_static::lazy_static! {
    // Allowed SCIM attributes - whitelist approach for security
    static ref ALLOWED_ATTRIBUTES: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("userName");
        set.insert("id");
        set.insert("active");
        set.insert("displayName");
        set.insert("email");
        set.insert("name.familyName");
        set.insert("name.givenName");
        set.insert("phoneNumber");
        set
    };

    // SQL injection patterns - enhanced detection
    static ref SQL_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)\b(select|insert|update|delete|drop|create|alter|exec|execute|union|script|declare|cursor|fetch|bulk|backup|restore)\b").unwrap(),
        Regex::new(r"(?i)(--|/\*|\*/|;|@@|@|\bxp_)").unwrap(),
        Regex::new(r"(?i)\b(or|and)\s+\d+\s*=\s*\d+").unwrap(),
        Regex::new(r"(?i)\b(or|and)\s+'[^']*'\s*=\s*'[^']*'").unwrap(),
        Regex::new(r"(?i)\bunion\s+(all\s+)?select").unwrap(),
    ];

    // XSS patterns - enhanced detection
    static ref XSS_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)<\s*script").unwrap(),
        Regex::new(r"(?i)javascript\s*:").unwrap(),
        Regex::new(r"(?i)on\w+\s*=").unwrap(),
        Regex::new(r"(?i)expression\s*\(").unwrap(),
        Regex::new(r"(?i)eval\s*\(").unwrap(),
    ];

    // Valid value pattern - alphanumeric, spaces, and common symbols
    static ref VALID_VALUE_PATTERN: Regex = Regex::new(r"^[a-zA-Z0-9\s\.\-_@\+\(\)]*$").unwrap();
}

/// Enhanced SCIM filter parser with comprehensive security validation
pub fn parse_scim_filter(filter: &str) -> Result<ScimFilter, ScimFilterError> {
    // Length validation
    if filter.len() > 500 {
        return Err(ScimFilterError::FilterTooLong);
    }

    // Basic format validation
    let parts: Vec<&str> = filter.split_whitespace().collect();
    if parts.len() < 2 || parts.len() > 3 {
        return Err(ScimFilterError::InvalidSyntax);
    }

    let attribute = parts[0].to_string();
    let operator_str = parts[1];
    let value = parts.get(2).map(|v| v.trim_matches('"').to_string());

    // Validate attribute against whitelist
    if !ALLOWED_ATTRIBUTES.contains(attribute.as_str()) {
        return Err(ScimFilterError::InvalidAttribute(attribute));
    }

    // Parse operator
    let operator = match operator_str.to_lowercase().as_str() {
        "eq" => ScimOperator::Eq,
        "ne" => ScimOperator::Ne,
        "co" => ScimOperator::Co,
        "sw" => ScimOperator::Sw,
        "ew" => ScimOperator::Ew,
        "pr" => ScimOperator::Pr,
        _ => {
            return Err(ScimFilterError::UnsupportedOperator(
                operator_str.to_string(),
            ))
        }
    };

    // Validate value if present
    if let Some(ref val) = value {
        // Check for injection attempts
        if detect_injection_attempts(val) {
            return Err(ScimFilterError::InjectionAttempt);
        }

        // Validate value format
        if !VALID_VALUE_PATTERN.is_match(val) {
            return Err(ScimFilterError::InvalidValue);
        }

        // Additional length check for values
        if val.len() > 255 {
            return Err(ScimFilterError::InvalidValue);
        }
    }

    // Operator-specific validation
    if operator != ScimOperator::Pr && value.is_none() {
        return Err(ScimFilterError::InvalidSyntax);
    }

    Ok(ScimFilter {
        attribute,
        operator,
        value,
    })
}

/// Detect potential injection attempts using pattern matching
fn detect_injection_attempts(input: &str) -> bool {
    let input_lower = input.to_lowercase();

    // Check SQL injection patterns
    for pattern in SQL_INJECTION_PATTERNS.iter() {
        if pattern.is_match(&input_lower) {
            return true;
        }
    }

    // Check XSS patterns
    for pattern in XSS_PATTERNS.iter() {
        if pattern.is_match(&input_lower) {
            return true;
        }
    }

    // Check for common injection indicators
    if input_lower.contains("/*") || 
       input_lower.contains("*/") || 
       input_lower.contains("--") ||
       input_lower.contains("xp_") ||
       input_lower.contains("sp_") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_filters() {
        assert!(parse_scim_filter("userName eq \"john\"").is_ok());
        assert!(parse_scim_filter("active eq true").is_ok());
        assert!(parse_scim_filter("email co \"@example.com\"").is_ok());
        assert!(parse_scim_filter("id pr").is_ok());
    }

    #[test]
    fn test_sql_injection_detection() {
        assert!(parse_scim_filter("userName eq \"john'; DROP TABLE users;--\"").is_err());
        assert!(parse_scim_filter("userName eq \"john UNION SELECT password FROM users\"").is_err());
        assert!(parse_scim_filter("userName eq \"john' OR '1'='1\"").is_err());
    }

    #[test]
    fn test_xss_detection() {
        assert!(parse_scim_filter("userName eq \"<script>alert('xss')</script>\"").is_err());
        assert!(parse_scim_filter("userName eq \"javascript:alert('xss')\"").is_err());
        assert!(parse_scim_filter("userName eq \"onload=alert('xss')\"").is_err());
    }

    #[test]
    fn test_attribute_whitelist() {
        assert!(parse_scim_filter("userName eq \"john\"").is_ok());
        assert!(parse_scim_filter("maliciousAttr eq \"value\"").is_err());
        assert!(parse_scim_filter("../../../etc/passwd eq \"value\"").is_err());
    }

    #[test]
    fn test_value_validation() {
        assert!(parse_scim_filter("userName eq \"valid-user@example.com\"").is_ok());
        assert!(parse_scim_filter("userName eq \"invalid<>chars\"").is_err());
        assert!(parse_scim_filter("userName eq \"too_long_value_that_exceeds_the_maximum_allowed_length_for_filter_values_which_should_be_rejected_by_the_validation_system_to_prevent_potential_buffer_overflow_attacks_or_denial_of_service_conditions_that_could_occur_from_processing_extremely_long_input_strings\"").is_err());
    }

    #[test]
    fn test_syntax_validation() {
        assert!(parse_scim_filter("userName").is_err()); // Missing operator
        assert!(parse_scim_filter("userName eq").is_err()); // Missing value for non-pr operator
        assert!(parse_scim_filter("userName invalid_op \"value\"").is_err()); // Invalid operator
    }
}
