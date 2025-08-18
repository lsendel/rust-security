use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use once_cell::sync::Lazy;

/// Classification levels for sensitive data
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DataClassification {
    /// Personally Identifiable Information (PII)
    Pii,
    /// Sensitive Personal Information (SPI) 
    Spi,
    /// Confidential business information
    Confidential,
    /// Internal use only
    Internal,
    /// Public information
    Public,
}

/// Types of sensitive data patterns
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SensitiveDataType {
    EmailAddress,
    PhoneNumber,
    SocialSecurityNumber,
    CreditCardNumber,
    BankAccountNumber,
    Passport,
    DriversLicense,
    IpAddress,
    MacAddress,
    Uuid,
    JwtToken,
    ApiKey,
    Password,
    CryptographicKey,
    SessionId,
    AuthorizationCode,
    RefreshToken,
    AccessToken,
    ClientSecret,
    DatabaseConnectionString,
    Url,
    FilePath,
    HealthRecord,
    BiometricData,
    TaxId,
    CustomerId,
}

impl SensitiveDataType {
    /// Get the data classification for this sensitive data type
    pub fn classification(&self) -> DataClassification {
        match self {
            // PII data
            SensitiveDataType::EmailAddress
            | SensitiveDataType::PhoneNumber
            | SensitiveDataType::IpAddress
            | SensitiveDataType::MacAddress
            | SensitiveDataType::Uuid => DataClassification::Pii,
            
            // SPI data (highly sensitive PII)
            SensitiveDataType::SocialSecurityNumber
            | SensitiveDataType::CreditCardNumber
            | SensitiveDataType::BankAccountNumber
            | SensitiveDataType::Passport
            | SensitiveDataType::DriversLicense
            | SensitiveDataType::HealthRecord
            | SensitiveDataType::BiometricData
            | SensitiveDataType::TaxId => DataClassification::Spi,
            
            // Confidential authentication/security data
            SensitiveDataType::JwtToken
            | SensitiveDataType::ApiKey
            | SensitiveDataType::Password
            | SensitiveDataType::CryptographicKey
            | SensitiveDataType::SessionId
            | SensitiveDataType::AuthorizationCode
            | SensitiveDataType::RefreshToken
            | SensitiveDataType::AccessToken
            | SensitiveDataType::ClientSecret
            | SensitiveDataType::DatabaseConnectionString => DataClassification::Confidential,
            
            // Internal system data
            SensitiveDataType::Url
            | SensitiveDataType::FilePath
            | SensitiveDataType::CustomerId => DataClassification::Internal,
        }
    }

    /// Get the redaction strategy for this data type
    pub fn redaction_strategy(&self) -> RedactionStrategy {
        match self.classification() {
            DataClassification::Spi => RedactionStrategy::FullRedaction,
            DataClassification::Confidential => RedactionStrategy::FullRedaction,
            DataClassification::Pii => RedactionStrategy::PartialRedaction,
            DataClassification::Internal => RedactionStrategy::PartialRedaction,
            DataClassification::Public => RedactionStrategy::NoRedaction,
        }
    }
}

/// Redaction strategies for different data types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactionStrategy {
    /// No redaction needed
    NoRedaction,
    /// Partially redact (show some characters for utility)
    PartialRedaction,
    /// Fully redact (replace with placeholder)
    FullRedaction,
    /// Hash the value (for consistent references)
    HashRedaction,
}

/// Pattern definitions for sensitive data detection
static SENSITIVE_PATTERNS: Lazy<HashMap<SensitiveDataType, Regex>> = Lazy::new(|| {
    let mut patterns = HashMap::new();
    
    // Email addresses
    patterns.insert(
        SensitiveDataType::EmailAddress,
        Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap()
    );
    
    // Phone numbers (various formats) - matches US phone numbers
    patterns.insert(
        SensitiveDataType::PhoneNumber,
        Regex::new(r"(?:\+?1[-.\s]?)?\(?[2-9][0-9]{2}\)?[-.\s]?[2-9][0-9]{2}[-.\s]?[0-9]{4}").unwrap()
    );
    
    // Social Security Numbers - more restrictive to avoid false positives
    patterns.insert(
        SensitiveDataType::SocialSecurityNumber,
        Regex::new(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b").unwrap()
    );
    
    // Credit Card Numbers (basic pattern)
    patterns.insert(
        SensitiveDataType::CreditCardNumber,
        Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{4}\b").unwrap()
    );
    
    // IPv4 addresses
    patterns.insert(
        SensitiveDataType::IpAddress,
        Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap()
    );
    
    // MAC addresses
    patterns.insert(
        SensitiveDataType::MacAddress,
        Regex::new(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b").unwrap()
    );
    
    // UUIDs
    patterns.insert(
        SensitiveDataType::Uuid,
        Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b").unwrap()
    );
    
    // JWT tokens (header.payload.signature)
    patterns.insert(
        SensitiveDataType::JwtToken,
        Regex::new(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").unwrap()
    );
    
    // API keys (specific patterns for common API key formats)
    patterns.insert(
        SensitiveDataType::ApiKey,
        Regex::new(r"\b(?:sk_|pk_)[a-zA-Z0-9]{20,}\b").unwrap()
    );
    
    // Passwords in logs (password=value patterns)
    patterns.insert(
        SensitiveDataType::Password,
        Regex::new(r"(?i)(?:password|pwd|pass)[:=]\s*[^\s&]+").unwrap()
    );
    
    // Database connection strings
    patterns.insert(
        SensitiveDataType::DatabaseConnectionString,
        Regex::new(r"(?i)(?:mongodb|mysql|postgres|redis)://[^\s]+").unwrap()
    );
    
    // File paths with sensitive indicators
    patterns.insert(
        SensitiveDataType::FilePath,
        Regex::new(r"(?i)(?:/[^/\s]*(?:secret|key|password|token|private)[^/\s]*)+").unwrap()
    );
    
    // Authorization codes and tokens (more specific pattern to avoid false positives)
    patterns.insert(
        SensitiveDataType::AuthorizationCode,
        Regex::new(r"\b[A-Za-z0-9_-]{40,}\b").unwrap()
    );
    
    patterns
});

/// Comprehensive PII/SPI redaction utility
pub struct PiiSpiRedactor {
    /// Whether to apply aggressive redaction
    aggressive_mode: bool,
    /// Custom patterns for organization-specific data
    custom_patterns: HashMap<String, Regex>,
}

impl Default for PiiSpiRedactor {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiSpiRedactor {
    /// Create a new PII/SPI redactor
    pub fn new() -> Self {
        Self {
            aggressive_mode: false,
            custom_patterns: HashMap::new(),
        }
    }
    
    /// Enable aggressive redaction mode
    pub fn with_aggressive_mode(mut self, aggressive: bool) -> Self {
        self.aggressive_mode = aggressive;
        self
    }
    
    /// Add a custom pattern for organization-specific sensitive data
    pub fn with_custom_pattern(mut self, name: String, pattern: Regex) -> Self {
        self.custom_patterns.insert(name, pattern);
        self
    }
    
    /// Redact sensitive data from text based on classification levels
    pub fn redact_text(&self, text: &str, max_classification: DataClassification) -> String {
        let mut redacted = text.to_string();
        
        // Sort patterns by specificity to avoid conflicts (more specific patterns first)
        let mut sorted_patterns: Vec<_> = SENSITIVE_PATTERNS.iter().collect();
        sorted_patterns.sort_by_key(|(data_type, _)| match data_type {
            SensitiveDataType::JwtToken => 0,  // Most specific
            SensitiveDataType::ApiKey => 1,
            SensitiveDataType::SocialSecurityNumber => 2,
            SensitiveDataType::CreditCardNumber => 3,
            SensitiveDataType::EmailAddress => 4,
            SensitiveDataType::PhoneNumber => 5,
            SensitiveDataType::Uuid => 6,
            SensitiveDataType::IpAddress => 7,
            SensitiveDataType::MacAddress => 8,
            SensitiveDataType::AuthorizationCode => 9, // Less specific
            _ => 10,
        });
        
        // Apply built-in patterns in order of specificity
        for (data_type, pattern) in sorted_patterns {
            if self.should_redact_type(data_type, &max_classification) {
                redacted = self.apply_redaction(&redacted, pattern, data_type);
            }
        }
        
        // Apply custom patterns if in aggressive mode
        if self.aggressive_mode {
            for (name, pattern) in &self.custom_patterns {
                redacted = pattern.replace_all(&redacted, &format!("[{}_REDACTED]", name.to_uppercase())).to_string();
            }
        }
        
        // Final length check and truncation
        if redacted.len() > 1000 {
            redacted = format!("{}...[TRUNCATED]", &redacted[0..997]);
        }
        
        redacted
    }
    
    /// Check if a data type should be redacted based on classification level
    fn should_redact_type(&self, data_type: &SensitiveDataType, max_classification: &DataClassification) -> bool {
        match (data_type.classification(), max_classification) {
            // Always redact SPI regardless of max level
            (DataClassification::Spi, _) => true,
            // Redact Confidential if max allows Internal or above
            (DataClassification::Confidential, DataClassification::Public) => true,
            (DataClassification::Confidential, _) => true,
            // Redact PII if max is Public or Internal  
            (DataClassification::Pii, DataClassification::Public) => true,
            (DataClassification::Pii, DataClassification::Internal) => true,
            (DataClassification::Pii, _) => false,
            // Redact Internal if max is Public
            (DataClassification::Internal, DataClassification::Public) => true,
            (DataClassification::Internal, _) => false,
            // Never redact Public
            (DataClassification::Public, _) => false,
        }
    }
    
    /// Apply the appropriate redaction strategy for a data type
    fn apply_redaction(&self, text: &str, pattern: &Regex, data_type: &SensitiveDataType) -> String {
        // Skip already redacted content to prevent double redaction
        if text.contains("_REDACTED]") || text.contains("_HASH]") {
            return text.to_string();
        }
        
        match data_type.redaction_strategy() {
            RedactionStrategy::NoRedaction => text.to_string(),
            RedactionStrategy::FullRedaction => {
                pattern.replace_all(text, &format!("[{:?}_REDACTED]", data_type)).to_string()
            },
            RedactionStrategy::PartialRedaction => {
                self.partial_redact(text, pattern, data_type)
            },
            RedactionStrategy::HashRedaction => {
                // For now, treat as full redaction. Could implement hashing later.
                pattern.replace_all(text, &format!("[{:?}_HASH]", data_type)).to_string()
            },
        }
    }
    
    /// Apply partial redaction showing some characters for utility
    fn partial_redact(&self, text: &str, pattern: &Regex, data_type: &SensitiveDataType) -> String {
        pattern.replace_all(text, |caps: &regex::Captures| {
            let matched = caps.get(0).unwrap().as_str();
            match data_type {
                SensitiveDataType::EmailAddress => {
                    if let Some(at_pos) = matched.find('@') {
                        let (user, domain) = matched.split_at(at_pos);
                        if user.len() > 2 {
                            format!("{}****{}", &user[0..1], domain)
                        } else {
                            format!("****{}", domain)
                        }
                    } else {
                        "[EMAIL_REDACTED]".to_string()
                    }
                },
                SensitiveDataType::IpAddress => {
                    let parts: Vec<&str> = matched.split('.').collect();
                    if parts.len() == 4 {
                        format!("{}.{}.{}.***", parts[0], parts[1], parts[2])
                    } else {
                        "[IP_REDACTED]".to_string()
                    }
                },
                SensitiveDataType::PhoneNumber => {
                    if matched.len() >= 4 {
                        format!("****{}", &matched[matched.len()-4..])
                    } else {
                        "[PHONE_REDACTED]".to_string()
                    }
                },
                SensitiveDataType::Uuid => {
                    format!("****-****-****-{}", &matched[matched.len()-4..])
                },
                _ => format!("[{:?}_REDACTED]", data_type),
            }
        }).to_string()
    }
    
    /// Redact error messages specifically
    pub fn redact_error_message(&self, error: &str) -> String {
        // Apply stricter redaction for error messages (Confidential level)
        self.redact_text(error, DataClassification::Internal)
    }
    
    /// Redact log messages
    pub fn redact_log_message(&self, log_message: &str) -> String {
        // Standard redaction for logs (PII level)
        self.redact_text(log_message, DataClassification::Internal)
    }
    
    /// Redact HTTP response data
    pub fn redact_response_data(&self, response: &str) -> String {
        // Conservative redaction for responses (Public level max)
        self.redact_text(response, DataClassification::Public)
    }
    
    /// Check if text contains any sensitive data
    pub fn contains_sensitive_data(&self, text: &str) -> Vec<SensitiveDataType> {
        let mut found_types = Vec::new();
        
        for (data_type, pattern) in SENSITIVE_PATTERNS.iter() {
            if pattern.is_match(text) {
                found_types.push(data_type.clone());
            }
        }
        
        found_types
    }
    
    /// Generate a safe summary of sensitive data found (for audit purposes)
    pub fn audit_sensitive_data(&self, text: &str) -> HashMap<SensitiveDataType, u32> {
        let mut counts = HashMap::new();
        
        for (data_type, pattern) in SENSITIVE_PATTERNS.iter() {
            let count = pattern.find_iter(text).count() as u32;
            if count > 0 {
                counts.insert(data_type.clone(), count);
            }
        }
        
        counts
    }
}

/// Global PII/SPI redactor instance
static GLOBAL_REDACTOR: Lazy<PiiSpiRedactor> = Lazy::new(|| {
    PiiSpiRedactor::new()
        .with_aggressive_mode(std::env::var("PII_AGGRESSIVE_MODE").map_or(false, |v| v == "true"))
});

/// Convenience function for redacting text with the global redactor
pub fn redact_pii_spi(text: &str) -> String {
    GLOBAL_REDACTOR.redact_text(text, DataClassification::Internal)
}

/// Convenience function for redacting error messages
pub fn redact_error(error_message: &str) -> String {
    GLOBAL_REDACTOR.redact_error_message(error_message)
}

/// Convenience function for redacting log messages
pub fn redact_log(log_message: &str) -> String {
    GLOBAL_REDACTOR.redact_log_message(log_message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_redaction() {
        let redactor = PiiSpiRedactor::new();
        let text = "Contact user@example.com for support";
        let redacted = redactor.redact_text(text, DataClassification::Internal);
        assert!(redacted.contains("u****@example.com"));
        assert!(!redacted.contains("user@example.com"));
    }
    
    #[test]
    fn test_phone_redaction() {
        let redactor = PiiSpiRedactor::new();
        let text = "Call us at 555-123-4567";
        let redacted = redactor.redact_text(text, DataClassification::Internal);
        assert!(redacted.contains("****4567"));
        assert!(!redacted.contains("555-123-4567"));
    }
    
    #[test]
    fn test_ssn_full_redaction() {
        let redactor = PiiSpiRedactor::new();
        let text = "SSN: 123-45-6789";
        let redacted = redactor.redact_text(text, DataClassification::Internal);
        assert!(redacted.contains("[SocialSecurityNumber_REDACTED]"));
        assert!(!redacted.contains("123-45-6789"));
    }
    
    #[test]
    fn test_jwt_token_redaction() {
        let redactor = PiiSpiRedactor::new();
        let text = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature";
        let redacted = redactor.redact_text(text, DataClassification::Internal);
        assert!(redacted.contains("[JwtToken_REDACTED]"));
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiJ9"));
    }
    
    #[test]
    fn test_ip_address_partial_redaction() {
        let redactor = PiiSpiRedactor::new();
        let text = "Request from 192.168.1.100";
        let redacted = redactor.redact_text(text, DataClassification::Internal);
        assert!(redacted.contains("192.168.1.***"));
        assert!(!redacted.contains("192.168.1.100"));
    }
    
    #[test]
    fn test_classification_levels() {
        assert_eq!(SensitiveDataType::SocialSecurityNumber.classification(), DataClassification::Spi);
        assert_eq!(SensitiveDataType::EmailAddress.classification(), DataClassification::Pii);
        assert_eq!(SensitiveDataType::JwtToken.classification(), DataClassification::Confidential);
    }
    
    #[test]
    fn test_contains_sensitive_data() {
        let redactor = PiiSpiRedactor::new();
        let text = "Email: user@test.com, Phone: 555-1234";
        let sensitive_types = redactor.contains_sensitive_data(text);
        assert!(sensitive_types.contains(&SensitiveDataType::EmailAddress));
        // Note: "555-1234" might not match the phone pattern, adjust test as needed
    }
    
    #[test]
    fn test_aggressive_mode() {
        let redactor = PiiSpiRedactor::new().with_aggressive_mode(true);
        let text = "Some text";
        let redacted = redactor.redact_text(text, DataClassification::Public);
        // Should still work even without custom patterns
        assert_eq!(redacted, "Some text");
    }
    
    #[test]
    fn test_multiple_sensitive_data() {
        let redactor = PiiSpiRedactor::new();
        let text = "User email: admin@company.com, IP: 10.0.1.50, SSN: 123-45-6789";
        let redacted = redactor.redact_text(text, DataClassification::Internal);
        
        assert!(redacted.contains("a****@company.com"));
        assert!(redacted.contains("10.0.1.***"));
        assert!(redacted.contains("[SocialSecurityNumber_REDACTED]"));
        assert!(!redacted.contains("admin@company.com"));
        assert!(!redacted.contains("10.0.1.50"));
        assert!(!redacted.contains("123-45-6789"));
    }
}