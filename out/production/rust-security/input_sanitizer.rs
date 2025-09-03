//! Comprehensive input sanitization and validation
//!
//! This module provides defense against injection attacks, XSS, and other
//! input-based vulnerabilities with comprehensive validation and sanitization.

use regex::Regex;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SanitizationError {
    #[error("Input too long: {length} exceeds maximum {max}")]
    InputTooLong { length: usize, max: usize },
    #[error("Invalid characters detected: {0}")]
    InvalidCharacters(String),
    #[error("Potential injection attack detected: {0}")]
    InjectionDetected(String),
    #[error("Input validation failed: {0}")]
    ValidationFailed(String),
    #[error("Encoding error: {0}")]
    EncodingError(String),
}

/// SQL injection patterns to detect and block
static SQL_INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Basic SQL injection patterns
        Regex::new(r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)")
            .unwrap(),
        Regex::new(r"(?i)(\b(UNION|OR|AND)\s+(SELECT|INSERT|UPDATE|DELETE)\b)").unwrap(),
        Regex::new(r"(?i)(\b(SCRIPT|JAVASCRIPT|VBSCRIPT|ONLOAD|ONERROR)\b)").unwrap(),
        // SQL comment patterns
        Regex::new(r"(--|/\*|\*/|#)").unwrap(),
        // SQL string manipulation
        Regex::new(r"(?i)(\b(CHAR|ASCII|SUBSTRING|CONCAT)\s*\()").unwrap(),
        // SQL system functions
        Regex::new(r"(?i)(\b(XP_|SP_|OPENROWSET|OPENDATASOURCE)\w*)").unwrap(),
        // SQL conditional patterns
        Regex::new(r"(?i)(\b(IF|CASE|WHEN|THEN|ELSE|END)\b)").unwrap(),
    ]
});

/// XSS patterns to detect and block
static XSS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Script tags
        Regex::new(r"(?i)<\s*script[^>]*>").unwrap(),
        Regex::new(r"(?i)</\s*script\s*>").unwrap(),
        // Event handlers
        Regex::new(r"(?i)\bon\w+\s*=").unwrap(),
        // JavaScript URLs
        Regex::new(r"(?i)javascript\s*:").unwrap(),
        // Data URLs with scripts
        Regex::new(r"(?i)data\s*:\s*text/html").unwrap(),
        // Style with expressions
        Regex::new(r"(?i)expression\s*\(").unwrap(),
        // Import statements
        Regex::new(r"(?i)@import").unwrap(),
        // Iframe and object tags
        Regex::new(r"(?i)<\s*(iframe|object|embed|applet)").unwrap(),
    ]
});

/// Command injection patterns
static COMMAND_INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Command separators
        Regex::new(r"[;&|`$]").unwrap(),
        // Command substitution
        Regex::new(r"\$\(.*\)").unwrap(),
        Regex::new(r"`.*`").unwrap(),
        // File operations
        Regex::new(r"(?i)\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig)\b").unwrap(),
        // Network operations
        Regex::new(r"(?i)\b(wget|curl|nc|telnet|ssh|ftp)\b").unwrap(),
        // System operations
        Regex::new(r"(?i)\b(rm|mv|cp|chmod|chown|kill|killall)\b").unwrap(),
    ]
});

/// LDAP injection patterns
static LDAP_INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // LDAP special characters
        Regex::new(r"[()&|!*\\]").unwrap(),
        // LDAP operators
        Regex::new(r"(?i)(\b(AND|OR|NOT)\b)").unwrap(),
        // LDAP wildcards
        Regex::new(r"\*").unwrap(),
    ]
});

/// Dangerous file extensions
static DANGEROUS_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "exe", "bat", "cmd", "com", "pif", "scr", "vbs", "js", "jar", "app", "deb", "pkg", "dmg",
        "rpm", "msi", "run", "bin", "sh", "ps1", "php", "asp", "aspx", "jsp", "py", "rb", "pl",
        "cgi",
    ]
    .iter()
    .copied()
    .collect()
});

/// Input sanitizer with comprehensive validation
pub struct InputSanitizer {
    max_length: usize,
    allow_html: bool,
    strict_mode: bool,
}

impl InputSanitizer {
    /// Create new sanitizer with default settings
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_length: 1024,
            allow_html: false,
            strict_mode: true,
        }
    }

    /// Create sanitizer for specific use cases
    #[must_use]
    pub const fn for_username() -> Self {
        Self {
            max_length: 64,
            allow_html: false,
            strict_mode: true,
        }
    }

    #[must_use]
    pub const fn for_email() -> Self {
        Self {
            max_length: 254, // RFC 5321 limit
            allow_html: false,
            strict_mode: true,
        }
    }

    #[must_use]
    pub const fn for_password() -> Self {
        Self {
            max_length: 128,
            allow_html: false,
            strict_mode: false, // Allow special characters in passwords
        }
    }

    #[must_use]
    pub const fn for_token() -> Self {
        Self {
            max_length: 2048,
            allow_html: false,
            strict_mode: true,
        }
    }

    #[must_use]
    pub const fn for_url() -> Self {
        Self {
            max_length: 2048,
            allow_html: false,
            strict_mode: true,
        }
    }

    /// Sanitize and validate input
    pub fn sanitize(&self, input: &str) -> Result<String, SanitizationError> {
        // Check length
        if input.len() > self.max_length {
            return Err(SanitizationError::InputTooLong {
                length: input.len(),
                max: self.max_length,
            });
        }

        // Check for null bytes and control characters
        if input.contains('\0') {
            return Err(SanitizationError::InvalidCharacters(
                "Null bytes not allowed".to_string(),
            ));
        }

        // Check for dangerous control characters
        for ch in input.chars() {
            if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' {
                return Err(SanitizationError::InvalidCharacters(format!(
                    "Control character not allowed: {ch:?}"
                )));
            }
        }

        // Check for injection attacks
        self.check_sql_injection(input)?;
        self.check_xss(input)?;
        self.check_command_injection(input)?;
        self.check_ldap_injection(input)?;

        // Normalize and sanitize
        let mut sanitized = input.to_string();

        // Normalize Unicode
        sanitized = self.normalize_unicode(&sanitized)?;

        // HTML encode if not allowing HTML
        if !self.allow_html {
            sanitized = self.html_encode(&sanitized);
        }

        // Apply strict mode restrictions
        if self.strict_mode {
            sanitized = self.apply_strict_mode(&sanitized)?;
        }

        Ok(sanitized)
    }

    /// Check for SQL injection patterns
    fn check_sql_injection(&self, input: &str) -> Result<(), SanitizationError> {
        for pattern in SQL_INJECTION_PATTERNS.iter() {
            if pattern.is_match(input) {
                return Err(SanitizationError::InjectionDetected(
                    "Potential SQL injection detected".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Check for XSS patterns
    fn check_xss(&self, input: &str) -> Result<(), SanitizationError> {
        if !self.allow_html {
            for pattern in XSS_PATTERNS.iter() {
                if pattern.is_match(input) {
                    return Err(SanitizationError::InjectionDetected(
                        "Potential XSS attack detected".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Check for command injection patterns
    fn check_command_injection(&self, input: &str) -> Result<(), SanitizationError> {
        for pattern in COMMAND_INJECTION_PATTERNS.iter() {
            if pattern.is_match(input) {
                return Err(SanitizationError::InjectionDetected(
                    "Potential command injection detected".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Check for LDAP injection patterns
    fn check_ldap_injection(&self, input: &str) -> Result<(), SanitizationError> {
        for pattern in LDAP_INJECTION_PATTERNS.iter() {
            if pattern.is_match(input) {
                return Err(SanitizationError::InjectionDetected(
                    "Potential LDAP injection detected".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Normalize Unicode to prevent bypass attacks
    fn normalize_unicode(&self, input: &str) -> Result<String, SanitizationError> {
        // Use NFC normalization to prevent Unicode bypass attacks
        use unicode_normalization::UnicodeNormalization;
        Ok(input.nfc().collect::<String>())
    }

    /// HTML encode dangerous characters
    fn html_encode(&self, input: &str) -> String {
        input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
            .replace('/', "&#x2F;")
    }

    /// Apply strict mode restrictions
    fn apply_strict_mode(&self, input: &str) -> Result<String, SanitizationError> {
        // Only allow alphanumeric, spaces, and safe punctuation
        let safe_chars: HashSet<char> =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .-_@+="
                .chars()
                .collect();

        for ch in input.chars() {
            if !safe_chars.contains(&ch) {
                return Err(SanitizationError::InvalidCharacters(format!(
                    "Character not allowed in strict mode: {ch}"
                )));
            }
        }

        Ok(input.to_string())
    }

    /// Validate email format
    pub fn validate_email(email: &str) -> Result<String, SanitizationError> {
        let sanitizer = Self::for_email();
        let sanitized = sanitizer.sanitize(email)?;

        // Basic email format validation
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .map_err(|e| SanitizationError::ValidationFailed(e.to_string()))?;

        if !email_regex.is_match(&sanitized) {
            return Err(SanitizationError::ValidationFailed(
                "Invalid email format".to_string(),
            ));
        }

        Ok(sanitized)
    }

    /// Validate URL format and safety
    pub fn validate_url(url: &str) -> Result<String, SanitizationError> {
        let sanitizer = Self::for_url();
        let sanitized = sanitizer.sanitize(url)?;

        // Parse URL to validate format
        let parsed_url = url::Url::parse(&sanitized)
            .map_err(|e| SanitizationError::ValidationFailed(format!("Invalid URL: {e}")))?;

        // Only allow safe schemes
        match parsed_url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(SanitizationError::ValidationFailed(format!(
                    "Unsafe URL scheme: {scheme}"
                )));
            }
        }

        // Check for dangerous hosts
        if let Some(host) = parsed_url.host_str() {
            if host == "localhost" || host.starts_with("127.") || host.starts_with("192.168.") {
                return Err(SanitizationError::ValidationFailed(
                    "Private network URLs not allowed".to_string(),
                ));
            }
        }

        Ok(sanitized)
    }

    /// Validate filename safety
    pub fn validate_filename(filename: &str) -> Result<String, SanitizationError> {
        let sanitizer = Self::new();
        let sanitized = sanitizer.sanitize(filename)?;

        // Check for path traversal
        if sanitized.contains("..") || sanitized.contains('/') || sanitized.contains('\\') {
            return Err(SanitizationError::ValidationFailed(
                "Path traversal not allowed in filename".to_string(),
            ));
        }

        // Check for dangerous extensions
        if let Some(extension) = std::path::Path::new(&sanitized).extension() {
            if let Some(ext_str) = extension.to_str() {
                if DANGEROUS_EXTENSIONS.contains(ext_str.to_lowercase().as_str()) {
                    return Err(SanitizationError::ValidationFailed(format!(
                        "Dangerous file extension: {ext_str}"
                    )));
                }
            }
        }

        Ok(sanitized)
    }
}

impl Default for InputSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Sanitize log output to prevent log injection
#[must_use]
pub fn sanitize_log_output(input: &str) -> String {
    input
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
        .chars()
        .filter(|&c| c.is_ascii_graphic() || c == ' ' || c == '\\')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_injection_detection() {
        let sanitizer = InputSanitizer::new();

        // Should detect SQL injection
        assert!(sanitizer.sanitize("'; DROP TABLE users; --").is_err());
        assert!(sanitizer.sanitize("1 OR 1=1").is_err());
        assert!(sanitizer.sanitize("UNION SELECT * FROM passwords").is_err());

        // Should allow safe input
        assert!(sanitizer.sanitize("normal text").is_ok());
    }

    #[test]
    fn test_xss_detection() {
        let sanitizer = InputSanitizer::new();

        // Should detect XSS
        assert!(sanitizer.sanitize("<script>alert('xss')</script>").is_err());
        assert!(sanitizer.sanitize("javascript:alert(1)").is_err());
        assert!(sanitizer.sanitize("<img onload=alert(1)>").is_err());

        // Should allow safe input
        assert!(sanitizer.sanitize("normal text").is_ok());
    }

    #[test]
    fn test_command_injection_detection() {
        let sanitizer = InputSanitizer::new();

        // Should detect command injection
        assert!(sanitizer.sanitize("test; rm -rf /").is_err());
        assert!(sanitizer.sanitize("$(whoami)").is_err());
        assert!(sanitizer.sanitize("`cat /etc/passwd`").is_err());

        // Should allow safe input
        assert!(sanitizer.sanitize("normal text").is_ok());
    }

    #[test]
    fn test_email_validation() {
        // Valid emails
        assert!(InputSanitizer::validate_email("user@example.com").is_ok());
        assert!(InputSanitizer::validate_email("test.email+tag@domain.co.uk").is_ok());

        // Invalid emails
        assert!(InputSanitizer::validate_email("invalid-email").is_err());
        assert!(InputSanitizer::validate_email("user@").is_err());
        assert!(InputSanitizer::validate_email("@domain.com").is_err());
    }

    #[test]
    fn test_url_validation() {
        // Valid URLs
        assert!(InputSanitizer::validate_url("https://example.com").is_ok());
        assert!(InputSanitizer::validate_url("http://api.service.com/endpoint").is_ok());

        // Invalid URLs
        assert!(InputSanitizer::validate_url("javascript:alert(1)").is_err());
        assert!(InputSanitizer::validate_url("ftp://example.com").is_err());
        assert!(InputSanitizer::validate_url("https://localhost").is_err());
    }

    #[test]
    fn test_filename_validation() {
        // Valid filenames
        assert!(InputSanitizer::validate_filename("document.pdf").is_ok());
        assert!(InputSanitizer::validate_filename("image.jpg").is_ok());

        // Invalid filenames
        assert!(InputSanitizer::validate_filename("../../../etc/passwd").is_err());
        assert!(InputSanitizer::validate_filename("malware.exe").is_err());
        assert!(InputSanitizer::validate_filename("script.js").is_err());
    }

    #[test]
    fn test_length_limits() {
        let sanitizer = InputSanitizer::new();
        let long_input = "a".repeat(2000);

        assert!(sanitizer.sanitize(&long_input).is_err());
        assert!(sanitizer.sanitize("short").is_ok());
    }

    #[test]
    fn test_log_sanitization() {
        let malicious_log = "User logged in\nFAKE LOG ENTRY: Admin access granted";
        let sanitized = sanitize_log_output(malicious_log);

        assert!(!sanitized.contains('\n'));
        assert!(sanitized.contains("\\n"));
    }
}
