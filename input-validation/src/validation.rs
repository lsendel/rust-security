//! Core validation module with security-first approach
//!
//! Provides comprehensive input validation with configurable limits and security rules

use crate::error_handling::{SecureResult, SecurityError, ValidationError, ValidationResult};
use aho_corasick::AhoCorasick;
use fancy_regex::Regex as FancyRegex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// Maximum input size limits for different security levels
pub const MAX_INPUT_SIZE_STRICT: usize = 4_096; // 4KB
pub const MAX_INPUT_SIZE_NORMAL: usize = 65_536; // 64KB
pub const MAX_INPUT_SIZE_RELAXED: usize = 1_048_576; // 1MB

/// Maximum field count limits
pub const MAX_FIELD_COUNT_STRICT: usize = 50;
pub const MAX_FIELD_COUNT_NORMAL: usize = 200;
pub const MAX_FIELD_COUNT_RELAXED: usize = 1000;

/// Validation timeout limits
pub const VALIDATION_TIMEOUT_STRICT: Duration = Duration::from_millis(100);
pub const VALIDATION_TIMEOUT_NORMAL: Duration = Duration::from_millis(500);
pub const VALIDATION_TIMEOUT_RELAXED: Duration = Duration::from_millis(2000);

/// Input type classification for validation rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InputType {
    /// OAuth parameters (client_id, redirect_uri, etc.)
    OAuth,
    /// SCIM filter expressions
    ScimFilter,
    /// JWT tokens and claims
    Jwt,
    /// Email addresses
    Email,
    /// Phone numbers
    Phone,
    /// URLs and URIs
    Url,
    /// Username/identifier
    Username,
    /// Generic text input
    Text,
    /// Numeric input
    Numeric,
    /// Boolean input
    Boolean,
    /// JSON data
    Json,
    /// XML data
    Xml,
    /// File paths
    FilePath,
    /// SQL queries (for safe validation)
    Sql,
    /// Regular expressions
    Regex,
    /// Custom type
    Custom(String),
}

impl fmt::Display for InputType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputType::OAuth => write!(f, "oauth"),
            InputType::ScimFilter => write!(f, "scim_filter"),
            InputType::Jwt => write!(f, "jwt"),
            InputType::Email => write!(f, "email"),
            InputType::Phone => write!(f, "phone"),
            InputType::Url => write!(f, "url"),
            InputType::Username => write!(f, "username"),
            InputType::Text => write!(f, "text"),
            InputType::Numeric => write!(f, "numeric"),
            InputType::Boolean => write!(f, "boolean"),
            InputType::Json => write!(f, "json"),
            InputType::Xml => write!(f, "xml"),
            InputType::FilePath => write!(f, "file_path"),
            InputType::Sql => write!(f, "sql"),
            InputType::Regex => write!(f, "regex"),
            InputType::Custom(name) => write!(f, "custom_{}", name),
        }
    }
}

/// Input size and complexity limits
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputLimits {
    /// Maximum input length in bytes
    pub max_length: usize,
    /// Maximum number of fields in structured input
    pub max_field_count: usize,
    /// Maximum nesting depth for structured data
    pub max_depth: usize,
    /// Maximum array size
    pub max_array_size: usize,
    /// Validation timeout
    pub timeout: Duration,
}

impl InputLimits {
    /// Strict limits for high-security environments
    pub fn strict() -> Self {
        Self {
            max_length: MAX_INPUT_SIZE_STRICT,
            max_field_count: MAX_FIELD_COUNT_STRICT,
            max_depth: 5,
            max_array_size: 100,
            timeout: VALIDATION_TIMEOUT_STRICT,
        }
    }

    /// Normal limits for production environments
    pub fn normal() -> Self {
        Self {
            max_length: MAX_INPUT_SIZE_NORMAL,
            max_field_count: MAX_FIELD_COUNT_NORMAL,
            max_depth: 10,
            max_array_size: 1000,
            timeout: VALIDATION_TIMEOUT_NORMAL,
        }
    }

    /// Relaxed limits for development/testing
    pub fn relaxed() -> Self {
        Self {
            max_length: MAX_INPUT_SIZE_RELAXED,
            max_field_count: MAX_FIELD_COUNT_RELAXED,
            max_depth: 20,
            max_array_size: 10000,
            timeout: VALIDATION_TIMEOUT_RELAXED,
        }
    }
}

/// Validation rule definition
#[derive(Debug, Clone)]
pub struct ValidationRule {
    /// Rule name/identifier
    pub name: String,
    /// Rule description
    pub description: String,
    /// Severity level (1-10, 10 being most severe)
    pub severity: u8,
    /// Validation function
    pub validator: fn(&str, &ValidatorConfig) -> Result<(), ValidationError>,
}

impl ValidationRule {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        severity: u8,
        validator: fn(&str, &ValidatorConfig) -> Result<(), ValidationError>,
    ) -> Self {
        Self { name: name.into(), description: description.into(), severity, validator }
    }
}

/// Security validator configuration
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    /// Input size and complexity limits
    pub input_limits: InputLimits,

    /// Security level (affects rule selection)
    pub security_level: SecurityLevel,

    /// Enabled validation rules per input type
    pub rules: HashMap<InputType, Vec<ValidationRule>>,

    /// Injection attack patterns
    pub injection_patterns: InjectionPatterns,

    /// Allowed character sets per input type
    pub allowed_charsets: HashMap<InputType, CharsetRule>,

    /// Custom validation configuration
    pub custom_config: HashMap<String, String>,
}

/// Security level configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Maximum security, minimal functionality
    Strict,
    /// Balanced security and functionality
    Normal,
    /// Relaxed security for development
    Relaxed,
}

/// Character set validation rules
#[derive(Debug, Clone)]
pub struct CharsetRule {
    /// Allowed characters (regex pattern)
    pub allowed_pattern: String,
    /// Disallowed characters (regex pattern)
    pub disallowed_pattern: Option<String>,
    /// Whether to allow Unicode
    pub allow_unicode: bool,
    /// Maximum byte length per character
    pub max_char_bytes: usize,
}

impl CharsetRule {
    /// ASCII alphanumeric only
    pub fn ascii_alphanumeric() -> Self {
        Self {
            allowed_pattern: r"^[a-zA-Z0-9]+$".to_string(),
            disallowed_pattern: None,
            allow_unicode: false,
            max_char_bytes: 1,
        }
    }

    /// ASCII alphanumeric with common symbols
    pub fn ascii_extended() -> Self {
        Self {
            allowed_pattern: r"^[a-zA-Z0-9\s\-_@.+()]+$".to_string(),
            disallowed_pattern: Some("[<>\"'&;\\\\]".to_string()),
            allow_unicode: false,
            max_char_bytes: 1,
        }
    }

    /// Unicode text with security restrictions
    pub fn unicode_text() -> Self {
        Self {
            allowed_pattern: r"^[\p{L}\p{N}\p{P}\p{S}\s]+$".to_string(),
            disallowed_pattern: Some("[<>\"'&;\\\\]".to_string()),
            allow_unicode: true,
            max_char_bytes: 4,
        }
    }
}

/// Injection attack pattern configuration
#[derive(Debug, Clone)]
pub struct InjectionPatterns {
    /// SQL injection patterns
    pub sql_patterns: AhoCorasick,
    /// XSS patterns
    pub xss_patterns: AhoCorasick,
    /// Command injection patterns
    pub command_patterns: AhoCorasick,
    /// Path traversal patterns
    pub path_traversal_patterns: AhoCorasick,
    /// LDAP injection patterns
    pub ldap_patterns: AhoCorasick,
    /// NoSQL injection patterns
    pub nosql_patterns: AhoCorasick,
}

impl InjectionPatterns {
    pub fn new() -> Self {
        let sql_patterns = vec![
            "union",
            "select",
            "insert",
            "update",
            "delete",
            "drop",
            "create",
            "alter",
            "exec",
            "execute",
            "--",
            "/*",
            "*/",
            ";",
            "xp_",
            "sp_",
            "waitfor delay",
            "benchmark(",
            "sleep(",
            "pg_sleep(",
            "information_schema",
            "sysobjects",
            "syscolumns",
        ];

        let xss_patterns = vec![
            "<script",
            "</script>",
            "javascript:",
            "vbscript:",
            "onload=",
            "onerror=",
            "onclick=",
            "onmouseover=",
            "<iframe",
            "<object",
            "<embed",
            "<form",
            "document.cookie",
            "document.write",
            "eval(",
            "setTimeout(",
            "setInterval(",
            "location.href",
            "window.open",
        ];

        let command_patterns = vec![
            "&&",
            "||",
            ";",
            "|",
            "`",
            "$(",
            "${",
            "cat ",
            "ls ",
            "pwd",
            "whoami",
            "id ",
            "ps ",
            "kill ",
            "rm ",
            "mv ",
            "cp ",
            "/bin/",
            "/usr/bin/",
            "cmd.exe",
            "powershell",
            "bash",
        ];

        let path_traversal_patterns = vec![
            "../",
            "..\\",
            "....//",
            "....\\\\",
            "%2e%2e%2f",
            "%2e%2e%5c",
            "..%2f",
            "..%5c",
            "%252e%252e%252f",
            "/etc/passwd",
            "/etc/shadow",
            "C:\\Windows",
            "C:\\Program Files",
            "web.config",
            ".env",
        ];

        let ldap_patterns = vec![
            "*)(", "*)&", "*)|", "*(", "*)", ")(", ")&", ")|", "admin*", "*admin", "cn=", "dc=",
            "ou=", "uid=",
        ];

        let nosql_patterns = vec![
            "$where",
            "$regex",
            "$ne",
            "$gt",
            "$lt",
            "$gte",
            "$lte",
            "$in",
            "$nin",
            "$or",
            "$and",
            "$not",
            "$nor",
            "$exists",
            "this.",
            "function(",
            "javascript:",
            "sleep(",
        ];

        Self {
            sql_patterns: AhoCorasick::new(&sql_patterns).unwrap(),
            xss_patterns: AhoCorasick::new(&xss_patterns).unwrap(),
            command_patterns: AhoCorasick::new(&command_patterns).unwrap(),
            path_traversal_patterns: AhoCorasick::new(&path_traversal_patterns).unwrap(),
            ldap_patterns: AhoCorasick::new(&ldap_patterns).unwrap(),
            nosql_patterns: AhoCorasick::new(&nosql_patterns).unwrap(),
        }
    }
}

impl Default for InjectionPatterns {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorConfig {
    /// Production configuration with strict security
    pub fn production() -> Self {
        let mut config = Self {
            input_limits: InputLimits::strict(),
            security_level: SecurityLevel::Strict,
            rules: HashMap::new(),
            injection_patterns: InjectionPatterns::new(),
            allowed_charsets: HashMap::new(),
            custom_config: HashMap::new(),
        };

        config.setup_default_rules();
        config.setup_default_charsets();
        config
    }

    /// Development configuration with relaxed limits
    pub fn development() -> Self {
        let mut config = Self {
            input_limits: InputLimits::relaxed(),
            security_level: SecurityLevel::Relaxed,
            rules: HashMap::new(),
            injection_patterns: InjectionPatterns::new(),
            allowed_charsets: HashMap::new(),
            custom_config: HashMap::new(),
        };

        config.setup_default_rules();
        config.setup_default_charsets();
        config
    }

    /// Setup default validation rules
    fn setup_default_rules(&mut self) {
        // OAuth validation rules
        let oauth_rules = vec![
            ValidationRule::new(
                "oauth_length",
                "Validate OAuth parameter length",
                5,
                |input, config| {
                    if input.len() > config.input_limits.max_length {
                        return Err(ValidationError::length(
                            "oauth_param",
                            config.input_limits.max_length,
                        ));
                    }
                    Ok(())
                },
            ),
            ValidationRule::new(
                "oauth_charset",
                "Validate OAuth parameter character set",
                7,
                |input, _config| {
                    // OAuth parameters should be URL-safe
                    if !input.chars().all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)) {
                        return Err(ValidationError::format(
                            "oauth_param",
                            "URL-safe characters only",
                        ));
                    }
                    Ok(())
                },
            ),
        ];
        self.rules.insert(InputType::OAuth, oauth_rules);

        // SCIM filter validation rules
        let scim_rules = vec![
            ValidationRule::new(
                "scim_length",
                "Validate SCIM filter length",
                8,
                |input, _config| {
                    if input.len() > 500 {
                        return Err(ValidationError::length("scim_filter", 500));
                    }
                    Ok(())
                },
            ),
            ValidationRule::new(
                "scim_balanced_parens",
                "Check balanced parentheses in SCIM filter",
                9,
                |input, _config| {
                    let mut count = 0;
                    for ch in input.chars() {
                        match ch {
                            '(' => count += 1,
                            ')' => {
                                count -= 1;
                                if count < 0 {
                                    return Err(ValidationError::format(
                                        "scim_filter",
                                        "balanced parentheses",
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }
                    if count != 0 {
                        return Err(ValidationError::format("scim_filter", "balanced parentheses"));
                    }
                    Ok(())
                },
            ),
            ValidationRule::new(
                "scim_injection",
                "Check for injection patterns in SCIM filter",
                10,
                |input, config| {
                    let input_lower = input.to_lowercase();

                    // Check for SQL injection
                    if config.injection_patterns.sql_patterns.is_match(&input_lower) {
                        return Err(ValidationError::injection("scim_filter"));
                    }

                    // Check for XSS
                    if config.injection_patterns.xss_patterns.is_match(&input_lower) {
                        return Err(ValidationError::injection("scim_filter"));
                    }

                    Ok(())
                },
            ),
        ];
        self.rules.insert(InputType::ScimFilter, scim_rules);

        // Email validation rules
        let email_rules = vec![
            ValidationRule::new("email_format", "Validate email format", 6, |input, _config| {
                let email_regex =
                    Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
                if !email_regex.is_match(input) {
                    return Err(ValidationError::format("email", "valid email address"));
                }
                Ok(())
            }),
            ValidationRule::new("email_length", "Validate email length", 5, |input, _config| {
                if input.len() > 320 {
                    return Err(ValidationError::length("email", 320));
                }
                Ok(())
            }),
        ];
        self.rules.insert(InputType::Email, email_rules);

        // Add more rules for other input types...
    }

    /// Setup default character set rules
    fn setup_default_charsets(&mut self) {
        self.allowed_charsets.insert(InputType::OAuth, CharsetRule::ascii_alphanumeric());
        self.allowed_charsets.insert(InputType::Email, CharsetRule::ascii_extended());
        self.allowed_charsets.insert(InputType::Username, CharsetRule::ascii_extended());
        self.allowed_charsets.insert(InputType::Text, CharsetRule::unicode_text());
        // Add more charset rules...
    }
}

/// Validated input wrapper
#[derive(Debug, Clone)]
pub struct ValidatedInput<T> {
    /// The validated value
    pub value: T,
    /// Validation metadata
    pub metadata: ValidationMetadata,
}

impl<T> ValidatedInput<T> {
    pub fn new(value: T, metadata: ValidationMetadata) -> Self {
        Self { value, metadata }
    }

    /// Get the inner value
    pub fn into_inner(self) -> T {
        self.value
    }

    /// Get a reference to the inner value
    pub fn as_ref(&self) -> &T {
        &self.value
    }
}

/// Validation metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationMetadata {
    /// Input type that was validated
    pub input_type: String,
    /// Number of rules applied
    pub rules_applied: u32,
    /// Validation duration
    pub duration: Duration,
    /// Input size in bytes
    pub input_size: usize,
    /// Security level used
    pub security_level: String,
    /// Any warnings (non-blocking issues)
    pub warnings: Vec<String>,
}

impl Default for ValidationMetadata {
    fn default() -> Self {
        Self {
            input_type: "unknown".to_string(),
            rules_applied: 0,
            duration: Duration::from_millis(0),
            input_size: 0,
            security_level: "normal".to_string(),
            warnings: Vec::new(),
        }
    }
}

/// Main security validator
#[derive(Debug, Clone)]
pub struct SecurityValidator {
    config: ValidatorConfig,
    #[cfg(feature = "metrics")]
    metrics: ValidationMetrics,
}

#[cfg(feature = "metrics")]
#[derive(Debug, Clone)]
struct ValidationMetrics {
    validations_total: prometheus::Counter,
    validation_duration: prometheus::Histogram,
    validation_errors: prometheus::CounterVec,
}

impl SecurityValidator {
    /// Create a new validator with the given configuration
    pub fn new(config: ValidatorConfig) -> anyhow::Result<Self> {
        #[cfg(feature = "metrics")]
        let metrics = ValidationMetrics {
            validations_total: prometheus::Counter::new(
                "input_validations_total",
                "Total number of input validations",
            )?,
            validation_duration: prometheus::Histogram::new(
                "input_validation_duration_seconds",
                "Duration of input validation operations",
            )?,
            validation_errors: prometheus::CounterVec::new(
                prometheus::Opts::new(
                    "input_validation_errors_total",
                    "Total number of validation errors by type",
                ),
                &["input_type", "error_code"],
            )?,
        };

        Ok(Self {
            config,
            #[cfg(feature = "metrics")]
            metrics,
        })
    }

    /// Validate input with specific type and rules
    pub fn validate(&self, input: &str, input_type: InputType) -> ValidationResult {
        let start_time = Instant::now();
        let mut result = ValidationResult::success();

        #[cfg(feature = "metrics")]
        self.metrics.validations_total.inc();

        // Check input size limits first
        if input.len() > self.config.input_limits.max_length {
            result.add_error(ValidationError::length(
                input_type.to_string(),
                self.config.input_limits.max_length,
            ));

            #[cfg(feature = "metrics")]
            self.metrics
                .validation_errors
                .with_label_values(&[&input_type.to_string(), "length_exceeded"])
                .inc();

            return result;
        }

        // Apply validation rules for this input type
        if let Some(rules) = self.config.rules.get(&input_type) {
            for rule in rules {
                if start_time.elapsed() > self.config.input_limits.timeout {
                    result.add_error(ValidationError::new(
                        input_type.to_string(),
                        "timeout",
                        "Validation timeout exceeded",
                    ));
                    break;
                }

                if let Err(error) = (rule.validator)(input, &self.config) {
                    result.add_error(error);

                    #[cfg(feature = "metrics")]
                    self.metrics
                        .validation_errors
                        .with_label_values(&[&input_type.to_string(), &rule.name])
                        .inc();
                }
            }
        }

        // Update metadata
        result.metadata.input_type = input_type.to_string();
        result.metadata.duration_micros = start_time.elapsed().as_micros() as u64;
        result.metadata.input_size = input.len();
        result.metadata.level = format!("{:?}", self.config.security_level).to_lowercase();

        #[cfg(feature = "metrics")]
        self.metrics.validation_duration.observe(start_time.elapsed().as_secs_f64());

        result
    }

    /// Validate and return typed result
    pub fn validate_typed<T>(
        &self,
        input: T,
        input_type: InputType,
    ) -> SecureResult<ValidatedInput<T>>
    where
        T: AsRef<str> + Clone,
    {
        let validation_result = self.validate(input.as_ref(), input_type);

        if validation_result.is_valid() {
            Ok(ValidatedInput::new(
                input,
                ValidationMetadata {
                    input_type: input_type.to_string(),
                    rules_applied: validation_result.metadata.rules_applied,
                    duration: Duration::from_micros(validation_result.metadata.duration_micros),
                    input_size: validation_result.metadata.input_size,
                    security_level: validation_result.metadata.level.clone(),
                    warnings: Vec::new(),
                },
            ))
        } else {
            Err(SecurityError::ValidationFailed)
        }
    }

    /// Validate multiple inputs of the same type
    pub fn validate_batch(&self, inputs: &[&str], input_type: InputType) -> Vec<ValidationResult> {
        inputs.iter().map(|input| self.validate(input, input_type)).collect()
    }

    /// Check if input contains injection patterns
    pub fn check_injection(&self, input: &str) -> Vec<String> {
        let mut detected_patterns = Vec::new();
        let input_lower = input.to_lowercase();

        if self.config.injection_patterns.sql_patterns.is_match(&input_lower) {
            detected_patterns.push("sql_injection".to_string());
        }

        if self.config.injection_patterns.xss_patterns.is_match(&input_lower) {
            detected_patterns.push("xss".to_string());
        }

        if self.config.injection_patterns.command_patterns.is_match(&input_lower) {
            detected_patterns.push("command_injection".to_string());
        }

        if self.config.injection_patterns.path_traversal_patterns.is_match(&input_lower) {
            detected_patterns.push("path_traversal".to_string());
        }

        detected_patterns
    }

    /// Get validator configuration
    pub fn config(&self) -> &ValidatorConfig {
        &self.config
    }
}

/// Quick validation functions for common use cases
pub mod quick {
    use super::*;

    /// Validate OAuth parameter
    pub fn validate_oauth_param(param: &str) -> SecureResult<String> {
        let validator = SecurityValidator::new(ValidatorConfig::production())
            .map_err(|_| SecurityError::ConfigurationError)?;

        validator
            .validate_typed(param.to_string(), InputType::OAuth)
            .map(|validated| validated.into_inner())
    }

    /// Validate SCIM filter
    pub fn validate_scim_filter(filter: &str) -> SecureResult<String> {
        let validator = SecurityValidator::new(ValidatorConfig::production())
            .map_err(|_| SecurityError::ConfigurationError)?;

        validator
            .validate_typed(filter.to_string(), InputType::ScimFilter)
            .map(|validated| validated.into_inner())
    }

    /// Validate email address
    pub fn validate_email(email: &str) -> SecureResult<String> {
        let validator = SecurityValidator::new(ValidatorConfig::production())
            .map_err(|_| SecurityError::ConfigurationError)?;

        validator
            .validate_typed(email.to_string(), InputType::Email)
            .map(|validated| validated.into_inner())
    }

    /// Check for any injection attempts
    pub fn check_injection_quick(input: &str) -> bool {
        let patterns = InjectionPatterns::new();
        let input_lower = input.to_lowercase();

        patterns.sql_patterns.is_match(&input_lower)
            || patterns.xss_patterns.is_match(&input_lower)
            || patterns.command_patterns.is_match(&input_lower)
            || patterns.path_traversal_patterns.is_match(&input_lower)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_limits() {
        let strict = InputLimits::strict();
        let normal = InputLimits::normal();
        let relaxed = InputLimits::relaxed();

        assert!(strict.max_length < normal.max_length);
        assert!(normal.max_length < relaxed.max_length);
    }

    #[test]
    fn test_validator_creation() {
        let config = ValidatorConfig::production();
        let validator = SecurityValidator::new(config).unwrap();

        assert_eq!(validator.config.security_level, SecurityLevel::Strict);
    }

    #[test]
    fn test_oauth_validation() {
        let config = ValidatorConfig::production();
        let validator = SecurityValidator::new(config).unwrap();

        let valid_param = "abc123";
        let result = validator.validate(valid_param, InputType::OAuth);
        assert!(result.is_valid());

        let invalid_param = "abc<script>";
        let result = validator.validate(invalid_param, InputType::OAuth);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_scim_filter_validation() {
        let config = ValidatorConfig::production();
        let validator = SecurityValidator::new(config).unwrap();

        let valid_filter = "userName eq \"john\"";
        let result = validator.validate(valid_filter, InputType::ScimFilter);
        assert!(result.is_valid());

        let invalid_filter = "userName eq \"john\"; DROP TABLE users";
        let result = validator.validate(invalid_filter, InputType::ScimFilter);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_injection_detection() {
        let config = ValidatorConfig::production();
        let validator = SecurityValidator::new(config).unwrap();

        let sql_injection = "' OR 1=1 --";
        let patterns = validator.check_injection(sql_injection);
        assert!(patterns.contains(&"sql_injection".to_string()));

        let xss_attempt = "<script>alert('xss')</script>";
        let patterns = validator.check_injection(xss_attempt);
        assert!(patterns.contains(&"xss".to_string()));
    }

    #[test]
    fn test_quick_validation() {
        use super::quick::*;

        assert!(validate_oauth_param("valid_param").is_ok());
        assert!(validate_oauth_param("<invalid>").is_err());

        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("invalid-email").is_err());

        assert!(!check_injection_quick("normal input"));
        assert!(check_injection_quick("'; DROP TABLE users --"));
    }

    #[test]
    fn test_validation_metadata() {
        let config = ValidatorConfig::production();
        let validator = SecurityValidator::new(config).unwrap();

        let result = validator.validate("test", InputType::Text);
        assert!(result.metadata.duration_micros > 0);
        assert_eq!(result.metadata.input_size, 4);
        assert_eq!(result.metadata.input_type, "text");
    }
}
