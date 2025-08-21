//! Input sanitization module for preventing injection attacks
//!
//! Provides comprehensive sanitization utilities for different input types

use crate::error_handling::{SecureResult, SecurityError};
use crate::validation::{InputType, ValidatorConfig};
use aho_corasick::AhoCorasick;
use fancy_regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Sanitization configuration
#[derive(Debug, Clone)]
pub struct SanitizationConfig {
    /// Whether to enable aggressive sanitization
    pub aggressive_mode: bool,

    /// Input type specific rules
    pub type_rules: HashMap<InputType, SanitizationRule>,

    /// Global sanitization patterns
    pub global_patterns: GlobalPatterns,

    /// Maximum length after sanitization
    pub max_sanitized_length: usize,

    /// Whether to preserve structure in JSON/XML
    pub preserve_structure: bool,
}

/// Sanitization rule for a specific input type
#[derive(Debug, Clone)]
pub struct SanitizationRule {
    /// Whether sanitization is enabled for this type
    pub enabled: bool,

    /// Patterns to remove completely
    pub remove_patterns: Vec<String>,

    /// Patterns to replace (pattern -> replacement)
    pub replace_patterns: Vec<(String, String)>,

    /// Characters to escape
    pub escape_chars: Vec<char>,

    /// Whether to normalize whitespace
    pub normalize_whitespace: bool,

    /// Whether to convert to lowercase
    pub to_lowercase: bool,

    /// Maximum allowed length after sanitization
    pub max_length: Option<usize>,
}

/// Global sanitization patterns for all input types
#[derive(Debug, Clone)]
pub struct GlobalPatterns {
    /// Null byte removal
    pub null_bytes: AhoCorasick,

    /// Control character removal
    pub control_chars: Regex,

    /// Unicode normalization patterns
    pub unicode_patterns: Vec<(String, String)>,

    /// ANSI escape sequence removal
    pub ansi_escape: Regex,
}

impl GlobalPatterns {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            null_bytes: AhoCorasick::new(&["\0", "%00", "\\x00", "\\u0000"])?,
            control_chars: Regex::new(r"[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]")?,
            unicode_patterns: vec![
                // Normalize different types of quotes
                ("\u{201c}".to_string(), "\"".to_string()),
                ("\u{201d}".to_string(), "\"".to_string()),
                ("\u{2018}".to_string(), "'".to_string()),
                ("\u{2019}".to_string(), "'".to_string()),
                // Normalize different types of hyphens
                ("–".to_string(), "-".to_string()),
                ("—".to_string(), "-".to_string()),
                ("―".to_string(), "-".to_string()),
            ],
            ansi_escape: Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]")?,
        })
    }
}

impl Default for GlobalPatterns {
    fn default() -> Self {
        Self::new().expect("Failed to create default global patterns")
    }
}

impl SanitizationRule {
    /// Create a strict sanitization rule
    pub fn strict() -> Self {
        Self {
            enabled: true,
            remove_patterns: vec![
                // SQL injection patterns
                r"(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)"
                    .to_string(),
                // XSS patterns
                r"(?i)<script.*?>.*?</script>".to_string(),
                r"(?i)javascript:".to_string(),
                r"(?i)on\w+\s*=".to_string(),
                // Command injection patterns
                r"[\|\&\;\`\$\(\)]".to_string(),
            ],
            replace_patterns: vec![
                // Replace dangerous characters
                ("<".to_string(), "&lt;".to_string()),
                (">".to_string(), "&gt;".to_string()),
                ("\"".to_string(), "&quot;".to_string()),
                ("'".to_string(), "&#x27;".to_string()),
                ("&".to_string(), "&amp;".to_string()),
            ],
            escape_chars: vec!['\\', '/', '\n', '\r', '\t'],
            normalize_whitespace: true,
            to_lowercase: false,
            max_length: Some(1000),
        }
    }

    /// Create a normal sanitization rule
    pub fn normal() -> Self {
        Self {
            enabled: true,
            remove_patterns: vec![
                // Basic XSS prevention
                r"(?i)<script.*?>.*?</script>".to_string(),
                r"(?i)javascript:".to_string(),
            ],
            replace_patterns: vec![
                ("<".to_string(), "&lt;".to_string()),
                (">".to_string(), "&gt;".to_string()),
            ],
            escape_chars: vec!['\\'],
            normalize_whitespace: true,
            to_lowercase: false,
            max_length: Some(5000),
        }
    }

    /// Create a minimal sanitization rule
    pub fn minimal() -> Self {
        Self {
            enabled: true,
            remove_patterns: vec![],
            replace_patterns: vec![],
            escape_chars: vec![],
            normalize_whitespace: false,
            to_lowercase: false,
            max_length: None,
        }
    }
}

impl SanitizationConfig {
    /// Create a strict sanitization configuration
    pub fn strict() -> Self {
        let mut type_rules = HashMap::new();

        // Strict rules for security-critical input types
        type_rules.insert(InputType::ScimFilter, SanitizationRule::strict());
        type_rules.insert(InputType::Sql, SanitizationRule::strict());
        type_rules.insert(InputType::Regex, SanitizationRule::strict());

        // Normal rules for other types
        type_rules.insert(InputType::Text, SanitizationRule::normal());
        type_rules.insert(InputType::Email, SanitizationRule::normal());
        type_rules.insert(InputType::Url, SanitizationRule::normal());

        // Minimal rules for structured data
        type_rules.insert(InputType::Json, SanitizationRule::minimal());
        type_rules.insert(InputType::Xml, SanitizationRule::minimal());

        Self {
            aggressive_mode: true,
            type_rules,
            global_patterns: GlobalPatterns::default(),
            max_sanitized_length: 10000,
            preserve_structure: false,
        }
    }

    /// Create a normal sanitization configuration
    pub fn normal() -> Self {
        let mut type_rules = HashMap::new();

        // Normal rules for most types
        for input_type in [
            InputType::Text,
            InputType::Email,
            InputType::Url,
            InputType::ScimFilter,
            InputType::Username,
        ] {
            type_rules.insert(input_type, SanitizationRule::normal());
        }

        // Minimal rules for structured data
        type_rules.insert(InputType::Json, SanitizationRule::minimal());
        type_rules.insert(InputType::Xml, SanitizationRule::minimal());

        Self {
            aggressive_mode: false,
            type_rules,
            global_patterns: GlobalPatterns::default(),
            max_sanitized_length: 100000,
            preserve_structure: true,
        }
    }
}

/// Sanitized input wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizedInput {
    /// Original input (truncated for security)
    pub original_preview: String,

    /// Sanitized input
    pub sanitized: String,

    /// Whether any sanitization was applied
    pub was_sanitized: bool,

    /// List of sanitization operations performed
    pub operations: Vec<String>,

    /// Input type
    pub input_type: InputType,

    /// Size reduction (original_size - sanitized_size)
    pub size_reduction: usize,
}

impl SanitizedInput {
    pub fn new(
        original: &str,
        sanitized: String,
        input_type: InputType,
        operations: Vec<String>,
    ) -> Self {
        let was_sanitized = original != sanitized;
        let size_reduction = original.len().saturating_sub(sanitized.len());

        Self {
            original_preview: if original.len() > 100 {
                format!("{}...", &original[..100])
            } else {
                original.to_string()
            },
            sanitized,
            was_sanitized,
            operations,
            input_type,
            size_reduction,
        }
    }

    /// Get the sanitized value
    pub fn value(&self) -> &str {
        &self.sanitized
    }

    /// Convert to owned string
    pub fn into_string(self) -> String {
        self.sanitized
    }
}

/// Main sanitizer implementation
#[derive(Debug, Clone)]
pub struct Sanitizer {
    config: SanitizationConfig,
}

impl Sanitizer {
    /// Create a new sanitizer with the given configuration
    pub fn new(config: SanitizationConfig) -> Self {
        Self { config }
    }

    /// Create a sanitizer with strict configuration
    pub fn strict() -> Self {
        Self::new(SanitizationConfig::strict())
    }

    /// Create a sanitizer with normal configuration
    pub fn normal() -> Self {
        Self::new(SanitizationConfig::normal())
    }

    /// Sanitize input based on its type
    pub fn sanitize(&self, input: &str, input_type: InputType) -> SecureResult<SanitizedInput> {
        let mut sanitized = input.to_string();
        let mut operations = Vec::new();

        // Apply global sanitization first
        sanitized = self.apply_global_sanitization(sanitized, &mut operations)?;

        // Apply type-specific sanitization
        if let Some(rule) = self.config.type_rules.get(&input_type) {
            if rule.enabled {
                sanitized = self.apply_rule_sanitization(sanitized, rule, &mut operations)?;
            }
        }

        // Check final length
        if sanitized.len() > self.config.max_sanitized_length {
            sanitized.truncate(self.config.max_sanitized_length);
            operations.push("truncated_to_max_length".to_string());
        }

        Ok(SanitizedInput::new(input, sanitized, input_type, operations))
    }

    /// Apply global sanitization patterns
    fn apply_global_sanitization(
        &self,
        mut input: String,
        operations: &mut Vec<String>,
    ) -> SecureResult<String> {
        // Remove null bytes
        if self.config.global_patterns.null_bytes.is_match(&input) {
            input = self.config.global_patterns.null_bytes.replace_all(&input, "");
            operations.push("removed_null_bytes".to_string());
        }

        // Remove control characters
        if self.config.global_patterns.control_chars.is_match(&input)? {
            input = self.config.global_patterns.control_chars.replace_all(&input, "").to_string();
            operations.push("removed_control_chars".to_string());
        }

        // Remove ANSI escape sequences
        if self.config.global_patterns.ansi_escape.is_match(&input)? {
            input = self.config.global_patterns.ansi_escape.replace_all(&input, "").to_string();
            operations.push("removed_ansi_escape".to_string());
        }

        // Apply Unicode normalization
        for (pattern, replacement) in &self.config.global_patterns.unicode_patterns {
            if input.contains(pattern) {
                input = input.replace(pattern, replacement);
                operations.push(format!("unicode_normalized_{}", pattern));
            }
        }

        Ok(input)
    }

    /// Apply rule-specific sanitization
    fn apply_rule_sanitization(
        &self,
        mut input: String,
        rule: &SanitizationRule,
        operations: &mut Vec<String>,
    ) -> SecureResult<String> {
        // Remove patterns
        for pattern in &rule.remove_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(&input)? {
                    input = regex.replace_all(&input, "").to_string();
                    operations.push(format!("removed_pattern_{}", pattern));
                }
            }
        }

        // Replace patterns
        for (pattern, replacement) in &rule.replace_patterns {
            if input.contains(pattern) {
                input = input.replace(pattern, replacement);
                operations.push(format!("replaced_{}_{}", pattern, replacement));
            }
        }

        // Escape characters
        for &ch in &rule.escape_chars {
            if input.contains(ch) {
                input = input.replace(ch, &format!("\\{}", ch));
                operations.push(format!("escaped_{}", ch));
            }
        }

        // Normalize whitespace
        if rule.normalize_whitespace {
            let original_len = input.len();
            input = input.split_whitespace().collect::<Vec<_>>().join(" ");
            if input.len() != original_len {
                operations.push("normalized_whitespace".to_string());
            }
        }

        // Convert to lowercase
        if rule.to_lowercase {
            let original = input.clone();
            input = input.to_lowercase();
            if input != original {
                operations.push("converted_to_lowercase".to_string());
            }
        }

        // Check rule-specific length limit
        if let Some(max_length) = rule.max_length {
            if input.len() > max_length {
                input.truncate(max_length);
                operations.push(format!("truncated_to_{}", max_length));
            }
        }

        Ok(input)
    }

    /// Sanitize multiple inputs of the same type
    pub fn sanitize_batch(
        &self,
        inputs: &[&str],
        input_type: InputType,
    ) -> Vec<SecureResult<SanitizedInput>> {
        inputs.iter().map(|input| self.sanitize(input, input_type)).collect()
    }

    /// Check if sanitization would be applied to input
    pub fn would_sanitize(&self, input: &str, input_type: InputType) -> bool {
        if let Ok(result) = self.sanitize(input, input_type) {
            result.was_sanitized
        } else {
            true // If sanitization fails, assume it would be applied
        }
    }
}

/// HTML-specific sanitization utilities
pub mod html {
    use super::*;

    /// HTML entity encoding
    pub fn encode_html_entities(input: &str) -> String {
        input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
            .replace('/', "&#x2F;")
    }

    /// Decode HTML entities
    pub fn decode_html_entities(input: &str) -> String {
        input
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#x27;", "'")
            .replace("&#x2F;", "/")
    }

    /// Remove all HTML tags
    pub fn strip_html_tags(input: &str) -> SecureResult<String> {
        let tag_regex = Regex::new(r"<[^>]*>")?;
        Ok(tag_regex.replace_all(input, "").to_string())
    }

    /// Sanitize for safe HTML output
    pub fn sanitize_for_html(input: &str) -> String {
        let encoded = encode_html_entities(input);
        // Additional XSS prevention
        encoded.replace("javascript:", "").replace("vbscript:", "").replace("data:", "")
    }
}

/// SQL-specific sanitization utilities
pub mod sql {
    use super::*;

    /// Escape SQL string literals
    pub fn escape_sql_string(input: &str) -> String {
        input.replace('\'', "''")
    }

    /// Remove SQL comment patterns
    pub fn remove_sql_comments(input: &str) -> SecureResult<String> {
        let comment_regex = Regex::new(r"(?m)--.*$|/\*.*?\*/")?;
        Ok(comment_regex.replace_all(input, "").to_string())
    }

    /// Sanitize SQL identifier (table/column names)
    pub fn sanitize_sql_identifier(input: &str) -> SecureResult<String> {
        // Only allow alphanumeric and underscore
        let identifier_regex = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$")?;

        if identifier_regex.is_match(input)? {
            Ok(input.to_string())
        } else {
            Err(SecurityError::ValidationFailed)
        }
    }
}

/// JSON-specific sanitization utilities
pub mod json {
    use super::*;
    use serde_json::{Map, Value};

    /// Sanitize JSON values recursively
    pub fn sanitize_json_value(value: &Value, max_depth: usize) -> SecureResult<Value> {
        if max_depth == 0 {
            return Err(SecurityError::SizeLimitExceeded);
        }

        match value {
            Value::String(s) => {
                let sanitizer = Sanitizer::normal();
                let sanitized = sanitizer.sanitize(s, InputType::Text)?;
                Ok(Value::String(sanitized.into_string()))
            }
            Value::Array(arr) => {
                let mut sanitized_arr = Vec::new();
                for item in arr {
                    sanitized_arr.push(sanitize_json_value(item, max_depth - 1)?);
                }
                Ok(Value::Array(sanitized_arr))
            }
            Value::Object(obj) => {
                let mut sanitized_obj = Map::new();
                for (key, val) in obj {
                    let sanitizer = Sanitizer::normal();
                    let sanitized_key = sanitizer.sanitize(key, InputType::Text)?;
                    let sanitized_val = sanitize_json_value(val, max_depth - 1)?;
                    sanitized_obj.insert(sanitized_key.into_string(), sanitized_val);
                }
                Ok(Value::Object(sanitized_obj))
            }
            _ => Ok(value.clone()),
        }
    }

    /// Sanitize JSON string
    pub fn sanitize_json_string(input: &str) -> SecureResult<String> {
        let parsed: Value =
            serde_json::from_str(input).map_err(|_| SecurityError::MalformedInput)?;

        let sanitized = sanitize_json_value(&parsed, 10)?;

        serde_json::to_string(&sanitized).map_err(|_| SecurityError::InternalError)
    }
}

/// URL-specific sanitization utilities
pub mod url {
    use super::*;
    use std::collections::HashSet;

    /// Allowed URL schemes for security
    const ALLOWED_SCHEMES: &[&str] = &["http", "https", "ftp", "ftps", "mailto"];

    /// Sanitize URL for safe usage
    pub fn sanitize_url(input: &str) -> SecureResult<String> {
        let parsed = ::url::Url::parse(input).map_err(|_| SecurityError::MalformedInput)?;

        // Check if scheme is allowed
        if !ALLOWED_SCHEMES.contains(&parsed.scheme()) {
            return Err(SecurityError::ValidationFailed);
        }

        // Remove dangerous patterns from query parameters
        let mut sanitized_url =
            format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));

        if let Some(port) = parsed.port() {
            sanitized_url.push_str(&format!(":{}", port));
        }

        sanitized_url.push_str(parsed.path());

        // Sanitize query parameters
        if let Some(query) = parsed.query() {
            let sanitizer = Sanitizer::normal();
            let sanitized_query = sanitizer.sanitize(query, InputType::Text)?;
            if !sanitized_query.value().is_empty() {
                sanitized_url.push('?');
                sanitized_url.push_str(sanitized_query.value());
            }
        }

        Ok(sanitized_url)
    }

    /// Extract and validate domain from URL
    pub fn extract_safe_domain(input: &str) -> SecureResult<String> {
        let parsed = ::url::Url::parse(input).map_err(|_| SecurityError::MalformedInput)?;

        if let Some(domain) = parsed.host_str() {
            // Basic domain validation
            let domain_regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
                .map_err(|_| SecurityError::InternalError)?;

            if domain_regex.is_match(domain).map_err(|_| SecurityError::InternalError)? {
                Ok(domain.to_string())
            } else {
                Err(SecurityError::ValidationFailed)
            }
        } else {
            Err(SecurityError::MalformedInput)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitizer_creation() {
        let sanitizer = Sanitizer::strict();
        assert!(sanitizer.config.aggressive_mode);

        let sanitizer = Sanitizer::normal();
        assert!(!sanitizer.config.aggressive_mode);
    }

    #[test]
    fn test_html_sanitization() {
        use super::html::*;

        let input = "<script>alert('xss')</script>";
        let sanitized = encode_html_entities(input);
        assert!(!sanitized.contains("<script>"));

        let input = "Hello <b>world</b>";
        let stripped = strip_html_tags(input).unwrap();
        assert_eq!(stripped, "Hello world");
    }

    #[test]
    fn test_sql_sanitization() {
        use super::sql::*;

        let input = "O'Reilly";
        let escaped = escape_sql_string(input);
        assert_eq!(escaped, "O''Reilly");

        let input = "SELECT * FROM users -- comment";
        let no_comments = remove_sql_comments(input).unwrap();
        assert!(!no_comments.contains("--"));
    }

    #[test]
    fn test_json_sanitization() {
        use super::json::*;

        let input = r#"{"name": "<script>alert('xss')</script>", "age": 30}"#;
        let sanitized = sanitize_json_string(input).unwrap();
        assert!(!sanitized.contains("<script>"));
    }

    #[test]
    fn test_url_sanitization() {
        use super::url::*;

        let valid_url = "https://example.com/path?query=value";
        let sanitized = sanitize_url(valid_url).unwrap();
        assert!(sanitized.starts_with("https://"));

        let invalid_url = "javascript:alert('xss')";
        assert!(sanitize_url(invalid_url).is_err());
    }

    #[test]
    fn test_input_sanitization() {
        let sanitizer = Sanitizer::strict();

        let xss_input = "<script>alert('xss')</script>";
        let result = sanitizer.sanitize(xss_input, InputType::Text).unwrap();
        assert!(result.was_sanitized);
        assert!(!result.sanitized.contains("<script>"));

        let safe_input = "Hello world";
        let result = sanitizer.sanitize(safe_input, InputType::Text).unwrap();
        assert!(!result.was_sanitized);
        assert_eq!(result.sanitized, safe_input);
    }

    #[test]
    fn test_global_patterns() {
        let patterns = GlobalPatterns::new().unwrap();

        let input_with_nulls = "Hello\0World";
        assert!(patterns.null_bytes.is_match(input_with_nulls));

        let input_with_control = "Hello\x07World";
        assert!(patterns.control_chars.is_match(input_with_control).unwrap());
    }
}
