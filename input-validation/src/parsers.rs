//! Safe parsers module for critical input types
//!
//! Provides secure parsing for SCIM filters, OAuth parameters, JWT tokens, and other formats

use crate::error_handling::{SecureResult, SecurityError, ValidationError};
use crate::sanitization::{SanitizationConfig, Sanitizer};
use crate::validation::{InputType, SecurityValidator, ValidatorConfig};
use fancy_regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

/// Parser configuration
#[derive(Debug, Clone)]
pub struct ParserConfig {
    /// Maximum input size to parse
    pub max_input_size: usize,

    /// Maximum parsing time
    pub max_parse_time: Duration,

    /// Maximum recursion depth for nested structures
    pub max_recursion_depth: usize,

    /// Whether to enable strict mode (more security, less permissive)
    pub strict_mode: bool,

    /// Whether to sanitize input before parsing
    pub sanitize_input: bool,

    /// Custom parsing limits per type
    pub type_limits: HashMap<String, TypeLimits>,
}

/// Type-specific parsing limits
#[derive(Debug, Clone)]
pub struct TypeLimits {
    pub max_tokens: usize,
    pub max_string_length: usize,
    pub max_array_size: usize,
    pub max_object_size: usize,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self::production()
    }
}

impl ParserConfig {
    /// Production configuration with strict limits
    pub fn production() -> Self {
        let mut type_limits = HashMap::new();

        type_limits.insert(
            "scim_filter".to_string(),
            TypeLimits {
                max_tokens: 50,
                max_string_length: 500,
                max_array_size: 10,
                max_object_size: 20,
            },
        );

        type_limits.insert(
            "oauth".to_string(),
            TypeLimits {
                max_tokens: 20,
                max_string_length: 2048,
                max_array_size: 5,
                max_object_size: 15,
            },
        );

        type_limits.insert(
            "jwt".to_string(),
            TypeLimits {
                max_tokens: 100,
                max_string_length: 4096,
                max_array_size: 20,
                max_object_size: 50,
            },
        );

        Self {
            max_input_size: 64 * 1024, // 64KB
            max_parse_time: Duration::from_millis(500),
            max_recursion_depth: 10,
            strict_mode: true,
            sanitize_input: true,
            type_limits,
        }
    }

    /// Development configuration with relaxed limits
    pub fn development() -> Self {
        let mut config = Self::production();
        config.max_input_size = 1024 * 1024; // 1MB
        config.max_parse_time = Duration::from_secs(5);
        config.strict_mode = false;
        config
    }
}

/// Parse result wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedResult<T> {
    /// Parsed value
    pub value: T,

    /// Parse metadata
    pub metadata: ParseMetadata,

    /// Any warnings during parsing
    pub warnings: Vec<String>,
}

impl<T> ParsedResult<T> {
    pub fn new(value: T, metadata: ParseMetadata) -> Self {
        Self { value, metadata, warnings: Vec::new() }
    }

    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }

    pub fn into_inner(self) -> T {
        self.value
    }
}

/// Parse operation metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseMetadata {
    /// Input size in bytes
    pub input_size: usize,

    /// Parse duration
    pub parse_duration: Duration,

    /// Number of tokens processed
    pub tokens_processed: usize,

    /// Maximum recursion depth reached
    pub max_depth_reached: usize,

    /// Whether input was sanitized
    pub was_sanitized: bool,

    /// Parse method used
    pub parse_method: String,
}

/// Parser error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParserError {
    /// Input too large
    SizeLimitExceeded,

    /// Parsing timeout
    TimeoutExceeded,

    /// Maximum recursion depth exceeded
    DepthLimitExceeded,

    /// Invalid syntax
    InvalidSyntax(String),

    /// Unsupported feature
    UnsupportedFeature(String),

    /// Security violation detected
    SecurityViolation(String),

    /// Internal parser error
    InternalError(String),
}

impl fmt::Display for ParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParserError::SizeLimitExceeded => write!(f, "Input size limit exceeded"),
            ParserError::TimeoutExceeded => write!(f, "Parse timeout exceeded"),
            ParserError::DepthLimitExceeded => write!(f, "Maximum recursion depth exceeded"),
            ParserError::InvalidSyntax(msg) => write!(f, "Invalid syntax: {}", msg),
            ParserError::UnsupportedFeature(feature) => {
                write!(f, "Unsupported feature: {}", feature)
            }
            ParserError::SecurityViolation(msg) => write!(f, "Security violation: {}", msg),
            ParserError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for ParserError {}

impl From<ParserError> for SecurityError {
    fn from(error: ParserError) -> Self {
        match error {
            ParserError::SizeLimitExceeded => SecurityError::SizeLimitExceeded,
            ParserError::TimeoutExceeded => SecurityError::ResourceExhaustion,
            ParserError::DepthLimitExceeded => SecurityError::SizeLimitExceeded,
            ParserError::SecurityViolation(_) => SecurityError::InjectionAttempt,
            _ => SecurityError::ParserError,
        }
    }
}

/// Base trait for safe parsers
pub trait SafeParser<T> {
    /// Parse input with security checks
    fn parse(&self, input: &str) -> Result<ParsedResult<T>, ParserError>;

    /// Validate input before parsing
    fn validate_input(&self, input: &str) -> Result<(), ParserError>;

    /// Get parser configuration
    fn config(&self) -> &ParserConfig;
}

/// SCIM filter parser
#[derive(Debug, Clone)]
pub struct ScimParser {
    config: ParserConfig,
    validator: SecurityValidator,
    sanitizer: Option<Sanitizer>,
}

/// SCIM filter AST nodes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScimFilter {
    /// Attribute comparison
    AttributeExpression { attribute: String, operator: ScimOperator, value: Option<String> },

    /// Logical AND
    And(Box<ScimFilter>, Box<ScimFilter>),

    /// Logical OR
    Or(Box<ScimFilter>, Box<ScimFilter>),

    /// Logical NOT
    Not(Box<ScimFilter>),

    /// Grouped expression
    Group(Box<ScimFilter>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScimOperator {
    Eq, // equal
    Ne, // not equal
    Co, // contains
    Sw, // starts with
    Ew, // ends with
    Pr, // present
    Gt, // greater than
    Ge, // greater than or equal
    Lt, // less than
    Le, // less than or equal
}

impl fmt::Display for ScimOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScimOperator::Eq => write!(f, "eq"),
            ScimOperator::Ne => write!(f, "ne"),
            ScimOperator::Co => write!(f, "co"),
            ScimOperator::Sw => write!(f, "sw"),
            ScimOperator::Ew => write!(f, "ew"),
            ScimOperator::Pr => write!(f, "pr"),
            ScimOperator::Gt => write!(f, "gt"),
            ScimOperator::Ge => write!(f, "ge"),
            ScimOperator::Lt => write!(f, "lt"),
            ScimOperator::Le => write!(f, "le"),
        }
    }
}

impl ScimParser {
    pub fn new(config: ParserConfig) -> anyhow::Result<Self> {
        let validator = SecurityValidator::new(ValidatorConfig::production())?;
        let sanitizer = if config.sanitize_input {
            Some(Sanitizer::new(SanitizationConfig::strict()))
        } else {
            None
        };

        Ok(Self { config, validator, sanitizer })
    }

    /// Parse SCIM filter with comprehensive security checks
    fn parse_filter(&self, input: &str, depth: usize) -> Result<ScimFilter, ParserError> {
        if depth > self.config.max_recursion_depth {
            return Err(ParserError::DepthLimitExceeded);
        }

        let trimmed = input.trim();

        // Handle grouped expressions
        if trimmed.starts_with('(') && trimmed.ends_with(')') {
            let inner = &trimmed[1..trimmed.len() - 1];
            let inner_filter = self.parse_filter(inner, depth + 1)?;
            return Ok(ScimFilter::Group(Box::new(inner_filter)));
        }

        // Look for logical operators (AND, OR)
        if let Some(and_pos) = self.find_logical_operator(trimmed, " and ") {
            let left = &trimmed[..and_pos];
            let right = &trimmed[and_pos + 5..];

            let left_filter = self.parse_filter(left, depth + 1)?;
            let right_filter = self.parse_filter(right, depth + 1)?;

            return Ok(ScimFilter::And(Box::new(left_filter), Box::new(right_filter)));
        }

        if let Some(or_pos) = self.find_logical_operator(trimmed, " or ") {
            let left = &trimmed[..or_pos];
            let right = &trimmed[or_pos + 4..];

            let left_filter = self.parse_filter(left, depth + 1)?;
            let right_filter = self.parse_filter(right, depth + 1)?;

            return Ok(ScimFilter::Or(Box::new(left_filter), Box::new(right_filter)));
        }

        // Handle NOT operator
        if trimmed.starts_with("not ") {
            let inner = &trimmed[4..];
            let inner_filter = self.parse_filter(inner, depth + 1)?;
            return Ok(ScimFilter::Not(Box::new(inner_filter)));
        }

        // Parse attribute expression
        self.parse_attribute_expression(trimmed)
    }

    /// Find logical operator position considering parentheses
    fn find_logical_operator(&self, input: &str, operator: &str) -> Option<usize> {
        let mut paren_count = 0;
        let mut pos = 0;

        while pos < input.len() {
            if let Some(ch) = input.chars().nth(pos) {
                match ch {
                    '(' => paren_count += 1,
                    ')' => paren_count -= 1,
                    _ => {
                        if paren_count == 0 && input[pos..].starts_with(operator) {
                            return Some(pos);
                        }
                    }
                }
            }
            pos += 1;
        }

        None
    }

    /// Parse attribute expression (e.g., "userName eq \"john\"")
    fn parse_attribute_expression(&self, input: &str) -> Result<ScimFilter, ParserError> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 2 {
            return Err(ParserError::InvalidSyntax("Missing operator".to_string()));
        }

        let attribute = parts[0].to_string();
        let operator_str = parts[1];

        // Validate attribute name
        if !self.is_valid_attribute_name(&attribute) {
            return Err(ParserError::SecurityViolation(format!(
                "Invalid attribute name: {}",
                attribute
            )));
        }

        // Parse operator
        let operator = match operator_str.to_lowercase().as_str() {
            "eq" => ScimOperator::Eq,
            "ne" => ScimOperator::Ne,
            "co" => ScimOperator::Co,
            "sw" => ScimOperator::Sw,
            "ew" => ScimOperator::Ew,
            "pr" => ScimOperator::Pr,
            "gt" => ScimOperator::Gt,
            "ge" => ScimOperator::Ge,
            "lt" => ScimOperator::Lt,
            "le" => ScimOperator::Le,
            _ => {
                return Err(ParserError::InvalidSyntax(format!(
                    "Unknown operator: {}",
                    operator_str
                )))
            }
        };

        // Parse value (if required)
        let value = if operator == ScimOperator::Pr {
            if parts.len() > 2 {
                return Err(ParserError::InvalidSyntax(
                    "Present operator should not have a value".to_string(),
                ));
            }
            None
        } else {
            if parts.len() < 3 {
                return Err(ParserError::InvalidSyntax("Missing value".to_string()));
            }

            let value_part = parts[2..].join(" ");
            let unquoted_value = self.unquote_value(&value_part)?;

            // Validate value
            if unquoted_value.len()
                > self
                    .config
                    .type_limits
                    .get("scim_filter")
                    .map(|limits| limits.max_string_length)
                    .unwrap_or(500)
            {
                return Err(ParserError::SizeLimitExceeded);
            }

            Some(unquoted_value)
        };

        Ok(ScimFilter::AttributeExpression { attribute, operator, value })
    }

    /// Validate attribute name
    fn is_valid_attribute_name(&self, name: &str) -> bool {
        // SCIM attribute names should follow specific patterns
        let attribute_regex = Regex::new(r"^[a-zA-Z][a-zA-Z0-9._]*$").unwrap();
        attribute_regex.is_match(name).unwrap_or(false) && name.len() <= 100
    }

    /// Remove quotes from value and validate
    fn unquote_value(&self, value: &str) -> Result<String, ParserError> {
        if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            let unquoted = &value[1..value.len() - 1];

            // Check for escaped quotes and other escape sequences
            let mut result = String::new();
            let mut chars = unquoted.chars().peekable();

            while let Some(ch) = chars.next() {
                match ch {
                    '\\' => {
                        if let Some(&next_ch) = chars.peek() {
                            match next_ch {
                                '"' | '\\' | '/' => {
                                    result.push(chars.next().unwrap());
                                }
                                'n' => {
                                    chars.next();
                                    result.push('\n');
                                }
                                'r' => {
                                    chars.next();
                                    result.push('\r');
                                }
                                't' => {
                                    chars.next();
                                    result.push('\t');
                                }
                                _ => {
                                    return Err(ParserError::InvalidSyntax(
                                        "Invalid escape sequence".to_string(),
                                    ));
                                }
                            }
                        } else {
                            return Err(ParserError::InvalidSyntax(
                                "Incomplete escape sequence".to_string(),
                            ));
                        }
                    }
                    _ => result.push(ch),
                }
            }

            Ok(result)
        } else {
            // Unquoted value - validate it doesn't contain special characters
            if value.chars().any(|c| " ()\"\\".contains(c)) {
                return Err(ParserError::InvalidSyntax(
                    "Unquoted value contains special characters".to_string(),
                ));
            }
            Ok(value.to_string())
        }
    }
}

impl SafeParser<ScimFilter> for ScimParser {
    fn parse(&self, input: &str) -> Result<ParsedResult<ScimFilter>, ParserError> {
        let start_time = std::time::Instant::now();

        self.validate_input(input)?;

        let mut parse_input = input.to_string();
        let was_sanitized = if let Some(ref sanitizer) = self.sanitizer {
            let sanitized = sanitizer
                .sanitize(input, InputType::ScimFilter)
                .map_err(|_| ParserError::SecurityViolation("Sanitization failed".to_string()))?;

            let sanitized_value = sanitized.into_string();
            let was_changed = sanitized_value != input;
            parse_input = sanitized_value;
            was_changed
        } else {
            false
        };

        let filter = self.parse_filter(&parse_input, 0)?;

        let metadata = ParseMetadata {
            input_size: input.len(),
            parse_duration: start_time.elapsed(),
            tokens_processed: parse_input.split_whitespace().count(),
            max_depth_reached: Self::calculate_parse_depth(&parse_input),
            was_sanitized,
            parse_method: "recursive_descent".to_string(),
        };

        Ok(ParsedResult::new(filter, metadata))
    }

    /// Calculate the parsing depth of a SCIM filter expression
    fn calculate_parse_depth(input: &str) -> usize {
        let mut depth = 0;
        let mut max_depth = 0;
        
        for char in input.chars() {
            match char {
                '(' => {
                    depth += 1;
                    max_depth = max_depth.max(depth);
                }
                ')' => {
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
        
        max_depth
    }

    fn validate_input(&self, input: &str) -> Result<(), ParserError> {
        if input.len() > self.config.max_input_size {
            return Err(ParserError::SizeLimitExceeded);
        }

        // Check for injection patterns
        let injection_patterns = self.validator.check_injection(input);
        if !injection_patterns.is_empty() {
            return Err(ParserError::SecurityViolation(format!(
                "Injection patterns detected: {:?}",
                injection_patterns
            )));
        }

        // Validate parentheses balance
        let mut paren_count = 0;
        for ch in input.chars() {
            match ch {
                '(' => paren_count += 1,
                ')' => {
                    paren_count -= 1;
                    if paren_count < 0 {
                        return Err(ParserError::InvalidSyntax(
                            "Unbalanced parentheses".to_string(),
                        ));
                    }
                }
                _ => {}
            }
        }

        if paren_count != 0 {
            return Err(ParserError::InvalidSyntax("Unbalanced parentheses".to_string()));
        }

        Ok(())
    }

    fn config(&self) -> &ParserConfig {
        &self.config
    }
}

/// OAuth parameter parser
#[derive(Debug, Clone)]
pub struct OAuthParser {
    config: ParserConfig,
    validator: SecurityValidator,
    sanitizer: Option<Sanitizer>,
}

/// OAuth parameters structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthParams {
    pub grant_type: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code: Option<String>,
    pub code_verifier: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub response_type: Option<String>,
    pub nonce: Option<String>,
    pub custom_params: HashMap<String, String>,
}

impl OAuthParser {
    pub fn new(config: ParserConfig) -> anyhow::Result<Self> {
        let validator = SecurityValidator::new(ValidatorConfig::production())?;
        let sanitizer = if config.sanitize_input {
            Some(Sanitizer::new(SanitizationConfig::normal()))
        } else {
            None
        };

        Ok(Self { config, validator, sanitizer })
    }

    /// Parse OAuth parameters from query string or form data
    fn parse_params(&self, input: &str) -> Result<OAuthParams, ParserError> {
        let mut params = OAuthParams {
            grant_type: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            state: None,
            code: None,
            code_verifier: None,
            code_challenge: None,
            code_challenge_method: None,
            response_type: None,
            nonce: None,
            custom_params: HashMap::new(),
        };

        // Parse key-value pairs
        for pair in input.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let decoded_key = urlencoding::decode(key).map_err(|_| {
                    ParserError::InvalidSyntax("Invalid URL encoding in key".to_string())
                })?;
                let decoded_value = urlencoding::decode(value).map_err(|_| {
                    ParserError::InvalidSyntax("Invalid URL encoding in value".to_string())
                })?;

                // Validate key and value lengths
                if decoded_key.len() > 100 {
                    return Err(ParserError::SizeLimitExceeded);
                }

                if decoded_value.len() > 4096 {
                    return Err(ParserError::SizeLimitExceeded);
                }

                // Validate and assign to appropriate field
                self.assign_oauth_param(&mut params, &decoded_key, &decoded_value)?;
            }
        }

        Ok(params)
    }

    /// Assign OAuth parameter to appropriate field
    fn assign_oauth_param(
        &self,
        params: &mut OAuthParams,
        key: &str,
        value: &str,
    ) -> Result<(), ParserError> {
        // Validate value based on parameter type
        match key {
            "grant_type" => {
                self.validate_grant_type(value)?;
                params.grant_type = Some(value.to_string());
            }
            "client_id" => {
                self.validate_client_id(value)?;
                params.client_id = Some(value.to_string());
            }
            "client_secret" => {
                self.validate_client_secret(value)?;
                params.client_secret = Some(value.to_string());
            }
            "redirect_uri" => {
                self.validate_redirect_uri(value)?;
                params.redirect_uri = Some(value.to_string());
            }
            "scope" => {
                self.validate_scope(value)?;
                params.scope = Some(value.to_string());
            }
            "state" => {
                self.validate_state(value)?;
                params.state = Some(value.to_string());
            }
            "code" => {
                self.validate_code(value)?;
                params.code = Some(value.to_string());
            }
            "code_verifier" => {
                self.validate_code_verifier(value)?;
                params.code_verifier = Some(value.to_string());
            }
            "code_challenge" => {
                self.validate_code_challenge(value)?;
                params.code_challenge = Some(value.to_string());
            }
            "code_challenge_method" => {
                self.validate_code_challenge_method(value)?;
                params.code_challenge_method = Some(value.to_string());
            }
            "response_type" => {
                self.validate_response_type(value)?;
                params.response_type = Some(value.to_string());
            }
            "nonce" => {
                self.validate_nonce(value)?;
                params.nonce = Some(value.to_string());
            }
            _ => {
                // Custom parameter
                if params.custom_params.len() >= 10 {
                    return Err(ParserError::SizeLimitExceeded);
                }
                params.custom_params.insert(key.to_string(), value.to_string());
            }
        }

        Ok(())
    }

    /// Validate grant_type parameter
    fn validate_grant_type(&self, value: &str) -> Result<(), ParserError> {
        const VALID_GRANT_TYPES: &[&str] = &[
            "authorization_code",
            "client_credentials",
            "password",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
        ];

        if !VALID_GRANT_TYPES.contains(&value) {
            return Err(ParserError::InvalidSyntax(format!("Invalid grant_type: {}", value)));
        }

        Ok(())
    }

    /// Validate client_id parameter
    fn validate_client_id(&self, value: &str) -> Result<(), ParserError> {
        if value.len() > 255 || value.is_empty() {
            return Err(ParserError::InvalidSyntax("Invalid client_id length".to_string()));
        }

        // Client ID should be URL-safe
        if !value.chars().all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)) {
            return Err(ParserError::InvalidSyntax("Invalid client_id format".to_string()));
        }

        Ok(())
    }

    /// Validate client_secret parameter
    fn validate_client_secret(&self, value: &str) -> Result<(), ParserError> {
        if value.len() > 512 || value.is_empty() {
            return Err(ParserError::InvalidSyntax("Invalid client_secret length".to_string()));
        }

        Ok(())
    }

    /// Validate redirect_uri parameter
    fn validate_redirect_uri(&self, value: &str) -> Result<(), ParserError> {
        if value.len() > 2048 {
            return Err(ParserError::SizeLimitExceeded);
        }

        // Parse as URL
        let url = Url::parse(value)
            .map_err(|_| ParserError::InvalidSyntax("Invalid redirect_uri format".to_string()))?;

        // Check allowed schemes
        match url.scheme() {
            "https" | "http" => Ok(()),
            "localhost" if !self.config.strict_mode => Ok(()),
            _ => Err(ParserError::SecurityViolation(format!(
                "Disallowed redirect_uri scheme: {}",
                url.scheme()
            ))),
        }
    }

    /// Validate scope parameter
    fn validate_scope(&self, value: &str) -> Result<(), ParserError> {
        if value.len() > 1000 {
            return Err(ParserError::SizeLimitExceeded);
        }

        // Scopes should be space-separated tokens
        for scope in value.split_whitespace() {
            if scope.len() > 100 {
                return Err(ParserError::InvalidSyntax("Scope token too long".to_string()));
            }

            if !scope.chars().all(|c| c.is_ascii_alphanumeric() || "-._:".contains(c)) {
                return Err(ParserError::InvalidSyntax("Invalid scope token format".to_string()));
            }
        }

        Ok(())
    }

    /// Validate state parameter
    fn validate_state(&self, value: &str) -> Result<(), ParserError> {
        if value.len() > 128 {
            return Err(ParserError::SizeLimitExceeded);
        }

        // State should be URL-safe
        if !value.chars().all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)) {
            return Err(ParserError::InvalidSyntax("Invalid state format".to_string()));
        }

        Ok(())
    }

    /// Validate authorization code
    fn validate_code(&self, value: &str) -> Result<(), ParserError> {
        if value.len() > 1024 || value.is_empty() {
            return Err(ParserError::InvalidSyntax("Invalid code length".to_string()));
        }

        Ok(())
    }

    /// Validate PKCE code_verifier
    fn validate_code_verifier(&self, value: &str) -> Result<(), ParserError> {
        if value.len() < 43 || value.len() > 128 {
            return Err(ParserError::InvalidSyntax("Invalid code_verifier length".to_string()));
        }

        // Should be URL-safe base64
        if !value.chars().all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)) {
            return Err(ParserError::InvalidSyntax("Invalid code_verifier format".to_string()));
        }

        Ok(())
    }

    /// Validate PKCE code_challenge
    fn validate_code_challenge(&self, value: &str) -> Result<(), ParserError> {
        if value.len() < 43 || value.len() > 128 {
            return Err(ParserError::InvalidSyntax("Invalid code_challenge length".to_string()));
        }

        Ok(())
    }

    /// Validate PKCE code_challenge_method
    fn validate_code_challenge_method(&self, value: &str) -> Result<(), ParserError> {
        match value {
            "plain" | "S256" => Ok(()),
            _ => {
                Err(ParserError::InvalidSyntax(format!("Invalid code_challenge_method: {}", value)))
            }
        }
    }

    /// Validate response_type parameter
    fn validate_response_type(&self, value: &str) -> Result<(), ParserError> {
        const VALID_RESPONSE_TYPES: &[&str] = &[
            "code",
            "token",
            "id_token",
            "code token",
            "code id_token",
            "token id_token",
            "code token id_token",
        ];

        if !VALID_RESPONSE_TYPES.contains(&value) {
            return Err(ParserError::InvalidSyntax(format!("Invalid response_type: {}", value)));
        }

        Ok(())
    }

    /// Validate nonce parameter
    fn validate_nonce(&self, value: &str) -> Result<(), ParserError> {
        if value.len() > 128 {
            return Err(ParserError::SizeLimitExceeded);
        }

        Ok(())
    }
}

impl SafeParser<OAuthParams> for OAuthParser {
    fn parse(&self, input: &str) -> Result<ParsedResult<OAuthParams>, ParserError> {
        let start_time = std::time::Instant::now();

        self.validate_input(input)?;

        let mut parse_input = input.to_string();
        let was_sanitized = if let Some(ref sanitizer) = self.sanitizer {
            let sanitized = sanitizer
                .sanitize(input, InputType::OAuth)
                .map_err(|_| ParserError::SecurityViolation("Sanitization failed".to_string()))?;

            let sanitized_value = sanitized.into_string();
            let was_changed = sanitized_value != input;
            parse_input = sanitized_value;
            was_changed
        } else {
            false
        };

        let params = self.parse_params(&parse_input)?;

        let metadata = ParseMetadata {
            input_size: input.len(),
            parse_duration: start_time.elapsed(),
            tokens_processed: parse_input.split('&').count(),
            max_depth_reached: 1,
            was_sanitized,
            parse_method: "key_value_pairs".to_string(),
        };

        Ok(ParsedResult::new(params, metadata))
    }

    fn validate_input(&self, input: &str) -> Result<(), ParserError> {
        if input.len() > self.config.max_input_size {
            return Err(ParserError::SizeLimitExceeded);
        }

        // Check for injection patterns
        let injection_patterns = self.validator.check_injection(input);
        if !injection_patterns.is_empty() {
            return Err(ParserError::SecurityViolation(format!(
                "Injection patterns detected: {:?}",
                injection_patterns
            )));
        }

        // Check parameter count
        let param_count = input.split('&').count();
        if param_count > 50 {
            return Err(ParserError::SizeLimitExceeded);
        }

        Ok(())
    }

    fn config(&self) -> &ParserConfig {
        &self.config
    }
}

/// JWT parser (simplified for validation purposes)
#[derive(Debug, Clone)]
pub struct JwtParser {
    config: ParserConfig,
    validator: SecurityValidator,
}

/// JWT structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtToken {
    pub header: JwtHeader,
    pub payload: serde_json::Value,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: Option<String>,
    pub kid: Option<String>,
}

impl JwtParser {
    pub fn new(config: ParserConfig) -> anyhow::Result<Self> {
        let validator = SecurityValidator::new(ValidatorConfig::production())?;

        Ok(Self { config, validator })
    }

    /// Parse JWT token structure (without signature verification)
    fn parse_jwt(&self, input: &str) -> Result<JwtToken, ParserError> {
        let parts: Vec<&str> = input.split('.').collect();

        if parts.len() != 3 {
            return Err(ParserError::InvalidSyntax("JWT must have 3 parts".to_string()));
        }

        // Decode header
        let header_bytes = base64::decode_config(parts[0], base64::URL_SAFE_NO_PAD)
            .map_err(|_| ParserError::InvalidSyntax("Invalid base64 in header".to_string()))?;

        let header: JwtHeader = serde_json::from_slice(&header_bytes)
            .map_err(|_| ParserError::InvalidSyntax("Invalid JSON in header".to_string()))?;

        // Validate header
        self.validate_jwt_header(&header)?;

        // Decode payload
        let payload_bytes = base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)
            .map_err(|_| ParserError::InvalidSyntax("Invalid base64 in payload".to_string()))?;

        if payload_bytes.len() > 64 * 1024 {
            return Err(ParserError::SizeLimitExceeded);
        }

        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|_| ParserError::InvalidSyntax("Invalid JSON in payload".to_string()))?;

        // Validate payload
        self.validate_jwt_payload(&payload)?;

        let signature = parts[2].to_string();

        Ok(JwtToken { header, payload, signature })
    }

    /// Validate JWT header
    fn validate_jwt_header(&self, header: &JwtHeader) -> Result<(), ParserError> {
        // Check algorithm
        const ALLOWED_ALGORITHMS: &[&str] =
            &["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"];

        if !ALLOWED_ALGORITHMS.contains(&header.alg.as_str()) {
            return Err(ParserError::SecurityViolation(format!(
                "Disallowed algorithm: {}",
                header.alg
            )));
        }

        // Reject "none" algorithm
        if header.alg == "none" {
            return Err(ParserError::SecurityViolation(
                "Algorithm 'none' is not allowed".to_string(),
            ));
        }

        // Validate typ if present
        if let Some(ref typ) = header.typ {
            if typ != "JWT" {
                return Err(ParserError::InvalidSyntax(format!("Invalid typ: {}", typ)));
            }
        }

        Ok(())
    }

    /// Validate JWT payload
    fn validate_jwt_payload(&self, payload: &serde_json::Value) -> Result<(), ParserError> {
        if let Some(obj) = payload.as_object() {
            // Check payload size
            if obj.len() > 100 {
                return Err(ParserError::SizeLimitExceeded);
            }

            // Validate standard claims
            if let Some(exp) = obj.get("exp") {
                if let Some(exp_num) = exp.as_u64() {
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

                    if exp_num < now {
                        return Err(ParserError::SecurityViolation("Token expired".to_string()));
                    }
                }
            }

            // Check for suspicious claims
            for (key, value) in obj {
                if key.len() > 100 {
                    return Err(ParserError::SizeLimitExceeded);
                }

                if let Some(str_val) = value.as_str() {
                    if str_val.len() > 4096 {
                        return Err(ParserError::SizeLimitExceeded);
                    }

                    // Check for injection patterns in string claims
                    let injection_patterns = self.validator.check_injection(str_val);
                    if !injection_patterns.is_empty() {
                        return Err(ParserError::SecurityViolation(
                            "Injection patterns in payload".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

impl SafeParser<JwtToken> for JwtParser {
    fn parse(&self, input: &str) -> Result<ParsedResult<JwtToken>, ParserError> {
        let start_time = std::time::Instant::now();

        self.validate_input(input)?;

        let token = self.parse_jwt(input)?;

        let metadata = ParseMetadata {
            input_size: input.len(),
            parse_duration: start_time.elapsed(),
            tokens_processed: 3,  // header, payload, signature
            max_depth_reached: 2, // header and payload objects
            was_sanitized: false,
            parse_method: "jwt_base64".to_string(),
        };

        Ok(ParsedResult::new(token, metadata))
    }

    fn validate_input(&self, input: &str) -> Result<(), ParserError> {
        if input.len() > self.config.max_input_size {
            return Err(ParserError::SizeLimitExceeded);
        }

        // Basic JWT format check
        if input.split('.').count() != 3 {
            return Err(ParserError::InvalidSyntax("Invalid JWT format".to_string()));
        }

        // Check for obvious injection patterns
        if input.contains(['\n', '\r', ' ', '\t']) {
            return Err(ParserError::InvalidSyntax("JWT contains invalid characters".to_string()));
        }

        Ok(())
    }

    fn config(&self) -> &ParserConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scim_parser() {
        let config = ParserConfig::production();
        let parser = ScimParser::new(config).unwrap();

        // Test simple attribute expression
        let _result = parser.parse("userName eq \"john\"");
        assert!(result.is_ok());

        let parsed = result.unwrap();
        match parsed.value {
            ScimFilter::AttributeExpression { attribute, operator, value } => {
                assert_eq!(attribute, "userName");
                assert_eq!(operator, ScimOperator::Eq);
                assert_eq!(value, Some("john".to_string()));
            }
            _ => panic!("Expected attribute expression"),
        }
    }

    #[test]
    fn test_scim_parser_complex() {
        let config = ParserConfig::production();
        let parser = ScimParser::new(config).unwrap();

        // Test complex expression with AND
        let _result = parser.parse("userName eq \"john\" and active eq true");
        assert!(result.is_ok());

        let parsed = result.unwrap();
        match parsed.value {
            ScimFilter::And(_, _) => {
                // Expected
            }
            _ => panic!("Expected AND expression"),
        }
    }

    #[test]
    fn test_scim_parser_injection() {
        let config = ParserConfig::production();
        let parser = ScimParser::new(config).unwrap();

        // Test SQL injection attempt
        let _result = parser.parse("userName eq \"john\"; DROP TABLE users");
        assert!(result.is_err());
    }

    #[test]
    fn test_oauth_parser() {
        let config = ParserConfig::production();
        let parser = OAuthParser::new(config).unwrap();

        let input = "grant_type=authorization_code&client_id=test123&redirect_uri=https://example.com/callback";
        let _result = parser.parse(input);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.value.grant_type, Some("authorization_code".to_string()));
        assert_eq!(parsed.value.client_id, Some("test123".to_string()));
    }

    #[test]
    fn test_oauth_parser_invalid_grant_type() {
        let config = ParserConfig::production();
        let parser = OAuthParser::new(config).unwrap();

        let input = "grant_type=invalid_type&client_id=test123";
        let _result = parser.parse(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_parser() {
        let config = ParserConfig::production();
        let parser = JwtParser::new(config).unwrap();

        // This is a sample JWT (header.payload.signature format)
        // Note: This is for testing parsing logic only, not a valid signed token
        let header =
            base64::encode_config(r#"{"alg":"RS256","typ":"JWT"}"#, base64::URL_SAFE_NO_PAD);
        let payload =
            base64::encode_config(r#"{"sub":"user123","exp":9999999999}"#, base64::URL_SAFE_NO_PAD);
        let signature = "fake_signature";

        let jwt = format!("{}.{}.{}", header, payload, signature);

        let _result = parser.parse(&jwt);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.value.header.alg, "RS256");
    }

    #[test]
    fn test_jwt_parser_none_algorithm() {
        let config = ParserConfig::production();
        let parser = JwtParser::new(config).unwrap();

        let header =
            base64::encode_config(r#"{"alg":"none","typ":"JWT"}"#, base64::URL_SAFE_NO_PAD);
        let payload = base64::encode_config(r#"{"sub":"user123"}"#, base64::URL_SAFE_NO_PAD);
        let signature = "";

        let jwt = format!("{}.{}.{}", header, payload, signature);

        let _result = parser.parse(&jwt);
        assert!(result.is_err());
    }

    #[test]
    fn test_parser_size_limits() {
        let mut config = ParserConfig::production();
        config.max_input_size = 100;

        let parser = ScimParser::new(config).unwrap();

        let large_input = "a".repeat(200);
        let _result = parser.parse(&large_input);
        assert!(matches!(result, Err(ParserError::SizeLimitExceeded)));
    }
}
