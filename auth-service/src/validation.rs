use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
use validator::{Validate, ValidationError, ValidationErrors};

/// Helper function to create a `ValidationError` with just a code
fn validation_error(code: &'static str) -> ValidationError {
    ValidationError {
        code: std::borrow::Cow::Borrowed(code),
        message: None,
        params: std::collections::HashMap::new(),
    }
}

/// Maximum lengths for various input fields
pub const MAX_CLIENT_ID_LENGTH: usize = 255;
pub const MAX_CLIENT_SECRET_LENGTH: usize = 128;
pub const MAX_SCOPE_LENGTH: usize = 1000;
pub const MAX_REDIRECT_URI_LENGTH: usize = 2048;
pub const MAX_USERNAME_LENGTH: usize = 255;
pub const MAX_EMAIL_LENGTH: usize = 320; // RFC 5321 limit
pub const MAX_PHONE_LENGTH: usize = 20;
pub const MAX_DISPLAY_NAME_LENGTH: usize = 255;
pub const MAX_GIVEN_NAME_LENGTH: usize = 100;
pub const MAX_FAMILY_NAME_LENGTH: usize = 100;
pub const MAX_FILTER_LENGTH: usize = 500;
pub const MAX_TOKEN_LENGTH: usize = 2048;
pub const MAX_STATE_LENGTH: usize = 128;
pub const MAX_NONCE_LENGTH: usize = 128;
pub const MAX_CODE_CHALLENGE_LENGTH: usize = 128;

/// `OAuth` 2.0 Token Request DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct TokenRequest {
    #[validate(length(min = 1, max = 50))]
    pub grant_type: String,

    #[validate(length(max = 255))]
    pub client_id: Option<String>,

    #[validate(length(max = 128))]
    pub client_secret: Option<String>,

    #[validate(length(max = 1024))]
    pub code: Option<String>,

    #[validate(url, length(max = 2048))]
    pub redirect_uri: Option<String>,

    #[validate(length(max = 2048))]
    pub refresh_token: Option<String>,

    #[validate(length(max = 1000), custom(function = "validate_scope"))]
    pub scope: Option<String>,

    #[validate(length(max = 128))]
    pub code_verifier: Option<String>,

    #[validate(length(max = 255))]
    pub username: Option<String>,

    #[validate(
        length(min = 12, max = 255),
        custom(function = "validate_password_strength")
    )]
    pub password: Option<String>,
}

/// `OAuth` 2.0 Authorization Request DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct AuthorizationRequest {
    #[validate(length(min = 1, max = 50))]
    pub response_type: String,

    #[validate(length(min = 1, max = 255))]
    pub client_id: String,

    #[validate(url, length(max = 2048))]
    pub redirect_uri: String,

    #[validate(length(max = 1000), custom(function = "validate_scope"))]
    pub scope: Option<String>,

    #[validate(length(max = 128))]
    pub state: Option<String>,

    #[validate(length(max = 128))]
    pub nonce: Option<String>,

    #[validate(length(max = 128))]
    pub code_challenge: Option<String>,

    #[validate(length(max = 10))]
    pub code_challenge_method: Option<String>,

    #[validate(range(min = 1, max = 3600))]
    pub max_age: Option<u32>,

    #[validate(length(max = 500))]
    pub prompt: Option<String>,
}

/// SCIM User DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ScimUser {
    #[validate(length(max = 255))]
    pub id: Option<String>,

    #[validate(length(max = 255))]
    pub external_id: Option<String>,

    #[validate(length(min = 1, max = 255))]
    pub user_name: String,

    #[validate(nested)]
    pub name: Option<ScimName>,

    #[validate(length(max = 255))]
    pub display_name: Option<String>,

    #[validate(length(max = 255))]
    pub nick_name: Option<String>,

    #[validate(url, length(max = 2048))]
    pub profile_url: Option<String>,

    #[validate(length(max = 255))]
    pub title: Option<String>,

    #[validate(length(max = 255))]
    pub user_type: Option<String>,

    #[validate(length(max = 10))]
    pub preferred_language: Option<String>,

    #[validate(length(max = 10))]
    pub locale: Option<String>,

    #[validate(length(max = 50))]
    pub timezone: Option<String>,

    pub active: Option<bool>,

    #[validate(nested)]
    pub emails: Option<Vec<ScimEmail>>,

    #[validate(nested)]
    pub phone_numbers: Option<Vec<ScimPhoneNumber>>,

    pub addresses: Option<Vec<ScimAddress>>,

    pub groups: Option<Vec<ScimGroup>>,

    pub roles: Option<Vec<ScimRole>>,

    pub entitlements: Option<Vec<ScimEntitlement>>,

    pub x509_certificates: Option<Vec<ScimX509Certificate>>,
}

/// SCIM Name DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ScimName {
    #[validate(length(max = 255))]
    pub formatted: Option<String>,

    #[validate(length(max = 100))]
    pub family_name: Option<String>,

    #[validate(length(max = 100))]
    pub given_name: Option<String>,

    #[validate(length(max = 100))]
    pub middle_name: Option<String>,

    #[validate(length(max = 20))]
    pub honorific_prefix: Option<String>,

    #[validate(length(max = 20))]
    pub honorific_suffix: Option<String>,
}

/// SCIM Email DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ScimEmail {
    #[validate(email, length(max = 320))]
    pub value: String,

    #[validate(length(max = 50))]
    #[serde(rename = "type")]
    pub email_type: Option<String>,

    pub primary: Option<bool>,

    #[validate(length(max = 255))]
    pub display: Option<String>,
}

/// SCIM Phone Number DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ScimPhoneNumber {
    #[validate(length(max = 20), custom(function = "validate_phone_number"))]
    pub value: String,

    #[validate(length(max = 50))]
    #[serde(rename = "type")]
    pub phone_type: Option<String>,

    pub primary: Option<bool>,

    #[validate(length(max = 255))]
    pub display: Option<String>,
}

/// SCIM Address DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ScimAddress {
    #[validate(length(max = 500))]
    pub formatted: Option<String>,

    #[validate(length(max = 255))]
    pub street_address: Option<String>,

    #[validate(length(max = 100))]
    pub locality: Option<String>,

    #[validate(length(max = 100))]
    pub region: Option<String>,

    #[validate(length(max = 20))]
    pub postal_code: Option<String>,

    #[validate(length(max = 100))]
    pub country: Option<String>,

    #[validate(length(max = 50))]
    #[serde(rename = "type")]
    pub address_type: Option<String>,

    pub primary: Option<bool>,
}

/// SCIM Group DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ScimGroup {
    #[validate(length(max = 255))]
    pub value: String,

    #[validate(length(max = 255))]
    pub display: Option<String>,

    #[validate(length(max = 50))]
    #[serde(rename = "type")]
    pub group_type: Option<String>,
}

/// SCIM Role DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ScimRole {
    #[validate(length(max = 255))]
    pub value: String,

    #[validate(length(max = 255))]
    pub display: Option<String>,

    #[validate(length(max = 50))]
    #[serde(rename = "type")]
    pub role_type: Option<String>,

    pub primary: Option<bool>,
}

/// SCIM Entitlement DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ScimEntitlement {
    #[validate(length(max = 255))]
    pub value: String,

    #[validate(length(max = 255))]
    pub display: Option<String>,

    #[validate(length(max = 50))]
    #[serde(rename = "type")]
    pub entitlement_type: Option<String>,

    pub primary: Option<bool>,
}

/// SCIM X509 Certificate DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ScimX509Certificate {
    #[validate(length(max = 10000))]
    pub value: String,

    #[validate(length(max = 255))]
    pub display: Option<String>,

    #[validate(length(max = 50))]
    #[serde(rename = "type")]
    pub certificate_type: Option<String>,

    pub primary: Option<bool>,
}

/// SCIM Filter Query DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ScimFilterQuery {
    #[validate(length(max = 500), custom(function = "validate_scim_filter"))]
    pub filter: Option<String>,

    #[validate(length(max = 255))]
    pub attributes: Option<String>,

    #[validate(length(max = 255))]
    pub excluded_attributes: Option<String>,

    #[validate(range(min = 1, max = 1000))]
    pub count: Option<usize>,

    #[validate(range(min = 1))]
    pub start_index: Option<usize>,

    #[validate(length(max = 100))]
    pub sort_by: Option<String>,

    #[validate(length(max = 10))]
    pub sort_order: Option<String>,
}

/// OIDC ID Token Claims DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct OidcIdTokenClaims {
    #[validate(length(max = 255))]
    pub iss: String,

    #[validate(length(max = 255))]
    pub sub: String,

    #[validate(length(max = 255))]
    pub aud: String,

    pub exp: i64,
    pub iat: i64,

    #[validate(length(max = 128))]
    pub nonce: Option<String>,

    #[validate(length(max = 128))]
    pub at_hash: Option<String>,

    #[validate(length(max = 128))]
    pub c_hash: Option<String>,

    #[validate(email, length(max = 320))]
    pub email: Option<String>,

    pub email_verified: Option<bool>,

    #[validate(length(max = 255))]
    pub name: Option<String>,

    #[validate(length(max = 100))]
    pub given_name: Option<String>,

    #[validate(length(max = 100))]
    pub family_name: Option<String>,

    #[validate(url, length(max = 2048))]
    pub picture: Option<String>,

    #[validate(length(max = 10))]
    pub locale: Option<String>,
}

/// MFA Challenge Request DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct MfaChallengeRequest {
    #[validate(length(min = 1, max = 255))]
    pub user_id: String,

    #[validate(length(max = 50))]
    pub challenge_type: String,

    #[validate(length(max = 2048))]
    pub context: Option<String>,
}

/// MFA Verification Request DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct MfaVerificationRequest {
    #[validate(length(min = 1, max = 255))]
    pub challenge_id: String,

    #[validate(length(min = 1, max = 20))]
    pub code: String,

    #[validate(length(max = 2048))]
    pub backup_code: Option<String>,
}

/// Token Introspection Request DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct TokenIntrospectionRequest {
    #[validate(length(min = 1, max = 2048))]
    pub token: String,

    #[validate(length(max = 50))]
    pub token_type_hint: Option<String>,

    #[validate(length(max = 255))]
    pub client_id: Option<String>,

    #[validate(length(max = 128))]
    pub client_secret: Option<String>,
}

/// Session Creation Request DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct SessionCreateRequest {
    #[validate(length(min = 1, max = 255))]
    pub user_id: String,

    #[validate(length(max = 255))]
    pub client_id: Option<String>,

    #[validate(range(min = 60, max = 86400))] // 1 minute to 24 hours
    pub duration: Option<u64>,

    #[validate(length(max = 1000))]
    pub scope: Option<String>,
}

/// Key Rotation Request DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct KeyRotationRequest {
    #[validate(length(max = 255))]
    pub key_id: Option<String>,

    #[validate(length(max = 50))]
    pub algorithm: Option<String>,

    #[validate(range(min = 2048, max = 4096))]
    pub key_size: Option<u32>,

    pub force: Option<bool>,
}

/// CORS Configuration DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CorsConfig {
    #[validate(nested)]
    pub allowed_origins: Vec<AllowedOrigin>,

    #[validate(length(max = 100))]
    pub allowed_methods: Vec<String>,

    #[validate(length(max = 100))]
    pub allowed_headers: Vec<String>,

    #[validate(length(max = 100))]
    pub exposed_headers: Vec<String>,

    #[validate(range(max = 86400))] // Max 24 hours
    pub max_age: Option<u64>,

    pub allow_credentials: bool,
}

/// Allowed Origin DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct AllowedOrigin {
    #[validate(length(max = 2048), custom(function = "validate_origin"))]
    pub origin: String,

    pub exact_match: bool,
}

/// Rate Limit Configuration DTO
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct RateLimitConfig {
    #[validate(range(min = 1, max = 10000))]
    pub requests_per_window: u32,

    #[validate(range(min = 1, max = 3600))]
    pub window_duration_secs: u32,

    #[validate(range(min = 0, max = 1000))]
    pub burst_allowance: u32,

    #[validate(range(min = 60, max = 86400))]
    pub cleanup_interval_secs: u32,
}

// Custom validation functions

/// Validate `OAuth` 2.0 scope parameter
fn validate_scope(scope: &str) -> Result<(), ValidationError> {
    // Check for valid scope format (space-separated tokens)
    if scope.is_empty() {
        return Err(validation_error("scope_empty"));
    }

    let scopes: Vec<&str> = scope.split_whitespace().collect();
    if scopes.is_empty() {
        return Err(validation_error("scope_invalid"));
    }

    // Validate each scope token
    for scope_token in scopes {
        if scope_token.is_empty() {
            return Err(validation_error("scope_token_empty"));
        }

        // Scope tokens should not contain certain characters
        if scope_token.contains(['\"', '\\', '\r', '\n', '\t']) {
            return Err(validation_error("scope_token_invalid_chars"));
        }

        if scope_token.len() > 100 {
            return Err(validation_error("scope_token_too_long"));
        }
    }

    Ok(())
}

/// Validate SCIM filter expression
fn validate_scim_filter(filter: &str) -> Result<(), ValidationError> {
    if filter.is_empty() {
        return Ok(());
    }

    // Basic SCIM filter validation
    // Check for balanced parentheses
    let mut paren_count = 0;
    for char in filter.chars() {
        match char {
            '(' => paren_count += 1,
            ')' => {
                paren_count -= 1;
                if paren_count < 0 {
                    return Err(validation_error("scim_filter_unbalanced_parens"));
                }
            }
            _ => {}
        }
    }

    if paren_count != 0 {
        return Err(validation_error("scim_filter_unbalanced_parens"));
    }

    // Check for SQL injection patterns
    let filter_lower = filter.to_lowercase();
    let sql_patterns = [
        "drop ", "delete ", "insert ", "update ", "create ", "alter ", "exec", "union", "script",
        "--", "/*", "*/", ";",
    ];

    for pattern in &sql_patterns {
        if filter_lower.contains(pattern) {
            return Err(validation_error("scim_filter_sql_injection"));
        }
    }

    // Check for XSS patterns
    let xss_patterns = ["<script", "javascript:", "onload=", "onerror="];
    for pattern in &xss_patterns {
        if filter_lower.contains(pattern) {
            return Err(validation_error("scim_filter_xss_attempt"));
        }
    }

    Ok(())
}

/// Validate phone number format
fn validate_phone_number(phone: &str) -> Result<(), ValidationError> {
    // Basic phone number validation
    if phone.is_empty() {
        return Err(validation_error("phone_empty"));
    }

    // Allow digits, spaces, hyphens, parentheses, and + for international format
    if !phone
        .chars()
        .all(|c| c.is_ascii_digit() || " -+()".contains(c))
    {
        return Err(validation_error("phone_invalid_chars"));
    }

    // Must contain at least some digits
    if !phone.chars().any(|c| c.is_ascii_digit()) {
        return Err(validation_error("phone_no_digits"));
    }

    Ok(())
}

/// Validate CORS origin
fn validate_origin(origin: &str) -> Result<(), ValidationError> {
    if origin == "*" {
        return Ok(()); // Wildcard is allowed
    }

    // Must be a valid URL or localhost
    if origin.starts_with("http://") || origin.starts_with("https://") {
        // Basic URL validation
        if url::Url::parse(origin).is_err() {
            return Err(validation_error("origin_invalid_url"));
        }
    } else if origin.starts_with("localhost:") || origin == "localhost" {
        // Allow localhost variations
        return Ok(());
    } else {
        return Err(validation_error("origin_invalid_format"));
    }

    Ok(())
}

/// Validate password strength
fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    let validator = PasswordValidator::new(password);
    
    validator.check_length()
            .check_character_types()
            .check_common_patterns()
            .check_sequential_chars()
            .finalize()
}

/// Helper struct for password validation with scoring
struct PasswordValidator<'a> {
    password: &'a str,
    score: u8,
    errors: Vec<&'static str>,
}

impl<'a> PasswordValidator<'a> {
    const MIN_SCORE: u8 = 4;
    const SPECIAL_CHARS: &'static str = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    
    fn new(password: &'a str) -> Self {
        Self {
            password,
            score: 0,
            errors: Vec::new(),
        }
    }

    fn check_length(mut self) -> Self {
        if self.password.len() < 12 {
            self.errors.push("Password must be at least 12 characters long");
        } else {
            self.score += 1;
        }
        self
    }

    fn check_character_types(self) -> Self {
        self.check_character_type(
            char::is_uppercase,
            "Password must contain at least one uppercase letter",
        )
        .check_character_type(
            char::is_lowercase,
            "Password must contain at least one lowercase letter",
        )
        .check_character_type(
            char::is_numeric,
            "Password must contain at least one digit",
        )
        .check_special_characters()
    }

    fn check_character_type(
        mut self,
        predicate: fn(char) -> bool,
        error_message: &'static str,
    ) -> Self {
        if self.password.chars().any(predicate) {
            self.score += 1;
        } else {
            self.errors.push(error_message);
        }
        self
    }

    fn check_special_characters(mut self) -> Self {
        if self.password.chars().any(|c| Self::SPECIAL_CHARS.contains(c)) {
            self.score += 1;
        } else {
            self.errors.push("Password must contain at least one special character");
        }
        self
    }

    fn check_common_patterns(mut self) -> Self {
        const COMMON_PATTERNS: &[&str] = &[
            "password", "123456", "qwerty", "admin", "root", 
            "user", "letmein", "welcome", "monkey", "dragon",
        ];

        let lowercase_password = self.password.to_lowercase();
        if COMMON_PATTERNS.iter().any(|&pattern| lowercase_password.contains(pattern)) {
            self.errors.push("Password contains common patterns and is not secure");
        }
        self
    }

    fn check_sequential_chars(mut self) -> Self {
        if has_sequential_chars(self.password) {
            self.errors.push("Password contains sequential characters");
        }
        self
    }

    fn finalize(self) -> Result<(), ValidationError> {
        if self.score < Self::MIN_SCORE || !self.errors.is_empty() {
            Err(validation_error("password_too_weak"))
        } else {
            Ok(())
        }
    }
}

/// Check for sequential characters (3 or more in a row)
fn has_sequential_chars(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();

    for window in chars.windows(3) {
        // Check for ascending sequence
        if window[0] as u8 + 1 == window[1] as u8 && window[1] as u8 + 1 == window[2] as u8 {
            return true;
        }
        // Check for descending sequence
        if window[0] as u8 == window[1] as u8 + 1 && window[1] as u8 == window[2] as u8 + 1 {
            return true;
        }
    }

    false
}

/// Validation result wrapper
#[derive(Debug, Serialize, ToSchema)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Option<HashMap<String, Vec<String>>>,
}

impl From<ValidationErrors> for ValidationResult {
    fn from(errors: ValidationErrors) -> Self {
        let mut error_map = HashMap::new();

        for (field, field_errors) in errors.field_errors() {
            let mut error_messages = Vec::new();
            for error in field_errors {
                let message = match error.code.as_ref() {
                    "length" => "Invalid length",
                    "range" => "Value out of range",
                    "email" => "Invalid email format",
                    "url" => "Invalid URL format",
                    "scope_empty" => "Scope cannot be empty",
                    "scope_invalid" => "Invalid scope format",
                    "scope_token_empty" => "Scope token cannot be empty",
                    "scope_token_invalid_chars" => "Scope token contains invalid characters",
                    "scope_token_too_long" => "Scope token too long",
                    "scim_filter_unbalanced_parens" => "SCIM filter has unbalanced parentheses",
                    "scim_filter_sql_injection" => "SCIM filter contains potential SQL injection",
                    "scim_filter_xss_attempt" => "SCIM filter contains potential XSS",
                    "phone_empty" => "Phone number cannot be empty",
                    "phone_invalid_chars" => "Phone number contains invalid characters",
                    "phone_no_digits" => "Phone number must contain digits",
                    "origin_invalid_url" => "Invalid origin URL",
                    "origin_invalid_format" => "Invalid origin format",
                    _ => "Invalid value",
                };
                error_messages.push(message.to_string());
            }
            error_map.insert(field.to_string(), error_messages);
        }

        Self {
            valid: false,
            errors: Some(error_map),
        }
    }
}

/// Trait for validating DTOs
pub trait ValidatedDto: Validate + Sized {
    /// Validate the DTO and return a structured result
    fn validate_dto(&self) -> ValidationResult {
        match self.validate() {
            Ok(()) => ValidationResult {
                valid: true,
                errors: None,
            },
            Err(errors) => errors.into(),
        }
    }

    /// Validate and return the DTO or an error
    ///
    /// # Errors
    ///
    /// Returns a `ValidationResult` containing validation errors if the DTO fails validation
    fn validate_and_return(self) -> Result<Self, ValidationResult> {
        let result = self.validate_dto();
        if result.valid {
            Ok(self)
        } else {
            Err(result)
        }
    }
}

// Implement ValidatedDto for all our DTOs
impl ValidatedDto for TokenRequest {}
impl ValidatedDto for AuthorizationRequest {}
impl ValidatedDto for ScimUser {}
impl ValidatedDto for ScimFilterQuery {}
impl ValidatedDto for OidcIdTokenClaims {}
impl ValidatedDto for MfaChallengeRequest {}
impl ValidatedDto for MfaVerificationRequest {}
impl ValidatedDto for TokenIntrospectionRequest {}
impl ValidatedDto for SessionCreateRequest {}
impl ValidatedDto for KeyRotationRequest {}
impl ValidatedDto for CorsConfig {}
impl ValidatedDto for RateLimitConfig {}

/// Validation middleware for Axum extractors
pub mod middleware {
    use super::{Deserialize, ValidatedDto};
    use crate::errors::{validation_error, AuthError};
    use axum::{extract::FromRequest, http::Request};

    /// Validated JSON extractor that automatically validates DTOs
    pub struct ValidatedJson<T>(pub T);

    #[axum::async_trait]
    impl<T, S> FromRequest<S> for ValidatedJson<T>
    where
        T: ValidatedDto + for<'de> Deserialize<'de>,
        S: Send + Sync,
    {
        type Rejection = AuthError;

        async fn from_request(
            req: Request<axum::body::Body>,
            state: &S,
        ) -> Result<Self, Self::Rejection> {
            let axum::Json(dto) = axum::Json::<T>::from_request(req, state)
                .await
                .map_err(|_| validation_error("json", "Invalid JSON format"))?;

            match dto.validate_and_return() {
                Ok(validated_dto) => Ok(Self(validated_dto)),
                Err(validation_result) => {
                    let field_errors = validation_result.errors.unwrap_or_default();
                    let error_msg = field_errors
                        .iter()
                        .map(|(field, errors)| {
                            format!("{field}: {joined}", joined = errors.join(", "))
                        })
                        .collect::<Vec<_>>()
                        .join("; ");

                    Err(validation_error("validation", &error_msg))
                }
            }
        }
    }

    /// Validated Query extractor that automatically validates DTOs
    pub struct ValidatedQuery<T>(pub T);

    #[axum::async_trait]
    impl<T, S> FromRequest<S> for ValidatedQuery<T>
    where
        T: ValidatedDto + for<'de> Deserialize<'de>,
        S: Send + Sync,
    {
        type Rejection = AuthError;

        async fn from_request(
            req: Request<axum::body::Body>,
            state: &S,
        ) -> Result<Self, Self::Rejection> {
            let axum::extract::Query(dto) = axum::extract::Query::<T>::from_request(req, state)
                .await
                .map_err(|_| validation_error("query", "Invalid query parameters"))?;

            match dto.validate_and_return() {
                Ok(validated_dto) => Ok(Self(validated_dto)),
                Err(validation_result) => {
                    let field_errors = validation_result.errors.unwrap_or_default();
                    let error_msg = field_errors
                        .iter()
                        .map(|(field, errors)| {
                            format!("{field}: {joined}", joined = errors.join(", "))
                        })
                        .collect::<Vec<_>>()
                        .join("; ");

                    Err(validation_error("validation", &error_msg))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_request_validation() {
        let mut request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            client_id: Some("test_client".to_string()),
            client_secret: Some("test_secret".to_string()),
            code: Some("auth_code_123".to_string()),
            redirect_uri: Some("https://example.com/callback".to_string()),
            refresh_token: None,
            scope: Some("read write".to_string()),
            code_verifier: None,
            username: None,
            password: None,
        };

        assert!(request.validate_dto().valid);

        // Test invalid grant type (too long)
        request.grant_type = "a".repeat(100);
        assert!(!request.validate_dto().valid);
    }

    #[test]
    fn test_scope_validation() {
        assert!(validate_scope("read").is_ok());
        assert!(validate_scope("read write").is_ok());
        assert!(validate_scope("").is_err());
        assert!(validate_scope("read\nwrite").is_err());
        assert!(validate_scope(&"a".repeat(101)).is_err());
    }

    #[test]
    fn test_scim_filter_validation() {
        assert!(validate_scim_filter("").is_ok());
        assert!(validate_scim_filter("userName eq \"john\"").is_ok());
        assert!(validate_scim_filter("(userName eq \"john\")").is_ok());

        // Test unbalanced parentheses
        assert!(validate_scim_filter("(userName eq \"john\"").is_err());
        assert!(validate_scim_filter("userName eq \"john\")").is_err());

        // Test SQL injection
        assert!(validate_scim_filter("userName eq \"john\"; DROP TABLE users").is_err());

        // Test XSS
        assert!(validate_scim_filter("userName eq \"<script>alert('xss')</script>\"").is_err());
    }

    #[test]
    fn test_phone_validation() {
        assert!(validate_phone_number("+1-555-123-4567").is_ok());
        assert!(validate_phone_number("(555) 123-4567").is_ok());
        assert!(validate_phone_number("5551234567").is_ok());

        assert!(validate_phone_number("").is_err());
        assert!(validate_phone_number("invalid-phone").is_err());
        assert!(validate_phone_number("abc-def-ghij").is_err());
    }

    #[test]
    fn test_origin_validation() {
        assert!(validate_origin("*").is_ok());
        assert!(validate_origin("https://example.com").is_ok());
        assert!(validate_origin("http://localhost:3000").is_ok());
        assert!(validate_origin("localhost").is_ok());

        assert!(validate_origin("invalid-origin").is_err());
        assert!(validate_origin("ftp://example.com").is_err());
    }

    #[test]
    fn test_scim_user_validation() {
        let user = ScimUser {
            id: None,
            external_id: None,
            user_name: "john.doe".to_string(),
            name: Some(ScimName {
                formatted: Some("John Doe".to_string()),
                family_name: Some("Doe".to_string()),
                given_name: Some("John".to_string()),
                middle_name: None,
                honorific_prefix: None,
                honorific_suffix: None,
            }),
            display_name: Some("John Doe".to_string()),
            nick_name: None,
            profile_url: Some("https://example.com/john".to_string()),
            title: None,
            user_type: None,
            preferred_language: None,
            locale: None,
            timezone: None,
            active: Some(true),
            emails: Some(vec![ScimEmail {
                value: "john.doe@example.com".to_string(),
                email_type: Some("work".to_string()),
                primary: Some(true),
                display: None,
            }]),
            phone_numbers: Some(vec![ScimPhoneNumber {
                value: "+1-555-123-4567".to_string(),
                phone_type: Some("work".to_string()),
                primary: Some(true),
                display: None,
            }]),
            addresses: None,
            groups: None,
            roles: None,
            entitlements: None,
            x509_certificates: None,
        };

        assert!(user.validate_dto().valid);
    }
}
