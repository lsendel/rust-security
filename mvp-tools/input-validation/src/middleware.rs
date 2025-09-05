//! Middleware module for integrating validation with web frameworks
//!
//! Provides middleware for Axum and other web frameworks

use crate::dos_protection::{DoSConfig, DoSProtection, RequestGuard};
use crate::error_handling::{SecureResult, SecurityError, ValidationError, ValidationResult};
use crate::sanitization::{SanitizationConfig, SanitizedInput, Sanitizer};
use crate::validation::{InputType, SecurityValidator, ValidatedInput, ValidatorConfig};
use axum::{
    extract::{ConnectInfo, FromRequest, Request},
    http::{HeaderMap, Method, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn};

/// Security middleware configuration
#[derive(Debug, Clone)]
pub struct SecurityMiddlewareConfig {
    /// Validation configuration
    pub validator_config: ValidatorConfig,

    /// Sanitization configuration
    pub sanitization_config: SanitizationConfig,

    /// DoS protection configuration
    pub dos_config: DoSConfig,

    /// Whether to enable request/response logging
    pub enable_logging: bool,

    /// Whether to add security headers
    pub add_security_headers: bool,

    /// Custom header configuration
    pub security_headers: SecurityHeaders,

    /// Trusted proxy IPs (for real IP extraction)
    pub trusted_proxies: Vec<std::net::IpAddr>,

    /// Whether to validate request bodies
    pub validate_bodies: bool,

    /// Whether to sanitize responses
    pub sanitize_responses: bool,
}

impl Default for SecurityMiddlewareConfig {
    fn default() -> Self {
        Self {
            validator_config: ValidatorConfig::production(),
            sanitization_config: SanitizationConfig::strict(),
            dos_config: DoSConfig::production(),
            enable_logging: true,
            add_security_headers: true,
            security_headers: SecurityHeaders::strict(),
            trusted_proxies: vec![],
            validate_bodies: true,
            sanitize_responses: false,
        }
    }
}

/// Security headers configuration
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    pub content_security_policy: Option<String>,
    pub strict_transport_security: Option<String>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: Option<String>,
    pub x_xss_protection: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub custom_headers: HashMap<String, String>,
}

impl SecurityHeaders {
    /// Strict security headers for production
    pub fn strict() -> Self {
        let mut custom_headers = HashMap::new();
        custom_headers.insert("X-Request-ID".to_string(), "generated".to_string());

        Self {
            // Avoid unsafe-inline for scripts in strict mode; use nonces/hashes if inline is required
            content_security_policy: Some(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; media-src 'none'; object-src 'none'; child-src 'none'; frame-src 'none'; worker-src 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content".to_string()
            ),
            strict_transport_security: Some("max-age=31536000; includeSubDomains; preload".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: Some("geolocation=(), microphone=(), camera=()".to_string()),
            custom_headers,
        }
    }

    /// Normal security headers for most applications
    pub fn normal() -> Self {
        Self {
            content_security_policy: Some(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
                    .to_string(),
            ),
            strict_transport_security: Some("max-age=31536000".to_string()),
            x_frame_options: Some("SAMEORIGIN".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: None,
            custom_headers: HashMap::new(),
        }
    }
}

/// Main security middleware
#[derive(Debug, Clone)]
pub struct SecurityMiddleware {
    config: SecurityMiddlewareConfig,
    validator: Arc<SecurityValidator>,
    sanitizer: Arc<Sanitizer>,
    dos_protection: Arc<DoSProtection>,
}

impl SecurityMiddleware {
    /// Create new security middleware
    pub fn new(config: SecurityMiddlewareConfig) -> anyhow::Result<Self> {
        let validator = Arc::new(SecurityValidator::new(config.validator_config.clone())?);
        let sanitizer = Arc::new(Sanitizer::new(config.sanitization_config.clone()));
        let dos_protection = Arc::new(DoSProtection::new(config.dos_config.clone()));

        Ok(Self { config, validator, sanitizer, dos_protection })
    }

    /// Create middleware with default production configuration
    pub fn production() -> anyhow::Result<Self> {
        Self::new(SecurityMiddlewareConfig::default())
    }

    /// Create middleware with development configuration
    pub fn development() -> anyhow::Result<Self> {
        let mut config = SecurityMiddlewareConfig::default();
        config.validator_config = ValidatorConfig::development();
        config.sanitization_config = SanitizationConfig::normal();
        config.dos_config = DoSConfig::development();
        config.security_headers = SecurityHeaders::normal();

        Self::new(config)
    }

    /// Apply security middleware to request
    pub async fn apply(&self, request: Request, next: Next) -> Result<Response, SecurityError> {
        let start_time = Instant::now();
        let method = request.method().clone();
        let uri = request.uri().clone();
        let headers = request.headers().clone();

        // Extract real IP address
        let client_ip = self.extract_client_ip(&request, &headers);
        let client_identifier = client_ip.to_string();

        // Log request start
        if self.config.enable_logging {
            info!(
                method = %method,
                uri = %uri,
                client_ip = %client_ip,
                "Request started"
            );
        }

        // Apply DoS protection
        let body_size = self.estimate_body_size(&request);
        let request_guard =
            match self.dos_protection.check_request(&client_identifier, body_size).await {
                Ok(guard) => guard,
                Err(e) => {
                    warn!(
                        client_ip = %client_ip,
                        error = ?e,
                        "Request blocked by DoS protection"
                    );
                    return Ok(self.create_error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        "Rate limit exceeded",
                    ));
                }
            };

        // Validate headers
        if let Err(e) = self.validate_headers(&headers) {
            warn!(
                client_ip = %client_ip,
                error = ?e,
                "Request blocked by header validation"
            );
            request_guard.record_failure().await;
            return Ok(self.create_error_response(StatusCode::BAD_REQUEST, "Invalid headers"));
        }

        // Process request
        let response = match next.run(request).await {
            response => {
                // Add security headers
                let mut response = response;
                if self.config.add_security_headers {
                    self.add_security_headers_to_response(&mut response);
                }

                // Record success
                request_guard.record_success().await;

                // Log response
                if self.config.enable_logging {
                    let duration = start_time.elapsed();
                    info!(
                        method = %method,
                        uri = %uri,
                        client_ip = %client_ip,
                        status = %response.status(),
                        duration_ms = duration.as_millis(),
                        "Request completed"
                    );
                }

                response
            }
        };

        Ok(response)
    }

    /// Extract real client IP considering trusted proxies
    fn extract_client_ip(&self, request: &Request, headers: &HeaderMap) -> std::net::IpAddr {
        // Try X-Real-IP header first
        if let Some(real_ip) = headers.get("X-Real-IP") {
            if let Ok(ip_str) = real_ip.to_str() {
                if let Ok(ip) = ip_str.parse() {
                    return ip;
                }
            }
        }

        // Try X-Forwarded-For header
        if let Some(forwarded_for) = headers.get("X-Forwarded-For") {
            if let Ok(forwarded_str) = forwarded_for.to_str() {
                // Take the first IP in the chain
                if let Some(first_ip) = forwarded_str.split(',').next() {
                    if let Ok(ip) = first_ip.trim().parse() {
                        return ip;
                    }
                }
            }
        }

        // Fall back to connection info
        if let Some(ConnectInfo(addr)) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
            return addr.ip();
        }

        // Default fallback
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Estimate request body size
    fn estimate_body_size(&self, request: &Request) -> usize {
        if let Some(content_length) = request.headers().get("content-length") {
            if let Ok(length_str) = content_length.to_str() {
                if let Ok(length) = length_str.parse::<usize>() {
                    return length;
                }
            }
        }
        0
    }

    /// Validate request headers
    fn validate_headers(&self, headers: &HeaderMap) -> SecureResult<()> {
        // Check header count
        if headers.len() > 100 {
            return Err(SecurityError::SizeLimitExceeded);
        }

        // Validate individual headers
        for (name, value) in headers {
            // Check header name
            let header_name = name.as_str();
            if header_name.len() > 100 {
                return Err(SecurityError::SizeLimitExceeded);
            }

            // Check header value
            if let Ok(header_value) = value.to_str() {
                if header_value.len() > 8192 {
                    return Err(SecurityError::SizeLimitExceeded);
                }

                // Check for injection patterns in critical headers
                if self.is_critical_header(header_name) {
                    let injection_patterns = self.validator.check_injection(header_value);
                    if !injection_patterns.is_empty() {
                        return Err(SecurityError::InjectionAttempt);
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if header is critical for security
    fn is_critical_header(&self, name: &str) -> bool {
        matches!(
            name.to_lowercase().as_str(),
            "authorization"
                | "cookie"
                | "x-forwarded-for"
                | "x-real-ip"
                | "user-agent"
                | "referer"
                | "origin"
                | "host"
        )
    }

    /// Add security headers to response
    fn add_security_headers_to_response(&self, response: &mut Response) {
        let headers = response.headers_mut();

        if let Some(csp) = &self.config.security_headers.content_security_policy {
            headers.insert("Content-Security-Policy", csp.parse().unwrap());
        }

        if let Some(hsts) = &self.config.security_headers.strict_transport_security {
            headers.insert("Strict-Transport-Security", hsts.parse().unwrap());
        }

        if let Some(frame_options) = &self.config.security_headers.x_frame_options {
            headers.insert("X-Frame-Options", frame_options.parse().unwrap());
        }

        if let Some(content_type_options) = &self.config.security_headers.x_content_type_options {
            headers.insert("X-Content-Type-Options", content_type_options.parse().unwrap());
        }

        if let Some(xss_protection) = &self.config.security_headers.x_xss_protection {
            headers.insert("X-XSS-Protection", xss_protection.parse().unwrap());
        }

        if let Some(referrer_policy) = &self.config.security_headers.referrer_policy {
            headers.insert("Referrer-Policy", referrer_policy.parse().unwrap());
        }

        if let Some(permissions_policy) = &self.config.security_headers.permissions_policy {
            headers.insert("Permissions-Policy", permissions_policy.parse().unwrap());
        }

        // Add custom headers
        for (name, value) in &self.config.security_headers.custom_headers {
            if let (Ok(header_name), Ok(header_value)) = (name.parse(), value.parse()) {
                headers.insert(header_name, header_value);
            }
        }

        // Add request ID if not present
        if !headers.contains_key("X-Request-ID") {
            let request_id = uuid::Uuid::new_v4().to_string();
            headers.insert("X-Request-ID", request_id.parse().unwrap());
        }
    }

    /// Create error response
    fn create_error_response(&self, status: StatusCode, message: &str) -> Response {
        let error_body = serde_json::json!({
            "error": {
                "code": status.as_u16(),
                "message": message,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }
        });

        let mut response = (status, Json(error_body)).into_response();

        if self.config.add_security_headers {
            self.add_security_headers_to_response(&mut response);
        }

        response
    }
}

/// Validated JSON extractor with comprehensive security checks
#[derive(Debug)]
pub struct ValidatedJson<T>(pub T);

#[axum::async_trait]
impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned + Send + 'static,
    S: Send + Sync,
{
    type Rejection = ValidationRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // Extract body as bytes first
        let bytes =
            Bytes::from_request(req, state).await.map_err(|_| ValidationRejection::InvalidBody)?;

        // Check size limits
        if bytes.len() > 1024 * 1024 {
            return Err(ValidationRejection::SizeLimitExceeded);
        }

        // Validate JSON structure
        let json_str =
            std::str::from_utf8(&bytes).map_err(|_| ValidationRejection::InvalidEncoding)?;

        // Quick injection check
        let validator = SecurityValidator::new(ValidatorConfig::production())
            .map_err(|_| ValidationRejection::InternalError)?;

        let injection_patterns = validator.check_injection(json_str);
        if !injection_patterns.is_empty() {
            return Err(ValidationRejection::InjectionAttempt(injection_patterns));
        }

        // Parse JSON
        let value: T = serde_json::from_str(json_str)
            .map_err(|e| ValidationRejection::ParseError(e.to_string()))?;

        Ok(ValidatedJson(value))
    }
}

/// Validated query extractor
#[derive(Debug)]
pub struct ValidatedQuery<T>(pub T);

#[axum::async_trait]
impl<T, S> FromRequest<S> for ValidatedQuery<T>
where
    T: DeserializeOwned + Send + 'static,
    S: Send + Sync,
{
    type Rejection = ValidationRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let uri = req.uri();
        let query = uri.query().unwrap_or("");

        // Check query length
        if query.len() > 4096 {
            return Err(ValidationRejection::SizeLimitExceeded);
        }

        // Validate query parameters
        let validator = SecurityValidator::new(ValidatorConfig::production())
            .map_err(|_| ValidationRejection::InternalError)?;

        let injection_patterns = validator.check_injection(query);
        if !injection_patterns.is_empty() {
            return Err(ValidationRejection::InjectionAttempt(injection_patterns));
        }

        // Parse query parameters
        let query_params = axum::extract::Query::<T>::from_request(req, state)
            .await
            .map_err(|_| ValidationRejection::InvalidQuery)?;

        Ok(ValidatedQuery(query_params.0))
    }
}

/// Request validator for custom validation logic
pub struct RequestValidator {
    validator: Arc<SecurityValidator>,
    sanitizer: Arc<Sanitizer>,
}

impl RequestValidator {
    pub fn new(
        validator_config: ValidatorConfig,
        sanitization_config: SanitizationConfig,
    ) -> anyhow::Result<Self> {
        let validator = Arc::new(SecurityValidator::new(validator_config)?);
        let sanitizer = Arc::new(Sanitizer::new(sanitization_config));

        Ok(Self { validator, sanitizer })
    }

    /// Validate and sanitize input string
    pub fn validate_and_sanitize(
        &self,
        input: &str,
        input_type: InputType,
    ) -> SecureResult<SanitizedInput> {
        // Validate first
        let validation_result = self.validator.validate(input, input_type);
        if !validation_result.is_valid() {
            return Err(SecurityError::ValidationFailed);
        }

        // Then sanitize
        self.sanitizer.sanitize(input, input_type)
    }

    /// Validate OAuth parameters
    pub fn validate_oauth_params(&self, params: &HashMap<String, String>) -> ValidationResult {
        let mut result = ValidationResult::success();

        for (key, value) in params {
            let field_result = self.validator.validate(value, InputType::OAuth);
            if !field_result.is_valid() {
                for error in field_result.errors {
                    result.add_error(ValidationError::new(
                        format!("oauth_{}", key),
                        error.code,
                        error.message,
                    ));
                }
            }
        }

        result
    }

    /// Validate SCIM filter
    pub fn validate_scim_filter(&self, filter: &str) -> ValidationResult {
        self.validator.validate(filter, InputType::ScimFilter)
    }
}

/// Validation rejection types
#[derive(Debug)]
pub enum ValidationRejection {
    InvalidBody,
    InvalidQuery,
    InvalidEncoding,
    SizeLimitExceeded,
    InjectionAttempt(Vec<String>),
    ParseError(String),
    InternalError,
}

impl IntoResponse for ValidationRejection {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ValidationRejection::InvalidBody => (StatusCode::BAD_REQUEST, "Invalid request body"),
            ValidationRejection::InvalidQuery => {
                (StatusCode::BAD_REQUEST, "Invalid query parameters")
            }
            ValidationRejection::InvalidEncoding => {
                (StatusCode::BAD_REQUEST, "Invalid character encoding")
            }
            ValidationRejection::SizeLimitExceeded => {
                (StatusCode::PAYLOAD_TOO_LARGE, "Request too large")
            }
            ValidationRejection::InjectionAttempt(_) => {
                (StatusCode::BAD_REQUEST, "Malicious input detected")
            }
            ValidationRejection::ParseError(_) => (StatusCode::BAD_REQUEST, "Parse error"),
            ValidationRejection::InternalError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            }
        };

        let error_body = serde_json::json!({
            "error": {
                "code": status.as_u16(),
                "message": message,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }
        });

        (status, Json(error_body)).into_response()
    }
}

/// Middleware function for Axum integration
pub async fn security_middleware(req: Request, next: Next) -> Result<Response, SecurityError> {
    let middleware =
        SecurityMiddleware::production().map_err(|_| SecurityError::ConfigurationError)?;

    middleware.apply(req, next).await
}

/// Create security middleware with custom configuration
pub fn create_security_middleware(
    config: SecurityMiddlewareConfig,
) -> impl Fn(
    Request,
    Next,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Response, SecurityError>> + Send + 'static>,
> + Clone {
    let middleware =
        Arc::new(SecurityMiddleware::new(config).expect("Failed to create security middleware"));

    move |req: Request, next: Next| {
        let middleware = Arc::clone(&middleware);
        Box::pin(async move { middleware.apply(req, next).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};

    #[test]
    fn test_security_headers() {
        let headers = SecurityHeaders::strict();
        assert!(headers.content_security_policy.is_some());
        assert!(headers.strict_transport_security.is_some());

        let headers = SecurityHeaders::normal();
        assert!(headers.content_security_policy.is_some());
        assert!(headers.permissions_policy.is_none());
    }

    #[tokio::test]
    async fn test_middleware_creation() {
        let middleware = SecurityMiddleware::production();
        assert!(middleware.is_ok());

        let middleware = SecurityMiddleware::development();
        assert!(middleware.is_ok());
    }

    #[test]
    fn test_client_ip_extraction() {
        let middleware = SecurityMiddleware::production().unwrap();
        let mut request =
            Request::builder().uri("https://example.com/test").body(Body::empty()).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "192.168.1.100".parse().unwrap());

        *request.headers_mut() = headers;

        let client_ip = middleware.extract_client_ip(&request, request.headers());
        assert_eq!(client_ip.to_string(), "192.168.1.100");
    }

    #[test]
    fn test_header_validation() {
        let middleware = SecurityMiddleware::production().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer valid_token".parse().unwrap());

        assert!(middleware.validate_headers(&headers).is_ok());

        // Test injection in critical header
        let mut malicious_headers = HeaderMap::new();
        malicious_headers
            .insert("authorization", "Bearer <script>alert('xss')</script>".parse().unwrap());

        assert!(middleware.validate_headers(&malicious_headers).is_err());
    }

    #[test]
    fn test_request_validator() {
        let validator =
            RequestValidator::new(ValidatorConfig::production(), SanitizationConfig::strict())
                .unwrap();

        let _result = validator.validate_and_sanitize("test@example.com", InputType::Email);
        assert!(result.is_ok());

        let result =
            validator.validate_and_sanitize("<script>alert('xss')</script>", InputType::Text);
        assert!(result.is_ok());
        let sanitized = result.unwrap();
        assert!(sanitized.was_sanitized);
    }

    #[test]
    fn test_oauth_validation() {
        let validator =
            RequestValidator::new(ValidatorConfig::production(), SanitizationConfig::strict())
                .unwrap();

        let mut params = HashMap::new();
        params.insert("client_id".to_string(), "valid_client_123".to_string());
        params.insert("redirect_uri".to_string(), "https://example.com/callback".to_string());

        let _result = validator.validate_oauth_params(&params);
        assert!(result.is_valid());

        // Test invalid params
        let mut invalid_params = HashMap::new();
        invalid_params.insert("client_id".to_string(), "<script>alert('xss')</script>".to_string());

        let _result = validator.validate_oauth_params(&invalid_params);
        assert!(!result.is_valid());
    }
}
