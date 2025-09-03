#![allow(clippy::unused_async)]
//! Enhanced Security Middleware
//!
//! Comprehensive security middleware with CSRF protection, advanced rate limiting,
//! input validation, and security headers enforcement.

use crate::services::constant_time_compare;
use axum::{
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

/// Configuration for enhanced security middleware
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Enable CSRF protection
    pub csrf_enabled: bool,
    /// CSRF token header name
    pub csrf_header: String,
    /// CSRF token cookie name
    pub csrf_cookie: String,
    /// CSRF token TTL
    pub csrf_ttl: Duration,
    /// Rate limiting enabled
    pub rate_limiting_enabled: bool,
    /// Rate limit per window
    pub rate_limit_requests: u32,
    /// Rate limit window duration
    pub rate_limit_window: Duration,
    /// Input validation enabled
    pub input_validation_enabled: bool,
    /// Maximum request body size
    pub max_body_size: usize,
    /// Security headers enabled
    pub security_headers_enabled: bool,
    /// Content Security Policy
    pub csp_policy: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            csrf_enabled: true,
            csrf_header: "X-CSRF-Token".to_string(),
            csrf_cookie: "csrf_token".to_string(),
            csrf_ttl: Duration::from_secs(3600), // 1 hour
            rate_limiting_enabled: true,
            rate_limit_requests: 100,
            rate_limit_window: Duration::from_secs(60), // 1 minute
            input_validation_enabled: true,
            max_body_size: 1024 * 1024, // 1MB
            security_headers_enabled: true,
            csp_policy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'".to_string(),
        }
    }
}

/// Enhanced security middleware
pub struct SecurityMiddleware {
    config: SecurityConfig,
    csrf_tokens: Arc<RwLock<HashMap<String, (String, Instant)>>>,
    rate_limiter: Arc<RateLimiter>,
    input_validator: Arc<InputValidator>,
}

impl SecurityMiddleware {
    /// Create a new security middleware
    pub fn new(config: SecurityConfig) -> Self {
        info!("Creating enhanced security middleware");

        Self {
            csrf_tokens: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RateLimiter::new(
                config.rate_limit_requests,
                config.rate_limit_window,
            )),
            input_validator: Arc::new(InputValidator::new(config.max_body_size)),
            config,
        }
    }

    /// Apply all security checks
    pub async fn apply(&self, mut req: Request, next: Next) -> Result<Response, StatusCode> {
        // Rate limiting check
        if self.config.rate_limiting_enabled {
            if let Err(response) = self.check_rate_limit(&req).await {
                return Ok(response);
            }
        }

        // CSRF protection for state-changing requests
        if self.config.csrf_enabled && self.is_state_changing_request(&req) {
            if let Err(response) = self.check_csrf_token(&req).await {
                return Ok(response);
            }
        }

        // Input validation
        if self.config.input_validation_enabled {
            if let Err(response) = self.validate_input(&mut req).await {
                return Ok(response);
            }
        }

        // Security headers
        let mut response = next.run(req).await;

        if self.config.security_headers_enabled {
            self.add_security_headers(&mut response);
        }

        Ok(response)
    }

    /// Check if request is state-changing (requires CSRF protection)
    fn is_state_changing_request(&self, req: &Request) -> bool {
        matches!(
            req.method(),
            &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE
        )
    }

    /// Check rate limiting
    async fn check_rate_limit(&self, req: &Request) -> Result<(), Response> {
        let client_ip = self.extract_client_ip(req);

        if self.rate_limiter.is_rate_limited(&client_ip).await {
            warn!("Rate limit exceeded for IP: {}", client_ip);

            let response = (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, "60")],
                axum::Json(serde_json::json!({
                    "error": "Rate limit exceeded",
                    "retry_after": 60
                })),
            )
                .into_response();

            Err(response)
        } else {
            Ok(())
        }
    }

    /// Check CSRF token
    /// Extract and validate CSRF tokens from request
    fn extract_csrf_tokens<'a>(&self, req: &'a Request) -> (Option<&'a str>, Option<String>) {
        let headers = req.headers();
        let header_token = headers
            .get(&self.config.csrf_header)
            .and_then(|h| h.to_str().ok());
        let cookie_token = self.extract_csrf_cookie(req);
        (header_token, cookie_token)
    }

    /// Validate tokens match between header and cookie
    fn validate_token_match(header_token: &str, cookie_token: &str) -> Result<(), Response> {
        if !constant_time_compare(header_token, cookie_token) {
            warn!("CSRF token mismatch");
            return Err(Self::csrf_error_response());
        }
        Ok(())
    }

    /// Validate stored token and expiration
    async fn validate_stored_token(
        &self,
        header_token: &str,
        cookie_token: &str,
    ) -> Result<(), Response> {
        let tokens = self.csrf_tokens.read().await;
        if let Some((stored_token, created)) = tokens.get(cookie_token) {
            if !constant_time_compare(header_token, stored_token) {
                warn!("Invalid CSRF token");
                return Err(Self::csrf_error_response());
            }

            if created.elapsed() > self.config.csrf_ttl {
                warn!("Expired CSRF token");
                return Err(Self::csrf_error_response());
            }
            Ok(())
        } else {
            warn!("Unknown CSRF token");
            Err(Self::csrf_error_response())
        }
    }

    async fn check_csrf_token(&self, req: &Request) -> Result<(), Response> {
        let (header_token, cookie_token) = self.extract_csrf_tokens(req);

        if let (Some(header), Some(cookie)) = (header_token, cookie_token) {
            Self::validate_token_match(header, &cookie)?;
            self.validate_stored_token(header, &cookie).await?;
            Ok(())
        } else {
            warn!("Missing CSRF token");
            Err(Self::csrf_error_response())
        }
    }

    /// Validate input data
    async fn validate_input(&self, req: &mut Request) -> Result<(), Response> {
        self.input_validator.validate_request(req).await
    }

    /// Add security headers to response
    fn add_security_headers(&self, response: &mut Response) {
        let headers = response.headers_mut();

        // Security headers
        headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
        headers.insert("X-Frame-Options", "DENY".parse().unwrap());
        headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
        headers.insert(
            "Referrer-Policy",
            "strict-origin-when-cross-origin".parse().unwrap(),
        );
        headers.insert(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()".parse().unwrap(),
        );

        // Content Security Policy
        headers.insert(
            "Content-Security-Policy",
            self.config.csp_policy.parse().unwrap(),
        );

        // HSTS (HTTP Strict Transport Security)
        headers.insert(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains".parse().unwrap(),
        );
    }

    /// Extract client IP from request
    fn extract_client_ip(&self, req: &Request) -> String {
        // Try X-Forwarded-For header first (for proxies)
        if let Some(xff) = req.headers().get("x-forwarded-for") {
            if let Ok(xff_str) = xff.to_str() {
                // Take first IP in case of multiple
                if let Some(first_ip) = xff_str.split(',').next() {
                    return first_ip.trim().to_string();
                }
            }
        }

        // Try X-Real-IP header
        if let Some(xri) = req.headers().get("x-real-ip") {
            if let Ok(xri_str) = xri.to_str() {
                return xri_str.to_string();
            }
        }

        // Fallback to connection info
        "unknown".to_string()
    }

    /// Extract CSRF token from cookies
    fn extract_csrf_cookie(&self, req: &Request) -> Option<String> {
        req.headers()
            .get("cookie")
            .and_then(|cookie| cookie.to_str().ok())
            .and_then(|cookie_str| {
                cookie_str
                    .split(';')
                    .map(str::trim)
                    .find(|s| s.starts_with(&format!("{}=", self.config.csrf_cookie)))
                    .and_then(|cookie| cookie.split('=').nth(1))
                    .map(std::string::ToString::to_string)
            })
    }

    /// Create CSRF error response
    fn csrf_error_response() -> Response {
        (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": "CSRF token validation failed",
                "message": "Invalid or missing CSRF token"
            })),
        )
            .into_response()
    }

    /// Generate a new CSRF token
    pub async fn generate_csrf_token(&self) -> (String, String) {
        let token = Uuid::new_v4().to_string();
        let cookie_value = Uuid::new_v4().to_string();

        let mut tokens = self.csrf_tokens.write().await;
        tokens.insert(cookie_value.clone(), (token.clone(), Instant::now()));

        // Clean up expired tokens
        tokens.retain(|_, (_, created)| created.elapsed() <= self.config.csrf_ttl);

        (token, cookie_value)
    }
}

/// Advanced rate limiter with sliding window
pub struct RateLimiter {
    requests: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    max_requests: u32,
    window: Duration,
}

impl RateLimiter {
    #[must_use]
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    pub async fn is_rate_limited(&self, key: &str) -> bool {
        let mut requests = self.requests.write().await;
        let now = Instant::now();

        let user_requests = requests.entry(key.to_string()).or_insert_with(Vec::new);

        // Remove requests outside the window
        user_requests.retain(|&time| now.duration_since(time) <= self.window);

        // Check if limit exceeded
        if user_requests.len() >= self.max_requests as usize {
            return true;
        }

        // Add current request
        user_requests.push(now);

        false
    }

    /// Get current request count for a key
    pub async fn request_count(&self, key: &str) -> usize {
        let requests = self.requests.read().await;
        requests.get(key).map_or(0, std::vec::Vec::len)
    }
}

/// Input validator for request data
pub struct InputValidator {
    max_body_size: usize,
}

impl InputValidator {
    #[must_use]
    pub const fn new(max_body_size: usize) -> Self {
        Self { max_body_size }
    }

    pub async fn validate_request(&self, req: &mut Request) -> Result<(), Response> {
        // Check content length
        if let Some(content_length) = req.headers().get("content-length") {
            if let Ok(length) = content_length.to_str().unwrap_or("0").parse::<usize>() {
                if length > self.max_body_size {
                    return Err((
                        StatusCode::PAYLOAD_TOO_LARGE,
                        axum::Json(serde_json::json!({
                            "error": "Request body too large",
                            "max_size": self.max_body_size
                        })),
                    )
                        .into_response());
                }
            }
        }

        // Validate content type for POST/PUT/PATCH requests
        if matches!(req.method(), &Method::POST | &Method::PUT | &Method::PATCH) {
            if let Some(content_type) = req.headers().get("content-type") {
                let ct_str = content_type.to_str().unwrap_or("");
                if !ct_str.contains("application/json")
                    && !ct_str.contains("application/x-www-form-urlencoded")
                {
                    return Err((
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        axum::Json(serde_json::json!({
                            "error": "Unsupported content type",
                            "supported": ["application/json", "application/x-www-form-urlencoded"]
                        })),
                    )
                        .into_response());
                }
            }
        }

        // Additional validation could be added here:
        // - SQL injection detection
        // - XSS pattern detection
        // - Path traversal detection
        // - Malformed JSON detection

        Ok(())
    }
}

/// Security monitoring and alerting
pub mod monitoring {
    use super::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug)]
    pub struct SecurityMetrics {
        pub csrf_attempts: AtomicU64,
        pub csrf_failures: AtomicU64,
        pub rate_limit_hits: AtomicU64,
        pub validation_failures: AtomicU64,
        pub suspicious_requests: AtomicU64,
    }

    impl Default for SecurityMetrics {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SecurityMetrics {
        #[must_use]
        pub const fn new() -> Self {
            Self {
                csrf_attempts: AtomicU64::new(0),
                csrf_failures: AtomicU64::new(0),
                rate_limit_hits: AtomicU64::new(0),
                validation_failures: AtomicU64::new(0),
                suspicious_requests: AtomicU64::new(0),
            }
        }

        pub fn record_csrf_attempt(&self) {
            self.csrf_attempts.fetch_add(1, Ordering::Relaxed);
        }

        pub fn record_csrf_failure(&self) {
            self.csrf_failures.fetch_add(1, Ordering::Relaxed);
        }

        pub fn record_rate_limit_hit(&self) {
            self.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
        }

        pub fn record_validation_failure(&self) {
            self.validation_failures.fetch_add(1, Ordering::Relaxed);
        }

        pub fn record_suspicious_request(&self) {
            self.suspicious_requests.fetch_add(1, Ordering::Relaxed);
        }

        pub fn get_stats(&self) -> HashMap<String, u64> {
            let mut stats = HashMap::new();
            stats.insert(
                "csrf_attempts".to_string(),
                self.csrf_attempts.load(Ordering::Relaxed),
            );
            stats.insert(
                "csrf_failures".to_string(),
                self.csrf_failures.load(Ordering::Relaxed),
            );
            stats.insert(
                "rate_limit_hits".to_string(),
                self.rate_limit_hits.load(Ordering::Relaxed),
            );
            stats.insert(
                "validation_failures".to_string(),
                self.validation_failures.load(Ordering::Relaxed),
            );
            stats.insert(
                "suspicious_requests".to_string(),
                self.suspicious_requests.load(Ordering::Relaxed),
            );
            stats
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(3, Duration::from_secs(1));

        let ip = "192.168.1.100";

        // First 3 requests should be allowed
        assert!(!limiter.is_rate_limited(ip).await);
        assert!(!limiter.is_rate_limited(ip).await);
        assert!(!limiter.is_rate_limited(ip).await);

        // 4th request should be rate limited
        assert!(limiter.is_rate_limited(ip).await);

        // Wait for window to reset
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!limiter.is_rate_limited(ip).await);
    }

    #[tokio::test]
    async fn test_csrf_token_generation() {
        let config = SecurityConfig::default();
        let middleware = SecurityMiddleware::new(config);

        let (token, cookie) = middleware.generate_csrf_token().await;

        assert!(!token.is_empty());
        assert!(!cookie.is_empty());
        assert_ne!(token, cookie); // Should be different for security
    }

    #[tokio::test]
    async fn test_input_validator_body_size() {
        let validator = InputValidator::new(100);

        // Create a request with large body
        let body = "x".repeat(200); // 200 bytes
        let request = Request::builder()
            .method("POST")
            .header("content-length", "200")
            .body(Body::from(body))
            .unwrap();

        let mut req = request;

        let result = validator.validate_request(&mut req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_security_headers() {
        let config = SecurityConfig::default();
        let middleware = SecurityMiddleware::new(config);

        let mut response = axum::response::Response::new(Body::empty());
        middleware.add_security_headers(&mut response);

        let headers = response.headers();

        assert_eq!(headers.get("X-Content-Type-Options").unwrap(), "nosniff");
        assert_eq!(headers.get("X-Frame-Options").unwrap(), "DENY");
        assert_eq!(headers.get("X-XSS-Protection").unwrap(), "1; mode=block");
        assert!(headers.get("Content-Security-Policy").is_some());
        assert!(headers.get("Strict-Transport-Security").is_some());
    }

    #[tokio::test]
    async fn test_client_ip_extraction() {
        let config = SecurityConfig::default();
        let middleware = SecurityMiddleware::new(config);

        // Test X-Forwarded-For header
        let request = Request::builder()
            .method("GET")
            .header("x-forwarded-for", "203.0.113.1, 198.51.100.1")
            .body(Body::empty())
            .unwrap();

        let ip = middleware.extract_client_ip(&request);
        assert_eq!(ip, "203.0.113.1");

        // Test X-Real-IP header
        let request = Request::builder()
            .method("GET")
            .header("x-real-ip", "198.51.100.2")
            .body(Body::empty())
            .unwrap();

        let ip = middleware.extract_client_ip(&request);
        assert_eq!(ip, "198.51.100.2");
    }
}
