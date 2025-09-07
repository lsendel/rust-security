use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Security level configuration for different environments
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SecurityLevel {
    /// Development - Enhanced security for development
    Development,
    /// Production - Strict security for production
    Production,
    /// Custom - User-defined security configuration
    Custom(Box<SecurityHeadersConfig>),
}

/// Configuration for security headers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct SecurityHeadersConfig {
    /// Content Security Policy directive
    pub csp: String,
    /// HTTP Strict Transport Security max-age
    pub hsts_max_age: u32,
    /// Whether to include subdomains in HSTS
    pub hsts_include_subdomains: bool,
    /// Whether to enable HSTS preload
    pub hsts_preload: bool,
    /// X-Frame-Options value
    pub frame_options: String,
    /// Whether to enable X-Content-Type-Options
    pub content_type_options: bool,
    /// X-XSS-Protection value
    pub xss_protection: String,
    /// Referrer-Policy value
    pub referrer_policy: String,
    /// Permissions-Policy directive
    pub permissions_policy: String,
    /// Cross-Origin-Embedder-Policy value
    pub coep: String,
    /// Cross-Origin-Opener-Policy value
    pub coop: String,
    /// Cross-Origin-Resource-Policy value
    pub corp: String,
    /// Whether to add security monitoring headers
    pub monitoring_headers: bool,
    /// Whether to add cache control headers
    pub cache_control: bool,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        let env = std::env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .to_lowercase();

        match env.as_str() {
            "production" | "prod" => Self::Production,
            _ => Self::Development,
        }
    }
}

impl SecurityLevel {
    /// Get the security headers configuration for this level
    #[must_use]
    pub fn get_config(&self) -> SecurityHeadersConfig {
        match self {
            Self::Development => SecurityHeadersConfig::development(),
            Self::Production => SecurityHeadersConfig::production(),
            Self::Custom(config) => (*config.as_ref()).clone(),
        }
    }
}

impl SecurityHeadersConfig {
    /// Enhanced development configuration with improved security
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn development() -> Self {
        Self {
            csp: "default-src 'self'; \
                  script-src 'self'; \
                  style-src 'self'; \
                  connect-src 'self' ws: wss:; \
                  img-src 'self' data: blob:; \
                  font-src 'self'; \
                  object-src 'none'; \
                  media-src 'self'; \
                  frame-ancestors 'self'; \
                  base-uri 'self'; \
                  form-action 'self'"
                .to_string(),
            hsts_max_age: 86400, // 1 day
            hsts_include_subdomains: false,
            hsts_preload: false,
            frame_options: "SAMEORIGIN".to_string(),
            content_type_options: true,
            xss_protection: "1; mode=block".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), \
                                magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=(), \
                                autoplay=(), encrypted-media=(), fullscreen=(), picture-in-picture=(), \
                                web-share=(), clipboard-read=(), clipboard-write=()"
                .to_string(),
            coep: "credentialless".to_string(), // More secure than unsafe-none but still allows development
            coop: "same-origin".to_string(),
            corp: "same-origin".to_string(),
            monitoring_headers: true,
            cache_control: true, // Enable cache control for better security
        }
    }

    /// Production configuration with strict security
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn production() -> Self {
        Self {
            csp: "default-src 'none'; \
                  script-src 'self' 'strict-dynamic'; \
                  style-src 'self'; \
                  img-src 'self' data:; \
                  connect-src 'self'; \
                  font-src 'self'; \
                  object-src 'none'; \
                  media-src 'self'; \
                  frame-src 'none'; \
                  worker-src 'self'; \
                  base-uri 'none'; \
                  form-action 'self'; \
                  frame-ancestors 'none'; \
                  upgrade-insecure-requests"
                .to_string(),
            hsts_max_age: 31_536_000, // 1 year
            hsts_include_subdomains: true,
            hsts_preload: true,
            frame_options: "DENY".to_string(),
            content_type_options: true,
            xss_protection: "1; mode=block".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), \
                                magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=(), \
                                autoplay=(), encrypted-media=(), fullscreen=(), picture-in-picture=(), \
                                web-share=(), clipboard-read=(), clipboard-write=(), sync-xhr=(), \
                                midi=(), bluetooth=(), serial=(), gamepad=(), hid=()"
                .to_string(),
            coep: "require-corp".to_string(),
            coop: "same-origin".to_string(),
            corp: "same-origin".to_string(),
            monitoring_headers: true,
            cache_control: true,
        }
    }

    /// Load configuration from environment variables
    #[must_use]
    pub fn from_env() -> Self {
        let base_config = if std::env::var("ENVIRONMENT")
            .unwrap_or_default()
            .to_lowercase()
            == "production"
        {
            Self::production()
        } else {
            Self::development()
        };

        Self {
            csp: std::env::var("SECURITY_CSP").unwrap_or(base_config.csp),
            hsts_max_age: std::env::var("SECURITY_HSTS_MAX_AGE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(base_config.hsts_max_age),
            hsts_include_subdomains: std::env::var("SECURITY_HSTS_INCLUDE_SUBDOMAINS")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(base_config.hsts_include_subdomains),
            hsts_preload: std::env::var("SECURITY_HSTS_PRELOAD")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(base_config.hsts_preload),
            frame_options: std::env::var("SECURITY_FRAME_OPTIONS")
                .unwrap_or(base_config.frame_options),
            content_type_options: std::env::var("SECURITY_CONTENT_TYPE_OPTIONS")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(base_config.content_type_options),
            xss_protection: std::env::var("SECURITY_XSS_PROTECTION")
                .unwrap_or(base_config.xss_protection),
            referrer_policy: std::env::var("SECURITY_REFERRER_POLICY")
                .unwrap_or(base_config.referrer_policy),
            permissions_policy: std::env::var("SECURITY_PERMISSIONS_POLICY")
                .unwrap_or(base_config.permissions_policy),
            coep: std::env::var("SECURITY_COEP").unwrap_or(base_config.coep),
            coop: std::env::var("SECURITY_COOP").unwrap_or(base_config.coop),
            corp: std::env::var("SECURITY_CORP").unwrap_or(base_config.corp),
            monitoring_headers: std::env::var("SECURITY_MONITORING_HEADERS")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(base_config.monitoring_headers),
            cache_control: std::env::var("SECURITY_CACHE_CONTROL")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(base_config.cache_control),
        }
    }
}

/// Enhanced security headers middleware with configurable security levels
pub async fn add_configurable_security_headers(
    config: SecurityHeadersConfig,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let _headers_present = response.headers().contains_key("content-type");
    let headers = response.headers_mut();

    // Content Security Policy
    if let Ok(csp_value) = config.csp.parse() {
        headers.insert("Content-Security-Policy", csp_value);
    }

    // HTTP Strict Transport Security
    let hsts_value = if config.hsts_include_subdomains && config.hsts_preload {
        format!(
            "max-age={}; includeSubDomains; preload",
            config.hsts_max_age
        )
    } else if config.hsts_include_subdomains {
        format!("max-age={}; includeSubDomains", config.hsts_max_age)
    } else {
        format!("max-age={}", config.hsts_max_age)
    };
    if let Ok(hsts_header_value) = hsts_value.parse() {
        headers.insert("Strict-Transport-Security", hsts_header_value);
    }

    // X-Frame-Options
    if let Ok(frame_options_value) = config.frame_options.parse() {
        headers.insert("X-Frame-Options", frame_options_value);
    }

    // X-Content-Type-Options
    if config.content_type_options {
        headers.insert(
            "X-Content-Type-Options",
            HeaderValue::from_static("nosniff"),
        );
    }

    // X-XSS-Protection
    if let Ok(xss_protection_value) = config.xss_protection.parse() {
        headers.insert("X-XSS-Protection", xss_protection_value);
    }

    // Referrer-Policy
    if let Ok(referrer_value) = config.referrer_policy.parse() {
        headers.insert("Referrer-Policy", referrer_value);
    }

    // Permissions-Policy
    if let Ok(permissions_value) = config.permissions_policy.parse() {
        headers.insert("Permissions-Policy", permissions_value);
    }

    // Cross-Origin policies
    if let Ok(coep_value) = config.coep.parse() {
        headers.insert("Cross-Origin-Embedder-Policy", coep_value);
    }
    if let Ok(coop_value) = config.coop.parse() {
        headers.insert("Cross-Origin-Opener-Policy", coop_value);
    }
    if let Ok(corp_value) = config.corp.parse() {
        headers.insert("Cross-Origin-Resource-Policy", corp_value);
    }

    // Additional modern security headers
    headers.insert(
        "X-Permitted-Cross-Domain-Policies",
        HeaderValue::from_static("none"),
    );
    headers.insert("X-DNS-Prefetch-Control", HeaderValue::from_static("off"));
    headers.insert("X-Download-Options", HeaderValue::from_static("noopen"));

    // Server identification (minimal information disclosure)
    headers.insert("Server", HeaderValue::from_static("AuthService/1.0"));

    // Cache control for sensitive endpoints
    if config.cache_control {
        headers.insert(
            "Cache-Control",
            HeaderValue::from_static("no-store, no-cache, must-revalidate, private, max-age=0"),
        );
        headers.insert("Pragma", HeaderValue::from_static("no-cache"));
        headers.insert("Expires", HeaderValue::from_static("0"));
    }

    // Add monitoring headers
    if config.monitoring_headers {
        if let Ok(timestamp) = SystemTime::now().duration_since(UNIX_EPOCH) {
            if let Ok(timestamp_value) = timestamp.as_secs().to_string().parse() {
                headers.insert("X-Response-Time", timestamp_value);
            }
        }
        if let Ok(uuid_value) = uuid::Uuid::new_v4().to_string().parse() {
            headers.insert("X-Request-ID", uuid_value);
        }
    }

    response
}

/// Enhanced security headers middleware
/// Implements comprehensive security headers following OWASP recommendations
/// Uses environment-based configuration
pub async fn add_security_headers(request: Request, next: Next) -> Response {
    let config = SecurityHeadersConfig::from_env();
    add_configurable_security_headers(config, request, next).await
}

/// Legacy security headers middleware for backward compatibility
pub async fn add_legacy_security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers_present = response.headers().contains_key("content-type");
    let headers = response.headers_mut();

    // Content Security Policy - Strict policy for security applications
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    );

    // Strict Transport Security - Force HTTPS for 1 year
    headers.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
    );

    // Prevent clickjacking
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));

    // Prevent MIME type sniffing
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );

    // XSS Protection (legacy but still useful)
    // Keep legacy X-XSS-Protection header for backward compatibility with existing clients/tests
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Referrer Policy - Limit referrer information
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Permissions Policy - Restrict browser features
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=(), autoplay=(), encrypted-media=(), fullscreen=(), picture-in-picture=()"),
    );

    // Cross-Origin Embedder Policy
    headers.insert(
        "Cross-Origin-Embedder-Policy",
        HeaderValue::from_static("require-corp"),
    );

    // Cross-Origin Opener Policy
    headers.insert(
        "Cross-Origin-Opener-Policy",
        HeaderValue::from_static("same-origin"),
    );

    // Cross-Origin Resource Policy
    headers.insert(
        "Cross-Origin-Resource-Policy",
        HeaderValue::from_static("same-origin"),
    );

    // Server identification (minimal information disclosure)
    headers.insert("Server", HeaderValue::from_static("AuthService/1.0"));

    // Cache control for sensitive endpoints
    // Avoid borrowing response immutably again; check based on header presence instead
    if headers_present {
        headers.insert(
            "Cache-Control",
            HeaderValue::from_static("no-store, no-cache, must-revalidate, private, max-age=0"),
        );
        headers.insert("Pragma", HeaderValue::from_static("no-cache"));
        headers.insert("Expires", HeaderValue::from_static("0"));
    }

    // Add timestamp for security monitoring
    if let Ok(timestamp) = SystemTime::now().duration_since(UNIX_EPOCH) {
        if let Ok(timestamp_value) = timestamp.as_secs().to_string().parse() {
            headers.insert("X-Response-Time", timestamp_value);
        }
    }

    response
}

/// Security headers for API responses with enhanced CORS handling
pub async fn add_api_security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // API-specific security headers
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));

    // Prevent caching of API responses
    headers.insert(
        "Cache-Control",
        HeaderValue::from_static("no-store, no-cache, must-revalidate, private, max-age=0"),
    );

    // Secure CORS headers for API (restrictive by default)
    // Only allow specific origins, not wildcard
    headers.insert(
        "Access-Control-Allow-Origin",
        HeaderValue::from_static("null"), // Will be overridden by CORS middleware if configured
    );

    headers.insert(
        "Access-Control-Allow-Methods",
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );

    headers.insert(
        "Access-Control-Allow-Headers",
        HeaderValue::from_static("Content-Type, Authorization, X-Requested-With"),
    );

    headers.insert(
        "Access-Control-Max-Age",
        HeaderValue::from_static("3600"), // Reduced to 1 hour for better security
    );

    // Ensure credentials are not allowed by default
    headers.insert(
        "Access-Control-Allow-Credentials",
        HeaderValue::from_static("false"),
    );

    response
}

/// Rate limiting headers
pub fn add_rate_limit_headers(
    response: &mut Response,
    limit: u32,
    remaining: u32,
    reset_time: u64,
) {
    let headers = response.headers_mut();

    if let Ok(limit_value) = limit.to_string().parse() {
        headers.insert("X-RateLimit-Limit", limit_value);
    }

    if let Ok(remaining_value) = remaining.to_string().parse() {
        headers.insert("X-RateLimit-Remaining", remaining_value);
    }

    if let Ok(reset_value) = reset_time.to_string().parse() {
        headers.insert("X-RateLimit-Reset", reset_value);
    }

    if remaining == 0 {
        headers.insert(
            "Retry-After",
            HeaderValue::from_static("60"), // Retry after 1 minute
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use tower::util::ServiceExt;

    async fn test_handler() -> &'static str {
        "test response"
    }

    #[tokio::test]
    async fn test_security_headers() {
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn(add_security_headers));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert!(headers.contains_key("Content-Security-Policy"));
        assert!(headers.contains_key("Strict-Transport-Security"));
        assert!(headers.contains_key("X-Frame-Options"));
        assert!(headers.contains_key("X-Content-Type-Options"));
        assert!(headers.contains_key("X-XSS-Protection"));
        assert!(headers.contains_key("Referrer-Policy"));
        assert!(headers.contains_key("Permissions-Policy"));
    }

    #[tokio::test]
    async fn test_api_security_headers() {
        let app = Router::new()
            .route("/api/test", get(test_handler))
            .layer(middleware::from_fn(add_api_security_headers));

        let request = Request::builder()
            .uri("/api/test")
            .body(Body::empty())
            .expect("Failed to build test request");

        let response = app
            .oneshot(request)
            .await
            .expect("Failed to execute request");

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert!(headers.contains_key("Cache-Control"));
        assert!(headers.contains_key("Access-Control-Allow-Origin"));
        assert!(headers.contains_key("Access-Control-Allow-Methods"));
        assert_eq!(
            headers
                .get("Access-Control-Allow-Credentials")
                .expect("Missing Access-Control-Allow-Credentials header"),
            "false"
        );
    }

    #[tokio::test]
    async fn test_enhanced_csp() {
        let config = SecurityHeadersConfig::development();
        assert!(config.csp.contains("object-src 'none'"));
        assert!(config.csp.contains("base-uri 'self'"));
        assert!(config.csp.contains("form-action 'self'"));

        let prod_config = SecurityHeadersConfig::production();
        assert!(prod_config.csp.contains("upgrade-insecure-requests"));
        assert!(prod_config.csp.contains("frame-ancestors 'none'"));
    }
}
