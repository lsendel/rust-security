//! # Security Headers Middleware
//!
//! This module provides comprehensive security headers middleware that implements
//! OWASP-recommended security headers to protect against common web attacks.
//!
//! ## Security Headers Implemented
//!
//! - **Strict-Transport-Security (HSTS)**: Forces HTTPS connections
//! - **Content-Security-Policy (CSP)**: Prevents XSS and injection attacks
//! - **X-Frame-Options**: Prevents clickjacking attacks
//! - **X-Content-Type-Options**: Prevents MIME type sniffing
//! - **Referrer-Policy**: Controls referrer information leakage
//! - **Permissions-Policy**: Controls browser feature access
//! - **X-XSS-Protection**: Legacy XSS protection (for older browsers)
//! - **Cache-Control**: Prevents sensitive data caching
//!
//! ## Usage
//!
//! ```rust
//! use axum::Router;
//! use auth_service::security::headers::{SecurityHeadersLayer, SecurityHeadersConfig};
//!
//! let config = SecurityHeadersConfig::strict_security();
//! let app = Router::new()
//!     .layer(SecurityHeadersLayer::new(config));
//! ```

use axum::body::Body;
use axum::{
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};
use tower::{Layer, Service};
use tracing::{debug, warn};

/// Configuration for security headers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersConfig {
    /// Enable HSTS (Strict-Transport-Security)
    pub enable_hsts: bool,
    /// HSTS max age in seconds
    pub hsts_max_age: u64,
    /// Include subdomains in HSTS
    pub hsts_include_subdomains: bool,
    /// HSTS preload directive
    pub hsts_preload: bool,
    
    /// Content Security Policy directives
    pub csp_directives: HashMap<String, Vec<String>>,
    /// Report CSP violations to this URI
    pub csp_report_uri: Option<String>,
    /// Enable CSP report-only mode (for testing)
    pub csp_report_only: bool,
    
    /// X-Frame-Options setting
    pub frame_options: FrameOptions,
    
    /// X-Content-Type-Options setting
    pub content_type_options: bool,
    
    /// Referrer Policy setting
    pub referrer_policy: ReferrerPolicy,
    
    /// Permissions Policy directives
    pub permissions_policy: HashMap<String, PermissionDirective>,
    
    /// Enable X-XSS-Protection header
    pub xss_protection: XssProtection,
    
    /// Custom cache control for sensitive endpoints
    pub cache_control: CacheControl,
    
    /// Custom headers to add
    pub custom_headers: HashMap<String, String>,
    
    /// Development mode (less strict headers)
    pub development_mode: bool,
}

/// X-Frame-Options values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FrameOptions {
    Deny,
    SameOrigin,
    AllowFrom(String),
}

/// Referrer Policy values  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReferrerPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

/// Permission Policy directive values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermissionDirective {
    None,
    Self_,
    All,
    Origins(Vec<String>),
}

/// X-XSS-Protection values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XssProtection {
    Disabled,
    Enabled,
    Block,
}

/// Cache Control configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheControl {
    pub no_cache: bool,
    pub no_store: bool,
    pub must_revalidate: bool,
    pub max_age: Option<u64>,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self::balanced_security()
    }
}

impl SecurityHeadersConfig {
    /// Create configuration with balanced security (recommended for most applications)
    pub fn balanced_security() -> Self {
        let mut csp_directives = HashMap::new();
        csp_directives.insert("default-src".to_string(), vec!["'self'".to_string()]);
        csp_directives.insert("script-src".to_string(), vec!["'self'".to_string(), "'unsafe-inline'".to_string()]);
        csp_directives.insert("style-src".to_string(), vec!["'self'".to_string(), "'unsafe-inline'".to_string()]);
        csp_directives.insert("img-src".to_string(), vec!["'self'".to_string(), "data:".to_string()]);
        csp_directives.insert("connect-src".to_string(), vec!["'self'".to_string()]);
        csp_directives.insert("font-src".to_string(), vec!["'self'".to_string()]);
        csp_directives.insert("object-src".to_string(), vec!["'none'".to_string()]);
        csp_directives.insert("frame-ancestors".to_string(), vec!["'none'".to_string()]);
        csp_directives.insert("base-uri".to_string(), vec!["'self'".to_string()]);
        csp_directives.insert("form-action".to_string(), vec!["'self'".to_string()]);

        let mut permissions_policy = HashMap::new();
        permissions_policy.insert("camera".to_string(), PermissionDirective::None);
        permissions_policy.insert("microphone".to_string(), PermissionDirective::None);
        permissions_policy.insert("geolocation".to_string(), PermissionDirective::None);
        permissions_policy.insert("payment".to_string(), PermissionDirective::None);
        permissions_policy.insert("usb".to_string(), PermissionDirective::None);

        Self {
            enable_hsts: true,
            hsts_max_age: 31536000, // 1 year
            hsts_include_subdomains: true,
            hsts_preload: false,
            
            csp_directives,
            csp_report_uri: None,
            csp_report_only: false,
            
            frame_options: FrameOptions::Deny,
            content_type_options: true,
            referrer_policy: ReferrerPolicy::StrictOriginWhenCrossOrigin,
            permissions_policy,
            xss_protection: XssProtection::Block,
            
            cache_control: CacheControl {
                no_cache: true,
                no_store: true,
                must_revalidate: true,
                max_age: None,
            },
            
            custom_headers: HashMap::new(),
            development_mode: false,
        }
    }

    /// Create configuration with strict security (maximum protection)
    pub fn strict_security() -> Self {
        let mut config = Self::balanced_security();
        
        // Stricter CSP
        config.csp_directives.insert("script-src".to_string(), vec!["'self'".to_string()]);
        config.csp_directives.insert("style-src".to_string(), vec!["'self'".to_string()]);
        config.csp_directives.insert("upgrade-insecure-requests".to_string(), vec![]);
        
        // Enable HSTS preload
        config.hsts_preload = true;
        
        // Stricter referrer policy
        config.referrer_policy = ReferrerPolicy::NoReferrer;
        
        config
    }

    /// Create configuration for development (more permissive)
    pub fn development() -> Self {
        let mut config = Self::balanced_security();
        
        // More permissive CSP for development
        config.csp_directives.insert("script-src".to_string(), vec![
            "'self'".to_string(), 
            "'unsafe-inline'".to_string(), 
            "'unsafe-eval'".to_string(),
            "localhost:*".to_string(),
            "127.0.0.1:*".to_string()
        ]);
        
        // Disable HSTS in development
        config.enable_hsts = false;
        config.development_mode = true;
        
        config
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = if std::env::var("DEVELOPMENT_MODE").map(|v| v == "true").unwrap_or(false) {
            Self::development()
        } else if std::env::var("STRICT_SECURITY").map(|v| v == "true").unwrap_or(false) {
            Self::strict_security()
        } else {
            Self::balanced_security()
        };

        // Override HSTS settings from environment
        if let Ok(max_age) = std::env::var("HSTS_MAX_AGE") {
            if let Ok(age) = max_age.parse::<u64>() {
                config.hsts_max_age = age;
            }
        }

        // Override CSP report URI
        if let Ok(report_uri) = std::env::var("CSP_REPORT_URI") {
            config.csp_report_uri = Some(report_uri);
        }

        config
    }
}

impl SecurityHeadersConfig {
    /// Build HSTS header value
    fn build_hsts_header(&self) -> Option<HeaderValue> {
        if !self.enable_hsts {
            return None;
        }

        let mut value = format!("max-age={}", self.hsts_max_age);
        
        if self.hsts_include_subdomains {
            value.push_str("; includeSubDomains");
        }
        
        if self.hsts_preload {
            value.push_str("; preload");
        }

        HeaderValue::from_str(&value).ok()
    }

    /// Build CSP header value
    fn build_csp_header(&self) -> Option<HeaderValue> {
        if self.csp_directives.is_empty() {
            return None;
        }

        let mut directives: Vec<String> = self.csp_directives
            .iter()
            .map(|(directive, values)| {
                if values.is_empty() {
                    directive.clone()
                } else {
                    format!("{} {}", directive, values.join(" "))
                }
            })
            .collect();

        if let Some(ref report_uri) = self.csp_report_uri {
            directives.push(format!("report-uri {}", report_uri));
        }

        let csp_value = directives.join("; ");
        HeaderValue::from_str(&csp_value).ok()
    }

    /// Build Frame Options header value
    fn build_frame_options_header(&self) -> HeaderValue {
        let value = match &self.frame_options {
            FrameOptions::Deny => "DENY",
            FrameOptions::SameOrigin => "SAMEORIGIN", 
            FrameOptions::AllowFrom(origin) => return HeaderValue::from_str(&format!("ALLOW-FROM {}", origin)).unwrap_or_else(|_| HeaderValue::from_static("DENY")),
        };
        HeaderValue::from_static(value)
    }

    /// Build Referrer Policy header value
    fn build_referrer_policy_header(&self) -> HeaderValue {
        let value = match self.referrer_policy {
            ReferrerPolicy::NoReferrer => "no-referrer",
            ReferrerPolicy::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            ReferrerPolicy::Origin => "origin",
            ReferrerPolicy::OriginWhenCrossOrigin => "origin-when-cross-origin",
            ReferrerPolicy::SameOrigin => "same-origin",
            ReferrerPolicy::StrictOrigin => "strict-origin",
            ReferrerPolicy::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            ReferrerPolicy::UnsafeUrl => "unsafe-url",
        };
        HeaderValue::from_static(value)
    }

    /// Build Permissions Policy header value
    fn build_permissions_policy_header(&self) -> Option<HeaderValue> {
        if self.permissions_policy.is_empty() {
            return None;
        }

        let directives: Vec<String> = self.permissions_policy
            .iter()
            .map(|(feature, directive)| {
                let allowlist = match directive {
                    PermissionDirective::None => "()".to_string(),
                    PermissionDirective::Self_ => "(self)".to_string(),
                    PermissionDirective::All => "*".to_string(),
                    PermissionDirective::Origins(origins) => {
                        format!("({})", origins.join(" "))
                    }
                };
                format!("{}={}", feature, allowlist)
            })
            .collect();

        let value = directives.join(", ");
        HeaderValue::from_str(&value).ok()
    }

    /// Build XSS Protection header value
    fn build_xss_protection_header(&self) -> Option<HeaderValue> {
        let value = match self.xss_protection {
            XssProtection::Disabled => "0",
            XssProtection::Enabled => "1",
            XssProtection::Block => "1; mode=block",
        };
        Some(HeaderValue::from_static(value))
    }

    /// Build Cache Control header value
    fn build_cache_control_header(&self) -> HeaderValue {
        let mut directives = Vec::new();

        if self.cache_control.no_cache {
            directives.push("no-cache".to_string());
        }
        
        if self.cache_control.no_store {
            directives.push("no-store".to_string());
        }
        
        if self.cache_control.must_revalidate {
            directives.push("must-revalidate".to_string());
        }

        if let Some(max_age) = self.cache_control.max_age {
            directives.push(format!("max-age={}", max_age));
        }

        let value = if directives.is_empty() {
            "no-cache, no-store, must-revalidate".to_string()
        } else {
            directives.join(", ")
        };

        HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("no-cache"))
    }
}

/// Security headers middleware layer
#[derive(Debug, Clone)]
pub struct SecurityHeadersLayer {
    config: SecurityHeadersConfig,
}

impl SecurityHeadersLayer {
    /// Create new security headers layer with configuration
    pub fn new(config: SecurityHeadersConfig) -> Self {
        Self { config }
    }

    /// Create layer with default configuration
    pub fn default() -> Self {
        Self::new(SecurityHeadersConfig::default())
    }

    /// Create layer with strict security configuration
    pub fn strict() -> Self {
        Self::new(SecurityHeadersConfig::strict_security())
    }

    /// Create layer with development configuration
    pub fn development() -> Self {
        Self::new(SecurityHeadersConfig::development())
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Security headers service implementation
#[derive(Debug, Clone)]
pub struct SecurityHeadersService<S> {
    inner: S,
    config: SecurityHeadersConfig,
}

impl<S, ReqBody> Service<Request<ReqBody>> for SecurityHeadersService<S>
where
    S: Service<Request<ReqBody>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);
        let config = self.config.clone();

        Box::pin(async move {
            let response = inner.call(request).await?;
            Ok(add_security_headers(response, &config))
        })
    }
}

/// Add security headers to response
fn add_security_headers(mut response: Response, config: &SecurityHeadersConfig) -> Response {
    let headers = response.headers_mut();

    // Add HSTS header
    if let Some(hsts_value) = config.build_hsts_header() {
        headers.insert(header::STRICT_TRANSPORT_SECURITY, hsts_value);
    }

    // Add CSP header
    if let Some(csp_value) = config.build_csp_header() {
        let header_name = if config.csp_report_only {
            "content-security-policy-report-only"
        } else {
            "content-security-policy"
        };
        
        if let Ok(header_name) = HeaderValue::from_str(header_name) {
            // Using insert with string key since header name is dynamic
            headers.insert(header::CONTENT_SECURITY_POLICY, csp_value);
        }
    }

    // Add X-Frame-Options header
    headers.insert(header::X_FRAME_OPTIONS, config.build_frame_options_header());

    // Add X-Content-Type-Options header
    if config.content_type_options {
        headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    }

    // Add Referrer-Policy header
    headers.insert(header::REFERRER_POLICY, config.build_referrer_policy_header());

    // Add Permissions-Policy header
    if let Some(permissions_value) = config.build_permissions_policy_header() {
        if let Ok(name) = HeaderValue::from_str("permissions-policy") {
            headers.append("permissions-policy", permissions_value);
        }
    }

    // Add X-XSS-Protection header
    if let Some(xss_value) = config.build_xss_protection_header() {
        headers.insert("x-xss-protection", xss_value);
    }

    // Add Cache-Control header for sensitive responses
    let is_sensitive_path = response.headers().get("content-type")
        .and_then(|ct| ct.to_str().ok())
        .map(|ct| ct.contains("application/json") || ct.contains("text/html"))
        .unwrap_or(true);
        
    if is_sensitive_path {
        headers.insert(header::CACHE_CONTROL, config.build_cache_control_header());
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }

    // Add custom headers
    for (name, value) in &config.custom_headers {
        if let (Ok(header_name), Ok(header_value)) = (
            HeaderValue::from_str(name),
            HeaderValue::from_str(value)
        ) {
            headers.append(name.as_str(), header_value);
        }
    }

    // Add security-specific headers for this auth service
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("x-download-options", HeaderValue::from_static("noopen"));
    headers.insert("x-permitted-cross-domain-policies", HeaderValue::from_static("none"));

    if config.development_mode {
        debug!("Applied security headers in development mode");
    } else {
        debug!("Applied production security headers");
    }

    response
}

/// Axum middleware function for security headers
pub async fn security_headers_middleware(
    request: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let config = SecurityHeadersConfig::from_env();
    let response = next.run(request).await;
    add_security_headers(response, &config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, response::Response, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_security_headers_middleware() {
        let config = SecurityHeadersConfig::balanced_security();
        let app = Router::new()
            .route("/", axum::routing::get(|| async { "Hello" }))
            .layer(SecurityHeadersLayer::new(config));

        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let headers = response.headers();

        // Check that security headers are present
        assert!(headers.contains_key(header::X_FRAME_OPTIONS));
        assert!(headers.contains_key(header::X_CONTENT_TYPE_OPTIONS));
        assert!(headers.contains_key(header::REFERRER_POLICY));
        assert!(headers.contains_key(header::STRICT_TRANSPORT_SECURITY));
    }

    #[test]
    fn test_csp_header_building() {
        let config = SecurityHeadersConfig::strict_security();
        let csp_header = config.build_csp_header().unwrap();
        let csp_str = csp_header.to_str().unwrap();
        
        assert!(csp_str.contains("default-src 'self'"));
        assert!(csp_str.contains("object-src 'none'"));
    }

    #[test]
    fn test_hsts_header_building() {
        let config = SecurityHeadersConfig::balanced_security();
        let hsts_header = config.build_hsts_header().unwrap();
        let hsts_str = hsts_header.to_str().unwrap();
        
        assert!(hsts_str.contains("max-age=31536000"));
        assert!(hsts_str.contains("includeSubDomains"));
    }

    #[test]
    fn test_development_config() {
        let config = SecurityHeadersConfig::development();
        
        assert!(!config.enable_hsts);
        assert!(config.development_mode);
        
        // Should have more permissive CSP
        let script_src = config.csp_directives.get("script-src").unwrap();
        assert!(script_src.contains(&"'unsafe-eval'".to_string()));
    }

    #[test] 
    fn test_strict_config() {
        let config = SecurityHeadersConfig::strict_security();
        
        assert!(config.hsts_preload);
        assert!(matches!(config.referrer_policy, ReferrerPolicy::NoReferrer));
        
        // Should have stricter CSP  
        let script_src = config.csp_directives.get("script-src").unwrap();
        assert_eq!(script_src, &vec!["'self'".to_string()]);
    }
}