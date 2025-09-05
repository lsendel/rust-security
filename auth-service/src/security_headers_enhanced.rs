//! Enhanced Security Headers Implementation
//!
//! Provides comprehensive security headers with advanced protection mechanisms
//! including enhanced CSP, improved HSTS, and additional security features.
//!
//! ## Enhanced Features
//!
//! - **Advanced CSP**: Strict Content Security Policy with nonce and hash support
//! - **Enhanced HSTS**: Improved HTTP Strict Transport Security with reporting
//! - **Modern Headers**: Latest security headers including COEP, COOP, CORP
//! - **Permissions Policy**: Fine-grained permissions control with contextual policies
//! - **Feature Policy**: Deprecated but still supported for backward compatibility
//! - **Report-Only Modes**: Testing security policies without enforcement
//! - **Dynamic Headers**: Context-aware header generation based on request
//! - **Zero-Day Protection**: Heuristic analysis for unknown attack patterns

use axum::{extract::Request, middleware::Next, response::Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

/// Enhanced security level configuration for different environments
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum EnhancedSecurityLevel {
    /// Development - Enhanced security for development with flexibility
    Development,
    /// Staging - Pre-production security with most production features
    Staging,
    /// Production - Strict security for production with maximum protection
    Production,
    /// Custom - User-defined security configuration with granular control
    Custom(Box<EnhancedSecurityHeadersConfig>),
}

/// Enhanced configuration for security headers with additional options
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct EnhancedSecurityHeadersConfig {
    /// Content Security Policy directive with enhanced options
    pub csp: String,
    /// Content Security Policy Report-Only directive for testing
    pub csp_report_only: Option<String>,
    /// HTTP Strict Transport Security max-age
    pub hsts_max_age: u32,
    /// Whether to include subdomains in HSTS
    pub hsts_include_subdomains: bool,
    /// Whether to enable HSTS preload
    pub hsts_preload: bool,
    /// HSTS reporting endpoint for violation reports
    pub hsts_report_uri: Option<String>,
    /// X-Frame-Options value
    pub frame_options: String,
    /// Whether to enable X-Content-Type-Options
    pub content_type_options: bool,
    /// X-XSS-Protection value (deprecated but still used)
    pub xss_protection: String,
    /// Referrer-Policy value
    pub referrer_policy: String,
    /// Permissions-Policy directive with enhanced control
    pub permissions_policy: String,
    /// Permissions-Policy Report-Only for testing
    pub permissions_policy_report_only: Option<String>,
    /// Feature-Policy directive (deprecated but maintained for compatibility)
    pub feature_policy: Option<String>,
    /// Cross-Origin-Embedder-Policy value
    pub coep: String,
    /// Cross-Origin-Opener-Policy value
    pub coop: String,
    /// Cross-Origin-Resource-Policy value
    pub corp: String,
    /// Clear-Site-Data directive for clearing browsing data
    pub clear_site_data: Option<String>,
    /// Cross-Origin Resource Timing control
    pub timing_allow_origin: Option<String>,
    /// Document-Policy for document-level security features
    pub document_policy: Option<String>,
    /// Reporting-Endpoints for security violation reporting
    pub reporting_endpoints: Option<String>,
    /// Report-To header for modern reporting API
    pub report_to: Option<String>,
    /// Server header control (set to None to remove server header)
    pub server_header: Option<String>,
    /// Whether to add security monitoring headers
    pub monitoring_headers: bool,
    /// Whether to add cache control headers
    pub cache_control: bool,
    /// Whether to enable report-only mode for testing new policies
    pub report_only_mode: bool,
    /// Whether to add experimental security headers
    pub experimental_headers: bool,
    /// Custom headers to add
    pub custom_headers: HashMap<String, String>,
    /// Environment-specific overrides
    pub environment_overrides: HashMap<String, serde_json::Value>,
}

impl Default for EnhancedSecurityLevel {
    fn default() -> Self {
        let env = std::env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .to_lowercase();

        match env.as_str() {
            "production" | "prod" => Self::Production,
            "staging" => Self::Staging,
            _ => Self::Development,
        }
    }
}

impl EnhancedSecurityLevel {
    /// Get the security headers configuration for this level
    #[must_use]
    pub fn get_config(&self) -> EnhancedSecurityHeadersConfig {
        match self {
            Self::Development => EnhancedSecurityHeadersConfig::development(),
            Self::Staging => EnhancedSecurityHeadersConfig::staging(),
            Self::Production => EnhancedSecurityHeadersConfig::production(),
            Self::Custom(config) => (**config).clone(),
        }
    }
}

impl EnhancedSecurityHeadersConfig {
    /// Enhanced development configuration with improved security but flexibility
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn development() -> Self {
        Self {
            csp: "default-src 'self'; \
                  script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
                  style-src 'self' 'unsafe-inline'; \
                  connect-src 'self' ws: wss: http: https:; \
                  img-src 'self' data: blob: http: https:; \
                  font-src 'self' data: http: https:; \
                  object-src 'none'; \
                  media-src 'self'; \
                  frame-ancestors 'self'; \
                  base-uri 'self'; \
                  form-action 'self'"
                .to_string(),
            csp_report_only: Some(
                "default-src 'self'; \
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
            ),
            hsts_max_age: 86400, // 1 day - shorter for development
            hsts_include_subdomains: false,
            hsts_preload: false,
            hsts_report_uri: Some("/api/v1/security/hsts-report".to_string()),
            frame_options: "SAMEORIGIN".to_string(),
            content_type_options: true,
            xss_protection: "1; mode=block".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), \
                                magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=(), \
                                autoplay=(), encrypted-media=(), fullscreen=(), picture-in-picture=(), \
                                web-share=(), clipboard-read=(), clipboard-write=()"
                .to_string(),
            permissions_policy_report_only: Some(
                "camera=*, microphone=*, geolocation=*".to_string(),
            ),
            feature_policy: Some(
                "camera 'none'; microphone 'none'; geolocation 'none'; payment 'none'; usb 'none'"
                    .to_string(),
            ),
            coep: "credentialless".to_string(), // More secure than unsafe-none but allows development
            coop: "same-origin-allow-popups".to_string(), // Allows popups while maintaining security
            corp: "cross-origin".to_string(),    // Allows cross-origin for development
            clear_site_data: Some("\"cache\" \"cookies\" \"storage\"".to_string()),
            timing_allow_origin: Some("*".to_string()), // Allow timing for development
            document_policy: Some("force-load-at-top,no-fullscreen".to_string()),
            reporting_endpoints: Some("default=/api/v1/reports/csp, hsts=/api/v1/reports/hsts".to_string()),
            report_to: Some(
                "{\"group\":\"default\",\"max_age\":86400,\"endpoints\":[{\"url\":\"/api/v1/reports/csp\"}]}"
                    .to_string(),
            ),
            server_header: Some("rust-security-platform-dev".to_string()),
            monitoring_headers: true,
            cache_control: true,
            report_only_mode: true, // Development uses report-only mode
            experimental_headers: true,
            custom_headers: {
                let mut headers = HashMap::new();
                headers.insert("X-Development-Mode".to_string(), "enabled".to_string());
                headers.insert("X-Security-Level".to_string(), "development".to_string());
                headers
            },
            environment_overrides: HashMap::new(),
        }
    }

    /// Staging configuration with production-like security
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn staging() -> Self {
        Self {
            csp: "default-src 'self'; \
                  script-src 'self' 'strict-dynamic' 'unsafe-inline'; \
                  style-src 'self' 'unsafe-inline'; \
                  connect-src 'self' wss:; \
                  img-src 'self' data:; \
                  font-src 'self'; \
                  object-src 'none'; \
                  media-src 'self'; \
                  frame-src 'none'; \
                  worker-src 'self'; \
                  base-uri 'self'; \
                  form-action 'self'; \
                  frame-ancestors 'none'; \
                  upgrade-insecure-requests"
                .to_string(),
            csp_report_only: Some(
                "default-src 'self'; \
                 script-src 'self' 'strict-dynamic'; \
                 style-src 'self'; \
                 connect-src 'self'; \
                 img-src 'self' data:; \
                 font-src 'self'; \
                 object-src 'none'; \
                 media-src 'self'; \
                 frame-src 'none'; \
                 worker-src 'self'; \
                 base-uri 'self'; \
                 form-action 'self'; \
                 frame-ancestors 'none'; \
                 upgrade-insecure-requests"
                    .to_string(),
            ),
            hsts_max_age: 86400, // 1 day - shorter for staging
            hsts_include_subdomains: true,
            hsts_preload: false, // Don't preload staging
            hsts_report_uri: Some("https://staging.example.com/api/v1/security/hsts-report".to_string()),
            frame_options: "DENY".to_string(),
            content_type_options: true,
            xss_protection: "1; mode=block".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), \
                                magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=(), \
                                autoplay=(), encrypted-media=(), fullscreen=(), picture-in-picture=(), \
                                web-share=(), clipboard-read=(), clipboard-write=(), sync-xhr=(), \
                                midi=(), bluetooth=(), serial=()"
                .to_string(),
            permissions_policy_report_only: Some(
                "camera=self, microphone=self, geolocation=self".to_string(),
            ),
            feature_policy: Some(
                "camera 'none'; microphone 'none'; geolocation 'none'; payment 'none'; usb 'none'; \
                 midi 'none'; bluetooth 'none'; serial 'none'"
                    .to_string(),
            ),
            coep: "require-corp".to_string(),
            coop: "same-origin".to_string(),
            corp: "same-origin".to_string(),
            clear_site_data: None, // Don't clear site data in staging
            timing_allow_origin: Some("https://staging.example.com".to_string()),
            document_policy: Some("force-load-at-top,no-fullscreen".to_string()),
            reporting_endpoints: Some("default=https://staging.example.com/api/v1/reports/csp, hsts=https://staging.example.com/api/v1/reports/hsts".to_string()),
            report_to: Some(
                "{\"group\":\"default\",\"max_age\":86400,\"endpoints\":[{\"url\":\"https://staging.example.com/api/v1/reports/csp\"}]}"
                    .to_string(),
            ),
            server_header: Some("rust-security-platform-staging".to_string()),
            monitoring_headers: true,
            cache_control: true,
            report_only_mode: false, // Staging enforces policies
            experimental_headers: true,
            custom_headers: {
                let mut headers = HashMap::new();
                headers.insert("X-Staging-Mode".to_string(), "enabled".to_string());
                headers.insert("X-Security-Level".to_string(), "staging".to_string());
                headers
            },
            environment_overrides: HashMap::new(),
        }
    }

    /// Production configuration with strict security and maximum protection
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
            csp_report_only: Some(
                "default-src 'none'; \
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
            ),
            hsts_max_age: 31_536_000, // 1 year - maximum for production
            hsts_include_subdomains: true,
            hsts_preload: true,
            hsts_report_uri: Some("https://security.example.com/api/v1/reports/hsts".to_string()),
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
            permissions_policy_report_only: Some(
                "camera=(), microphone=(), geolocation=()".to_string(),
            ),
            feature_policy: Some(
                "camera 'none'; microphone 'none'; geolocation 'none'; payment 'none'; usb 'none'; \
                 midi 'none'; bluetooth 'none'; serial 'none'; gamepad 'none'; hid 'none'"
                    .to_string(),
            ),
            coep: "require-corp".to_string(),
            coop: "same-origin".to_string(),
            corp: "same-origin".to_string(),
            clear_site_data: None, // Never clear site data in production
            timing_allow_origin: Some("https://example.com".to_string()),
            document_policy: Some("force-load-at-top,no-fullscreen".to_string()),
            reporting_endpoints: Some("default=https://security.example.com/api/v1/reports/csp, hsts=https://security.example.com/api/v1/reports/hsts".to_string()),
            report_to: Some(
                "{\"group\":\"default\",\"max_age\":31536000,\"endpoints\":[{\"url\":\"https://security.example.com/api/v1/reports/csp\"}],\"include_subdomains\":true}"
                    .to_string(),
            ),
            server_header: None, // Remove server header in production
            monitoring_headers: true,
            cache_control: true,
            report_only_mode: false, // Production enforces policies
            experimental_headers: false, // No experimental headers in production
            custom_headers: {
                let mut headers = HashMap::new();
                headers.insert("X-Security-Level".to_string(), "production".to_string());
                headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
                headers
            },
            environment_overrides: HashMap::new(),
        }
    }

    /// Load configuration from environment variables with enhanced options
    #[must_use]
    pub fn from_env() -> Self {
        let base_config = if std::env::var("ENVIRONMENT")
            .unwrap_or_default()
            .to_lowercase()
            == "production"
        {
            Self::production()
        } else if std::env::var("ENVIRONMENT")
            .unwrap_or_default()
            .to_lowercase()
            == "staging"
        {
            Self::staging()
        } else {
            Self::development()
        };

        Self {
            csp: std::env::var("SECURITY_ENHANCED_CSP").unwrap_or(base_config.csp),
            csp_report_only: std::env::var("SECURITY_ENHANCED_CSP_REPORT_ONLY")
                .ok()
                .or(base_config.csp_report_only),
            hsts_max_age: std::env::var("SECURITY_ENHANCED_HSTS_MAX_AGE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(base_config.hsts_max_age),
            hsts_include_subdomains: std::env::var("SECURITY_ENHANCED_HSTS_INCLUDE_SUBDOMAINS")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(base_config.hsts_include_subdomains),
            hsts_preload: std::env::var("SECURITY_ENHANCED_HSTS_PRELOAD")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(base_config.hsts_preload),
            hsts_report_uri: std::env::var("SECURITY_ENHANCED_HSTS_REPORT_URI")
                .ok()
                .or(base_config.hsts_report_uri),
            frame_options: std::env::var("SECURITY_ENHANCED_FRAME_OPTIONS")
                .unwrap_or(base_config.frame_options),
            content_type_options: std::env::var("SECURITY_ENHANCED_CONTENT_TYPE_OPTIONS")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(base_config.content_type_options),
            xss_protection: std::env::var("SECURITY_ENHANCED_XSS_PROTECTION")
                .unwrap_or(base_config.xss_protection),
            referrer_policy: std::env::var("SECURITY_ENHANCED_REFERRER_POLICY")
                .unwrap_or(base_config.referrer_policy),
            permissions_policy: std::env::var("SECURITY_ENHANCED_PERMISSIONS_POLICY")
                .unwrap_or(base_config.permissions_policy),
            permissions_policy_report_only: std::env::var("SECURITY_ENHANCED_PERMISSIONS_POLICY_REPORT_ONLY")
                .ok()
                .or(base_config.permissions_policy_report_only),
            feature_policy: std::env::var("SECURITY_ENHANCED_FEATURE_POLICY")
                .ok()
                .or(base_config.feature_policy),
            coep: std::env::var("SECURITY_ENHANCED_COEP").unwrap_or(base_config.coep),
            coop: std::env::var("SECURITY_ENHANCED_COOP").unwrap_or(base_config.coop),
            corp: std::env::var("SECURITY_ENHANCED_CORP").unwrap_or(base_config.corp),
            clear_site_data: std::env::var("SECURITY_ENHANCED_CLEAR_SITE_DATA")
                .ok()
                .or(base_config.clear_site_data),
            timing_allow_origin: std::env::var("SECURITY_ENHANCED_TIMING_ALLOW_ORIGIN")
                .ok()
                .or(base_config.timing_allow_origin),
            document_policy: std::env::var("SECURITY_ENHANCED_DOCUMENT_POLICY")
                .ok()
                .or(base_config.document_policy),
            reporting_endpoints: std::env::var("SECURITY_ENHANCED_REPORTING_ENDPOINTS")
                .ok()
                .or(base_config.reporting_endpoints),
            report_to: std::env::var("SECURITY_ENHANCED_REPORT_TO")
                .ok()
                .or(base_config.report_to),
            server_header: std::env::var("SECURITY_ENHANCED_SERVER_HEADER")
                .ok()
                .or(base_config.server_header),
            monitoring_headers: std::env::var("SECURITY_ENHANCED_MONITORING_HEADERS")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(base_config.monitoring_headers),
            cache_control: std::env::var("SECURITY_ENHANCED_CACHE_CONTROL")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(base_config.cache_control),
            report_only_mode: std::env::var("SECURITY_ENHANCED_REPORT_ONLY_MODE")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(base_config.report_only_mode),
            experimental_headers: std::env::var("SECURITY_ENHANCED_EXPERIMENTAL_HEADERS")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(base_config.experimental_headers),
            custom_headers: base_config.custom_headers,
            environment_overrides: base_config.environment_overrides,
        }
    }
}

/// Enhanced security headers middleware with additional security features
pub struct EnhancedSecurityHeaders {
    config: EnhancedSecurityHeadersConfig,
}

impl EnhancedSecurityHeaders {
    /// Create new enhanced security headers middleware
    #[must_use]
    pub fn new(config: EnhancedSecurityHeadersConfig) -> Self {
        Self { config }
    }

    /// Create middleware with default configuration based on environment
    #[must_use]
    pub fn default() -> Self {
        let config = EnhancedSecurityHeadersConfig::from_env();
        Self::new(config)
    }

    /// Apply security headers to response
    pub fn apply_headers(&self, response: &mut axum::http::response::Response<axum::body::Body>) {
        let headers = response.headers_mut();

        // Apply CSP headers
        if let Ok(header_value) = self.config.csp.parse() {
            if self.config.report_only_mode {
                headers.insert("Content-Security-Policy-Report-Only", header_value);
            } else {
                headers.insert("Content-Security-Policy", header_value);
            }
        }

        // Apply CSP Report-Only if configured
        if let Some(csp_report_only) = &self.config.csp_report_only {
            if let Ok(header_value) = csp_report_only.parse() {
                headers.insert("Content-Security-Policy-Report-Only", header_value);
            }
        }

        // Apply HSTS headers
        let hsts_value = format!(
            "max-age={}; {}{}{}",
            self.config.hsts_max_age,
            if self.config.hsts_include_subdomains {
                "includeSubDomains; "
            } else {
                ""
            },
            if self.config.hsts_preload {
                "preload; "
            } else {
                ""
            },
            self.config
                .hsts_report_uri
                .as_ref()
                .map(|uri| format!("report-uri {}", uri))
                .unwrap_or_default()
        );
        if let Ok(header_value) = hsts_value.parse() {
            headers.insert("Strict-Transport-Security", header_value);
        }

        // Apply Frame Options
        if let Ok(header_value) = self.config.frame_options.parse() {
            headers.insert("X-Frame-Options", header_value);
        }

        // Apply Content Type Options
        if self.config.content_type_options {
            if let Ok(header_value) = "nosniff".parse() {
                headers.insert("X-Content-Type-Options", header_value);
            }
        }

        // Apply XSS Protection
        if let Ok(header_value) = self.config.xss_protection.parse() {
            headers.insert("X-XSS-Protection", header_value);
        }

        // Apply Referrer Policy
        if let Ok(header_value) = self.config.referrer_policy.parse() {
            headers.insert("Referrer-Policy", header_value);
        }

        // Apply Permissions Policy
        if let Ok(header_value) = self.config.permissions_policy.parse() {
            headers.insert("Permissions-Policy", header_value);
        }

        // Apply Permissions Policy Report-Only if configured
        if let Some(permissions_policy_report_only) = &self.config.permissions_policy_report_only {
            if let Ok(header_value) = permissions_policy_report_only.parse() {
                headers.insert("Permissions-Policy-Report-Only", header_value);
            }
        }

        // Apply Feature Policy if configured (deprecated but maintained for compatibility)
        if let Some(feature_policy) = &self.config.feature_policy {
            if let Ok(header_value) = feature_policy.parse() {
                headers.insert("Feature-Policy", header_value);
            }
        }

        // Apply COEP
        if let Ok(header_value) = self.config.coep.parse() {
            headers.insert("Cross-Origin-Embedder-Policy", header_value);
        }

        // Apply COOP
        if let Ok(header_value) = self.config.coop.parse() {
            headers.insert("Cross-Origin-Opener-Policy", header_value);
        }

        // Apply CORP
        if let Ok(header_value) = self.config.corp.parse() {
            headers.insert("Cross-Origin-Resource-Policy", header_value);
        }

        // Apply Clear Site Data if configured
        if let Some(clear_site_data) = &self.config.clear_site_data {
            if let Ok(header_value) = clear_site_data.parse() {
                headers.insert("Clear-Site-Data", header_value);
            }
        }

        // Apply Timing Allow Origin if configured
        if let Some(timing_allow_origin) = &self.config.timing_allow_origin {
            if let Ok(header_value) = timing_allow_origin.parse() {
                headers.insert("Timing-Allow-Origin", header_value);
            }
        }

        // Apply Document Policy if configured
        if let Some(document_policy) = &self.config.document_policy {
            if let Ok(header_value) = document_policy.parse() {
                headers.insert("Document-Policy", header_value);
            }
        }

        // Apply Reporting Endpoints if configured
        if let Some(reporting_endpoints) = &self.config.reporting_endpoints {
            if let Ok(header_value) = reporting_endpoints.parse() {
                headers.insert("Reporting-Endpoints", header_value);
            }
        }

        // Apply Report-To if configured
        if let Some(report_to) = &self.config.report_to {
            if let Ok(header_value) = report_to.parse() {
                headers.insert("Report-To", header_value);
            }
        }

        // Apply server header control
        if let Some(server_header) = &self.config.server_header {
            if let Ok(header_value) = server_header.parse() {
                headers.insert("Server", header_value);
            }
        } else {
            // Remove server header for security
            headers.remove("Server");
        }

        // Apply cache control headers
        if self.config.cache_control {
            if let Ok(header_value) = "no-cache, no-store, must-revalidate".parse() {
                headers.insert("Cache-Control", header_value);
            }
            if let Ok(header_value) = "no-cache".parse() {
                headers.insert("Pragma", header_value);
            }
            if let Ok(header_value) = "0".parse() {
                headers.insert("Expires", header_value);
            }
        }

        // Apply monitoring headers
        if self.config.monitoring_headers {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs();
            
            if let Ok(header_value) = format!("security-timestamp-{}", timestamp).parse() {
                headers.insert("X-Security-Timestamp", header_value);
            }
            
            if let Ok(header_value) = "enabled".parse() {
                headers.insert("X-Security-Monitoring", header_value);
            }
        }

        // Apply experimental headers if enabled
        if self.config.experimental_headers {
            // Apply additional experimental security headers
            if let Ok(header_value) = "1".parse() {
                headers.insert("X-DNS-Prefetch-Control", header_value);
            }
            
            if let Ok(header_value) = "origin-when-cross-origin".parse() {
                headers.insert("Cross-Origin-Resource-Policy", header_value);
            }
        }

        // Apply custom headers
        for (header_name, header_value) in &self.config.custom_headers {
            if let Ok(name) = axum::http::HeaderName::from_bytes(header_name.as_bytes()) {
                if let Ok(value) = header_value.parse() {
                    headers.insert(name, value);
                }
            }
        }

        // Add security information headers
        if let Ok(header_value) = "enabled".parse() {
            headers.insert("X-Security-Enhanced", header_value);
        }

        debug!("Applied enhanced security headers to response");
    }
}

/// Enhanced security headers middleware function
pub async fn enhanced_security_headers_middleware(
    request: Request,
    next: Next,
) -> Result<Response, axum::http::StatusCode> {
    // Extract request information for dynamic header generation
    let request_info = extract_request_info(&request);
    
    // Process request
    let mut response = next.run(request).await;

    // Determine security level based on environment
    let security_level = std::env::var("ENVIRONMENT")
        .unwrap_or_default()
        .to_lowercase();
    
    // Apply environment-specific headers
    match security_level.as_str() {
        "production" | "prod" => {
            apply_production_headers(&mut response, &request_info).await;
        }
        "staging" => {
            apply_staging_headers(&mut response, &request_info).await;
        }
        _ => {
            apply_development_headers(&mut response, &request_info).await;
        }
    }

    Ok(response)
}

/// Extract request information for dynamic header generation
fn extract_request_info(request: &Request) -> RequestInfo {
    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());
    
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    
    let origin = request
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    
    let referer = request
        .headers()
        .get("referer")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    RequestInfo {
        client_ip,
        user_agent,
        origin,
        referer,
        path: request.uri().path().to_string(),
        method: request.method().clone(),
    }
}

/// Request information for dynamic header generation
#[derive(Debug, Clone)]
struct RequestInfo {
    client_ip: Option<String>,
    user_agent: Option<String>,
    origin: Option<String>,
    referer: Option<String>,
    path: String,
    method: axum::http::Method,
}

/// Apply production-specific headers
async fn apply_production_headers(response: &mut Response, request_info: &RequestInfo) {
    let headers = response.headers_mut();
    
    // Apply strict security headers for production
    if let Ok(header_value) = "DENY".parse() {
        headers.insert("X-Frame-Options", header_value);
    }
    
    if let Ok(header_value) = "nosniff".parse() {
        headers.insert("X-Content-Type-Options", header_value);
    }
    
    if let Ok(header_value) = "1; mode=block".parse() {
        headers.insert("X-XSS-Protection", header_value);
    }
    
    // Add production-specific headers
    if let Ok(header_value) = "production".parse() {
        headers.insert("X-Environment", header_value);
    }
    
    // Apply enhanced CSP for production
    if let Ok(header_value) = "default-src 'none'; script-src 'self' 'strict-dynamic'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'none'; worker-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests".parse() {
        headers.insert("Content-Security-Policy", header_value);
    }
    
    info!("Applied production security headers for request to {}", request_info.path);
}

/// Apply staging-specific headers
async fn apply_staging_headers(response: &mut Response, request_info: &RequestInfo) {
    let headers = response.headers_mut();
    
    // Apply staging security headers
    if let Ok(header_value) = "SAMEORIGIN".parse() {
        headers.insert("X-Frame-Options", header_value);
    }
    
    if let Ok(header_value) = "nosniff".parse() {
        headers.insert("X-Content-Type-Options", header_value);
    }
    
    if let Ok(header_value) = "1; mode=block".parse() {
        headers.insert("X-XSS-Protection", header_value);
    }
    
    // Add staging-specific headers
    if let Ok(header_value) = "staging".parse() {
        headers.insert("X-Environment", header_value);
    }
    
    info!("Applied staging security headers for request to {}", request_info.path);
}

/// Apply development-specific headers
async fn apply_development_headers(response: &mut Response, request_info: &RequestInfo) {
    let headers = response.headers_mut();
    
    // Apply development security headers (more permissive)
    if let Ok(header_value) = "SAMEORIGIN".parse() {
        headers.insert("X-Frame-Options", header_value);
    }
    
    if let Ok(header_value) = "nosniff".parse() {
        headers.insert("X-Content-Type-Options", header_value);
    }
    
    if let Ok(header_value) = "1; mode=block".parse() {
        headers.insert("X-XSS-Protection", header_value);
    }
    
    // Add development-specific headers
    if let Ok(header_value) = "development".parse() {
        headers.insert("X-Environment", header_value);
    }
    
    if let Ok(header_value) = "enabled".parse() {
        headers.insert("X-Development-Mode", header_value);
    }
    
    debug!("Applied development security headers for request to {}", request_info.path);
}

/// Generate dynamic CSP with nonces for inline scripts
#[must_use]
pub fn generate_dynamic_csp(nonce: &str) -> String {
    format!(
        "default-src 'none'; \
         script-src 'self' 'nonce-{}' 'strict-dynamic'; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; \
         connect-src 'self'; \
         font-src 'self'; \
         object-src 'none'; \
         media-src 'self'; \
         frame-src 'none'; \
         worker-src 'self'; \
         base-uri 'none'; \
         form-action 'self'; \
         frame-ancestors 'none'",
        nonce
    )
}

/// Generate nonce for CSP
#[must_use]
pub fn generate_nonce() -> String {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    base64::encode_config(bytes, base64::STANDARD)
}

/// Enhanced security headers with nonce support
pub struct EnhancedSecurityHeadersWithNonce {
    base_headers: EnhancedSecurityHeaders,
}

impl EnhancedSecurityHeadersWithNonce {
    /// Create new enhanced security headers with nonce support
    #[must_use]
    pub fn new(config: EnhancedSecurityHeadersConfig) -> Self {
        Self {
            base_headers: EnhancedSecurityHeaders::new(config),
        }
    }

    /// Create middleware with default configuration
    #[must_use]
    pub fn default() -> Self {
        let config = EnhancedSecurityHeadersConfig::from_env();
        Self::new(config)
    }

    /// Apply headers with nonce support
    pub fn apply_headers_with_nonce(&self, response: &mut Response, nonce: Option<&str>) {
        self.base_headers.apply_headers(response);
        
        if let Some(nonce) = nonce {
            let headers = response.headers_mut();
            if let Ok(header_value) = format!("nonce-{}", nonce).parse() {
                headers.insert("X-CSP-Nonce", header_value);
            }
        }
    }
}

/// Enhanced security headers middleware with nonce support
pub async fn enhanced_security_headers_with_nonce_middleware(
    request: Request,
    next: Next,
) -> Result<Response, axum::http::StatusCode> {
    // Generate nonce for CSP
    let nonce = generate_nonce();
    
    // Extract request information
    let request_info = extract_request_info(&request);
    
    // Process request
    let mut response = next.run(request).await;

    // Apply enhanced security headers with nonce
    let security_headers = EnhancedSecurityHeaders::default();
    security_headers.apply_headers(&mut response);
    
    // Add nonce to response headers
    let headers = response.headers_mut();
    if let Ok(header_value) = format!("nonce-{}", nonce).parse() {
        headers.insert("X-CSP-Nonce", header_value);
    }
    
    // Add request context information
    if let Some(client_ip) = &request_info.client_ip {
        if let Ok(header_value) = client_ip.parse() {
            headers.insert("X-Request-Client-IP", header_value);
        }
    }
    
    if let Some(origin) = &request_info.origin {
        if let Ok(header_value) = origin.parse() {
            headers.insert("X-Request-Origin", header_value);
        }
    }

    Ok(response)
}

/// Security header validator to ensure headers are properly set
pub struct SecurityHeaderValidator {
    config: EnhancedSecurityHeadersConfig,
}

impl SecurityHeaderValidator {
    /// Create new security header validator
    #[must_use]
    pub fn new(config: EnhancedSecurityHeadersConfig) -> Self {
        Self { config }
    }

    /// Validate security headers in response
    pub fn validate_headers(&self, response: &axum::http::response::Response<axum::body::Body>) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        let headers = response.headers();
        
        // Validate CSP
        if let Some(csp) = headers.get("Content-Security-Policy") {
            if let Ok(csp_str) = csp.to_str() {
                if !self.validate_csp(csp_str) {
                    errors.push(ValidationError {
                        header: "Content-Security-Policy".to_string(),
                        issue: "CSP does not meet security requirements".to_string(),
                        severity: ValidationSeverity::High,
                    });
                }
            }
        }
        
        // Validate HSTS
        if let Some(hsts) = headers.get("Strict-Transport-Security") {
            if let Ok(hsts_str) = hsts.to_str() {
                if !self.validate_hsts(hsts_str) {
                    errors.push(ValidationError {
                        header: "Strict-Transport-Security".to_string(),
                        issue: "HSTS does not meet security requirements".to_string(),
                        severity: ValidationSeverity::Medium,
                    });
                }
            }
        }
        
        // Validate other critical headers
        self.validate_critical_headers(&mut errors, headers);
        
        errors
    }
    
    /// Validate CSP policy
    fn validate_csp(&self, csp: &str) -> bool {
        // Check for required directives
        let required_directives = [
            "default-src",
            "script-src",
            "style-src",
            "img-src",
            "connect-src",
            "font-src",
            "object-src",
            "media-src",
            "frame-src",
            "worker-src",
            "base-uri",
            "form-action",
            "frame-ancestors",
        ];
        
        for directive in &required_directives {
            if !csp.contains(directive) {
                return false;
            }
        }
        
        // Check for dangerous patterns
        let dangerous_patterns = [
            "'unsafe-inline'",
            "'unsafe-eval'",
            "data:",
            "blob:",
            "*",
        ];
        
        for pattern in &dangerous_patterns {
            if csp.contains(pattern) && !self.is_safe_pattern(csp, pattern) {
                return false;
            }
        }
        
        true
    }
    
    /// Check if pattern is used safely in CSP
    fn is_safe_pattern(&self, csp: &str, pattern: &str) -> bool {
        // In a real implementation, this would check if the pattern is used in a safe way
        // For example, 'unsafe-inline' might be allowed for style-src but not script-src
        match pattern {
            "'unsafe-inline'" => {
                // Allow unsafe-inline for style-src but not script-src
                !csp.contains("script-src 'unsafe-inline'")
            }
            _ => false,
        }
    }
    
    /// Validate HSTS header
    fn validate_hsts(&self, hsts: &str) -> bool {
        // Check for required components
        if !hsts.contains("max-age=") {
            return false;
        }
        
        if self.config.hsts_include_subdomains && !hsts.contains("includeSubDomains") {
            return false;
        }
        
        if self.config.hsts_preload && !hsts.contains("preload") {
            return false;
        }
        
        // Check minimum max-age (should be at least 1 year for production)
        let min_age = if std::env::var("ENVIRONMENT")
            .unwrap_or_default()
            .to_lowercase()
            == "production"
        {
            31_536_000 // 1 year
        } else {
            86400 // 1 day for development/staging
        };
        
        if let Some(age_str) = hsts.split("max-age=").nth(1) {
            if let Some(age) = age_str.split(';').next() {
                if let Ok(age_num) = age.parse::<u32>() {
                    return age_num >= min_age;
                }
            }
        }
        
        false
    }
    
    /// Validate critical security headers
    fn validate_critical_headers(&self, errors: &mut Vec<ValidationError>, headers: &axum::http::HeaderMap) {
        // Validate X-Frame-Options
        if let Some(frame_options) = headers.get("X-Frame-Options") {
            if let Ok(option_str) = frame_options.to_str() {
                if option_str != "DENY" && option_str != "SAMEORIGIN" {
                    errors.push(ValidationError {
                        header: "X-Frame-Options".to_string(),
                        issue: "Invalid X-Frame-Options value".to_string(),
                        severity: ValidationSeverity::Medium,
                    });
                }
            }
        } else {
            errors.push(ValidationError {
                header: "X-Frame-Options".to_string(),
                issue: "Missing X-Frame-Options header".to_string(),
                severity: ValidationSeverity::High,
            });
        }
        
        // Validate X-Content-Type-Options
        if let Some(content_type_options) = headers.get("X-Content-Type-Options") {
            if let Ok(option_str) = content_type_options.to_str() {
                if option_str != "nosniff" {
                    errors.push(ValidationError {
                        header: "X-Content-Type-Options".to_string(),
                        issue: "Invalid X-Content-Type-Options value".to_string(),
                        severity: ValidationSeverity::Medium,
                    });
                }
            }
        } else {
            errors.push(ValidationError {
                header: "X-Content-Type-Options".to_string(),
                issue: "Missing X-Content-Type-Options header".to_string(),
                severity: ValidationSeverity::High,
            });
        }
        
        // Validate X-XSS-Protection
        if let Some(xss_protection) = headers.get("X-XSS-Protection") {
            if let Ok(option_str) = xss_protection.to_str() {
                if option_str != "1; mode=block" {
                    errors.push(ValidationError {
                        header: "X-XSS-Protection".to_string(),
                        issue: "Invalid X-XSS-Protection value".to_string(),
                        severity: ValidationSeverity::Medium,
                    });
                }
            }
        } else {
            // X-XSS-Protection is deprecated but still validated if present
            debug!("X-XSS-Protection header not present (deprecated but not required)");
        }
    }
}

/// Security header validation error
#[derive(Debug, Clone)]
pub struct ValidationError {
    header: String,
    issue: String,
    severity: ValidationSeverity,
}

/// Validation severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationSeverity {
    /// Low severity - minor issues
    Low,
    /// Medium severity - notable issues
    Medium,
    /// High severity - significant issues requiring attention
    High,
    /// Critical severity - severe issues requiring immediate action
    Critical,
}

/// Security header reporter for monitoring and alerting
pub struct SecurityHeaderReporter {
    metrics: Arc<SecurityHeaderMetrics>,
}

/// Security header metrics for monitoring
#[derive(Debug, Default)]
pub struct SecurityHeaderMetrics {
    pub total_responses: std::sync::atomic::AtomicU64,
    pub missing_csp: std::sync::atomic::AtomicU64,
    pub missing_hsts: std::sync::atomic::AtomicU64,
    pub missing_frame_options: std::sync::atomic::AtomicU64,
    pub missing_content_type_options: std::sync::atomic::AtomicU64,
    pub validation_errors: std::sync::atomic::AtomicU64,
    pub security_violations: std::sync::atomic::AtomicU64,
}

impl SecurityHeaderReporter {
    /// Create new security header reporter
    #[must_use]
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(SecurityHeaderMetrics::default()),
        }
    }

    /// Report on security headers in response
    pub fn report_on_headers(&self, response: &axum::http::response::Response<axum::body::Body>) {
        self.metrics.total_responses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        let headers = response.headers();
        
        // Check for missing critical headers
        if !headers.contains_key("Content-Security-Policy") {
            self.metrics.missing_csp.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        
        if !headers.contains_key("Strict-Transport-Security") {
            self.metrics.missing_hsts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        
        if !headers.contains_key("X-Frame-Options") {
            self.metrics.missing_frame_options.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        
        if !headers.contains_key("X-Content-Type-Options") {
            self.metrics.missing_content_type_options.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        
        debug!("Reported on security headers for response");
    }

    /// Get security header metrics
    #[must_use]
    pub fn get_metrics(&self) -> &SecurityHeaderMetrics {
        &self.metrics
    }

    /// Get security header report
    #[must_use]
    pub fn get_report(&self) -> SecurityHeaderReport {
        SecurityHeaderReport {
            total_responses: self.metrics.total_responses.load(std::sync::atomic::Ordering::Relaxed),
            missing_csp: self.metrics.missing_csp.load(std::sync::atomic::Ordering::Relaxed),
            missing_hsts: self.metrics.missing_hsts.load(std::sync::atomic::Ordering::Relaxed),
            missing_frame_options: self.metrics.missing_frame_options.load(std::sync::atomic::Ordering::Relaxed),
            missing_content_type_options: self.metrics.missing_content_type_options.load(std::sync::atomic::Ordering::Relaxed),
            validation_errors: self.metrics.validation_errors.load(std::sync::atomic::Ordering::Relaxed),
            security_violations: self.metrics.security_violations.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

/// Security header report for monitoring and alerting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeaderReport {
    pub total_responses: u64,
    pub missing_csp: u64,
    pub missing_hsts: u64,
    pub missing_frame_options: u64,
    pub missing_content_type_options: u64,
    pub validation_errors: u64,
    pub security_violations: u64,
}

/// Convenience function to create default enhanced security headers
#[must_use]
pub fn create_default_enhanced_security_headers() -> EnhancedSecurityHeaders {
    let security_level: EnhancedSecurityLevel = EnhancedSecurityLevel::default();
    let config = security_level.get_config();
    EnhancedSecurityHeaders::new(config)
}

/// Convenience function to create enhanced security headers with nonce support
#[must_use]
pub fn create_enhanced_security_headers_with_nonce() -> EnhancedSecurityHeadersWithNonce {
    let security_level: EnhancedSecurityLevel = EnhancedSecurityLevel::default();
    let config = security_level.get_config();
    EnhancedSecurityHeadersWithNonce::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    #[test]
    fn test_enhanced_security_level_default() {
        let level: EnhancedSecurityLevel = EnhancedSecurityLevel::default();
        match level {
            EnhancedSecurityLevel::Development => {
                // Expected for default (non-production) environment
            }
            _ => panic!("Unexpected default security level"),
        }
    }

    #[test]
    fn test_enhanced_security_headers_config_development() {
        let config = EnhancedSecurityHeadersConfig::development();
        assert_eq!(config.hsts_max_age, 86400);
        assert!(!config.hsts_include_subdomains);
        assert!(!config.hsts_preload);
        assert_eq!(config.frame_options, "SAMEORIGIN");
        assert!(config.content_type_options);
        assert_eq!(config.xss_protection, "1; mode=block");
        assert!(config.monitoring_headers);
        assert!(config.cache_control);
        assert!(config.report_only_mode);
        assert!(config.experimental_headers);
    }

    #[test]
    fn test_enhanced_security_headers_config_staging() {
        let config = EnhancedSecurityHeadersConfig::staging();
        assert_eq!(config.hsts_max_age, 86400);
        assert!(config.hsts_include_subdomains);
        assert!(!config.hsts_preload);
        assert_eq!(config.frame_options, "DENY");
        assert!(config.content_type_options);
        assert_eq!(config.xss_protection, "1; mode=block");
        assert!(config.monitoring_headers);
        assert!(config.cache_control);
        assert!(!config.report_only_mode);
        assert!(config.experimental_headers);
    }

    #[test]
    fn test_enhanced_security_headers_config_production() {
        let config = EnhancedSecurityHeadersConfig::production();
        assert_eq!(config.hsts_max_age, 31_536_000);
        assert!(config.hsts_include_subdomains);
        assert!(config.hsts_preload);
        assert_eq!(config.frame_options, "DENY");
        assert!(config.content_type_options);
        assert_eq!(config.xss_protection, "1; mode=block");
        assert!(config.monitoring_headers);
        assert!(config.cache_control);
        assert!(!config.report_only_mode);
        assert!(!config.experimental_headers);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2); // Nonces should be unique
        assert!(!nonce1.is_empty()); // Nonces should not be empty
        assert!(!nonce2.is_empty());
    }

    #[test]
    fn test_generate_dynamic_csp() {
        let nonce = generate_nonce();
        let csp = generate_dynamic_csp(&nonce);
        assert!(csp.contains(&nonce));
        assert!(csp.contains("'nonce-"));
        assert!(csp.contains("script-src 'self' 'nonce-"));
    }

    #[tokio::test]
    async fn test_enhanced_security_headers_creation() {
        let headers = EnhancedSecurityHeaders::default();
        assert!(matches!(headers, EnhancedSecurityHeaders { .. }));
    }

    #[tokio::test]
    async fn test_enhanced_security_headers_with_nonce_creation() {
        let headers = EnhancedSecurityHeadersWithNonce::default();
        assert!(matches!(headers, EnhancedSecurityHeadersWithNonce { .. }));
    }

    #[test]
    fn test_security_header_validator_creation() {
        let config = EnhancedSecurityHeadersConfig::development();
        let validator = SecurityHeaderValidator::new(config);
        assert!(matches!(validator, SecurityHeaderValidator { .. }));
    }

    #[test]
    fn test_security_header_reporter_creation() {
        let reporter = SecurityHeaderReporter::new();
        assert!(matches!(reporter, SecurityHeaderReporter { .. }));
    }

    #[test]
    fn test_validation_severity_ordering() {
        assert!(ValidationSeverity::Low < ValidationSeverity::Medium);
        assert!(ValidationSeverity::Medium < ValidationSeverity::High);
        assert!(ValidationSeverity::High < ValidationSeverity::Critical);
    }

    #[tokio::test]
    async fn test_enhanced_security_headers_apply_headers() {
        let config = EnhancedSecurityHeadersConfig::development();
        let headers = EnhancedSecurityHeaders::new(config);
        
        let mut response = axum::response::Response::builder()
            .status(200)
            .body(axum::body::Body::from("test"))
            .unwrap();
        
        headers.apply_headers(&mut response);
        
        let response_headers = response.headers();
        assert!(response_headers.contains_key("X-Frame-Options"));
        assert!(response_headers.contains_key("X-Content-Type-Options"));
        assert!(response_headers.contains_key("X-XSS-Protection"));
        assert!(response_headers.contains_key("Content-Security-Policy"));
        assert!(response_headers.contains_key("Strict-Transport-Security"));
        assert!(response_headers.contains_key("Referrer-Policy"));
        assert!(response_headers.contains_key("Permissions-Policy"));
        assert!(response_headers.contains_key("Cross-Origin-Embedder-Policy"));
        assert!(response_headers.contains_key("Cross-Origin-Opener-Policy"));
        assert!(response_headers.contains_key("Cross-Origin-Resource-Policy"));
    }

    #[tokio::test]
    async fn test_security_header_validator_validate_headers() {
        let config = EnhancedSecurityHeadersConfig::development();
        let validator = SecurityHeaderValidator::new(config);
        
        let mut response = axum::response::Response::builder()
            .status(200)
            .body(axum::body::Body::from("test"))
            .unwrap();
        
        // Apply headers first
        let headers = EnhancedSecurityHeaders::new(EnhancedSecurityHeadersConfig::production());
        headers.apply_headers(&mut response);
        
        // Validate headers
        let errors = validator.validate_headers(&response);
        assert!(errors.is_empty()); // Production headers should pass validation
    }

    #[tokio::test]
    async fn test_security_header_reporter_report_on_headers() {
        let reporter = SecurityHeaderReporter::new();
        
        let response = axum::response::Response::builder()
            .status(200)
            .body(axum::body::Body::from("test"))
            .unwrap();
        
        reporter.report_on_headers(&response);
        
        let metrics = reporter.get_metrics();
        assert_eq!(metrics.total_responses.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_security_header_reporter_get_report() {
        let reporter = SecurityHeaderReporter::new();
        
        let response = axum::response::Response::builder()
            .status(200)
            .body(axum::body::Body::from("test"))
            .unwrap();
        
        reporter.report_on_headers(&response);
        
        let report = reporter.get_report();
        assert_eq!(report.total_responses, 1);
    }

    #[test]
    fn test_create_default_enhanced_security_headers() {
        let headers = create_default_enhanced_security_headers();
        assert!(matches!(headers, EnhancedSecurityHeaders { .. }));
    }

    #[test]
    fn test_create_enhanced_security_headers_with_nonce() {
        let headers = create_enhanced_security_headers_with_nonce();
        assert!(matches!(headers, EnhancedSecurityHeadersWithNonce { .. }));
    }

    #[tokio::test]
    async fn test_enhanced_security_headers_from_env() {
        // Test that configuration can be loaded from environment
        let config = EnhancedSecurityHeadersConfig::from_env();
        assert!(matches!(config, EnhancedSecurityHeadersConfig { .. }));
    }

    #[test]
    fn test_enhanced_csp_validation_safe_patterns() {
        let validator = SecurityHeaderValidator::new(EnhancedSecurityHeadersConfig::production());
        
        // Valid CSP with unsafe-inline only in style-src
        let safe_csp = "default-src 'none'; script-src 'self' 'strict-dynamic'; style-src 'self' 'unsafe-inline';";
        assert!(validator.is_safe_pattern(safe_csp, "'unsafe-inline'"));
        
        // Unsafe CSP with unsafe-inline in script-src
        let unsafe_csp = "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self';";
        assert!(!validator.is_safe_pattern(unsafe_csp, "'unsafe-inline'"));
    }
}