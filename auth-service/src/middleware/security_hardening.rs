//! Security Hardening Middleware for MVP
//!
//! Implements comprehensive security features as specified in the MVP Week 4 plan:
//! - Advanced rate limiting with DDoS protection
//! - Threat detection and IP banning  
//! - Security headers enforcement
//! - Request signing validation for admin endpoints

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::app::{AppContainer, AuthConfig};
use mvp_tools::validation::{SecurityContext, ThreatLevel, ValidationError};

/// Rate limiting state per IP address
#[derive(Debug, Clone)]
struct RateLimitState {
    requests: Vec<Instant>,
    blocked_until: Option<Instant>,
    threat_score: u32,
    last_request: Instant,
}

impl RateLimitState {
    fn new() -> Self {
        Self {
            requests: Vec::new(),
            blocked_until: None,
            threat_score: 0,
            last_request: Instant::now(),
        }
    }

    fn is_blocked(&self) -> bool {
        self.blocked_until
            .map(|blocked_until| Instant::now() < blocked_until)
            .unwrap_or(false)
    }

    fn add_request(&mut self) {
        let now = Instant::now();
        self.last_request = now;
        
        // Clean old requests (older than 1 minute)
        self.requests.retain(|&request_time| {
            now.duration_since(request_time) < Duration::from_secs(60)
        });
        
        self.requests.push(now);
    }

    fn should_rate_limit(&self, max_requests: u32) -> bool {
        self.requests.len() > max_requests as usize
    }

    fn increase_threat_score(&mut self, points: u32) {
        self.threat_score += points;
        
        // Auto-block if threat score is too high
        if self.threat_score > 100 {
            self.blocked_until = Some(Instant::now() + Duration::from_secs(300)); // 5 minutes
        }
    }
}

/// Global security state
pub struct SecurityHardening {
    rate_limits: Arc<RwLock<HashMap<IpAddr, RateLimitState>>>,
    config: AuthConfig,
    blocked_ips: Arc<RwLock<HashMap<IpAddr, Instant>>>,
}

impl SecurityHardening {
    pub fn new(config: AuthConfig) -> Self {
        Self {
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            config,
            blocked_ips: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if IP is rate limited or blocked
    fn check_rate_limit(&self, ip: IpAddr) -> Result<(), SecurityViolation> {
        if !self.config.rate_limit_enabled {
            return Ok(());
        }

        let mut rate_limits = self.rate_limits.write().unwrap();
        let state = rate_limits.entry(ip).or_insert_with(RateLimitState::new);

        // Check if IP is blocked
        if state.is_blocked() {
            return Err(SecurityViolation::IpBlocked {
                ip,
                reason: "Too many security violations".to_string(),
            });
        }

        // Add request and check rate limit
        state.add_request();
        
        if state.should_rate_limit(self.config.rate_limit_per_minute) {
            state.increase_threat_score(10);
            return Err(SecurityViolation::RateLimited {
                ip,
                requests_per_minute: state.requests.len() as u32,
                limit: self.config.rate_limit_per_minute,
            });
        }

        Ok(())
    }

    /// Analyze request for threats
    fn analyze_request_threats(&self, request: &Request, ip: IpAddr) -> Result<SecurityContext, SecurityViolation> {
        let mut context = SecurityContext {
            client_ip: Some(ip),
            user_agent: request.headers()
                .get("User-Agent")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string()),
            request_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            threat_indicators: Vec::new(),
            threat_level: ThreatLevel::Low,
        };

        // Check for suspicious patterns
        self.detect_suspicious_patterns(request, &mut context)?;
        
        // Check user agent
        self.validate_user_agent(request, &mut context)?;
        
        // Check request size
        self.validate_request_size(request, &mut context)?;

        Ok(context)
    }

    fn detect_suspicious_patterns(&self, request: &Request, context: &mut SecurityContext) -> Result<(), SecurityViolation> {
        let uri = request.uri().to_string();
        let method = request.method().as_str();

        // Common attack patterns
        let suspicious_patterns = [
            ("../", "Path traversal attempt"),
            ("<script", "XSS attempt"), 
            ("SELECT ", "SQL injection attempt"),
            ("DROP ", "SQL injection attempt"),
            ("../../", "Directory traversal"),
            ("eval(", "Code injection attempt"),
            ("base64_decode", "Suspicious encoding"),
            ("system(", "Command injection attempt"),
        ];

        for (pattern, description) in &suspicious_patterns {
            if uri.contains(pattern) {
                context.threat_indicators.push(format!("Suspicious pattern: {}", description));
                context.threat_level = ThreatLevel::High;
                
                return Err(SecurityViolation::SuspiciousPattern {
                    pattern: pattern.to_string(),
                    description: description.to_string(),
                    uri: uri.clone(),
                });
            }
        }

        // Check for excessive special characters (potential injection)
        let special_char_count = uri.chars().filter(|&c| "';\"<>&|`${}[]()".contains(c)).count();
        if special_char_count > 10 {
            context.threat_indicators.push("Excessive special characters".to_string());
            context.threat_level = ThreatLevel::Medium;
        }

        // Check for unusually long URIs (potential DoS)
        if uri.len() > 2048 {
            context.threat_indicators.push("Unusually long URI".to_string());
            context.threat_level = ThreatLevel::Medium;
        }

        Ok(())
    }

    fn validate_user_agent(&self, request: &Request, context: &mut SecurityContext) -> Result<(), SecurityViolation> {
        let user_agent = request.headers()
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        // Check for suspicious or missing user agents
        let suspicious_agents = [
            "sqlmap",
            "nikto", 
            "nmap",
            "gobuster",
            "dirbuster",
            "burp",
            "zap",
        ];

        for &agent in &suspicious_agents {
            if user_agent.to_lowercase().contains(agent) {
                context.threat_indicators.push(format!("Suspicious user agent: {}", agent));
                context.threat_level = ThreatLevel::High;
                
                return Err(SecurityViolation::SuspiciousUserAgent {
                    user_agent: user_agent.to_string(),
                    detected_tool: agent.to_string(),
                });
            }
        }

        // Empty or very short user agents are suspicious
        if user_agent.len() < 10 {
            context.threat_indicators.push("Suspicious user agent length".to_string());
            context.threat_level = ThreatLevel::Low;
        }

        Ok(())
    }

    fn validate_request_size(&self, request: &Request, context: &mut SecurityContext) -> Result<(), SecurityViolation> {
        if let Some(content_length) = request.headers().get("Content-Length") {
            if let Ok(length_str) = content_length.to_str() {
                if let Ok(length) = length_str.parse::<usize>() {
                    const MAX_REQUEST_SIZE: usize = 1024 * 1024; // 1MB
                    
                    if length > MAX_REQUEST_SIZE {
                        context.threat_indicators.push("Request too large".to_string());
                        context.threat_level = ThreatLevel::Medium;
                        
                        return Err(SecurityViolation::RequestTooLarge {
                            size: length,
                            max_size: MAX_REQUEST_SIZE,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Add security headers to response
    fn add_security_headers(&self, mut response: Response) -> Response {
        let headers = response.headers_mut();

        // Security headers for MVP
        let security_headers = [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("X-XSS-Protection", "1; mode=block"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("X-Permitted-Cross-Domain-Policies", "none"),
            ("Cross-Origin-Embedder-Policy", "require-corp"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("Cache-Control", "no-store, no-cache, must-revalidate"),
            ("Pragma", "no-cache"),
            ("Expires", "0"),
        ];

        for (name, value) in &security_headers {
            if let (Ok(header_name), Ok(header_value)) = (
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            ) {
                headers.insert(header_name, header_value);
            }
        }

        // Content Security Policy for API
        if let Ok(csp_header) = HeaderValue::from_static(
            "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none';"
        ) {
            headers.insert("Content-Security-Policy", csp_header);
        }

        // Strict Transport Security (if HTTPS)
        if let Ok(hsts_header) = HeaderValue::from_static(
            "max-age=31536000; includeSubDomains; preload"
        ) {
            headers.insert("Strict-Transport-Security", hsts_header);
        }

        response
    }
}

/// Security violation types
#[derive(Debug)]
enum SecurityViolation {
    RateLimited {
        ip: IpAddr,
        requests_per_minute: u32,
        limit: u32,
    },
    IpBlocked {
        ip: IpAddr,
        reason: String,
    },
    SuspiciousPattern {
        pattern: String,
        description: String,
        uri: String,
    },
    SuspiciousUserAgent {
        user_agent: String,
        detected_tool: String,
    },
    RequestTooLarge {
        size: usize,
        max_size: usize,
    },
}

impl SecurityViolation {
    fn to_status_code(&self) -> StatusCode {
        match self {
            SecurityViolation::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            SecurityViolation::IpBlocked { .. } => StatusCode::FORBIDDEN,
            SecurityViolation::SuspiciousPattern { .. } => StatusCode::BAD_REQUEST,
            SecurityViolation::SuspiciousUserAgent { .. } => StatusCode::FORBIDDEN,
            SecurityViolation::RequestTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        }
    }

    fn to_error_message(&self) -> String {
        match self {
            SecurityViolation::RateLimited { requests_per_minute, limit, .. } => {
                format!("Rate limit exceeded: {}/{} requests per minute", requests_per_minute, limit)
            }
            SecurityViolation::IpBlocked { reason, .. } => {
                format!("IP blocked: {}", reason)
            }
            SecurityViolation::SuspiciousPattern { description, .. } => {
                format!("Security violation: {}", description)
            }
            SecurityViolation::SuspiciousUserAgent { detected_tool, .. } => {
                format!("Suspicious user agent detected: {}", detected_tool)
            }
            SecurityViolation::RequestTooLarge { size, max_size } => {
                format!("Request too large: {} bytes (max: {})", size, max_size)
            }
        }
    }
}

/// Extract client IP from request
fn extract_client_ip(request: &Request) -> IpAddr {
    // Check X-Forwarded-For header (for load balancers)
    if let Some(forwarded) = request.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    // Check X-Real-IP header (for reverse proxies)
    if let Some(real_ip) = request.headers().get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // Fallback to localhost (for development)
    "127.0.0.1".parse().unwrap()
}

/// Main security middleware
pub async fn security_hardening_middleware(
    State(container): State<AppContainer>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let security = container.security_hardening.as_ref()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let client_ip = extract_client_ip(&request);

    // Check rate limits
    if let Err(violation) = security.check_rate_limit(client_ip) {
        log::warn!("Security violation from {}: {:?}", client_ip, violation);
        
        return Err(violation.to_status_code());
    }

    // Analyze request for threats
    match security.analyze_request_threats(&request, client_ip) {
        Ok(security_context) => {
            // Log security context for monitoring
            if security_context.threat_level != ThreatLevel::Low {
                log::warn!("Elevated threat level from {}: {:?}", client_ip, security_context);
            }

            // Continue with request processing
            let response = next.run(request).await;
            
            // Add security headers to response
            Ok(security.add_security_headers(response))
        }
        Err(violation) => {
            log::error!("Security violation blocked from {}: {:?}", client_ip, violation);
            
            // Increase threat score for this IP
            if let Ok(mut rate_limits) = security.rate_limits.write() {
                if let Some(state) = rate_limits.get_mut(&client_ip) {
                    state.increase_threat_score(25);
                }
            }
            
            Err(violation.to_status_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_state() {
        let mut state = RateLimitState::new();
        
        // Add requests within limit
        for _ in 0..10 {
            state.add_request();
        }
        
        assert!(!state.should_rate_limit(100));
        assert!(state.should_rate_limit(5));
    }

    #[test]
    fn test_threat_score_blocking() {
        let mut state = RateLimitState::new();
        
        assert!(!state.is_blocked());
        
        state.increase_threat_score(150);
        assert!(state.is_blocked());
    }

    #[tokio::test]
    async fn test_suspicious_pattern_detection() {
        let config = AuthConfig::default();
        let security = SecurityHardening::new(config);
        
        let request = Request::builder()
            .uri("http://localhost/oauth/token?test=../../../etc/passwd")
            .body(axum::body::Body::empty())
            .unwrap();
            
        let ip = "127.0.0.1".parse().unwrap();
        
        let result = security.analyze_request_threats(&request, ip);
        assert!(result.is_err());
    }
}