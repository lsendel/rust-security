use axum::response::IntoResponse;
use axum::{extract::Request, middleware::Next, response::Response};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;

/// Security headers middleware
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Security headers
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    headers.insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    headers.insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
            .parse()
            .unwrap(),
    );
    headers.insert(
        "Referrer-Policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=()".parse().unwrap(),
    );

    response
}

/// Input validation for common security issues
pub fn validate_token_input(token: &str) -> Result<(), &'static str> {
    if token.is_empty() {
        return Err("Token cannot be empty");
    }

    if token.len() > 1024 {
        return Err("Token too long");
    }

    // Check for common injection patterns
    if token.contains('\0') || token.contains('\n') || token.contains('\r') {
        return Err("Invalid characters in token");
    }

    // Check for SQL injection patterns
    let suspicious_patterns = ["'", "\"", ";", "--", "/*", "*/", "xp_", "sp_"];
    for pattern in &suspicious_patterns {
        if token.to_lowercase().contains(pattern) {
            return Err("Suspicious characters detected");
        }
    }

    Ok(())
}

/// Validate client credentials format
pub fn validate_client_credentials(
    client_id: &str,
    client_secret: &str,
) -> Result<(), &'static str> {
    if client_id.is_empty() || client_secret.is_empty() {
        return Err("Client credentials cannot be empty");
    }

    if client_id.len() > 255 || client_secret.len() > 255 {
        return Err("Client credentials too long");
    }

    // Basic format validation
    if !client_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Invalid client_id format");
    }

    Ok(())
}

/// Create security middleware stack (without rate limiting for now)
pub fn security_middleware() -> ServiceBuilder<
    tower::layer::util::Stack<
        tower_http::limit::RequestBodyLimitLayer,
        tower::layer::util::Identity,
    >,
> {
    ServiceBuilder::new().layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1MB limit
}

static RATE_LIMITER: Lazy<Mutex<HashMap<String, (u32, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static RATE_LIMIT_PER_MIN: Lazy<u32> = Lazy::new(|| {
    std::env::var("RATE_LIMIT_REQUESTS_PER_MINUTE")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(60)
});

/// Simple global rate limiter: configurable requests/min per client IP (via X-Forwarded-For)
pub async fn rate_limit(request: Request, next: Next) -> Response {
    let key = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .split(',')
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_string();

    let now = Instant::now();
    let mut map = RATE_LIMITER.lock().await;
    let window = Duration::from_secs(60);
    let limit: u32 = *RATE_LIMIT_PER_MIN;
    let entry = map.entry(key).or_insert((0, now));
    if now.duration_since(entry.1) > window {
        *entry = (0, now);
    }
    if entry.0 >= limit {
        let elapsed = now.duration_since(entry.1).as_secs();
        let mut retry_after = 60u64.saturating_sub(elapsed);
        if retry_after == 0 {
            retry_after = 1;
        }
        let mut response =
            (axum::http::StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
        response
            .headers_mut()
            .insert("Retry-After", format!("{}", retry_after).parse().unwrap());
        return response;
    }
    entry.0 += 1;
    drop(map);

    next.run(request).await
}

/// Sanitize log output to prevent log injection
pub fn sanitize_log_input(input: &str) -> String {
    input
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
        .chars()
        .filter(|&c| c.is_ascii_graphic() || c == ' ' || c == '\\')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_token_input() {
        assert!(validate_token_input("valid_token_123").is_ok());
        assert!(validate_token_input("").is_err());
        assert!(validate_token_input(&"x".repeat(2000)).is_err());
        assert!(validate_token_input("token\0with\0nulls").is_err());
        assert!(validate_token_input("token\nwith\nnewlines").is_err());
        assert!(validate_token_input("token'; DROP TABLE users; --").is_err());
    }

    #[test]
    fn test_validate_client_credentials() {
        assert!(validate_client_credentials("valid_client", "valid_secret").is_ok());
        assert!(validate_client_credentials("", "secret").is_err());
        assert!(validate_client_credentials("client", "").is_err());
        assert!(validate_client_credentials("client-123_test", "secret").is_ok());
        assert!(validate_client_credentials("client@invalid", "secret").is_err());
    }

    #[test]
    fn test_sanitize_log_input() {
        assert_eq!(sanitize_log_input("normal text"), "normal text");
        assert_eq!(
            sanitize_log_input("text\nwith\nnewlines"),
            "text\\nwith\\nnewlines"
        );
        assert_eq!(
            sanitize_log_input("text\rwith\rcarriage"),
            "text\\rwith\\rcarriage"
        );
        assert_eq!(sanitize_log_input("text\twith\ttabs"), "text\\twith\\ttabs");
    }
}
