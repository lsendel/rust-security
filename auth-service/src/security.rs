use axum::response::IntoResponse;
use axum::{extract::Request, middleware::Next, response::Response};
#[allow(unused_imports)]
use base64::Engine as _;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;

/// Generate a token binding value from client information
pub fn generate_token_binding(client_ip: &str, user_agent: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(client_ip.as_bytes());
    hasher.update(user_agent.as_bytes());
    hasher.update(b"token_binding_salt"); // Add a salt for security
    let result = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(result)
}

/// Validate token binding to ensure token is used from the same client
pub fn validate_token_binding(stored_binding: &str, client_ip: &str, user_agent: &str) -> bool {
    let current_binding = generate_token_binding(client_ip, user_agent);
    stored_binding == current_binding
}

/// PKCE (Proof Key for Code Exchange) support
/// Generate a cryptographically secure code verifier for PKCE
pub fn generate_code_verifier() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a code challenge from a code verifier using SHA256
pub fn generate_code_challenge(code_verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let result = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result)
}

/// Verify a code verifier against a code challenge
pub fn verify_code_challenge(code_verifier: &str, code_challenge: &str) -> bool {
    let computed_challenge = generate_code_challenge(code_verifier);
    computed_challenge == code_challenge
}

/// PKCE challenge methods - Only S256 is supported for security
/// The "plain" method has been removed as it's vulnerable to downgrade attacks
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    S256,
}

impl std::str::FromStr for CodeChallengeMethod {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "S256" => Ok(CodeChallengeMethod::S256),
            "plain" => Err("Plain PKCE method is not supported for security reasons"),
            _ => Err("Invalid code challenge method. Only S256 is supported"),
        }
    }
}

/// Validate PKCE parameters - Only S256 method is supported
pub fn validate_pkce_params(
    code_verifier: &str,
    code_challenge: &str,
    method: CodeChallengeMethod,
) -> bool {
    match method {
        CodeChallengeMethod::S256 => verify_code_challenge(code_verifier, code_challenge),
    }
}

/// Request signing for critical operations
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

/// Generate a request signature using HMAC-SHA256
pub fn generate_request_signature(
    method: &str,
    path: &str,
    body: &str,
    timestamp: i64,
    secret: &str,
) -> Result<String, &'static str> {
    let message = format!("{}\n{}\n{}\n{}", method, path, body, timestamp);

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| "Invalid secret key")?;

    mac.update(message.as_bytes());
    let result = mac.finalize();

    Ok(base64::engine::general_purpose::STANDARD.encode(result.into_bytes()))
}

/// Verify a request signature
pub fn verify_request_signature(
    method: &str,
    path: &str,
    body: &str,
    timestamp: i64,
    signature: &str,
    secret: &str,
) -> Result<bool, &'static str> {
    // Check timestamp to prevent replay attacks (5 minute window)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "System time error")?
        .as_secs() as i64;

    if (now - timestamp).abs() > crate::REQUEST_TIMESTAMP_WINDOW_SECONDS {
        return Err("Request timestamp too old or too far in the future");
    }

    let expected_signature = generate_request_signature(method, path, body, timestamp, secret)?;

    // Constant-time comparison between provided and expected signatures
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for i in 0..a.len() {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }

    let provided_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature.as_bytes())
        .map_err(|_| "Invalid signature encoding")?;
    let expected_bytes = base64::engine::general_purpose::STANDARD
        .decode(expected_signature.as_bytes())
        .map_err(|_| "Internal signature encoding error")?;

    Ok(constant_time_eq(&provided_bytes, &expected_bytes))
}

/// Middleware for request signature validation
pub async fn validate_request_signature(
    request: Request,
    next: Next,
) -> Result<Response, axum::http::StatusCode> {
    // In test mode, bypass signature checks to keep integration tests simple
    if std::env::var("TEST_MODE").ok().as_deref() == Some("1") {
        return Ok(next.run(request).await);
    }
    // Only validate signatures for critical operations
    let path = request.uri().path().to_string();
    let requires_signature =
        path.starts_with("/oauth/revoke") || path.starts_with("/admin/") || path.contains("delete");

    if !requires_signature {
        return Ok(next.run(request).await);
    }

    let (parts, body) = request.into_parts();

    let signature = parts
        .headers
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(axum::http::StatusCode::BAD_REQUEST)?;

    let timestamp_str = parts
        .headers
        .get("x-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or(axum::http::StatusCode::BAD_REQUEST)?;

    let timestamp: i64 = timestamp_str.parse().map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

    // Get signing secret from environment
    let secret = match std::env::var("REQUEST_SIGNING_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            // Allow missing secret only in test mode
            if std::env::var("TEST_MODE").ok().as_deref() == Some("1") {
                String::from("test_secret")
            } else {
                return Err(axum::http::StatusCode::UNAUTHORIZED);
            }
        }
    };

    // Read the actual request body
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    let body_str =
        std::str::from_utf8(&body_bytes).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

    match verify_request_signature(
        parts.method.as_str(),
        &path,
        body_str,
        timestamp,
        signature,
        &secret,
    ) {
        Ok(true) => {
            // Reconstruct the request with the consumed body
            let request = Request::from_parts(parts, axum::body::Body::from(body_bytes));
            Ok(next.run(request).await)
        }
        Ok(false) => Err(axum::http::StatusCode::UNAUTHORIZED),
        Err(_) => Err(axum::http::StatusCode::BAD_REQUEST),
    }
}

/// Extract client information for token binding
pub fn extract_client_info(headers: &axum::http::HeaderMap) -> (String, String) {
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .split(',')
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_string();

    let user_agent =
        headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();

    (client_ip, user_agent)
}

/// Security headers middleware
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Security headers with proper error handling
    if let Ok(value) = "nosniff".parse() {
        headers.insert("X-Content-Type-Options", value);
    }
    if let Ok(value) = "DENY".parse() {
        headers.insert("X-Frame-Options", value);
    }
    if let Ok(value) = "1; mode=block".parse() {
        headers.insert("X-XSS-Protection", value);
    }
    if let Ok(value) = "max-age=31536000; includeSubDomains".parse() {
        headers.insert("Strict-Transport-Security", value);
    }
    if let Ok(value) = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'".parse() {
        headers.insert("Content-Security-Policy", value);
    }
    if let Ok(value) = "strict-origin-when-cross-origin".parse() {
        headers.insert("Referrer-Policy", value);
    }
    if let Ok(value) = "geolocation=(), microphone=(), camera=()".parse() {
        headers.insert("Permissions-Policy", value);
    }

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
    if !client_id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
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
    ServiceBuilder::new().layer(RequestBodyLimitLayer::new(crate::MAX_REQUEST_BODY_SIZE))
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
    if std::env::var("DISABLE_RATE_LIMIT").ok().as_deref() == Some("1")
        || std::env::var("TEST_MODE").ok().as_deref() == Some("1")
    {
        return next.run(request).await;
    }
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
        response.headers_mut().insert("Retry-After", format!("{}", retry_after).parse().unwrap());
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
        assert_eq!(sanitize_log_input("text\nwith\nnewlines"), "text\\nwith\\nnewlines");
        assert_eq!(sanitize_log_input("text\rwith\rcarriage"), "text\\rwith\\rcarriage");
        assert_eq!(sanitize_log_input("text\twith\ttabs"), "text\\twith\\ttabs");
    }
}
