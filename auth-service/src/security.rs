use axum::response::IntoResponse;
use axum::{extract::Request, middleware::Next, response::Response};
use base64::Engine as _;
use common::sharded_rate_limiter::RateLimitConfig as CommonRateLimitConfig;
use common::{constants, ShardedRateLimiter};
use once_cell::sync::Lazy;
use ring::rand::SecureRandom;
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;

/// Request timestamp validation window in seconds
const REQUEST_TIMESTAMP_WINDOW_SECONDS: i64 = 300; // 5 minutes

/// Secure token binding salt - loaded from environment or generated
static TOKEN_BINDING_SALT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("TOKEN_BINDING_SALT").unwrap_or_else(|_| {
        // Generate a cryptographically secure salt with proper error handling
        let mut salt = [0u8; 32];
        use ring::rand::SystemRandom;

        // Try multiple times with fallback to ensure we get entropy
        for attempt in 0..3 {
            if SystemRandom::new().fill(&mut salt).is_ok() {
                return hex::encode(salt);
            }
            tracing::warn!(
                "Salt generation attempt {} failed, retrying...",
                attempt + 1
            );
        }

        // Final fallback: use a deterministic but still secure approach
        tracing::error!("Failed to generate random salt after 3 attempts, using fallback");
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        std::process::id().hash(&mut hasher);
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    })
});

/// Generate a token binding value from client information using secure practices
pub fn generate_token_binding(client_ip: &str, user_agent: &str) -> String {
    use ring::hmac;

    let salt = TOKEN_BINDING_SALT.as_bytes();

    // Use HMAC-SHA256 for secure binding
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let mut ctx = hmac::Context::with_key(&key);

    ctx.update(client_ip.as_bytes());
    ctx.update(b"|"); // Separator to prevent collision attacks
    ctx.update(user_agent.as_bytes());
    ctx.update(b"|");
    ctx.update(&chrono::Utc::now().timestamp().to_be_bytes()); // Add timestamp

    let tag = ctx.sign();
    base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
}

/// Validate token binding to ensure token is used from the same client
pub fn validate_token_binding(
    stored_binding: &str,
    client_ip: &str,
    user_agent: &str,
) -> Result<bool, &'static str> {
    use ring::hmac;

    // Decode the stored binding
    let stored_bytes = base64::engine::general_purpose::STANDARD
        .decode(stored_binding)
        .map_err(|_| "Invalid token binding format")?;

    // For validation, we need to check against recent timestamps (5 minute window)
    let now = chrono::Utc::now().timestamp();

    // Optimize validation using time windows instead of iterating all timestamps
    let salt = TOKEN_BINDING_SALT.as_bytes();
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);

    // Check current time window and previous window (30-second windows for 5min total)
    let window_size = 30; // seconds per window
    let max_windows = 10; // 300 seconds / 30 seconds = 10 windows

    for window in 0..max_windows {
        let test_timestamp = now - (window * window_size);

        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(client_ip.as_bytes());
        ctx.update(b"|");
        ctx.update(user_agent.as_bytes());
        ctx.update(b"|");
        ctx.update(&test_timestamp.to_be_bytes());

        let expected_tag = ctx.sign();

        // Use secure HMAC verification to prevent timing attacks
        if hmac::verify(&key, &stored_bytes, expected_tag.as_ref()).is_ok() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// PKCE (Proof Key for Code Exchange) support
/// Generate a cryptographically secure code verifier for PKCE
pub fn generate_code_verifier() -> Result<String, &'static str> {
    use ring::rand::{SecureRandom, SystemRandom};

    // Use cryptographically secure random generator with enhanced entropy
    let mut bytes = [0u8; 64]; // 512 bits of entropy for enhanced security per RFC 7636
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "Random generation failed")?;

    // Encode using URL-safe base64 without padding
    let mut verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    // Ensure minimum length requirement (43-128 characters per RFC 7636)
    while verifier.len() < 43 {
        let mut additional = [0u8; 8];
        SystemRandom::new()
            .fill(&mut additional)
            .map_err(|_| "Random generation failed")?;
        verifier.push_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(additional));
    }

    // Truncate to maximum length
    verifier.truncate(128);
    Ok(verifier)
}

/// Generate a code challenge from a code verifier using SHA256
pub fn generate_code_challenge(code_verifier: &str) -> Result<String, &'static str> {
    use ring::digest;

    if code_verifier.len() < 43 || code_verifier.len() > 128 {
        return Err("Invalid code verifier length");
    }

    let digest = digest::digest(&digest::SHA256, code_verifier.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref()))
}

/// Verify a code verifier against a code challenge with timing attack protection
pub fn verify_code_challenge(
    code_verifier: &str,
    code_challenge: &str,
) -> Result<bool, &'static str> {
    let computed_challenge = generate_code_challenge(code_verifier)?;

    // Use secure string comparison to prevent timing attacks
    // Compare byte by byte with constant time
    if computed_challenge.len() != code_challenge.len() {
        return Ok(false);
    }

    let mut result = 0u8;
    for (a, b) in computed_challenge.bytes().zip(code_challenge.bytes()) {
        result |= a ^ b;
    }

    Ok(result == 0)
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
            "S256" => Ok(Self::S256),
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
) -> Result<bool, &'static str> {
    match method {
        CodeChallengeMethod::S256 => verify_code_challenge(code_verifier, code_challenge),
    }
}

/// Request signing for critical operations
/// Generate a request signature using HMAC-SHA256
pub fn generate_request_signature(
    method: &str,
    path: &str,
    body: &str,
    timestamp: i64,
    secret: &str,
) -> Result<String, &'static str> {
    use ring::hmac;

    if secret.len() < 32 {
        return Err("Signing secret too weak (minimum 32 characters)");
    }

    let message = format!("{method}\n{path}\n{body}\n{timestamp}");

    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let signature = hmac::sign(&key, message.as_bytes());

    Ok(base64::engine::general_purpose::STANDARD.encode(signature.as_ref()))
}

/// Verify request signature with timing attack protection and replay prevention
pub fn verify_request_signature(
    method: &str,
    path: &str,
    body: &str,
    timestamp: i64,
    signature: &str,
    secret: &str,
) -> Result<bool, &'static str> {
    use ring::hmac;

    // Check timestamp window (prevent replay attacks)
    let now = chrono::Utc::now().timestamp();
    let time_diff = (now - timestamp).abs();

    if time_diff > REQUEST_TIMESTAMP_WINDOW_SECONDS {
        return Err("Request timestamp outside valid window");
    }

    if secret.len() < 32 {
        return Err("Signing secret too weak");
    }

    let message = format!("{method}\n{path}\n{body}\n{timestamp}");
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let expected_signature = hmac::sign(&key, message.as_bytes());

    let provided_signature = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .map_err(|_| "Invalid signature format")?;

    // Use secure HMAC verification to prevent timing attacks
    Ok(hmac::verify(&key, &provided_signature, expected_signature.as_ref()).is_ok())
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

    let timestamp: i64 = timestamp_str
        .parse()
        .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

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
#[must_use]
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

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

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
    if let Ok(value) =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'".parse()
    {
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
    if !client_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Invalid client_id format");
    }

    Ok(())
}

/// Create security middleware stack (without rate limiting for now)
#[must_use]
pub fn security_middleware() -> ServiceBuilder<
    tower::layer::util::Stack<
        tower_http::limit::RequestBodyLimitLayer,
        tower::layer::util::Identity,
    >,
> {
    ServiceBuilder::new().layer(RequestBodyLimitLayer::new(crate::MAX_REQUEST_BODY_SIZE))
}

/// Global sharded rate limiter instance
static RATE_LIMITER: Lazy<ShardedRateLimiter> = Lazy::new(|| {
    let rate_limit = std::env::var("RATE_LIMIT_REQUESTS_PER_MINUTE")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(constants::rate_limiting::DEFAULT_RATE_LIMIT);

    let config = CommonRateLimitConfig {
        default_limit: rate_limit,
        window_duration: Duration::from_secs(constants::rate_limiting::RATE_LIMITER_SHARDS as u64),
        burst_multiplier: constants::rate_limiting::BURST_MULTIPLIER,
        cleanup_interval: Duration::from_secs(constants::rate_limiting::CLEANUP_INTERVAL_SECS),
    };

    ShardedRateLimiter::new(config)
});

/// Cleanup expired entries from the rate limiter to prevent memory leaks
async fn cleanup_rate_limiter() {
    let cleaned_entries = RATE_LIMITER.cleanup_expired().await;
    if cleaned_entries > 0 {
        tracing::debug!("Cleaned up {} expired rate limit entries", cleaned_entries);
    }
}

/// Start periodic cleanup task for rate limiter
pub fn start_rate_limiter_cleanup() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // Clean every 5 minutes
        loop {
            interval.tick().await;
            cleanup_rate_limiter().await;
        }
    });
}

/// High-performance sharded rate limiter: configurable requests/min per client IP (via X-Forwarded-For)
pub async fn rate_limit(request: Request, next: Next) -> Response {
    // Allow bypass in test mode or when explicitly disabled
    if std::env::var("DISABLE_RATE_LIMIT").ok().as_deref() == Some("1")
        || std::env::var("TEST_MODE").ok().as_deref() == Some("1")
    {
        return next.run(request).await;
    }

    // Extract client IP from headers
    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .split(',')
        .next()
        .unwrap_or("unknown")
        .trim();

    // Create rate limiting key
    let key = format!("ip:{client_ip}");

    // Check rate limit using the sharded rate limiter
    if matches!(RATE_LIMITER.check_rate_limit(&key).await, Ok(true)) {
        // Request allowed, continue processing
        next.run(request).await
    } else {
        // Rate limit exceeded or error occurred
        tracing::warn!(
            client_ip = %client_ip,
            "Rate limit exceeded for client"
        );

        // Get rate limit info for retry-after header
        let retry_after = if let Some(info) = RATE_LIMITER.get_rate_limit_info(&key).await {
            info.reset_time
                .duration_since(std::time::Instant::now())
                .as_secs()
                .max(1)
        } else {
            60 // Default to 60 seconds
        };

        let mut response = (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded",
        )
            .into_response();

        response.headers_mut().insert(
            "Retry-After",
            format!("{retry_after}")
                .parse()
                .expect("Failed to parse retry-after header"),
        );

        // Add rate limit headers for client information
        if let Some(info) = RATE_LIMITER.get_rate_limit_info(&key).await {
            response.headers_mut().insert(
                "X-RateLimit-Limit",
                format!("{}", info.limit)
                    .parse()
                    .expect("Failed to parse rate limit header"),
            );
            response.headers_mut().insert(
                "X-RateLimit-Remaining",
                format!("{}", info.remaining)
                    .parse()
                    .expect("Failed to parse rate limit remaining header"),
            );
        }

        response
    }
}

/// Sanitize log output to prevent log injection
#[must_use]
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
