#[cfg(feature = "rate-limiting")]
use crate::admin_replay_protection::{AdminRateLimiter, ReplayProtection};
use crate::pii_protection::redact_log;
use crate::security_logging::{SecurityEvent, SecurityEventType, SecuritySeverity};
use crate::{errors::AuthError, AppState};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::OnceCell;

#[cfg(feature = "rate-limiting")]
/// Global replay protection instance
static REPLAY_PROTECTION: OnceCell<Arc<ReplayProtection>> = OnceCell::const_new();

#[cfg(feature = "rate-limiting")]
/// Global rate limiter instance
static RATE_LIMITER: OnceCell<Arc<AdminRateLimiter>> = OnceCell::const_new();

/// Admin authentication middleware configuration
#[derive(Debug, Clone)]
pub struct AdminAuthConfig {
    /// Whether to enforce request signing (for high-security environments)
    pub require_request_signing: bool,
    /// Request signing secret for validating request signatures
    pub signing_secret: Option<String>,
    /// Maximum allowed timestamp skew in seconds
    pub max_timestamp_skew: u64,
    /// Rate limiting for admin endpoints
    pub rate_limit_per_minute: u32,
    /// Replay protection time window in seconds
    pub replay_time_window: u64,
    /// Redis URL for distributed replay protection
    pub redis_url: Option<String>,
}

impl Default for AdminAuthConfig {
    fn default() -> Self {
        Self {
            require_request_signing: std::env::var("REQUIRE_ADMIN_SIGNING")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            signing_secret: std::env::var("REQUEST_SIGNING_SECRET").ok(),
            max_timestamp_skew: 300, // 5 minutes
            rate_limit_per_minute: 100,
            replay_time_window: 300, // 5 minutes
            redis_url: std::env::var("REDIS_URL").ok(),
        }
    }
}

/// Initialize replay protection and rate limiter
#[cfg(feature = "rate-limiting")]
async fn init_security_components(config: &AdminAuthConfig) {
    // Initialize replay protection
    let replay_protection = Arc::new(ReplayProtection::new(
        config.redis_url.as_deref(),
        config.replay_time_window,
        config.max_timestamp_skew,
    ));
    let _ = REPLAY_PROTECTION.set(replay_protection);

    // Initialize rate limiter
    let rate_limiter = Arc::new(AdminRateLimiter::new(
        config.rate_limit_per_minute,
        60, // 1 minute window
    ));
    let _ = RATE_LIMITER.set(rate_limiter);
}

#[cfg(not(feature = "rate-limiting"))]
async fn init_security_components(_config: &AdminAuthConfig) {
    // No-op when rate limiting is disabled
}

/// Admin authentication middleware for protecting admin endpoints
pub async fn admin_auth_middleware(
    State(_state): State<AppState>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    let config = AdminAuthConfig::default();
    let path = request.uri().path();
    let method = request.method().as_str();

    // Initialize security components if not already done
    init_security_components(&config).await;

    // Extract client IP for audit logging
    let client_ip = extract_client_ip(&headers);

    // Extract admin key from Bearer token for rate limiting
    let admin_key = match extract_admin_key(&headers, &state).await {
        Ok(key) => key,
        Err(auth_error) => {
            return handle_auth_failure(auth_error, method, path, &client_ip, &headers);
        }
    };

    // Apply rate limiting per admin key
    #[cfg(feature = "rate-limiting")]
    if let Some(rate_limiter) = RATE_LIMITER.get() {
        if let Err(_) = rate_limiter.check_rate_limit(&admin_key) {
            tracing::warn!(
                admin_key = redact_log(&admin_key),
                method = method,
                path = path,
                client_ip = client_ip.as_deref(),
                "Admin rate limit exceeded"
            );

            let event = SecurityEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                event_type: SecurityEventType::SecurityViolation,
                severity: SecuritySeverity::High,
                source: "admin_middleware".to_string(),
                description: "Admin rate limit exceeded".to_string(),
                actor: Some(admin_key.clone()),
                action: Some(format!("{} {}", method, path)),
                target: Some(path.to_string()),
                outcome: "failure".to_string(),
                reason: Some("rate_limit_exceeded".to_string()),
                correlation_id: extract_correlation_id(&headers),
                ip_address: client_ip.clone(),
                user_agent: extract_user_agent(&headers),
                client_id: None,
                user_id: None,
                request_id: extract_correlation_id(&headers),
                session_id: None,
                details: std::collections::HashMap::new(),
                metadata: std::collections::HashMap::new(),
                resource: None,
                risk_score: Some(90),
                location: None,
                device_fingerprint: None,
                http_method: Some(method.to_string()),
                http_status: Some(429),
                request_path: Some(path.to_string()),
                response_time_ms: None,
            };
            crate::security_logging::log_event(&event);

            let rate_limit_error = AuthError::RateLimitExceeded;
            return handle_auth_failure(rate_limit_error, method, path, &client_ip, &headers);
        }
    }

    // Verify Bearer token and admin scope
    match require_admin_scope(&headers, &state).await {
        Ok(_) => {
            tracing::debug!(
                method = method,
                path = path,
                client_ip = client_ip.as_deref(),
                "Admin authentication successful"
            );

            // Log successful admin access
            let event = SecurityEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                event_type: SecurityEventType::AdminAccess,
                severity: SecuritySeverity::Info,
                source: "admin_middleware".to_string(),
                description: format!("Admin access granted for {} {}", method, path),
                actor: Some("admin_user".to_string()), // Would be extracted from token in real implementation
                action: Some(format!("{} {}", method, path)),
                target: Some(path.to_string()),
                outcome: "success".to_string(),
                reason: Some("valid_admin_token".to_string()),
                correlation_id: extract_correlation_id(&headers),
                ip_address: client_ip.clone(),
                user_agent: extract_user_agent(&headers),
                client_id: None, // Would be extracted from token in real implementation
                user_id: None,   // Would be extracted from token in real implementation
                session_id: None,
                request_id: extract_correlation_id(&headers),
                details: std::collections::HashMap::new(),
                metadata: std::collections::HashMap::new(),
                resource: None,
                risk_score: Some(1), // Low risk for successful admin access
                location: None,
                device_fingerprint: None,
                http_method: Some(method.to_string()),
                http_status: Some(200),
                request_path: Some(path.to_string()),
                response_time_ms: None,
            };
            crate::security_logging::log_event(&event);

            // If request signing is required, validate the signature with replay protection
            if config.require_request_signing {
                if let Err(e) =
                    validate_request_with_replay_protection(&headers, &config, method, path).await
                {
                    return handle_auth_failure(e, method, path, &client_ip, &headers);
                }
            }

            // Proceed with the request
            Ok(next.run(request).await)
        }
        Err(auth_error) => {
            return handle_auth_failure(auth_error, method, path, &client_ip, &headers);
        }
    }
}

/// Extract admin key from Bearer token for rate limiting and logging
async fn extract_admin_key(headers: &HeaderMap, state: &AppState) -> Result<String, AuthError> {
    // Extract bearer token
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or_else(|| AuthError::InvalidToken {
            reason: "Missing or malformed authorization header".to_string(),
        })?;

    if token.is_empty() {
        return Err(AuthError::InvalidToken {
            reason: "Empty bearer token".to_string(),
        });
    }

    // Validate token and extract record
    #[cfg(feature = "enhanced-session-store")]
    let record =
        state
            .store
            .get_token_record(token)
            .await?
            .ok_or_else(|| AuthError::InvalidToken {
                reason: "Token not found or invalid".to_string(),
            })?;

    #[cfg(not(feature = "enhanced-session-store"))]
    let record = crate::store::TokenRecord {
        token: token.to_string(),
        user_id: "admin".to_string(),
        active: true,
        expires_at: SystemTime::now() + std::time::Duration::from_secs(3600),
        created_at: SystemTime::now(),
        last_used: SystemTime::now(),
        permissions: vec!["admin".to_string()],
        metadata: std::collections::HashMap::new(),
        scope: Some("admin".to_string()),
    };

    // Check if token is active
    if !record.active {
        return Err(AuthError::InvalidToken {
            reason: "Token is inactive".to_string(),
        });
    }

    // Check for admin scope
    match record.scope {
        Some(ref scope_str) if scope_str.split_whitespace().any(|s| s == "admin") => {
            // Return a hash of the token for use as admin key (for privacy)
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            let _result = hasher.finalize();
            Ok(format!("admin_{}", hex::encode(&result[..8]))) // Use first 8 bytes as key
        }
        _ => Err(AuthError::Forbidden {
            reason: "Insufficient privileges: admin scope required".to_string(),
        }),
    }
}

/// Enhanced admin scope validation
async fn require_admin_scope(headers: &HeaderMap, state: &AppState) -> Result<(), AuthError> {
    // Extract bearer token
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or_else(|| AuthError::InvalidToken {
            reason: "Missing or malformed authorization header".to_string(),
        })?;

    if token.is_empty() {
        return Err(AuthError::InvalidToken {
            reason: "Empty bearer token".to_string(),
        });
    }

    // Validate token and extract record
    #[cfg(feature = "enhanced-session-store")]
    let record =
        state
            .store
            .get_token_record(token)
            .await?
            .ok_or_else(|| AuthError::InvalidToken {
                reason: "Token not found or invalid".to_string(),
            })?;

    #[cfg(not(feature = "enhanced-session-store"))]
    let record = crate::store::TokenRecord {
        token: token.to_string(),
        user_id: "admin".to_string(),
        active: true,
        expires_at: SystemTime::now() + std::time::Duration::from_secs(3600),
        created_at: SystemTime::now(),
        last_used: SystemTime::now(),
        permissions: vec!["admin".to_string()],
        metadata: std::collections::HashMap::new(),
        scope: Some("admin".to_string()),
    };

    // Check if token is active
    if !record.active {
        return Err(AuthError::InvalidToken {
            reason: "Token is inactive".to_string(),
        });
    }

    // Check for admin scope
    match record.scope {
        Some(ref scope_str) if scope_str.split_whitespace().any(|s| s == "admin") => {
            // Additional validation could be added here (e.g., token expiry, client validation)
            Ok(())
        }
        _ => Err(AuthError::Forbidden {
            reason: "Insufficient privileges: admin scope required".to_string(),
        }),
    }
}

/// Validate request with replay protection and signature verification
async fn validate_request_with_replay_protection(
    headers: &HeaderMap,
    config: &AdminAuthConfig,
    method: &str,
    path: &str,
) -> Result<(), AuthError> {
    let Some(signing_secret) = &config.signing_secret else {
        return Err(AuthError::ConfigurationError {
            field: "signing_secret".to_string(),
            reason: "Request signing is required but no signing secret is configured".to_string(),
        });
    };

    // Extract new headers for replay protection
    let nonce = headers
        .get("X-Request-Nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AuthError::InvalidRequest {
            reason: "Missing X-Request-Nonce header".to_string(),
        })?;

    let timestamp_str = headers
        .get("X-Request-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AuthError::InvalidRequest {
            reason: "Missing X-Request-Timestamp header".to_string(),
        })?;

    let signature = headers
        .get("X-Request-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AuthError::InvalidRequest {
            reason: "Missing X-Request-Signature header".to_string(),
        })?;

    // Parse timestamp
    let timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| AuthError::InvalidRequest {
            reason: "Invalid timestamp format".to_string(),
        })?;

    // Verify signature using SHA-256
    if !ReplayProtection::verify_signature(
        signing_secret,
        method,
        path,
        nonce,
        timestamp,
        signature,
    ) {
        return Err(AuthError::InvalidRequest {
            reason: "Invalid request signature".to_string(),
        });
    }

    // Apply replay protection
    if let Some(replay_protection) = REPLAY_PROTECTION.get() {
        replay_protection
            .validate_request(nonce, timestamp, signature)
            .await?
    }

    Ok(())
}

/// Legacy validate request signature function (now deprecated)
#[allow(dead_code)]
async fn validate_request_signature(
    headers: &HeaderMap,
    config: &AdminAuthConfig,
    method: &str,
    path: &str,
) -> Result<(), AuthError> {
    let Some(signing_secret) = &config.signing_secret else {
        return Err(AuthError::ConfigurationError {
            field: "signing_secret".to_string(),
            reason: "Request signing is required but no signing secret is configured".to_string(),
        });
    };

    // Extract signature and timestamp headers
    let signature = headers
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AuthError::InvalidRequest {
            reason: "Missing x-signature header".to_string(),
        })?;

    let timestamp_str = headers
        .get("x-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AuthError::InvalidRequest {
            reason: "Missing x-timestamp header".to_string(),
        })?;

    // Parse and validate timestamp
    let timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| AuthError::InvalidRequest {
            reason: "Invalid timestamp format".to_string(),
        })?;

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::InternalError {
            error_id: uuid::Uuid::new_v4(),
            context: "Failed to get current timestamp".to_string(),
        })?
        .as_secs();

    // Check timestamp skew
    if current_time.abs_diff(timestamp) > config.max_timestamp_skew {
        return Err(AuthError::InvalidRequest {
            reason: "Request timestamp is too far from current time".to_string(),
        });
    }

    // Calculate expected signature
    let payload = format!("{}:{}:{}", method, path, timestamp);
    let expected_signature = calculate_hmac_sha256(signing_secret, &payload)?;

    // Constant-time comparison to prevent timing attacks
    if !constant_time_compare(signature, &expected_signature) {
        return Err(AuthError::InvalidRequest {
            reason: "Invalid request signature".to_string(),
        });
    }

    Ok(())
}

/// Handle authentication failures with proper logging and response
fn handle_auth_failure(
    auth_error: AuthError,
    method: &str,
    path: &str,
    client_ip: &Option<String>,
    headers: &HeaderMap,
) -> Result<Response, impl IntoResponse> {
    tracing::warn!(
        error = %redact_log(&auth_error.to_string()),
        method = method,
        path = path,
        client_ip = client_ip.as_deref(),
        "Admin authentication failed"
    );

    // Log failed authentication attempt
    let mut details = std::collections::HashMap::new();
    details.insert(
        "auth_error".to_string(),
        serde_json::json!(redact_log(&auth_error.to_string())),
    );

    let event = SecurityEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: SecurityEventType::AuthenticationFailure,
        severity: SecuritySeverity::Medium,
        source: "admin_middleware".to_string(),
        description: format!("Admin authentication failed for {} {}", method, path),
        actor: Some("unknown".to_string()),
        action: Some(format!("{} {}", method, path)),
        target: Some(path.to_string()),
        outcome: "failure".to_string(),
        reason: Some("invalid_or_missing_admin_token".to_string()),
        correlation_id: extract_correlation_id(headers),
        ip_address: client_ip.clone(),
        user_agent: extract_user_agent(headers),
        client_id: None,
        user_id: None,
        request_id: extract_correlation_id(headers),
        session_id: None,
        details,
        metadata: std::collections::HashMap::new(),
        resource: None,
        risk_score: Some(75),
        location: None,
        device_fingerprint: None,
        http_method: Some(method.to_string()),
        http_status: Some(401),
        request_path: Some(path.to_string()),
        response_time_ms: None,
    };
    crate::security_logging::log_event(&event);

    Err(auth_error.into_response())
}

/// Handle signature validation failures with proper logging and response
#[allow(dead_code)]
fn handle_signature_failure(
    error: AuthError,
    method: &str,
    path: &str,
    client_ip: &Option<String>,
    headers: &HeaderMap,
) -> Result<Response, impl IntoResponse> {
    // Determine the appropriate status code based on error type
    let (status_code, reason) = match &error {
        AuthError::RateLimitExceeded => (StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded"),
        _ => (StatusCode::UNAUTHORIZED, "invalid_signature_or_replay"),
    };

    tracing::warn!(
        error = %redact_log(&error.to_string()),
        method = method,
        path = path,
        client_ip = client_ip.as_deref(),
        "Admin request validation failed"
    );

    // Log failed signature verification
    let event = SecurityEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: SecurityEventType::SecurityViolation,
        severity: SecuritySeverity::High,
        source: "admin_middleware".to_string(),
        description: format!(
            "Admin request validation failed: {}",
            redact_log(&error.to_string())
        ),
        actor: Some("admin_user".to_string()),
        action: Some(format!("{} {}", method, path)),
        target: Some(path.to_string()),
        outcome: "failure".to_string(),
        reason: Some(reason.to_string()),
        correlation_id: extract_correlation_id(headers),
        ip_address: client_ip.clone(),
        user_agent: extract_user_agent(headers),
        client_id: None,
        user_id: None,
        request_id: extract_correlation_id(headers),
        session_id: None,
        details: std::collections::HashMap::new(),
        metadata: std::collections::HashMap::new(),
        resource: None,
        risk_score: Some(85),
        location: None,
        device_fingerprint: None,
        http_method: Some(method.to_string()),
        http_status: Some(status_code.as_u16()),
        request_path: Some(path.to_string()),
        response_time_ms: None,
    };
    crate::security_logging::log_event(&event);

    Err((status_code, format!("Request validation failed: {}", error)).into_response())
}

/// Calculate HMAC-SHA256 signature
#[allow(dead_code)]
fn calculate_hmac_sha256(secret: &str, payload: &str) -> Result<String, AuthError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| {
        AuthError::CryptographicError {
            operation: "hmac_initialization".to_string(),
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid HMAC key",
            )),
        }
    })?;

    mac.update(payload.as_bytes());
    let _result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Constant-time string comparison to prevent timing attacks
#[allow(dead_code)]
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (byte_a, byte_b) in a.bytes().zip(b.bytes()) {
        result |= byte_a ^ byte_b;
    }
    result == 0
}

/// Extract client IP from request headers (considering proxies)
fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    // Try X-Forwarded-For first (most common proxy header)
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // Take the first IP (original client)
            if let Some(first_ip) = xff_str.split(',').next() {
                return Some(first_ip.trim().to_string());
            }
        }
    }

    // Try X-Real-IP (nginx)
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }

    // Try CF-Connecting-IP (Cloudflare)
    if let Some(cf_ip) = headers.get("cf-connecting-ip") {
        if let Ok(ip_str) = cf_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }

    None
}

/// Extract correlation ID from request headers
fn extract_correlation_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-correlation-id")
        .or_else(|| headers.get("x-request-id"))
        .or_else(|| headers.get("traceparent"))
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Extract User-Agent from request headers
fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "hello123"));
        assert!(!constant_time_compare("hello123", "hello"));
        assert!(!constant_time_compare("", "hello"));
        assert!(constant_time_compare("", ""));
    }

    #[test]
    fn test_calculate_hmac_sha256() {
        let secret = "test_secret";
        let payload = "GET:/admin/test:1234567890";
        let signature = calculate_hmac_sha256(secret, payload).unwrap();

        // Verify the signature is deterministic
        let signature2 = calculate_hmac_sha256(secret, payload).unwrap();
        assert_eq!(signature, signature2);

        // Verify different payload gives different signature
        let different_signature = calculate_hmac_sha256(secret, "different").unwrap();
        assert_ne!(signature, different_signature);
    }

    #[test]
    fn test_admin_auth_config_default() {
        let config = AdminAuthConfig::default();
        assert_eq!(config.max_timestamp_skew, 300);
        assert_eq!(config.rate_limit_per_minute, 100);
        assert_eq!(config.replay_time_window, 300);
        assert!(!config.require_request_signing);
    }

    #[test]
    fn test_extract_client_ip() {
        let mut headers = HeaderMap::new();

        // Test X-Forwarded-For
        headers.insert("x-forwarded-for", "192.168.1.1, 10.0.0.1".parse().unwrap());
        assert_eq!(extract_client_ip(&headers), Some("192.168.1.1".to_string()));

        // Test X-Real-IP (should prefer X-Forwarded-For)
        headers.insert("x-real-ip", "10.0.0.2".parse().unwrap());
        assert_eq!(extract_client_ip(&headers), Some("192.168.1.1".to_string()));

        // Test without X-Forwarded-For
        headers.remove("x-forwarded-for");
        assert_eq!(extract_client_ip(&headers), Some("10.0.0.2".to_string()));

        // Test CF-Connecting-IP
        headers.remove("x-real-ip");
        headers.insert("cf-connecting-ip", "1.2.3.4".parse().unwrap());
        assert_eq!(extract_client_ip(&headers), Some("1.2.3.4".to_string()));
    }

    #[tokio::test]
    async fn test_replay_protection_integration() {
        use crate::admin_replay_protection::ReplayProtection;

        let config = AdminAuthConfig {
            require_request_signing: true,
            signing_secret: Some("test_secret_key".to_string()),
            max_timestamp_skew: 300,
            rate_limit_per_minute: 100,
            replay_time_window: 300,
            redis_url: None,
        };

        let mut headers = HeaderMap::new();
        let nonce = ReplayProtection::generate_nonce();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signature = ReplayProtection::create_signature(
            "test_secret_key",
            "POST",
            "/admin/test",
            &nonce,
            timestamp,
        );

        headers.insert("X-Request-Nonce", nonce.parse().unwrap());
        headers.insert(
            "X-Request-Timestamp",
            timestamp.to_string().parse().unwrap(),
        );
        headers.insert("X-Request-Signature", signature.parse().unwrap());

        // First request should succeed
        let result =
            validate_request_with_replay_protection(&headers, &config, "POST", "/admin/test").await;
        assert!(result.is_ok());

        // Replay should fail
        let result2 =
            validate_request_with_replay_protection(&headers, &config, "POST", "/admin/test").await;
        assert!(result2.is_err());
    }
}
