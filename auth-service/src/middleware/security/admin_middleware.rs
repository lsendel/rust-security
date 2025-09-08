use crate::application::state::app_state::AppState;
use crate::infrastructure::http::policy_client;
use crate::infrastructure::security::security_logging::{
    SecurityEvent, SecurityEventType, SecuritySeverity,
};
#[cfg(feature = "rate-limiting")]
use crate::middleware::security::admin_replay_protection::{AdminRateLimiter, ReplayProtection};
use crate::pii_protection::redact_log;
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
fn init_security_components(config: &AdminAuthConfig) {
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
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    let config = AdminAuthConfig::default();
    let path = request.uri().path();
    let method = request.method().as_str();

    // Initialize security components if not already done
    init_security_components(&config);

    // Extract client IP for audit logging
    let client_ip = extract_client_ip(&headers);

    // Extract admin key from Bearer token for rate limiting
    let admin_key = match extract_admin_key(&headers, &state).await {
        Ok(key) => key,
        Err(auth_error) => {
            return handle_auth_failure(auth_error, method, path, client_ip.as_ref(), &headers);
        }
    };

    // Apply rate limiting per admin key
    #[cfg(feature = "rate-limiting")]
    if let Some(rate_limiter) = RATE_LIMITER.get() {
        if rate_limiter.check_rate_limit(&admin_key).is_err() {
            tracing::warn!(
                admin_key = redact_log(&admin_key),
                method = method,
                path = path,
                client_ip = client_ip,
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
                action: Some(format!("{method} {path}")),
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
            crate::infrastructure::security::security_logging::log_event(&event);

            let rate_limit_error = crate::shared::error::AppError::RateLimitExceeded;
            return handle_auth_failure(
                rate_limit_error,
                method,
                path,
                client_ip.as_ref(),
                &headers,
            );
        }
    }

    // Verify Bearer token and admin scope
    match require_admin_scope(&headers, &state).await {
        Ok(()) => {
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
                description: format!("Admin access granted for {method} {path}"),
                actor: Some("admin_user".to_string()), // Would be extracted from token in real implementation
                action: Some(format!("{method} {path}")),
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
            crate::infrastructure::security::security_logging::log_event(&event);

            // If request signing is required, validate the signature with replay protection
            if config.require_request_signing {
                if let Err(e) =
                    validate_request_with_replay_protection(&headers, &config, method, path).await
                {
                    return handle_auth_failure(e, method, path, client_ip.as_ref(), &headers);
                }
            }

            // Optional remote policy gate for admin endpoints
            if std::env::var("ENABLE_REMOTE_POLICY")
                .unwrap_or_else(|_| "0".to_string())
                .eq("1")
            {
                let req_id = headers
                    .get("x-request-id")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                let policy_base = std::env::var("POLICY_SERVICE_BASE_URL")
                    .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string());
                // Derive granular admin action from path
                fn admin_action_for(path: &str, method: &str) -> String {
                    // Users admin APIs (collection vs. single resource)
                    if path.starts_with("/admin/users/") {
                        // likely /admin/users/:id
                        return match method {
                            "GET" => "Admin::users_read_one".to_string(),
                            "PUT" | "PATCH" => "Admin::users_update_one".to_string(),
                            "DELETE" => "Admin::users_delete_one".to_string(),
                            _ => format!("Admin::users_manage_one:{}", method),
                        };
                    }
                    if path.starts_with("/admin/users") {
                        return match method {
                            "GET" => "Admin::users_read".to_string(),
                            "POST" => "Admin::users_create".to_string(),
                            "PUT" | "PATCH" => "Admin::users_update".to_string(),
                            "DELETE" => "Admin::users_delete".to_string(),
                            _ => format!("Admin::users_manage:{}", method),
                        };
                    }
                    // Key rotation (non-PQ)
                    if path.starts_with("/admin/keys/rotate") {
                        return match method {
                            "POST" | "PUT" => "Admin::keys_rotate".to_string(),
                            _ => "Admin::keys_read".to_string(),
                        };
                    }
                    // Metrics/Health
                    if path.starts_with("/admin/metrics") {
                        return "Admin::metrics_read".to_string();
                    }
                    if path.starts_with("/admin/health") {
                        return "Admin::health_read".to_string();
                    }
                    if path.starts_with("/admin/post-quantum/keys/rotate") {
                        return "Admin::pq_keys_rotate".to_string();
                    }
                    if path.starts_with("/admin/post-quantum/keys/stats") {
                        return "Admin::pq_keys_stats".to_string();
                    }
                    if path.starts_with("/admin/post-quantum/metrics") {
                        return "Admin::pq_metrics".to_string();
                    }
                    if path.starts_with("/admin/post-quantum/benchmark") {
                        return "Admin::pq_benchmark".to_string();
                    }
                    if path.starts_with("/admin/post-quantum/config") {
                        return "Admin::pq_config".to_string();
                    }
                    if path.starts_with("/admin/post-quantum/migration/phase") {
                        return "Admin::pq_migration_phase".to_string();
                    }
                    if path.starts_with("/admin/post-quantum/migration/timeline") {
                        return "Admin::pq_migration_timeline".to_string();
                    }
                    if path.starts_with("/admin/post-quantum/compliance/report") {
                        return "Admin::pq_compliance_report".to_string();
                    }
                    if path.starts_with("/admin/post-quantum/health") {
                        return "Admin::pq_health".to_string();
                    }
                    if path.starts_with("/admin/post-quantum/emergency/rollback") {
                        return "Admin::pq_emergency_rollback".to_string();
                    }
                    if path.starts_with("/admin/billing") {
                        return match method {
                            "GET" => "Admin::billing_read".to_string(),
                            "DELETE" => "Admin::billing_delete".to_string(),
                            _ => "Admin::billing_update".to_string(),
                        };
                    }
                    // Default generic admin action with method
                    format!("Admin::access:{}", method)
                }

                let payload = policy_client::PolicyAuthorizeRequest {
                    request_id: req_id.clone(),
                    principal: serde_json::json!({"type":"Admin","id": admin_key}),
                    action: admin_action_for(path, method),
                    resource: serde_json::json!({"type":"AdminEndpoint","id": path}),
                    context: serde_json::json!({"method": method}),
                };
                match policy_client::authorize_basic(&policy_base, &req_id, &payload).await {
                    Ok(decision) if decision.eq_ignore_ascii_case("allow") => {}
                    Ok(decision) => {
                        let err = crate::shared::error::AppError::Forbidden {
                            reason: format!("Policy decision: {}", decision),
                        };
                        return handle_auth_failure(
                            err,
                            method,
                            path,
                            client_ip.as_ref(),
                            &headers,
                        );
                    }
                    Err(e) => {
                        let fail_open = std::env::var("POLICY_FAIL_OPEN")
                            .unwrap_or_else(|_| "0".to_string())
                            .eq("1");
                        if !fail_open {
                            let err = crate::shared::error::AppError::ServiceUnavailable {
                                reason: format!("Policy check failed: {}", e),
                            };
                            return handle_auth_failure(
                                err,
                                method,
                                path,
                                client_ip.as_ref(),
                                &headers,
                            );
                        }
                        tracing::warn!(request_id = %req_id, error = %e, "Admin policy check failed; proceeding due to POLICY_FAIL_OPEN=1");
                    }
                }
            }

            // Proceed with the request
            Ok(next.run(request).await)
        }
        Err(auth_error) => {
            handle_auth_failure(auth_error, method, path, client_ip.as_ref(), &headers)
        }
    }
}

/// Extract admin key from Bearer token for rate limiting and logging
async fn extract_admin_key(
    headers: &HeaderMap,
    _state: &AppState,
) -> Result<String, crate::shared::error::AppError> {
    // Extract bearer token
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth.strip_prefix("Bearer ").ok_or_else(|| {
        crate::shared::error::AppError::InvalidToken(
            "Missing or malformed authorization header".to_string(),
        )
    })?;

    if token.is_empty() {
        return Err(crate::shared::error::AppError::InvalidToken(
            "Empty bearer token".to_string(),
        ));
    }

    // Validate token and extract record
    #[cfg(feature = "redis-sessions")]
    let record = _state.store.get_token_record(token).await?.ok_or_else(|| {
        crate::shared::error::AppError::InvalidToken("Token not found or invalid".to_string())
    })?;

    #[cfg(not(feature = "redis-sessions"))]
    return Err(crate::shared::error::AppError::ConfigurationError(
        "Admin token validation backend is not configured".to_string(),
    ));

    #[cfg(feature = "redis-sessions")]
    {
        // Check if token is active
        if !record.active {
            return Err(crate::shared::error::AppError::InvalidToken(
                "Token is inactive".to_string(),
            ));
        }

        // Check for admin scope
        match record.scope {
            Some(ref scope_str) if scope_str.split_whitespace().any(|s| s == "admin") => {
                // Return a hash of the token for use as admin key (for privacy)
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(token.as_bytes());
                let result = hasher.finalize();
                Ok(format!("admin_{}", hex::encode(&result[..8]))) // Use first 8 bytes as key
            }
            _ => Err(crate::shared::error::AppError::Forbidden {
                reason: "Insufficient privileges: admin scope required".to_string(),
            }),
        }
    }
}

/// Enhanced admin scope validation
async fn require_admin_scope(
    headers: &HeaderMap,
    _state: &AppState,
) -> Result<(), crate::shared::error::AppError> {
    // Extract bearer token
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth.strip_prefix("Bearer ").ok_or_else(|| {
        crate::shared::error::AppError::InvalidToken(
            "Missing or malformed authorization header".to_string(),
        )
    })?;

    if token.is_empty() {
        return Err(crate::shared::error::AppError::InvalidToken(
            "Empty bearer token".to_string(),
        ));
    }

    // Validate token and extract record
    #[cfg(feature = "redis-sessions")]
    let record = _state.store.get_token_record(token).await?.ok_or_else(|| {
        crate::shared::error::AppError::InvalidToken("Token not found or invalid".to_string())
    })?;

    #[cfg(not(feature = "redis-sessions"))]
    return Err(crate::shared::error::AppError::ConfigurationError(
        "Admin token validation backend is not configured".to_string(),
    ));

    #[cfg(feature = "redis-sessions")]
    {
        // Check if token is active
        if !record.active {
            return Err(crate::shared::error::AppError::InvalidToken(
                "Token is inactive".to_string(),
            ));
        }

        // Check for admin scope
        match record.scope {
            Some(ref scope_str) if scope_str.split_whitespace().any(|s| s == "admin") => {
                // Additional validation could be added here (e.g., token expiry, client validation)
                Ok(())
            }
            _ => Err(crate::shared::error::AppError::Forbidden {
                reason: "Insufficient privileges: admin scope required".to_string(),
            }),
        }
    }
}

/// Validate request with replay protection and signature verification
async fn validate_request_with_replay_protection(
    headers: &HeaderMap,
    config: &AdminAuthConfig,
    method: &str,
    path: &str,
) -> Result<(), crate::shared::error::AppError> {
    let Some(signing_secret) = &config.signing_secret else {
        return Err(crate::shared::error::AppError::ConfigurationError(
            "Request signing is required but no signing secret is configured".to_string(),
        ));
    };

    // Extract new headers for replay protection
    let nonce = headers
        .get("X-Request-Nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| crate::shared::error::AppError::InvalidRequest {
            reason: "Missing X-Request-Nonce header".to_string(),
        })?;

    let timestamp_str = headers
        .get("X-Request-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| crate::shared::error::AppError::InvalidRequest {
            reason: "Missing X-Request-Timestamp header".to_string(),
        })?;

    let signature = headers
        .get("X-Request-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| crate::shared::error::AppError::InvalidRequest {
            reason: "Missing X-Request-Signature header".to_string(),
        })?;

    // Parse timestamp
    let timestamp: u64 =
        timestamp_str
            .parse()
            .map_err(|_| crate::shared::error::AppError::InvalidRequest {
                reason: "Invalid timestamp format".to_string(),
            })?;

    // Verify signature using SHA-256
    #[cfg(feature = "rate-limiting")]
    if !ReplayProtection::verify_signature(
        signing_secret,
        method,
        path,
        nonce,
        timestamp,
        signature,
    ) {
        return Err(crate::shared::error::AppError::InvalidRequest {
            reason: "Invalid request signature".to_string(),
        });
    }

    // Apply replay protection
    #[cfg(feature = "rate-limiting")]
    if let Some(replay_protection) = REPLAY_PROTECTION.get() {
        replay_protection
            .validate_request(nonce, timestamp, signature, signing_secret, method, path)
            .await?;
    }

    Ok(())
}

/// Legacy validate request signature function (now deprecated)
#[allow(dead_code)]
fn validate_request_signature(
    headers: &HeaderMap,
    config: &AdminAuthConfig,
    method: &str,
    path: &str,
) -> Result<(), crate::shared::error::AppError> {
    let Some(signing_secret) = &config.signing_secret else {
        return Err(crate::shared::error::AppError::ConfigurationError(
            "Request signing is required but no signing secret is configured".to_string(),
        ));
    };

    // Extract signature and timestamp headers
    let signature = headers
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| crate::shared::error::AppError::InvalidRequest {
            reason: "Missing x-signature header".to_string(),
        })?;

    let timestamp_str = headers
        .get("x-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| crate::shared::error::AppError::InvalidRequest {
            reason: "Missing x-timestamp header".to_string(),
        })?;

    // Parse and validate timestamp
    let timestamp: u64 =
        timestamp_str
            .parse()
            .map_err(|_| crate::shared::error::AppError::InvalidRequest {
                reason: "Invalid timestamp format".to_string(),
            })?;

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            crate::shared::error::AppError::Internal("Failed to get current timestamp".to_string())
        })?
        .as_secs();

    // Check timestamp skew
    if current_time.abs_diff(timestamp) > config.max_timestamp_skew {
        return Err(crate::shared::error::AppError::InvalidRequest {
            reason: "Request timestamp is too far from current time".to_string(),
        });
    }

    // Calculate expected signature
    let payload = format!("{method}:{path}:{timestamp}");
    let expected_signature = calculate_hmac_sha256(signing_secret, &payload)?;

    // Constant-time comparison to prevent timing attacks
    if !constant_time_compare(signature, &expected_signature) {
        return Err(crate::shared::error::AppError::InvalidRequest {
            reason: "Invalid request signature".to_string(),
        });
    }

    Ok(())
}

/// Handle authentication failures with proper logging and response
fn handle_auth_failure(
    auth_error: crate::shared::error::AppError,
    method: &str,
    path: &str,
    client_ip: Option<&String>,
    headers: &HeaderMap,
) -> Result<Response, impl IntoResponse> {
    tracing::warn!(
        error = %redact_log(&auth_error.to_string()),
        method = method,
        path = path,
        client_ip = client_ip,
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
        description: format!("Admin authentication failed for {method} {path}"),
        actor: Some("unknown".to_string()),
        action: Some(format!("{method} {path}")),
        target: Some(path.to_string()),
        outcome: "failure".to_string(),
        reason: Some("invalid_or_missing_admin_token".to_string()),
        correlation_id: extract_correlation_id(headers),
        ip_address: client_ip.cloned(),
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
    crate::infrastructure::security::security_logging::log_event(&event);

    Err(auth_error.into_response())
}

/// Handle signature validation failures with proper logging and response
#[allow(dead_code)]
fn handle_signature_failure(
    error: &crate::shared::error::AppError,
    method: &str,
    path: &str,
    client_ip: Option<&String>,
    headers: &HeaderMap,
) -> Result<Response, impl IntoResponse> {
    // Determine the appropriate status code based on error type
    let (status_code, reason) = match &error {
        crate::shared::error::AppError::RateLimitExceeded => {
            (StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded")
        }
        _ => (StatusCode::UNAUTHORIZED, "invalid_signature_or_replay"),
    };

    tracing::warn!(
        error = %redact_log(&error.to_string()),
        method = method,
        path = path,
        client_ip = client_ip,
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
        action: Some(format!("{method} {path}")),
        target: Some(path.to_string()),
        outcome: "failure".to_string(),
        reason: Some(reason.to_string()),
        correlation_id: extract_correlation_id(headers),
        ip_address: client_ip.cloned(),
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
    crate::infrastructure::security::security_logging::log_event(&event);

    Err((status_code, format!("Request validation failed: {error}")).into_response())
}

/// Calculate HMAC-SHA256 signature
#[allow(dead_code)]
fn calculate_hmac_sha256(
    secret: &str,
    payload: &str,
) -> Result<String, crate::shared::error::AppError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| {
        crate::shared::error::AppError::CryptographicError(
            "HMAC initialization failed: Invalid HMAC key".to_string(),
        )
    })?;

    mac.update(payload.as_bytes());
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Constant-time string comparison to prevent timing attacks
/// Uses the secure implementation from the password service
fn constant_time_compare(a: &str, b: &str) -> bool {
    crate::services::constant_time_compare(a, b)
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
        let secret = std::env::var("TEST_SECRET")
            .unwrap_or_else(|_| "test_secret_for_development_only".to_string());
        let payload = "GET:/admin/test:1234567890";
        let signature = calculate_hmac_sha256(&secret, payload).unwrap();

        // Verify the signature is deterministic
        let signature2 = calculate_hmac_sha256(&secret, payload).unwrap();
        assert_eq!(signature, signature2);

        // Verify different payload gives different signature
        let different_signature = calculate_hmac_sha256(&secret, "different").unwrap();
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
        use crate::middleware::security::admin_replay_protection::ReplayProtection;

        let config = AdminAuthConfig {
            require_request_signing: true,
            signing_secret: Some(
                std::env::var("TEST_SIGNING_SECRET")
                    .unwrap_or_else(|_| "test_signing_secret_for_development_only".to_string()),
            ),
            max_timestamp_skew: 300,
            rate_limit_per_minute: 100,
            replay_time_window: 300,
            redis_url: None,
        };

        // Initialize replay protection for testing
        let replay_protection = Arc::new(ReplayProtection::new(
            None,
            config.replay_time_window,
            config.max_timestamp_skew,
        ));
        let _ = REPLAY_PROTECTION.set(replay_protection);

        let mut headers = HeaderMap::new();
        let nonce = ReplayProtection::generate_nonce();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let secret_key = config.signing_secret.as_ref().unwrap();
        let signature = ReplayProtection::create_signature(
            secret_key,
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
