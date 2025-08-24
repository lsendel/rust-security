//! Simplified observability module for basic authentication logging
//!
//! This module provides simple logging functions for authentication events
//! using structured logging with the tracing crate.

/// Log successful authentication
pub fn log_auth_success(user_id: &str, auth_method: &str, client_ip: Option<&str>) {
    match client_ip {
        Some(ip) => tracing::info!(
            user_id = user_id,
            auth_method = auth_method,
            client_ip = ip,
            "Authentication successful"
        ),
        None => tracing::info!(
            user_id = user_id,
            auth_method = auth_method,
            "Authentication successful"
        ),
    }
}

/// Log failed authentication attempt
pub fn log_auth_failure(user_id: Option<&str>, auth_method: &str, reason: &str, client_ip: Option<&str>) {
    match (user_id, client_ip) {
        (Some(uid), Some(ip)) => tracing::warn!(
            user_id = uid,
            auth_method = auth_method,
            reason = reason,
            client_ip = ip,
            "Authentication failed"
        ),
        (Some(uid), None) => tracing::warn!(
            user_id = uid,
            auth_method = auth_method,
            reason = reason,
            "Authentication failed"
        ),
        (None, Some(ip)) => tracing::warn!(
            auth_method = auth_method,
            reason = reason,
            client_ip = ip,
            "Authentication failed"
        ),
        (None, None) => tracing::warn!(
            auth_method = auth_method,
            reason = reason,
            "Authentication failed"
        ),
    }
}

/// Log token operations
pub fn log_token_operation(operation: &str, user_id: &str, token_type: &str) {
    tracing::info!(
        operation = operation,
        user_id = user_id,
        token_type = token_type,
        "Token operation completed"
    );
}

/// Log security events
pub fn log_security_event(event_type: &str, user_id: Option<&str>, details: &str, severity: &str) {
    match user_id {
        Some(uid) => match severity {
            "high" | "critical" => tracing::error!(
                event_type = event_type,
                user_id = uid,
                details = details,
                severity = severity,
                "Security event detected"
            ),
            "medium" => tracing::warn!(
                event_type = event_type,
                user_id = uid,
                details = details,
                severity = severity,
                "Security event detected"
            ),
            _ => tracing::info!(
                event_type = event_type,
                user_id = uid,
                details = details,
                severity = severity,
                "Security event detected"
            ),
        },
        None => match severity {
            "high" | "critical" => tracing::error!(
                event_type = event_type,
                details = details,
                severity = severity,
                "Security event detected"
            ),
            "medium" => tracing::warn!(
                event_type = event_type,
                details = details,
                severity = severity,
                "Security event detected"
            ),
            _ => tracing::info!(
                event_type = event_type,
                details = details,
                severity = severity,
                "Security event detected"
            ),
        },
    }
}

/// Log user session events
pub fn log_session_event(event_type: &str, user_id: &str, session_id: &str) {
    tracing::info!(
        event_type = event_type,
        user_id = user_id,
        session_id = session_id,
        "Session event"
    );
}
