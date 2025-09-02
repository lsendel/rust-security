//! Simplified observability module for basic authentication logging
//!
//! This module provides simple logging functions for authentication events
//! using structured logging with the tracing crate.

/// Log successful authentication
pub fn log_auth_success(user_id: &str, auth_method: &str, client_ip: Option<&str>) {
    if let Some(ip) = client_ip {
        tracing::info!(
            user_id = user_id,
            auth_method = auth_method,
            client_ip = ip,
            "Authentication successful"
        );
    } else {
        tracing::info!(
            user_id = user_id,
            auth_method = auth_method,
            "Authentication successful"
        );
    }
}

/// Log failed authentication attempt
/// Helper function to log auth failure with complete information
fn log_auth_failure_full(user_id: &str, auth_method: &str, reason: &str, client_ip: &str) {
    tracing::warn!(user_id, auth_method, reason, client_ip, "Authentication failed");
}

/// Helper function to log auth failure with user ID only
fn log_auth_failure_user_only(user_id: &str, auth_method: &str, reason: &str) {
    tracing::warn!(user_id, auth_method, reason, "Authentication failed");
}

/// Helper function to log auth failure with IP only
fn log_auth_failure_ip_only(auth_method: &str, reason: &str, client_ip: &str) {
    tracing::warn!(auth_method, reason, client_ip, "Authentication failed");
}

/// Helper function to log auth failure with minimal information
fn log_auth_failure_minimal(auth_method: &str, reason: &str) {
    tracing::warn!(auth_method, reason, "Authentication failed");
}

pub fn log_auth_failure(
    user_id: Option<&str>,
    auth_method: &str,
    reason: &str,
    client_ip: Option<&str>,
) {
    match (user_id, client_ip) {
        (Some(uid), Some(ip)) => log_auth_failure_full(uid, auth_method, reason, ip),
        (Some(uid), None) => log_auth_failure_user_only(uid, auth_method, reason),
        (None, Some(ip)) => log_auth_failure_ip_only(auth_method, reason, ip),
        (None, None) => log_auth_failure_minimal(auth_method, reason),
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
/// Helper function to log security events with user ID
fn log_security_event_with_user(event_type: &str, user_id: &str, details: &str, severity: &str) {
    match severity {
        "high" | "critical" => tracing::error!(
            event_type = event_type,
            user_id = user_id,
            details = details,
            severity = severity,
            "Security event detected"
        ),
        "medium" => tracing::warn!(
            event_type = event_type,
            user_id = user_id,
            details = details,
            severity = severity,
            "Security event detected"
        ),
        _ => tracing::info!(
            event_type = event_type,
            user_id = user_id,
            details = details,
            severity = severity,
            "Security event detected"
        ),
    }
}

/// Helper function to log security events without user ID
fn log_security_event_anonymous(event_type: &str, details: &str, severity: &str) {
    match severity {
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
    }
}

pub fn log_security_event(event_type: &str, user_id: Option<&str>, details: &str, severity: &str) {
    match user_id {
        Some(uid) => log_security_event_with_user(event_type, uid, details, severity),
        None => log_security_event_anonymous(event_type, details, severity),
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
