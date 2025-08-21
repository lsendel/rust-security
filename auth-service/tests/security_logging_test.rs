use auth_service::security_logging::{
    SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity,
};
use serde_json::Value;

#[test]
fn test_security_event_creation() {
    let event = SecurityEvent::new(
        SecurityEventType::AuthenticationAttempt,
        SecuritySeverity::Medium,
        "auth-service".to_string(),
        "Test authentication attempt".to_string(),
    )
    .with_client_id("test_client".to_string())
    .with_ip_address("127.0.0.1".to_string())
    .with_outcome("success".to_string());

    assert_eq!(event.event_type, SecurityEventType::AuthenticationAttempt);
    assert_eq!(event.severity, SecuritySeverity::Medium);
    assert_eq!(event.source, "auth-service");
    assert_eq!(event.description, "Test authentication attempt");
    assert_eq!(event.client_id, Some("test_client".to_string()));
    assert_eq!(event.ip_address, Some("127.0.0.1".to_string()));
    assert_eq!(event.outcome, "success");
}

#[test]
fn test_security_logger_auth_attempt() {
    // This test verifies that the security logger can be called without panicking
    // In a real environment, this would output to the configured logging system
    SecurityLogger::log_auth_attempt(
        "test_client",
        "127.0.0.1",
        Some("test-agent/1.0"),
        "success",
        Some(
            [
                (
                    "grant_type".to_string(),
                    Value::String("client_credentials".to_string()),
                ),
                ("has_scope".to_string(), Value::Bool(true)),
            ]
            .into(),
        ),
    );

    // If we reach here without panicking, the test passes
    assert!(true);
}

#[test]
fn test_security_logger_token_operation() {
    SecurityLogger::log_token_operation(
        "issue",
        "access_token",
        "test_client",
        "127.0.0.1",
        "success",
        Some(
            [(
                "grant_type".to_string(),
                Value::String("client_credentials".to_string()),
            )]
            .into(),
        ),
    );

    // If we reach here without panicking, the test passes
    assert!(true);
}

#[test]
fn test_security_logger_validation_failure() {
    SecurityLogger::log_validation_failure(
        "/oauth/token",
        "invalid_scope",
        Some("test_client"),
        "127.0.0.1",
        Some(
            [(
                "requested_scope".to_string(),
                Value::String("invalid_scope".to_string()),
            )]
            .into(),
        ),
    );

    // If we reach here without panicking, the test passes
    assert!(true);
}

#[test]
fn test_security_logger_rate_limit() {
    SecurityLogger::log_rate_limit_exceeded("test_client", "127.0.0.1", "/oauth/token", 100, 50);

    // If we reach here without panicking, the test passes
    assert!(true);
}

#[test]
fn test_security_event_risk_score_validation() {
    let event = SecurityEvent::new(
        SecurityEventType::SuspiciousActivity,
        SecuritySeverity::High,
        "auth-service".to_string(),
        "Test suspicious activity".to_string(),
    )
    .with_risk_score(150); // Should be clamped to 100

    assert_eq!(event.risk_score, Some(100));
}

#[test]
fn test_security_event_with_details() {
    let mut event = SecurityEvent::new(
        SecurityEventType::TokenIssued,
        SecuritySeverity::Low,
        "auth-service".to_string(),
        "Token issued".to_string(),
    );

    event = event.with_detail("token_type".to_string(), "access_token");
    event = event.with_detail("expires_in".to_string(), 3600);
    event = event.with_detail("has_refresh".to_string(), true);

    assert_eq!(event.details.len(), 3);
    assert_eq!(
        event.details.get("token_type"),
        Some(&Value::String("access_token".to_string()))
    );
    assert_eq!(
        event.details.get("expires_in"),
        Some(&Value::Number(3600.into()))
    );
    assert_eq!(event.details.get("has_refresh"), Some(&Value::Bool(true)));
}
