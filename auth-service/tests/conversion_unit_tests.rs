//! Unit tests for event conversion utilities

use auth_service::core::security::{SecurityEventType, ViolationSeverity};
#[cfg(feature = "threat-hunting")]
use auth_service::threat_types::{ThreatSecurityEventType, ThreatSeverity};

#[cfg(feature = "threat-hunting")]
#[test]
fn test_security_event_type_conversion() {
    // Test all SecurityEventType variants convert correctly
    let conversions = vec![
        (
            SecurityEventType::AuthenticationFailure,
            ThreatSecurityEventType::AuthenticationFailure,
        ),
        (
            SecurityEventType::AuthenticationSuccess,
            ThreatSecurityEventType::AuthenticationSuccess,
        ),
        (
            SecurityEventType::AuthenticationAttempt,
            ThreatSecurityEventType::AuthenticationAttempt,
        ),
        (
            SecurityEventType::Login,
            ThreatSecurityEventType::AuthenticationSuccess,
        ),
        (
            SecurityEventType::AuthorizationDenied,
            ThreatSecurityEventType::AuthorizationDenied,
        ),
        (
            SecurityEventType::SuspiciousActivity,
            ThreatSecurityEventType::SuspiciousActivity,
        ),
        (
            SecurityEventType::RateLimitExceeded,
            ThreatSecurityEventType::RateLimitExceeded,
        ),
        (
            SecurityEventType::PolicyViolation,
            ThreatSecurityEventType::PolicyViolation,
        ),
        (
            SecurityEventType::ThreatDetected,
            ThreatSecurityEventType::ThreatDetected,
        ),
        (
            SecurityEventType::AnomalyDetected,
            ThreatSecurityEventType::AnomalyDetected,
        ),
        (
            SecurityEventType::SecurityScanTriggered,
            ThreatSecurityEventType::SecurityScanTriggered,
        ),
        (
            SecurityEventType::MfaFailure,
            ThreatSecurityEventType::MfaFailure,
        ),
        (
            SecurityEventType::MfaChallenge,
            ThreatSecurityEventType::MfaChallenge,
        ),
        (
            SecurityEventType::PasswordChange,
            ThreatSecurityEventType::PasswordChange,
        ),
        (
            SecurityEventType::DataAccess,
            ThreatSecurityEventType::DataAccess,
        ),
    ];

    for (security_type, expected_threat_type) in conversions {
        let converted: ThreatSecurityEventType = security_type.into();
        assert_eq!(converted, expected_threat_type);
    }
}

#[cfg(feature = "threat-hunting")]
#[test]
fn test_violation_severity_conversion() {
    // Test all ViolationSeverity variants convert correctly
    let conversions = vec![
        (ViolationSeverity::Low, ThreatSeverity::Low),
        (ViolationSeverity::Medium, ThreatSeverity::Medium),
        (ViolationSeverity::High, ThreatSeverity::High),
        (ViolationSeverity::Critical, ThreatSeverity::Critical),
    ];

    for (violation_severity, expected_threat_severity) in conversions {
        let converted: ThreatSeverity = violation_severity.into();
        assert_eq!(converted, expected_threat_severity);
    }
}

#[test]
fn test_no_feature_compilation() {
    // This test ensures the code compiles without the threat-hunting feature
    let event_type = SecurityEventType::AuthenticationFailure;
    let severity = ViolationSeverity::High;

    // Basic assertions to ensure types work
    assert_eq!(format!("{:?}", event_type), "AuthenticationFailure");
    assert_eq!(format!("{:?}", severity), "High");
}

#[cfg(feature = "threat-hunting")]
#[test]
fn test_conversion_preserves_data() {
    use auth_service::core::auth::AuthContext;
    use auth_service::core::security::{SecurityContext, SecurityEvent, SecurityLevel};
    use std::collections::HashMap;
    use std::net::IpAddr;
    use chrono::Utc;
    use std::time::SystemTime;

    let security_event = SecurityEvent {
        timestamp: Utc::now(),
        event_type: SecurityEventType::AuthenticationFailure,
        security_context: SecurityContext {
            client_ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
            user_agent: "Test Agent".to_string(),
            fingerprint: "unique-fingerprint".to_string(),
            security_level: SecurityLevel::High,
            risk_score: 0.9,
            threat_indicators: vec![],
            flags: Default::default(),
            metadata: HashMap::new(),
        },
        auth_context: Some(AuthContext {
            user_id: "user123".to_string(),
            session_id: "session456".to_string(),
            authenticated_at: SystemTime::now(),
            expires_at: SystemTime::now(),
            scopes: vec!["admin".to_string()],
            claims: HashMap::new(),
        }),
        details: HashMap::new(),
        severity: ViolationSeverity::Critical,
        user_id: Some("user123".to_string()),
        session_id: Some("session456".to_string()),
        ip_address: Some("10.0.0.1".parse::<IpAddr>().unwrap()),
        location: None,
        device_fingerprint: Some("unique-fingerprint".to_string()),
        risk_score: Some(90),
        outcome: Some("failure".to_string()),
        mfa_used: false,
        user_agent: Some("Test Agent".to_string()),
    };

    let threat_event: auth_service::threat_types::ThreatSecurityEvent = (&security_event).into();

    // Verify data preservation
    assert_eq!(threat_event.severity, ThreatSeverity::Critical);
    assert_eq!(threat_event.source, "auth-service");
    assert_eq!(threat_event.user_id, Some("user123".to_string()));
    assert_eq!(threat_event.session_id, Some("session456".to_string()));
    assert_eq!(
        threat_event.ip_address,
        Some("10.0.0.1".parse::<IpAddr>().unwrap())
    );
    assert_eq!(threat_event.user_agent, Some("Test Agent".to_string()));
    assert_eq!(
        threat_event.device_fingerprint,
        Some("unique-fingerprint".to_string())
    );
    assert_eq!(threat_event.risk_score, Some(90)); // 0.9 * 100
    assert!(!threat_event.event_id.is_empty());
}
