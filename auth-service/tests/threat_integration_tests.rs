//! Integration tests for threat detection system

use auth_service::core::auth::AuthContext;
use auth_service::core::security::{
    SecurityContext, SecurityEvent, SecurityEventType, SecurityLevel, ViolationSeverity,
};
#[cfg(feature = "threat-hunting")]
use auth_service::{
    auth_service_integration::AuthServiceWithThreatProcessing,
    event_conversion::convert_security_events,
    threat_adapter::{process_with_conversion, ThreatDetectionAdapter},
    threat_processor::ThreatProcessor,
};
use chrono::Utc;
use std::collections::HashMap;
use std::net::IpAddr;
#[cfg(feature = "threat-hunting")]
use std::sync::Arc;

fn create_test_security_event() -> SecurityEvent {
    SecurityEvent {
        timestamp: Utc::now(),
        event_type: SecurityEventType::AuthenticationFailure,
        security_context: SecurityContext {
            client_ip: "192.168.1.100".parse::<IpAddr>().unwrap(),
            user_agent: "Mozilla/5.0 Test".to_string(),
            fingerprint: "test-fingerprint-123".to_string(),
            security_level: SecurityLevel::High,
            risk_score: 0.75,
            threat_indicators: vec![],
            flags: Default::default(),
            metadata: HashMap::new(),
        },
        auth_context: Some(AuthContext {
            user_id: "test-user-456".to_string(),
            session_id: "session-789".to_string(),
            authenticated_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now(),
            scopes: vec!["read".to_string(), "write".to_string()],
            claims: HashMap::new(),
        }),
        details: {
            let mut details = HashMap::new();
            details.insert("attempt_count".to_string(), "3".to_string());
            details.insert("source".to_string(), "login_form".to_string());
            details
        },
        severity: ViolationSeverity::High,
        user_id: Some("test-user-456".to_string()),
        session_id: Some("session-789".to_string()),
        ip_address: Some("192.168.1.100".parse::<IpAddr>().unwrap()),
        location: Some("Test Location".to_string()),
        device_fingerprint: Some("test-fingerprint-123".to_string()),
        risk_score: Some(75),
        outcome: Some("failure".to_string()),
        mfa_used: false,
        user_agent: Some("Mozilla/5.0 Test".to_string()),
    }
}

#[cfg(feature = "threat-hunting")]
#[tokio::test]
async fn test_event_conversion_integration() {
    let security_event = create_test_security_event();

    // Test single event conversion
    let result = process_with_conversion(&security_event, |threat_event| async move {
        // Verify conversion worked correctly
        assert_eq!(
            threat_event.severity,
            auth_service::threat_types::ThreatSeverity::High
        );
        assert_eq!(threat_event.source, "auth-service");
        assert_eq!(threat_event.user_id, Some("test-user-456".to_string()));
        assert!(threat_event.ip_address.is_some());
        assert!(threat_event.user_agent.is_some());
        assert!(threat_event.risk_score.is_some());
        Ok(())
    })
    .await;

    assert!(result.is_ok());
}

#[cfg(feature = "threat-hunting")]
#[tokio::test]
async fn test_batch_conversion() {
    let events = vec![
        create_test_security_event(),
        create_test_security_event(),
        create_test_security_event(),
    ];

    let threat_events = convert_security_events(&events);
    assert_eq!(threat_events.len(), 3);

    for threat_event in threat_events {
        assert_eq!(
            threat_event.severity,
            auth_service::threat_types::ThreatSeverity::High
        );
        assert_eq!(threat_event.source, "auth-service");
    }
}

#[tokio::test]
async fn test_threat_processor_no_feature() {
    #[cfg(not(feature = "threat-hunting"))]
    {
        // ThreatProcessor is not available when threat-hunting feature is disabled
        // This test just verifies the code compiles without the feature
        let event = create_test_security_event();
        assert_eq!(event.severity, ViolationSeverity::High);
    }
}

#[cfg(feature = "threat-hunting")]
#[tokio::test]
async fn test_auth_service_integration() {
    let threat_processor = Arc::new(ThreatProcessor::new());
    let auth_service = AuthServiceWithThreatProcessing::new(threat_processor.clone());

    let event = create_test_security_event();
    let result = auth_service.process_security_event(event).await;

    assert!(result.is_ok());
    assert!(!threat_processor.is_enabled().await); // No-op implementation
}

#[tokio::test]
async fn test_multiple_event_types() {
    let event_types = vec![
        SecurityEventType::AuthenticationFailure,
        SecurityEventType::AuthenticationSuccess,
        SecurityEventType::AuthorizationDenied,
        SecurityEventType::SuspiciousActivity,
        SecurityEventType::RateLimitExceeded,
    ];

    for event_type in &event_types {
        let mut event = create_test_security_event();
        event.event_type = event_type.clone();

        #[cfg(feature = "threat-hunting")]
        {
            let result = process_with_conversion(&event, |threat_event| async move {
                // Verify event type conversion
                assert!(!threat_event.event_id.is_empty());
                assert_eq!(threat_event.source, "auth-service");
                Ok(())
            })
            .await;
            assert!(result.is_ok());
        }

        #[cfg(not(feature = "threat-hunting"))]
        {
            // Just verify the event can be created
            assert_eq!(event.event_type, *event_type);
        }
    }
}

#[tokio::test]
async fn test_error_handling() {
    let event = create_test_security_event();

    #[cfg(feature = "threat-hunting")]
    {
        let result = process_with_conversion(&event, |_threat_event| async move {
            Err("Simulated processing error".into())
        })
        .await;

        assert!(result.is_err());
    }

    #[cfg(not(feature = "threat-hunting"))]
    {
        // No-op test for non-threat-hunting builds
        assert_eq!(event.severity, ViolationSeverity::High);
    }
}
