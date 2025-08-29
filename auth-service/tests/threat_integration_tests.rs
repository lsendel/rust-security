//! Integration tests for threat detection system

use auth_service::core::security::{SecurityEvent, SecurityEventType, SecurityContext, SecurityLevel, ViolationSeverity};
use auth_service::core::auth::AuthContext;
#[cfg(feature = "threat-hunting")]
use auth_service::{
    event_conversion::convert_security_events,
    threat_adapter::{ThreatDetectionAdapter, process_with_conversion},
    threat_processor::ThreatProcessor,
    auth_service_integration::AuthServiceWithThreatProcessing,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

fn create_test_security_event() -> SecurityEvent {
    SecurityEvent {
        timestamp: SystemTime::now(),
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
            authenticated_at: SystemTime::now(),
            expires_at: SystemTime::now(),
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
    }
}

#[cfg(feature = "threat-hunting")]
#[tokio::test]
async fn test_event_conversion_integration() {
    let security_event = create_test_security_event();
    
    // Test single event conversion
    let result = process_with_conversion(&security_event, |threat_event| async move {
        // Verify conversion worked correctly
        assert_eq!(threat_event.severity, auth_service::threat_types::ThreatSeverity::High);
        assert_eq!(threat_event.source, "auth-service");
        assert_eq!(threat_event.user_id, Some("test-user-456".to_string()));
        assert!(threat_event.ip_address.is_some());
        assert!(threat_event.user_agent.is_some());
        assert!(threat_event.risk_score.is_some());
        Ok(())
    }).await;
    
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
        assert_eq!(threat_event.severity, auth_service::threat_types::ThreatSeverity::High);
        assert_eq!(threat_event.source, "auth-service");
    }
}

#[tokio::test]
async fn test_threat_processor_no_feature() {
    #[cfg(not(feature = "threat-hunting"))]
    {
        let processor = ThreatProcessor::new();
        let event = create_test_security_event();
        
        let result = processor.process_event(&event).await;
        assert!(result.is_ok());
        assert!(!processor.is_enabled().await);
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
    
    for event_type in event_types {
        let mut event = create_test_security_event();
        event.event_type = event_type;
        
        #[cfg(feature = "threat-hunting")]
        {
            let result = process_with_conversion(&event, |threat_event| async move {
                // Verify event type conversion
                assert!(!threat_event.event_id.is_empty());
                assert_eq!(threat_event.source, "auth-service");
                Ok(())
            }).await;
            assert!(result.is_ok());
        }
        
        #[cfg(not(feature = "threat-hunting"))]
        {
            // Just verify the event can be created
            assert_eq!(event.event_type, event_type);
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
        }).await;
        
        assert!(result.is_err());
    }
    
    #[cfg(not(feature = "threat-hunting"))]
    {
        // No-op test for non-threat-hunting builds
        assert_eq!(event.severity, ViolationSeverity::High);
    }
}
