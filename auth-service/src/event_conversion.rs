//! Event conversion utilities for bridging core security and threat detection systems

#[cfg(feature = "threat-hunting")]
use crate::threat_types::{ThreatSecurityEvent, ThreatSecurityEventType, ThreatSeverity, EventOutcome};
use chrono::{DateTime, Utc};
use std::time::SystemTime;

/// Convert SecurityEventType to ThreatSecurityEventType
#[cfg(feature = "threat-hunting")]
impl From<SecurityEventType> for ThreatSecurityEventType {
    fn from(event_type: SecurityEventType) -> Self {
        match event_type {
            SecurityEventType::AuthenticationFailure => ThreatSecurityEventType::AuthenticationFailure,
            SecurityEventType::AuthenticationSuccess => ThreatSecurityEventType::AuthenticationSuccess,
            SecurityEventType::AuthenticationAttempt => ThreatSecurityEventType::AuthenticationAttempt,
            SecurityEventType::Login => ThreatSecurityEventType::AuthenticationSuccess,
            SecurityEventType::AuthorizationDenied => ThreatSecurityEventType::AuthorizationDenied,
            SecurityEventType::SuspiciousActivity => ThreatSecurityEventType::SuspiciousActivity,
            SecurityEventType::RateLimitExceeded => ThreatSecurityEventType::RateLimitExceeded,
            SecurityEventType::PolicyViolation => ThreatSecurityEventType::PolicyViolation,
            SecurityEventType::ThreatDetected => ThreatSecurityEventType::ThreatDetected,
            SecurityEventType::AnomalyDetected => ThreatSecurityEventType::AnomalyDetected,
            SecurityEventType::SecurityScanTriggered => ThreatSecurityEventType::SecurityScanTriggered,
            SecurityEventType::MfaFailure => ThreatSecurityEventType::MfaFailure,
            SecurityEventType::MfaChallenge => ThreatSecurityEventType::MfaChallenge,
            SecurityEventType::PasswordChange => ThreatSecurityEventType::PasswordChange,
            SecurityEventType::DataAccess => ThreatSecurityEventType::DataAccess,
        }
    }
}

/// Convert ViolationSeverity to ThreatSeverity
#[cfg(feature = "threat-hunting")]
impl From<ViolationSeverity> for ThreatSeverity {
    fn from(severity: ViolationSeverity) -> Self {
        match severity {
            ViolationSeverity::Low => ThreatSeverity::Low,
            ViolationSeverity::Medium => ThreatSeverity::Medium,
            ViolationSeverity::High => ThreatSeverity::High,
            ViolationSeverity::Critical => ThreatSeverity::Critical,
        }
    }
}

/// Convert SystemTime to DateTime<Utc>
fn system_time_to_datetime(time: SystemTime) -> DateTime<Utc> {
    DateTime::from(time)
}

/// Convert SecurityEvent to ThreatSecurityEvent
#[cfg(feature = "threat-hunting")]
impl From<&SecurityEvent> for ThreatSecurityEvent {
    fn from(event: &SecurityEvent) -> Self {
        let timestamp = system_time_to_datetime(event.timestamp);
        
        ThreatSecurityEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            event_type: event.event_type.clone().into(),
            severity: event.severity.into(),
            source: "auth-service".to_string(),
            client_id: None, // AuthContext doesn't have client_id
            user_id: event.auth_context.as_ref().map(|ctx| ctx.user_id.clone()),
            ip_address: Some(event.security_context.client_ip),
            user_agent: Some(event.security_context.user_agent.clone()),
            request_id: None, // SecurityContext doesn't have request_id
            session_id: event.auth_context.as_ref().map(|ctx| ctx.session_id.clone()),
            description: format!("{:?} event", event.event_type),
            details: event.details.iter().map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone()))).collect(),
            outcome: EventOutcome::Success,
            resource: None,
            action: None,
            risk_score: Some((event.security_context.risk_score * 100.0) as u8),
            location: None,
            device_fingerprint: Some(event.security_context.fingerprint.clone()),
            mfa_used: false,
            token_binding_info: None,
        }
    }
}

/// Conversion helper for batch operations
#[cfg(feature = "threat-hunting")]
pub fn convert_security_events(events: &[SecurityEvent]) -> Vec<ThreatSecurityEvent> {
    events.iter().map(|event| event.into()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::security::{SecurityContext, SecurityLevel};
    use crate::core::auth::AuthContext;
    use std::net::IpAddr;

    #[cfg(feature = "threat-hunting")]
    #[test]
    fn test_event_type_conversion() {
        assert_eq!(
            ThreatSecurityEventType::from(SecurityEventType::AuthenticationFailure),
            ThreatSecurityEventType::AuthenticationFailure
        );
    }

    #[cfg(feature = "threat-hunting")]
    #[test]
    fn test_severity_conversion() {
        assert_eq!(
            ThreatSeverity::from(ViolationSeverity::Critical),
            ThreatSeverity::Critical
        );
    }

    #[cfg(feature = "threat-hunting")]
    #[test]
    fn test_security_event_conversion() {
        let security_event = SecurityEvent {
            timestamp: SystemTime::now(),
            event_type: SecurityEventType::AuthenticationFailure,
            security_context: SecurityContext {
                client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
                user_agent: "test-agent".to_string(),
                fingerprint: "test-fingerprint".to_string(),
                security_level: SecurityLevel::High,
                risk_score: 0.5,
                threat_indicators: vec![],
                flags: vec![],
                metadata: std::collections::HashMap::new(),
            },
            auth_context: Some(AuthContext {
                user_id: "user-123".to_string(),
                session_id: "session-123".to_string(),
                authenticated_at: SystemTime::now(),
                expires_at: SystemTime::now(),
                scopes: vec!["read".to_string()],
                claims: std::collections::HashMap::new(),
            }),
            details: std::collections::HashMap::new(),
            severity: ViolationSeverity::High,
        };

        let threat_event: ThreatSecurityEvent = (&security_event).into();
        
        assert_eq!(threat_event.event_type, ThreatSecurityEventType::AuthenticationFailure);
        assert_eq!(threat_event.severity, ThreatSeverity::High);
        assert_eq!(threat_event.user_id, Some("user-123".to_string()));
    }
}
