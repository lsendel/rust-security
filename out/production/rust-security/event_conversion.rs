//! Event conversion utilities for bridging core security and threat detection systems

use crate::core::security::{SecurityEvent, SecurityEventType, ViolationSeverity};
use crate::threat_types::{
    EventOutcome, ThreatSecurityEvent, ThreatSecurityEventType, ThreatSeverity,
};

/// Convert `SecurityEventType` to `ThreatSecurityEventType`
impl From<SecurityEventType> for ThreatSecurityEventType {
    fn from(event_type: SecurityEventType) -> Self {
        match event_type {
            SecurityEventType::AuthenticationFailure => Self::AuthenticationFailure,
            SecurityEventType::AuthenticationSuccess | SecurityEventType::Login => {
                Self::AuthenticationSuccess
            }
            SecurityEventType::AuthenticationAttempt => Self::AuthenticationAttempt,
            SecurityEventType::AuthorizationDenied => Self::AuthorizationDenied,
            SecurityEventType::SuspiciousActivity => Self::SuspiciousActivity,
            SecurityEventType::RateLimitExceeded => Self::RateLimitExceeded,
            SecurityEventType::PolicyViolation => Self::PolicyViolation,
            SecurityEventType::ThreatDetected => Self::ThreatDetected,
            SecurityEventType::AnomalyDetected => Self::AnomalyDetected,
            SecurityEventType::SecurityScanTriggered => Self::SecurityScanTriggered,
            SecurityEventType::MfaFailure => Self::MfaFailure,
            SecurityEventType::MfaChallenge => Self::MfaChallenge,
            SecurityEventType::PasswordChange => Self::PasswordChange,
            SecurityEventType::DataAccess => Self::DataAccess,
        }
    }
}

/// Convert `ViolationSeverity` to `ThreatSeverity`
impl From<ViolationSeverity> for ThreatSeverity {
    fn from(severity: ViolationSeverity) -> Self {
        match severity {
            ViolationSeverity::Low => Self::Low,
            ViolationSeverity::Medium => Self::Medium,
            ViolationSeverity::High => Self::High,
            ViolationSeverity::Critical => Self::Critical,
        }
    }
}

/// Convert `SecurityEvent` to `ThreatSecurityEvent`
impl From<&SecurityEvent> for ThreatSecurityEvent {
    fn from(event: &SecurityEvent) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: event.timestamp,
            event_type: event.event_type.clone().into(),
            severity: event.severity.into(),
            source: "auth-service".to_string(),
            client_id: None,
            user_id: event.user_id.clone(),
            ip_address: event.ip_address,
            user_agent: event.user_agent.clone(),
            request_id: None,
            session_id: event.session_id.clone(),
            description: format!("{:?} event", event.event_type),
            details: event
                .details
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect(),
            outcome: EventOutcome::Success,
            resource: None,
            action: None,
            risk_score: event.risk_score,
            location: None, // Will be converted separately
            device_fingerprint: event.device_fingerprint.clone(),
            mfa_used: event.mfa_used,
            token_binding_info: None,
        }
    }
}

/// Conversion helper for batch operations
#[must_use]
pub fn convert_security_events(events: &[SecurityEvent]) -> Vec<ThreatSecurityEvent> {
    events.iter().map(std::convert::Into::into).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::auth::AuthContext;
    use crate::core::security::{SecurityContext, SecurityFlags, SecurityLevel};
    use std::net::IpAddr;
    use std::time::SystemTime;

    #[test]
    fn test_event_type_conversion() {
        assert_eq!(
            ThreatSecurityEventType::from(SecurityEventType::AuthenticationFailure),
            ThreatSecurityEventType::AuthenticationFailure
        );
    }

    #[test]
    fn test_severity_conversion() {
        assert_eq!(
            ThreatSeverity::from(ViolationSeverity::Critical),
            ThreatSeverity::Critical
        );
    }

    #[test]
    fn test_security_event_conversion() {
        let security_event = SecurityEvent {
            timestamp: chrono::Utc::now(),
            event_type: SecurityEventType::AuthenticationFailure,
            security_context: SecurityContext {
                client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
                user_agent: "test-agent".to_string(),
                fingerprint: "test-fingerprint".to_string(),
                security_level: SecurityLevel::High,
                risk_score: 0.5,
                threat_indicators: vec![],
                flags: SecurityFlags::default(),
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
            user_id: Some("user-123".to_string()),
            session_id: Some("session-123".to_string()),
            ip_address: Some("127.0.0.1".parse::<IpAddr>().unwrap()),
            location: Some("US".to_string()),
            device_fingerprint: Some("device-123".to_string()),
            risk_score: Some(50),
            outcome: Some("failure".to_string()),
            mfa_used: false,
            user_agent: Some("test-agent".to_string()),
        };

        let threat_event: ThreatSecurityEvent = (&security_event).into();

        assert_eq!(
            threat_event.event_type,
            ThreatSecurityEventType::AuthenticationFailure
        );
        assert_eq!(threat_event.severity, ThreatSeverity::High);
        assert_eq!(threat_event.user_id, Some("user-123".to_string()));
    }
}
