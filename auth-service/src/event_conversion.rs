//! Event conversion utilities for bridging core security and threat detection systems

#[cfg(feature = "threat-hunting")]
use crate::core::security::{SecurityEvent, SecurityEventType, ViolationSeverity};
#[cfg(feature = "threat-hunting")]
use crate::threat_types::{
    EventOutcome, ThreatSecurityEvent, ThreatSecurityEventType, ThreatSeverity,
};

/// Convert `SecurityEventType` to `ThreatSecurityEventType`
#[cfg(feature = "threat-hunting")]
impl From<SecurityEventType> for ThreatSecurityEventType {
    fn from(event_type: SecurityEventType) -> Self {
        match event_type {
            SecurityEventType::AuthenticationFailure => Self::AuthenticationFailure,
            SecurityEventType::AuthenticationSuccess | SecurityEventType::Login => Self::AuthenticationSuccess,
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
#[cfg(feature = "threat-hunting")]
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
#[cfg(feature = "threat-hunting")]
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
#[cfg(feature = "threat-hunting")]
#[must_use]
pub fn convert_security_events(events: &[SecurityEvent]) -> Vec<ThreatSecurityEvent> {
    events.iter().map(std::convert::Into::into).collect()
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "threat-hunting")]
    use super::*;
    #[cfg(feature = "threat-hunting")]
    use crate::core::auth::AuthContext;
    #[cfg(feature = "threat-hunting")]
    use crate::core::security::{SecurityContext, SecurityLevel};
    #[cfg(feature = "threat-hunting")]
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

        assert_eq!(
            threat_event.event_type,
            ThreatSecurityEventType::AuthenticationFailure
        );
        assert_eq!(threat_event.severity, ThreatSeverity::High);
        assert_eq!(threat_event.user_id, Some("user-123".to_string()));
    }
}
