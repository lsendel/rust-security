//! Threat detection adapter interface for bridging core security and threat modules

use crate::core::security::SecurityEvent;
#[cfg(feature = "threat-hunting")]
use crate::event_conversion::convert_security_events;
#[cfg(feature = "threat-hunting")]
use crate::threat_types::ThreatSecurityEvent;

/// Adapter trait for threat detection modules
#[cfg(feature = "threat-hunting")]
pub trait ThreatDetectionAdapter {
    /// Process a security event through threat detection
    async fn process_security_event(&self, event: &SecurityEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    
    /// Process multiple security events in batch
    async fn process_security_events(&self, events: &[SecurityEvent]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for event in events {
            self.process_security_event(event).await?;
        }
        Ok(())
    }
}

/// Helper function to convert and process security events
#[cfg(feature = "threat-hunting")]
pub async fn process_with_conversion<F, Fut>(
    event: &SecurityEvent,
    processor: F,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: FnOnce(ThreatSecurityEvent) -> Fut,
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>,
{
    let threat_event: ThreatSecurityEvent = event.into();
    processor(threat_event).await
}

/// Batch processing helper
#[cfg(feature = "threat-hunting")]
pub async fn process_batch_with_conversion<F, Fut>(
    events: &[SecurityEvent],
    processor: F,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: FnOnce(Vec<ThreatSecurityEvent>) -> Fut,
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>,
{
    let threat_events = convert_security_events(events);
    processor(threat_events).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::security::{SecurityContext, SecurityLevel, ViolationSeverity};
    use crate::core::auth::AuthContext;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::time::SystemTime;

    #[cfg(feature = "threat-hunting")]
    #[tokio::test]
    async fn test_process_with_conversion() {
        let event = SecurityEvent {
            timestamp: SystemTime::now(),
            event_type: crate::core::security::SecurityEventType::AuthenticationFailure,
            security_context: SecurityContext {
                client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
                user_agent: "test".to_string(),
                fingerprint: "test".to_string(),
                security_level: SecurityLevel::High,
                risk_score: 0.8,
                threat_indicators: vec![],
                flags: Default::default(),
                metadata: HashMap::new(),
            },
            auth_context: None,
            details: HashMap::new(),
            severity: ViolationSeverity::High,
        };

        let result = process_with_conversion(&event, |threat_event| async move {
            assert_eq!(threat_event.severity, crate::threat_types::ThreatSeverity::High);
            Ok(())
        }).await;

        assert!(result.is_ok());
    }
}
