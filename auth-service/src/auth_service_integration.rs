//! Integration point for threat processing in the auth service

use crate::core::security::SecurityEvent;
use crate::threat_processor::ThreatProcessor;
use std::sync::Arc;

/// Auth service with integrated threat processing
pub struct AuthServiceWithThreatProcessing {
    threat_processor: Arc<ThreatProcessor>,
}

impl AuthServiceWithThreatProcessing {
    /// Create a new auth service with threat processing
    pub fn new(threat_processor: Arc<ThreatProcessor>) -> Self {
        Self { threat_processor }
    }

    /// Process a security event through the threat detection pipeline
    pub async fn process_security_event(&self, event: SecurityEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Process the event through threat detection
        self.threat_processor.process_event(&event).await?;
        
        // Continue with normal auth service processing
        // (This would integrate with existing auth service logic)
        
        Ok(())
    }

    /// Get the threat processor for direct access
    pub fn threat_processor(&self) -> &Arc<ThreatProcessor> {
        &self.threat_processor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::security::{SecurityContext, SecurityLevel, ViolationSeverity, SecurityEventType};
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_auth_service_integration() {
        let threat_processor = Arc::new(ThreatProcessor::new());
        let auth_service = AuthServiceWithThreatProcessing::new(threat_processor);

        let event = SecurityEvent {
            timestamp: SystemTime::now(),
            event_type: SecurityEventType::AuthenticationFailure,
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

        let result = auth_service.process_security_event(event).await;
        assert!(result.is_ok());
    }
}
