//! Threat detection adapter interface for bridging core security and threat modules

use crate::core::security::SecurityEvent;
use crate::event_conversion::convert_security_events;
use crate::threat_types::ThreatSecurityEvent;

/// Adapter trait for threat detection modules
#[async_trait::async_trait]
pub trait ThreatDetectionAdapter {
    async fn process_security_event(
        &self,
        event: &SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    async fn process_security_events(
        &self,
        events: &[SecurityEvent],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for event in events {
            self.process_security_event(event).await?;
        }
        Ok(())
    }
}

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