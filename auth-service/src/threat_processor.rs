#![allow(clippy::unused_async)]
//! Unified threat processing service that coordinates all threat detection modules

use crate::core::security::SecurityEvent;
#[cfg(feature = "threat-hunting")]
use crate::threat_adapter::ThreatDetectionAdapter;
#[cfg(feature = "threat-hunting")]
use crate::{
    threat_behavioral_analyzer::AdvancedBehavioralThreatDetector as BehavioralAnalyzer,
    threat_intelligence::ThreatIntelligenceCorrelator as ThreatIntelligenceEngine,
    threat_response_orchestrator::ThreatResponseOrchestrator,
};
#[cfg(feature = "threat-hunting")]
use std::sync::Arc;
#[cfg(feature = "threat-hunting")]
use tokio::sync::RwLock;

/// Unified threat processing service
#[cfg(feature = "threat-hunting")]
pub struct ThreatProcessor {
    behavioral_analyzer: Arc<BehavioralAnalyzer>,
    intelligence_engine: Arc<ThreatIntelligenceEngine>,
    response_orchestrator: Arc<ThreatResponseOrchestrator>,
    enabled: Arc<RwLock<bool>>,
}

#[cfg(feature = "threat-hunting")]
impl ThreatProcessor {
    /// Create a new threat processor
    #[must_use]
    pub fn new(
        behavioral_analyzer: Arc<BehavioralAnalyzer>,
        intelligence_engine: Arc<ThreatIntelligenceEngine>,
        response_orchestrator: Arc<ThreatResponseOrchestrator>,
    ) -> Self {
        Self {
            behavioral_analyzer,
            intelligence_engine,
            response_orchestrator,
            enabled: Arc::new(RwLock::new(true)),
        }
    }

    /// Process a security event through all threat detection modules
    ///
    /// # Errors
    ///
    /// Currently returns Ok(()) even if individual modules fail, as errors are logged
    /// rather than propagated. This may change in future versions.
    #[allow(clippy::cognitive_complexity)]
    pub async fn process_event(
        &self,
        event: &SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !*self.enabled.read().await {
            return Ok(());
        }

        // Process through behavioral analyzer
        if let Err(e) = self.behavioral_analyzer.process_security_event(event).await {
            tracing::warn!("Behavioral analysis failed: {}", e);
        }

        // Process through intelligence engine
        if let Err(e) = self.intelligence_engine.process_security_event(event).await {
            tracing::warn!("Intelligence correlation failed: {}", e);
        }

        // Process through response orchestrator
        if let Err(e) = self
            .response_orchestrator
            .process_security_event(event)
            .await
        {
            tracing::warn!("Response orchestration failed: {}", e);
        }

        Ok(())
    }

    /// Process multiple events in batch
    ///
    /// # Errors
    ///
    /// Currently returns Ok(()) even if individual modules fail, as errors are logged
    /// rather than propagated. This may change in future versions.
    pub async fn process_events(
        &self,
        events: &[SecurityEvent],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !*self.enabled.read().await {
            return Ok(());
        }

        for event in events {
            self.process_event(event).await?;
        }
        Ok(())
    }

    /// Enable or disable threat processing
    pub async fn set_enabled(&self, enabled: bool) {
        *self.enabled.write().await = enabled;
    }

    /// Check if threat processing is enabled
    pub async fn is_enabled(&self) -> bool {
        *self.enabled.read().await
    }
}

/// No-op implementation when threat-hunting feature is disabled
#[cfg(not(feature = "threat-hunting"))]
pub struct ThreatProcessor;

#[cfg(not(feature = "threat-hunting"))]
impl Default for ThreatProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "threat-hunting"))]
impl ThreatProcessor {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Process a security event (no-op implementation for when threat-hunting is disabled)
    ///
    /// # Errors
    ///
    /// This implementation never returns an error
    pub async fn process_event(
        &self,
        _event: &SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    /// Process multiple security events (no-op implementation for when threat-hunting is disabled)
    ///
    /// # Errors
    ///
    /// This implementation never returns an error
    pub async fn process_events(
        &self,
        _events: &[SecurityEvent],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub async fn set_enabled(&self, _enabled: bool) {}

    pub async fn is_enabled(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "threat-hunting")]
    #[tokio::test]
    async fn test_threat_processor_disabled_feature() {
        #[cfg(not(feature = "threat-hunting"))]
        {
            let processor = crate::threat_processor::ThreatProcessor::new();
            assert!(!processor.is_enabled().await);
        }
    }
}
