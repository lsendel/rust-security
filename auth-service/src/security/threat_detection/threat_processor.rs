#![allow(clippy::unused_async)]
//! Unified threat processing service that coordinates all threat detection modules

use crate::core::security::SecurityEvent;
use crate::security::threat_detection::threat_adapter::ThreatDetectionAdapter;
use crate::{
    security::threat_detection::threat_behavioral_analyzer::AdvancedBehavioralThreatDetector as BehavioralAnalyzer,
    security::threat_detection::threat_response_orchestrator::ThreatResponseOrchestrator,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Stub implementation for ThreatIntelligenceEngine
pub struct ThreatIntelligenceEngine;

impl ThreatIntelligenceEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ThreatIntelligenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of ThreatDetectionAdapter for ThreatIntelligenceEngine
#[async_trait::async_trait]
impl crate::security::threat_detection::threat_adapter::ThreatDetectionAdapter for ThreatIntelligenceEngine {
    async fn process_security_event(
        &self,
        _event: &crate::core::security::SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Stub implementation
        Ok(())
    }
}

/// Unified threat processing service
pub struct ThreatProcessor {
    behavioral_analyzer: Arc<BehavioralAnalyzer>,
    intelligence_engine: Arc<ThreatIntelligenceEngine>,
    response_orchestrator: Arc<ThreatResponseOrchestrator>,
    enabled: Arc<RwLock<bool>>,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_threat_processor_enabled() {
        // This test would need mock implementations of the threat modules
        // For now, we just test basic functionality
        let config = crate::security::threat_behavioral_analyzer::BehavioralAnalysisConfig::default();
        let behavioral_analyzer = Arc::new(BehavioralAnalyzer::new(config));
        let intelligence_engine = Arc::new(ThreatIntelligenceEngine::new());
        let response_orchestrator = Arc::new(ThreatResponseOrchestrator::new(
            crate::security::threat_response_orchestrator::ThreatResponseConfig::default(),
        ));

        let processor = ThreatProcessor::new(
            behavioral_analyzer,
            intelligence_engine,
            response_orchestrator,
        );

        assert!(processor.is_enabled().await);

        processor.set_enabled(false).await;
        assert!(!processor.is_enabled().await);
    }
}
