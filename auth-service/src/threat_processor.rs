#![allow(clippy::unused_async)]
//! Unified threat processing service that coordinates all threat detection modules

use crate::core::security::SecurityEvent;
use crate::threat_adapter::ThreatDetectionAdapter;
use crate::{
    threat_behavioral_analyzer::AdvancedBehavioralThreatDetector as BehavioralAnalyzer,
    threat_intelligence::ThreatIntelligenceCorrelator as ThreatIntelligenceEngine,
    threat_response_orchestrator::ThreatResponseOrchestrator,
};
use std::sync::Arc;
use tokio::sync::RwLock;

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
        let config = crate::threat_behavioral_analyzer::BehavioralAnalysisConfig::default();
        let behavioral_analyzer = Arc::new(BehavioralAnalyzer::new(config));
        let intelligence_engine = Arc::new(ThreatIntelligenceEngine::new(
            crate::threat_intelligence::ThreatIntelligenceConfig::default(),
        ));
        let response_orchestrator = Arc::new(ThreatResponseOrchestrator::new(
            crate::threat_response_orchestrator::ThreatResponseConfig::default(),
        ));
        
        let processor = ThreatProcessor::new(
            behavioral_analyzer,
            intelligence_engine, 
            response_orchestrator
        );
        
        assert!(processor.is_enabled().await);
        
        processor.set_enabled(false).await;
        assert!(!processor.is_enabled().await);
    }
}