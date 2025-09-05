//! Threat Intelligence Module
//!
//! Advanced threat detection and behavioral analysis capabilities for
//! identifying and responding to security threats in real-time.

pub mod behavioral_analysis;

use crate::monitoring::security_alerts::{SecurityAlert, SecurityEvent, AlertSeverity};
use behavioral_analysis::{
    BehavioralAnalysisEngine, BehaviorSnapshot, AnomalyDetection, GeoLocation
};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

/// Integrated threat intelligence service
pub struct ThreatIntelligenceService {
    behavioral_engine: BehavioralAnalysisEngine,
    alert_service: Arc<SecurityAlert>,
    enabled: bool,
}

impl ThreatIntelligenceService {
    /// Create new threat intelligence service
    pub fn new(alert_service: Arc<SecurityAlert>) -> Self {
        Self {
            behavioral_engine: BehavioralAnalysisEngine::new(),
            alert_service,
            enabled: true,
        }
    }

    /// Enable or disable threat intelligence
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        info!("Threat intelligence service: {}", if enabled { "enabled" } else { "disabled" });
    }

    /// Analyze authentication event for threats
    pub async fn analyze_authentication_event(
        &self,
        user_id: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        endpoint: Option<String>,
        success: bool,
        request_count: u32,
        session_duration: Option<f64>,
    ) -> Vec<AnomalyDetection> {
        if !self.enabled {
            return Vec::new();
        }

        let timestamp = chrono::Utc::now().timestamp() as u64;
        
        // Create behavior snapshot
        let snapshot = BehaviorSnapshot {
            user_id: user_id.to_string(),
            timestamp,
            ip_address,
            user_agent,
            endpoint,
            session_duration,
            request_count,
            failed_attempts: if success { 0 } else { 1 },
            geolocation: self.resolve_geolocation(ip_address).await,
        };

        debug!(
            "Analyzing authentication event for user: {} from IP: {:?}",
            user_id, ip_address
        );

        // Perform behavioral analysis
        let anomalies = self.behavioral_engine.analyze_behavior(snapshot).await;

        // Send alerts for detected anomalies
        for anomaly in &anomalies {
            if anomaly.risk_score >= 0.3 { // Configurable threshold
                let security_event = self.behavioral_engine.create_security_event(anomaly);
                
                if let Err(e) = self.alert_service.send_alert(&security_event).await {
                    warn!("Failed to send security alert: {}", e);
                } else {
                    info!(
                        "Security alert sent for anomaly: {:?} (risk: {:.2})",
                        anomaly.anomaly_type, anomaly.risk_score
                    );
                }
            }
        }

        anomalies
    }

    /// Analyze API access patterns
    pub async fn analyze_api_access(
        &self,
        user_id: &str,
        ip_address: Option<IpAddr>,
        endpoint: &str,
        method: &str,
        request_count: u32,
        response_time_ms: u64,
    ) -> Vec<AnomalyDetection> {
        if !self.enabled {
            return Vec::new();
        }

        let timestamp = chrono::Utc::now().timestamp() as u64;
        
        let snapshot = BehaviorSnapshot {
            user_id: user_id.to_string(),
            timestamp,
            ip_address,
            user_agent: None,
            endpoint: Some(format!("{} {}", method, endpoint)),
            session_duration: Some(response_time_ms as f64 / 1000.0),
            request_count,
            failed_attempts: 0,
            geolocation: self.resolve_geolocation(ip_address).await,
        };

        debug!(
            "Analyzing API access for user: {} to endpoint: {} {}",
            user_id, method, endpoint
        );

        let anomalies = self.behavioral_engine.analyze_behavior(snapshot).await;

        // Send alerts for high-risk anomalies
        for anomaly in &anomalies {
            if anomaly.risk_score >= 0.4 {
                let security_event = self.behavioral_engine.create_security_event(anomaly);
                
                if let Err(e) = self.alert_service.send_alert(&security_event).await {
                    warn!("Failed to send API access alert: {}", e);
                }
            }
        }

        anomalies
    }

    /// Get user risk assessment
    pub async fn get_user_risk_score(&self, user_id: &str) -> f64 {
        if let Some(profile) = self.behavioral_engine.get_user_profile(user_id).await {
            profile.risk_score
        } else {
            0.0 // No profile means no risk (yet)
        }
    }

    /// Get threat intelligence analytics
    pub async fn get_analytics(&self) -> behavioral_analysis::BehavioralAnalytics {
        self.behavioral_engine.get_analytics().await
    }

    /// Configure learning mode
    pub fn set_learning_enabled(&mut self, enabled: bool) {
        self.behavioral_engine.set_learning_enabled(enabled);
    }

    /// Resolve IP address to geolocation (stub implementation)
    async fn resolve_geolocation(&self, ip_address: Option<IpAddr>) -> Option<GeoLocation> {
        if let Some(_ip) = ip_address {
            // In a real implementation, this would call a geolocation service
            // For now, return a default location
            Some(GeoLocation {
                country: "Unknown".to_string(),
                city: "Unknown".to_string(),
                latitude: 0.0,
                longitude: 0.0,
            })
        } else {
            None
        }
    }
}

/// Threat intelligence middleware for automatic analysis
pub async fn threat_intelligence_middleware(
    user_id: Option<String>,
    ip_address: Option<IpAddr>,
    user_agent: Option<String>,
    endpoint: String,
    request_count: u32,
) {
    if let Some(user_id) = user_id {
        // This would integrate with the global threat intelligence service
        debug!(
            "Threat intelligence analysis for user: {} at endpoint: {}",
            user_id, endpoint
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::alert_handlers::AlertHandlerFactory;
    use crate::monitoring::security_alerts::SecurityAlert;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_threat_intelligence_service() {
        let handlers = AlertHandlerFactory::create_handlers();
        let alert_service = Arc::new(SecurityAlert::new(handlers));
        
        let mut service = ThreatIntelligenceService::new(alert_service);
        service.set_enabled(true);

        let anomalies = service.analyze_authentication_event(
            "test_user",
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Some("Mozilla/5.0".to_string()),
            Some("/api/v1/auth/login".to_string()),
            true,
            1,
            Some(1000.0),
        ).await;

        // First authentication should not trigger anomalies
        assert!(anomalies.is_empty());

        let risk_score = service.get_user_risk_score("test_user").await;
        assert_eq!(risk_score, 0.0); // Initial risk score
    }

    #[tokio::test]
    async fn test_api_access_analysis() {
        let handlers = AlertHandlerFactory::create_handlers();
        let alert_service = Arc::new(SecurityAlert::new(handlers));
        
        let service = ThreatIntelligenceService::new(alert_service);

        let anomalies = service.analyze_api_access(
            "test_user",
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            "/api/v1/users",
            "GET",
            10,
            250,
        ).await;

        // First API access should create profile
        assert!(anomalies.is_empty());
    }
}