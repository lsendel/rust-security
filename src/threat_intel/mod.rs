pub mod feeds;
pub mod detector;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub ip: String,
    pub risk_score: u8,
    pub threat_type: ThreatType,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    Malware,
    Botnet,
    BruteForce,
    Suspicious,
}

#[derive(Debug, Clone)]
pub struct ThreatIntelService {
    indicators: Arc<RwLock<HashMap<String, ThreatIndicator>>>,
}

impl ThreatIntelService {
    pub fn new() -> Self {
        Self {
            indicators: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn check_ip(&self, ip: &str) -> Option<ThreatIndicator> {
        let indicators = self.indicators.read().await;
        indicators.get(ip).cloned()
    }

    pub async fn add_indicator(&self, indicator: ThreatIndicator) {
        let mut indicators = self.indicators.write().await;
        indicators.insert(indicator.ip.clone(), indicator);
    }

    pub async fn is_blocked(&self, ip: &str, threshold: u8) -> bool {
        if let Some(indicator) = self.check_ip(ip).await {
            indicator.risk_score >= threshold && indicator.expires_at > chrono::Utc::now()
        } else {
            false
        }
    }

    pub async fn cleanup_expired(&self) {
        let mut indicators = self.indicators.write().await;
        let now = chrono::Utc::now();
        indicators.retain(|_, indicator| indicator.expires_at > now);
    }
}
