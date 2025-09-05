use crate::threat_intel::{ThreatIndicator, ThreatIntelService, ThreatType};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;

pub struct ThreatDetector {
    service: ThreatIntelService,
    login_attempts: Arc<RwLock<HashMap<String, Vec<chrono::DateTime<chrono::Utc>>>>>,
}

impl ThreatDetector {
    pub fn new(service: ThreatIntelService) -> Self {
        Self {
            service,
            login_attempts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn record_failed_login(&self, ip: &str) {
        let mut attempts = self.login_attempts.write().await;
        let now = chrono::Utc::now();
        let ip_attempts = attempts.entry(ip.to_string()).or_insert_with(Vec::new);
        
        ip_attempts.push(now);
        ip_attempts.retain(|&time| now.signed_duration_since(time).num_minutes() < 15);

        if ip_attempts.len() >= 5 {
            self.service.add_indicator(ThreatIndicator {
                ip: ip.to_string(),
                risk_score: 80,
                threat_type: ThreatType::BruteForce,
                expires_at: now + chrono::Duration::hours(1),
            }).await;
        }
    }

    pub async fn analyze_request(&self, ip: &str, user_agent: &str) -> u8 {
        let mut risk_score = 0;

        if user_agent.contains("bot") || user_agent.len() < 10 {
            risk_score += 30;
        }

        if let Some(attempts) = self.login_attempts.read().await.get(ip) {
            risk_score += (attempts.len() as u8 * 10).min(50);
        }

        risk_score
    }
}
