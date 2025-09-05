use crate::threat_intel::{ThreatIntelService, feeds::ThreatFeedManager, detector::ThreatDetector};
use tokio::time::{interval, Duration};

pub struct ThreatAuthService {
    pub intel_service: ThreatIntelService,
    pub detector: ThreatDetector,
    pub feed_manager: ThreatFeedManager,
}

impl ThreatAuthService {
    pub fn new(feed_urls: Vec<String>) -> Self {
        let intel_service = ThreatIntelService::new();
        let detector = ThreatDetector::new(intel_service.clone());
        let feed_manager = ThreatFeedManager::new(intel_service.clone(), feed_urls);

        Self {
            intel_service,
            detector,
            feed_manager,
        }
    }

    pub async fn start(&self) {
        tokio::spawn({
            let feed_manager = self.feed_manager.clone();
            async move {
                feed_manager.start_feed_updates().await;
            }
        });

        tokio::spawn({
            let intel_service = self.intel_service.clone();
            async move {
                let mut cleanup_interval = interval(Duration::from_secs(3600)); // 1 hour
                loop {
                    cleanup_interval.tick().await;
                    intel_service.cleanup_expired().await;
                }
            }
        });
    }

    pub async fn handle_auth_failure(&self, ip: &str) {
        self.detector.record_failed_login(ip).await;
    }

    pub async fn assess_risk(&self, ip: &str, user_agent: &str) -> u8 {
        let base_risk = self.detector.analyze_request(ip, user_agent).await;
        
        if let Some(indicator) = self.intel_service.check_ip(ip).await {
            base_risk.max(indicator.risk_score)
        } else {
            base_risk
        }
    }
}
