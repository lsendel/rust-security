use crate::threat_intel::{ThreatIndicator, ThreatIntelService, ThreatType};
use reqwest::Client;
use serde_json::Value;
use tokio::time::{interval, Duration};

pub struct ThreatFeedManager {
    service: ThreatIntelService,
    client: Client,
    feeds: Vec<String>,
}

impl ThreatFeedManager {
    pub fn new(service: ThreatIntelService, feeds: Vec<String>) -> Self {
        Self {
            service,
            client: Client::new(),
            feeds,
        }
    }

    pub async fn start_feed_updates(&self) {
        let mut interval = interval(Duration::from_secs(300)); // 5 minutes
        
        loop {
            interval.tick().await;
            for feed_url in &self.feeds {
                if let Err(e) = self.update_from_feed(feed_url).await {
                    eprintln!("Feed update failed for {}: {}", feed_url, e);
                }
            }
        }
    }

    async fn update_from_feed(&self, url: &str) -> Result<(), Box<dyn std::error::Error>> {
        let response: Value = self.client.get(url).send().await?.json().await?;
        
        if let Some(indicators) = response["indicators"].as_array() {
            for indicator in indicators {
                if let Some(ip) = indicator["ip"].as_str() {
                    let risk_score = indicator["risk_score"].as_u64().unwrap_or(50) as u8;
                    let threat_type = match indicator["type"].as_str() {
                        Some("malware") => ThreatType::Malware,
                        Some("botnet") => ThreatType::Botnet,
                        Some("bruteforce") => ThreatType::BruteForce,
                        _ => ThreatType::Suspicious,
                    };

                    let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);
                    
                    self.service.add_indicator(ThreatIndicator {
                        ip: ip.to_string(),
                        risk_score,
                        threat_type,
                        expires_at,
                    }).await;
                }
            }
        }
        Ok(())
    }
}
