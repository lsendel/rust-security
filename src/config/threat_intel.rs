use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    pub enabled: bool,
    pub block_threshold: u8,
    pub feed_urls: Vec<String>,
    pub update_interval_seconds: u64,
    pub cleanup_interval_seconds: u64,
    pub brute_force_threshold: usize,
    pub brute_force_window_minutes: i64,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_threshold: 70,
            feed_urls: vec![
                "https://api.threatintel.example.com/v1/indicators".to_string(),
            ],
            update_interval_seconds: 300,
            cleanup_interval_seconds: 3600,
            brute_force_threshold: 5,
            brute_force_window_minutes: 15,
        }
    }
}

impl ThreatIntelConfig {
    pub fn from_env() -> Self {
        Self {
            enabled: std::env::var("THREAT_INTEL_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            block_threshold: std::env::var("THREAT_INTEL_BLOCK_THRESHOLD")
                .unwrap_or_else(|_| "70".to_string())
                .parse()
                .unwrap_or(70),
            feed_urls: std::env::var("THREAT_INTEL_FEEDS")
                .unwrap_or_else(|_| "https://api.threatintel.example.com/v1/indicators".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            update_interval_seconds: std::env::var("THREAT_INTEL_UPDATE_INTERVAL")
                .unwrap_or_else(|_| "300".to_string())
                .parse()
                .unwrap_or(300),
            cleanup_interval_seconds: std::env::var("THREAT_INTEL_CLEANUP_INTERVAL")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .unwrap_or(3600),
            brute_force_threshold: std::env::var("BRUTE_FORCE_THRESHOLD")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .unwrap_or(5),
            brute_force_window_minutes: std::env::var("BRUTE_FORCE_WINDOW_MINUTES")
                .unwrap_or_else(|_| "15".to_string())
                .parse()
                .unwrap_or(15),
        }
    }
}
