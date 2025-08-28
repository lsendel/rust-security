//! Security Metrics Module
//!
//! Provides security-related metrics collection and reporting functionality.

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::RwLock;

/// Global security metrics instance
pub static SECURITY_METRICS: Lazy<SecurityMetrics> = Lazy::new(|| SecurityMetrics::new());

/// Security metrics collector
pub struct SecurityMetrics {
    failed_logins: RwLock<HashMap<String, u64>>,
    blocked_ips: RwLock<HashMap<String, u64>>,
    security_events: RwLock<HashMap<String, u64>>,
}

impl SecurityMetrics {
    /// Create a new SecurityMetrics instance
    pub fn new() -> Self {
        Self {
            failed_logins: RwLock::new(HashMap::new()),
            blocked_ips: RwLock::new(HashMap::new()),
            security_events: RwLock::new(HashMap::new()),
        }
    }

    /// Record a failed login attempt
    pub fn record_failed_login(&self, ip: &str) {
        let mut logins = self.failed_logins.write().unwrap();
        *logins.entry(ip.to_string()).or_insert(0) += 1;
    }

    /// Record a blocked IP
    pub fn record_blocked_ip(&self, ip: &str) {
        let mut blocked = self.blocked_ips.write().unwrap();
        *blocked.entry(ip.to_string()).or_insert(0) += 1;
    }

    /// Record a security event
    pub fn record_security_event(&self, event_type: &str) {
        let mut events = self.security_events.write().unwrap();
        *events.entry(event_type.to_string()).or_insert(0) += 1;
    }

    /// Get failed login count for an IP
    pub fn get_failed_login_count(&self, ip: &str) -> u64 {
        let logins = self.failed_logins.read().unwrap();
        logins.get(ip).copied().unwrap_or(0)
    }

    /// Get all security metrics
    pub fn get_all_metrics(&self) -> HashMap<String, u64> {
        let mut all_metrics = HashMap::new();

        let failed_logins = self.failed_logins.read().unwrap();
        for (ip, count) in failed_logins.iter() {
            all_metrics.insert(format!("failed_logins_{}", ip), *count);
        }

        let blocked_ips = self.blocked_ips.read().unwrap();
        for (ip, count) in blocked_ips.iter() {
            all_metrics.insert(format!("blocked_ip_{}", ip), *count);
        }

        let security_events = self.security_events.read().unwrap();
        for (event, count) in security_events.iter() {
            all_metrics.insert(format!("security_event_{}", event), *count);
        }

        all_metrics
    }
}

impl Default for SecurityMetrics {
    fn default() -> Self {
        Self::new()
    }
}
