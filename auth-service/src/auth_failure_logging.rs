use crate::security_logging::{SecurityEvent, SecurityEventType, SecuritySeverity};
use dashmap::DashMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Enhanced authentication failure tracking and logging
pub struct AuthFailureTracker {
    /// Track failure counts per IP address
    ip_failures: DashMap<String, FailureStats>,
    /// Track failure counts per client ID
    client_failures: DashMap<String, FailureStats>,
    /// Track failure counts per user agent
    user_agent_failures: DashMap<String, FailureStats>,
    /// Global failure counter
    global_failures: AtomicU64,
    /// Configuration
    config: AuthFailureConfig,
}

#[derive(Debug, Clone)]
pub struct AuthFailureConfig {
    /// Maximum failures before marking as suspicious
    pub max_failures_per_ip: u32,
    /// Maximum failures before marking client as suspicious
    pub max_failures_per_client: u32,
    /// Time window for failure counting (seconds)
    pub failure_window_secs: u64,
    /// Whether to log all failures or only suspicious ones
    pub log_all_failures: bool,
    /// Whether to include request details in logs
    pub include_request_details: bool,
}

impl Default for AuthFailureConfig {
    fn default() -> Self {
        Self {
            max_failures_per_ip: 10,
            max_failures_per_client: 20,
            failure_window_secs: 3600, // 1 hour
            log_all_failures: true,
            include_request_details: true,
        }
    }
}

#[derive(Debug)]
pub struct FailureStats {
    /// Total failure count
    count: AtomicU64,
    /// First failure timestamp
    first_failure: AtomicU64,
    /// Last failure timestamp
    last_failure: AtomicU64,
    /// Whether marked as suspicious
    is_suspicious: std::sync::atomic::AtomicBool,
}

impl FailureStats {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            count: AtomicU64::new(0),
            first_failure: AtomicU64::new(now),
            last_failure: AtomicU64::new(now),
            is_suspicious: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn increment(&self, max_failures: u32, window_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.last_failure.store(now, Ordering::Relaxed);

        // Check if we're in a new window
        let first_failure = self.first_failure.load(Ordering::Relaxed);
        if now > first_failure + window_secs {
            // Reset window
            self.first_failure.store(now, Ordering::Relaxed);
            self.count.store(1, Ordering::Relaxed);
            self.is_suspicious.store(false, Ordering::Relaxed);
            return false;
        }

        let count = self.count.fetch_add(1, Ordering::Relaxed) + 1;

        // Check if should be marked suspicious
        if count >= u64::from(max_failures) {
            self.is_suspicious.store(true, Ordering::Relaxed);
            return true;
        }

        false
    }

    fn get_stats(&self) -> (u64, u64, u64, bool) {
        (
            self.count.load(Ordering::Relaxed),
            self.first_failure.load(Ordering::Relaxed),
            self.last_failure.load(Ordering::Relaxed),
            self.is_suspicious.load(Ordering::Relaxed),
        )
    }
}

impl AuthFailureTracker {
    #[must_use] pub fn new(config: AuthFailureConfig) -> Self {
        Self {
            ip_failures: DashMap::new(),
            client_failures: DashMap::new(),
            user_agent_failures: DashMap::new(),
            global_failures: AtomicU64::new(0),
            config,
        }
    }

    /// Log authentication failure with comprehensive tracking
    pub fn log_auth_failure(
        &self,
        failure_type: AuthFailureType,
        client_id: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        failure_reason: &str,
        additional_context: Option<HashMap<String, Value>>,
    ) {
        // Increment global counter
        self.global_failures.fetch_add(1, Ordering::Relaxed);

        let mut is_suspicious = false;
        let mut suspicious_reasons = Vec::new();

        // Track IP-based failures
        if let Some(ip) = ip_address {
            let entry = self
                .ip_failures
                .entry(ip.to_string())
                .or_insert_with(FailureStats::new);
            if entry.increment(
                self.config.max_failures_per_ip,
                self.config.failure_window_secs,
            ) {
                is_suspicious = true;
                suspicious_reasons.push(format!("IP {ip} exceeded failure threshold"));
            }
        }

        // Track client-based failures
        if let Some(client) = client_id {
            let entry = self
                .client_failures
                .entry(client.to_string())
                .or_insert_with(FailureStats::new);
            if entry.increment(
                self.config.max_failures_per_client,
                self.config.failure_window_secs,
            ) {
                is_suspicious = true;
                suspicious_reasons.push(format!("Client {client} exceeded failure threshold"));
            }
        }

        // Track user agent patterns
        if let Some(ua) = user_agent {
            // Only track suspicious user agents
            if self.is_suspicious_user_agent(ua) {
                let entry = self
                    .user_agent_failures
                    .entry(ua.to_string())
                    .or_insert_with(FailureStats::new);
                entry.increment(50, self.config.failure_window_secs); // Higher threshold for UA
                suspicious_reasons.push("Suspicious user agent detected".to_string());
                is_suspicious = true;
            }
        }

        // Determine severity based on failure type and suspicion level
        let severity = match failure_type {
            AuthFailureType::InvalidCredentials => {
                if is_suspicious {
                    SecuritySeverity::High
                } else {
                    SecuritySeverity::Medium
                }
            }
            AuthFailureType::AccountLocked => SecuritySeverity::High,
            AuthFailureType::AccountDisabled => SecuritySeverity::Medium,
            AuthFailureType::InvalidClient => SecuritySeverity::High,
            AuthFailureType::ExpiredToken => SecuritySeverity::Low,
            AuthFailureType::InvalidToken => SecuritySeverity::Medium,
            AuthFailureType::InsufficientScope => SecuritySeverity::Medium,
            AuthFailureType::RateLimited => SecuritySeverity::Warning,
            AuthFailureType::MfaRequired => SecuritySeverity::Info,
            AuthFailureType::MfaFailed => SecuritySeverity::High,
            AuthFailureType::SuspiciousActivity => SecuritySeverity::Critical,
        };

        // Create detailed security event
        let mut event = SecurityEvent::new(
            SecurityEventType::AuthenticationFailure,
            severity,
            "auth-service".to_string(),
            format!("Authentication failure: {failure_reason}"),
        )
        .with_action("authentication".to_string())
        .with_detail_string("failure_type".to_string(), format!("{failure_type:?}"))
        .with_detail_string("failure_reason".to_string(), failure_reason.to_string())
        .with_outcome("failure".to_string());

        // Add context information
        if let Some(client) = client_id {
            event = event.with_detail_string("client_id".to_string(), client.to_string());
        }

        if let Some(ip) = ip_address {
            event = event.with_detail_string("ip_address".to_string(), ip.to_string());
        }

        if let Some(ua) = user_agent {
            event = event.with_detail_string("user_agent".to_string(), ua.to_string());
        }

        // Add suspicious activity indicators
        if is_suspicious {
            event = event.with_detail_string("is_suspicious".to_string(), "true".to_string());
            event = event.with_detail_string(
                "suspicious_reasons".to_string(),
                suspicious_reasons.join(", "),
            );
        }

        // Add additional context
        if let Some(context) = additional_context {
            for (key, value) in context {
                event.details.insert(key, value);
            }
        }

        // Add failure statistics
        if self.config.include_request_details {
            if let Some(ip) = ip_address {
                if let Some(ip_stats) = self.ip_failures.get(ip) {
                    let (count, first, _last, suspicious) = ip_stats.get_stats();
                    event =
                        event.with_detail_string("ip_failure_count".to_string(), count.to_string());
                    event =
                        event.with_detail_string("ip_first_failure".to_string(), first.to_string());
                    event = event
                        .with_detail_string("ip_is_suspicious".to_string(), suspicious.to_string());
                }
            }
        }

        // Log the event
        let mut event = event
            .with_actor(if is_suspicious { "attacker" } else { "user" }.to_string())
            .with_action("authenticate".to_string())
            .with_target("auth_service".to_string())
            .with_outcome("failure".to_string())
            .with_reason(failure_reason.to_string());

        crate::security_logging::log_event(&mut event);

        // Log additional alert for suspicious activity
        if is_suspicious {
            self.log_suspicious_activity_alert(
                client_id,
                ip_address,
                user_agent,
                &suspicious_reasons,
            );
        }
    }

    /// Check if user agent appears suspicious
    fn is_suspicious_user_agent(&self, user_agent: &str) -> bool {
        let ua_lower = user_agent.to_lowercase();

        // Common bot/scanner patterns
        let suspicious_patterns = [
            "bot", "crawler", "spider", "scraper", "scanner", "curl", "wget", "python", "go-http",
            "java", "postman", "insomnia", "httpie", "nmap", "nikto", "sqlmap", "burp", "zap",
        ];

        suspicious_patterns
            .iter()
            .any(|pattern| ua_lower.contains(pattern))
    }

    /// Log suspicious activity alert
    fn log_suspicious_activity_alert(
        &self,
        client_id: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        reasons: &[String],
    ) {
        let mut event = SecurityEvent::new(
            SecurityEventType::SuspiciousActivity,
            SecuritySeverity::Critical,
            "auth-service".to_string(),
            "Suspicious authentication activity detected".to_string(),
        )
        .with_action("suspicious_activity_detection".to_string())
        .with_detail_string("reasons".to_string(), reasons.join("; "))
        .with_outcome("alert_generated".to_string());

        if let Some(client) = client_id {
            event = event.with_detail_string("client_id".to_string(), client.to_string());
        }

        if let Some(ip) = ip_address {
            event = event.with_detail_string("ip_address".to_string(), ip.to_string());
        }

        if let Some(ua) = user_agent {
            event = event.with_detail_string("user_agent".to_string(), ua.to_string());
        }

        let mut event = event
            .with_actor("system".to_string())
            .with_action("detect_attack".to_string())
            .with_target("user_account".to_string())
            .with_outcome("detected".to_string())
            .with_reason("Suspicious authentication patterns detected".to_string());

        crate::security_logging::log_event(&mut event);
    }

    /// Get failure statistics
    pub fn get_failure_stats(&self) -> FailureStatsSummary {
        FailureStatsSummary {
            global_failures: self.global_failures.load(Ordering::Relaxed),
            unique_failing_ips: self.ip_failures.len(),
            unique_failing_clients: self.client_failures.len(),
            suspicious_ips: self
                .ip_failures
                .iter()
                .filter(|entry| entry.value().is_suspicious.load(Ordering::Relaxed))
                .count(),
            suspicious_clients: self
                .client_failures
                .iter()
                .filter(|entry| entry.value().is_suspicious.load(Ordering::Relaxed))
                .count(),
        }
    }

    /// Check if IP is marked as suspicious
    pub fn is_ip_suspicious(&self, ip: &str) -> bool {
        self.ip_failures
            .get(ip)
            .is_some_and(|entry| entry.is_suspicious.load(Ordering::Relaxed))
    }

    /// Check if client is marked as suspicious
    pub fn is_client_suspicious(&self, client_id: &str) -> bool {
        self.client_failures
            .get(client_id)
            .is_some_and(|entry| entry.is_suspicious.load(Ordering::Relaxed))
    }
}

/// Types of authentication failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFailureType {
    InvalidCredentials,
    AccountLocked,
    AccountDisabled,
    InvalidClient,
    ExpiredToken,
    InvalidToken,
    InsufficientScope,
    RateLimited,
    MfaRequired,
    MfaFailed,
    SuspiciousActivity,
}

#[derive(Debug, Clone)]
pub struct FailureStatsSummary {
    pub global_failures: u64,
    pub unique_failing_ips: usize,
    pub unique_failing_clients: usize,
    pub suspicious_ips: usize,
    pub suspicious_clients: usize,
}

/// Global authentication failure tracker
static AUTH_FAILURE_TRACKER: once_cell::sync::Lazy<AuthFailureTracker> =
    once_cell::sync::Lazy::new(|| AuthFailureTracker::new(AuthFailureConfig::default()));

/// Convenience function to log authentication failures
pub fn log_auth_failure(
    failure_type: AuthFailureType,
    client_id: Option<&str>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    failure_reason: &str,
    additional_context: Option<HashMap<String, Value>>,
) {
    AUTH_FAILURE_TRACKER.log_auth_failure(
        failure_type,
        client_id,
        ip_address,
        user_agent,
        failure_reason,
        additional_context,
    );
}

/// Get failure statistics
pub fn get_auth_failure_stats() -> FailureStatsSummary {
    AUTH_FAILURE_TRACKER.get_failure_stats()
}

/// Check if IP is suspicious
pub fn is_ip_suspicious(ip: &str) -> bool {
    AUTH_FAILURE_TRACKER.is_ip_suspicious(ip)
}

/// Check if client is suspicious
pub fn is_client_suspicious(client_id: &str) -> bool {
    AUTH_FAILURE_TRACKER.is_client_suspicious(client_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_tracking() {
        let config = AuthFailureConfig {
            max_failures_per_ip: 3,
            max_failures_per_client: 5,
            failure_window_secs: 3600,
            log_all_failures: true,
            include_request_details: true,
        };

        let tracker = AuthFailureTracker::new(config);

        // Simulate failures from same IP
        for _i in 0..5 {
            tracker.log_auth_failure(
                AuthFailureType::InvalidCredentials,
                Some("test_client"),
                Some("192.168.1.1"),
                Some("Mozilla/5.0"),
                "Invalid password",
                None,
            );
        }

        // IP should be marked as suspicious after 3 failures
        assert!(tracker.is_ip_suspicious("192.168.1.1"));

        let stats = tracker.get_failure_stats();
        assert_eq!(stats.global_failures, 5);
        assert_eq!(stats.unique_failing_ips, 1);
        assert_eq!(stats.suspicious_ips, 1);
    }

    #[test]
    fn test_suspicious_user_agent_detection() {
        let tracker = AuthFailureTracker::new(AuthFailureConfig::default());

        assert!(tracker.is_suspicious_user_agent("curl/7.68.0"));
        assert!(tracker.is_suspicious_user_agent("python-requests/2.25.1"));
        assert!(tracker.is_suspicious_user_agent("Googlebot/2.1"));
        assert!(!tracker.is_suspicious_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ));
    }

    #[test]
    fn test_failure_window_reset() {
        let config = AuthFailureConfig {
            max_failures_per_ip: 2,
            failure_window_secs: 1, // 1 second window
            ..Default::default()
        };

        let tracker = AuthFailureTracker::new(config);

        // First failure
        tracker.log_auth_failure(
            AuthFailureType::InvalidCredentials,
            None,
            Some("192.168.1.2"),
            None,
            "Test failure",
            None,
        );

        // Wait for window to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Second failure should start new window
        tracker.log_auth_failure(
            AuthFailureType::InvalidCredentials,
            None,
            Some("192.168.1.2"),
            None,
            "Test failure",
            None,
        );

        // Should not be suspicious yet (new window)
        assert!(!tracker.is_ip_suspicious("192.168.1.2"));
    }
}
