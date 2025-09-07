//! Security Metrics Module
//!
//! Provides security-related metrics collection and reporting functionality.

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

/// Global security metrics instance
pub static SECURITY_METRICS: LazyLock<SecurityMetrics> = LazyLock::new(SecurityMetrics::new);

/// Security metrics collector optimized for concurrent access
pub struct SecurityMetrics {
    // Use DashMap for better concurrent performance instead of RwLock<HashMap>
    failed_logins: DashMap<String, AtomicU64>,
    blocked_ips: DashMap<String, AtomicU64>,
    security_events: DashMap<String, AtomicU64>,

    // Global counters for common metrics
    total_failed_logins: AtomicU64,
    total_blocked_ips: AtomicU64,
    total_security_events: AtomicU64,
}

impl SecurityMetrics {
    /// Create a new `SecurityMetrics` instance
    #[must_use]
    pub fn new() -> Self {
        Self {
            failed_logins: DashMap::new(),
            blocked_ips: DashMap::new(),
            security_events: DashMap::new(),
            total_failed_logins: AtomicU64::new(0),
            total_blocked_ips: AtomicU64::new(0),
            total_security_events: AtomicU64::new(0),
        }
    }

    /// Record a failed login attempt
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn record_failed_login(&self, ip: &str) {
        let logins = self
            .failed_logins
            .entry(ip.to_string())
            .or_insert(AtomicU64::new(0));
        logins.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record a blocked IP
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn record_blocked_ip(&self, ip: &str) {
        let blocked = self
            .blocked_ips
            .entry(ip.to_string())
            .or_insert(AtomicU64::new(0));
        blocked.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a security event
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn record_security_event(&self, event_type: &str) {
        let events = self
            .security_events
            .entry(event_type.to_string())
            .or_insert(AtomicU64::new(0));
        events.fetch_add(1, Ordering::Relaxed);
    }

    /// Get failed login count for an IP
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn get_failed_login_count(&self, ip: &str) -> u64 {
        self.failed_logins
            .get(ip)
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get all security metrics
    /// # Panics
    /// Panics if internal locks are poisoned.
    pub fn get_all_metrics(&self) -> HashMap<String, u64> {
        let mut all_metrics = HashMap::new();

        for entry in &self.failed_logins {
            let ip = entry.key();
            let count = entry.value().load(Ordering::Relaxed);
            all_metrics.insert(format!("failed_logins_{ip}"), count);
        }

        for entry in &self.blocked_ips {
            let ip = entry.key();
            let count = entry.value().load(Ordering::Relaxed);
            all_metrics.insert(format!("blocked_ip_{ip}"), count);
        }

        for entry in &self.security_events {
            let event = entry.key();
            let count = entry.value().load(Ordering::Relaxed);
            all_metrics.insert(format!("security_event_{event}"), count);
        }

        all_metrics
    }
}

impl Default for SecurityMetrics {
    fn default() -> Self {
        Self::new()
    }
}
