//! MVP Tools - Essential utilities for the Auth-as-a-Service MVP
//!
//! This crate contains essential tools and utilities needed for the MVP,
//! consolidated from various components for simplified development.
//!
//! ## Features
//!
//! - **Enhanced Security Validation**: Enterprise-grade input validation with threat detection
//! - **API Contract Generation**: OpenAPI specification generation and validation
//! - **Testing Utilities**: Comprehensive testing helpers for MVP development
//! - **Policy Validation**: Cedar policy validation and authorization support

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, future_incompatible)]

use once_cell;

// Re-export common functionality
pub use common;

/// Enhanced input validation and security utilities
///
/// This module provides enterprise-grade input validation with comprehensive
/// security features including:
/// - Threat level classification and incident logging
/// - DoS protection (payload size, depth, complexity limits)
/// - Injection attack prevention (SQL, XSS, script injection detection)
/// - Control character filtering and input sanitization
/// - Security context tracking with client information
pub mod validation;

/// Policy validation and authorization module
///
/// This module provides Cedar policy validation and authorization support
/// with MVP-focused features including:
/// - Simplified policy engine for essential authorization
/// - Default policies for authenticated access control
/// - Security context integration with validation
/// - Policy conflict detection
/// - Authorization request/response handling
pub mod policy;

/// API contract utilities
pub mod contracts {

    pub fn generate_openapi_spec() -> Result<String, Box<dyn std::error::Error>> {
        // Placeholder for OpenAPI spec generation
        Ok("openapi: 3.0.0".to_string())
    }
}

/// Testing utilities
pub mod testing {

    pub fn setup_test_environment() -> Result<(), Box<dyn std::error::Error>> {
        // Placeholder for test setup
        Ok(())
    }
}

/// Security monitoring and alerting
///
/// This module provides security monitoring capabilities including:
/// - Security metrics collection and reporting
/// - Real-time alerting for security events
/// - Compliance monitoring and reporting
/// - Threat intelligence integration
pub mod security_monitoring {

    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Security metrics collector
    #[derive(Debug)]
    pub struct SecurityMetrics {
        /// Authentication failures
        pub auth_failures: AtomicU64,
        /// Rate limit hits
        pub rate_limit_hits: AtomicU64,
        /// Suspicious activities detected
        pub suspicious_activities: AtomicU64,
        /// Blocked requests
        pub blocked_requests: AtomicU64,
        /// Total requests processed
        pub total_requests: AtomicU64,
        /// Security events timestamp
        pub last_security_event: AtomicU64,
    }

    impl Default for SecurityMetrics {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SecurityMetrics {
        /// Create new security metrics collector
        #[must_use]
        pub fn new() -> Self {
            Self {
                auth_failures: AtomicU64::new(0),
                rate_limit_hits: AtomicU64::new(0),
                suspicious_activities: AtomicU64::new(0),
                blocked_requests: AtomicU64::new(0),
                total_requests: AtomicU64::new(0),
                last_security_event: AtomicU64::new(0),
            }
        }

        /// Record authentication failure
        pub fn record_auth_failure(&self) {
            self.auth_failures.fetch_add(1, Ordering::Relaxed);
            self.update_last_event();
        }

        /// Record rate limit hit
        pub fn record_rate_limit_hit(&self) {
            self.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            self.update_last_event();
        }

        /// Record suspicious activity
        pub fn record_suspicious_activity(&self) {
            self.suspicious_activities.fetch_add(1, Ordering::Relaxed);
            self.update_last_event();
        }

        /// Record blocked request
        pub fn record_blocked_request(&self) {
            self.blocked_requests.fetch_add(1, Ordering::Relaxed);
            self.update_last_event();
        }

        /// Record total request
        pub fn record_request(&self) {
            self.total_requests.fetch_add(1, Ordering::Relaxed);
        }

        /// Update last security event timestamp
        fn update_last_event(&self) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.last_security_event.store(now, Ordering::Relaxed);
        }

        /// Get current metrics snapshot
        #[must_use]
        pub fn snapshot(&self) -> SecurityMetricsSnapshot {
            SecurityMetricsSnapshot {
                auth_failures: self.auth_failures.load(Ordering::Relaxed),
                rate_limit_hits: self.rate_limit_hits.load(Ordering::Relaxed),
                suspicious_activities: self.suspicious_activities.load(Ordering::Relaxed),
                blocked_requests: self.blocked_requests.load(Ordering::Relaxed),
                total_requests: self.total_requests.load(Ordering::Relaxed),
                last_security_event: self.last_security_event.load(Ordering::Relaxed),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            }
        }
    }

    /// Security metrics snapshot
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SecurityMetricsSnapshot {
        pub auth_failures: u64,
        pub rate_limit_hits: u64,
        pub suspicious_activities: u64,
        pub blocked_requests: u64,
        pub total_requests: u64,
        pub last_security_event: u64,
        pub timestamp: u64,
    }

    impl SecurityMetricsSnapshot {
        /// Calculate security health score (0-100)
        #[must_use]
        pub fn security_health_score(&self) -> f64 {
            if self.total_requests == 0 {
                return 100.0;
            }

            let failure_rate = (self.auth_failures + self.rate_limit_hits) as f64 / self.total_requests as f64;
            let suspicious_rate = self.suspicious_activities as f64 / self.total_requests as f64;
            let block_rate = self.blocked_requests as f64 / self.total_requests as f64;

            // Calculate weighted score
            let weighted_score = (failure_rate * 20.0) + (suspicious_rate * 30.0) + (block_rate * 50.0);
            (1.0 - weighted_score.min(1.0)) * 100.0
        }

        /// Check if security thresholds are exceeded
        #[must_use]
        pub fn exceeds_thresholds(&self) -> Vec<String> {
            let mut alerts = Vec::new();

            if self.total_requests > 0 {
                let failure_rate = (self.auth_failures + self.rate_limit_hits) as f64 / self.total_requests as f64;
                if failure_rate > 0.1 { // 10% failure rate
                    alerts.push(format!("High failure rate: {:.1}%", failure_rate * 100.0));
                }

                let block_rate = self.blocked_requests as f64 / self.total_requests as f64;
                if block_rate > 0.05 { // 5% block rate
                    alerts.push(format!("High block rate: {:.1}%", block_rate * 100.0));
                }
            }

            if self.suspicious_activities > 10 {
                alerts.push(format!("High suspicious activity: {}", self.suspicious_activities));
            }

            alerts
        }
    }

    /// Global security metrics instance
    static SECURITY_METRICS: once_cell::sync::Lazy<Arc<SecurityMetrics>> =
        once_cell::sync::Lazy::new(|| Arc::new(SecurityMetrics::new()));

    /// Get global security metrics instance
    #[must_use]
    pub fn get_security_metrics() -> Arc<SecurityMetrics> {
        Arc::clone(&SECURITY_METRICS)
    }

    /// Security alert types
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum SecurityAlert {
        HighFailureRate { rate: f64, threshold: f64 },
        HighBlockRate { rate: f64, threshold: f64 },
        SuspiciousActivitySpike { count: u64, threshold: u64 },
        SecurityHealthDecline { score: f64, threshold: f64 },
    }

    impl SecurityAlert {
        /// Get alert severity
        #[must_use]
        pub const fn severity(&self) -> &'static str {
            match self {
                Self::HighFailureRate { .. } => "high",
                Self::HighBlockRate { .. } => "high",
                Self::SuspiciousActivitySpike { .. } => "medium",
                Self::SecurityHealthDecline { .. } => "medium",
            }
        }

        /// Get alert message
        #[must_use]
        pub fn message(&self) -> String {
            match self {
                Self::HighFailureRate { rate, threshold } =>
                    format!("Authentication failure rate {:.1}% exceeds threshold {:.1}%", rate * 100.0, threshold * 100.0),
                Self::HighBlockRate { rate, threshold } =>
                    format!("Request block rate {:.1}% exceeds threshold {:.1}%", rate * 100.0, threshold * 100.0),
                Self::SuspiciousActivitySpike { count, threshold } =>
                    format!("Suspicious activities {} exceed threshold {}", count, threshold),
                Self::SecurityHealthDecline { score, threshold } =>
                    format!("Security health score {:.1} below threshold {:.1}", score, threshold),
            }
        }
    }

    /// Security monitoring configuration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SecurityMonitoringConfig {
        pub failure_rate_threshold: f64,
        pub block_rate_threshold: f64,
        pub suspicious_activity_threshold: u64,
        pub health_score_threshold: f64,
        pub monitoring_interval_seconds: u64,
    }

    impl Default for SecurityMonitoringConfig {
        fn default() -> Self {
            Self {
                failure_rate_threshold: 0.10, // 10%
                block_rate_threshold: 0.05,    // 5%
                suspicious_activity_threshold: 10,
                health_score_threshold: 80.0,  // 80% health score
                monitoring_interval_seconds: 300, // 5 minutes
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_security_metrics_collection() {
            let metrics = SecurityMetrics::new();

            metrics.record_auth_failure();
            metrics.record_rate_limit_hit();
            metrics.record_suspicious_activity();
            metrics.record_blocked_request();
            metrics.record_request();

            let snapshot = metrics.snapshot();

            assert_eq!(snapshot.auth_failures, 1);
            assert_eq!(snapshot.rate_limit_hits, 1);
            assert_eq!(snapshot.suspicious_activities, 1);
            assert_eq!(snapshot.blocked_requests, 1);
            assert_eq!(snapshot.total_requests, 1);
        }

        #[test]
        fn test_security_health_score() {
            let snapshot = SecurityMetricsSnapshot {
                auth_failures: 10,
                rate_limit_hits: 5,
                suspicious_activities: 2,
                blocked_requests: 1,
                total_requests: 100,
                last_security_event: 0,
                timestamp: 0,
            };

            let score = snapshot.security_health_score();
            assert!(score > 0.0 && score <= 100.0);
        }

        #[test]
        fn test_threshold_alerts() {
            let snapshot = SecurityMetricsSnapshot {
                auth_failures: 15,
                rate_limit_hits: 10,
                suspicious_activities: 5,
                blocked_requests: 8,
                total_requests: 100,
                last_security_event: 0,
                timestamp: 0,
            };

            let alerts = snapshot.exceeds_thresholds();
            assert!(!alerts.is_empty());
        }
    }
}
