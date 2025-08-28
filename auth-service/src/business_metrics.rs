//! Simple Business Metrics for Auth Service
//!
//! MVP implementation for tracking basic authentication operation counts.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

/// Simple auth metrics using HashMap counters
pub struct AuthMetrics {
    login_attempts: RwLock<HashMap<String, u64>>,
    active_sessions: RwLock<u64>,
    token_operations: RwLock<HashMap<String, u64>>,
}

impl AuthMetrics {
    pub fn new() -> Self {
        Self {
            login_attempts: RwLock::new(HashMap::new()),
            active_sessions: RwLock::new(0),
            token_operations: RwLock::new(HashMap::new()),
        }
    }

    /// Increment login success counter
    pub fn record_login_success(&self) {
        let mut attempts = self.login_attempts.write().unwrap();
        *attempts.entry("success".to_string()).or_insert(0) += 1;
    }

    /// Increment login failure counter
    pub fn record_login_failure(&self) {
        let mut attempts = self.login_attempts.write().unwrap();
        *attempts.entry("failure".to_string()).or_insert(0) += 1;
    }

    /// Increment active session counter
    pub fn session_started(&self) {
        let mut count = self.active_sessions.write().unwrap();
        *count += 1;
    }

    /// Decrement active session counter
    pub fn session_ended(&self) {
        let mut count = self.active_sessions.write().unwrap();
        if *count > 0 {
            *count -= 1;
        }
    }

    /// Increment token issue counter
    pub fn record_token_issued(&self) {
        let mut operations = self.token_operations.write().unwrap();
        *operations.entry("issued".to_string()).or_insert(0) += 1;
    }

    /// Increment token revoke counter
    pub fn record_token_revoked(&self) {
        let mut operations = self.token_operations.write().unwrap();
        *operations.entry("revoked".to_string()).or_insert(0) += 1;
    }

    /// Get login attempt counts
    pub fn get_login_attempts(&self) -> HashMap<String, u64> {
        self.login_attempts.read().unwrap().clone()
    }

    /// Get active session count
    pub fn get_active_sessions(&self) -> u64 {
        *self.active_sessions.read().unwrap()
    }

    /// Get token operation counts
    pub fn get_token_operations(&self) -> HashMap<String, u64> {
        self.token_operations.read().unwrap().clone()
    }

    /// Get all metrics as a simple summary
    pub fn get_summary(&self) -> MetricsSummary {
        MetricsSummary {
            login_attempts: self.get_login_attempts(),
            active_sessions: self.get_active_sessions(),
            token_operations: self.get_token_operations(),
        }
    }

    /// Reset all counters (useful for testing)
    pub fn reset(&self) {
        self.login_attempts.write().unwrap().clear();
        *self.active_sessions.write().unwrap() = 0;
        self.token_operations.write().unwrap().clear();
    }
}

/// Simple metrics summary struct
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub login_attempts: HashMap<String, u64>,
    pub active_sessions: u64,
    pub token_operations: HashMap<String, u64>,
}

impl Default for AuthMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Global metrics instance
static METRICS: std::sync::OnceLock<AuthMetrics> = std::sync::OnceLock::new();

/// Get the global metrics instance
pub fn get_metrics() -> &'static AuthMetrics {
    METRICS.get_or_init(AuthMetrics::new)
}

/// Business metrics helper for compatibility with other modules
pub struct BusinessMetricsHelper;

/// Type alias for compatibility with other modules
pub type BusinessMetricsRegistry = BusinessMetricsHelper;

impl BusinessMetricsHelper {
    /// Create a new BusinessMetricsHelper instance
    pub fn new() -> Self {
        Self
    }

    /// Record rate limit enforcement
    pub fn record_rate_limit_enforcement(
        _path: &str,
        _client_key: &str,
        _action: &str,
        _request_type: &str,
    ) {
        let metrics = get_metrics();
        if _action == "allowed" {
            metrics.record_login_success();
        } else if _action == "blocked" {
            metrics.record_login_failure();
        }
    }

    /// Record cache operation
    pub fn record_cache_operation(
        _cache_type: &str,
        _operation: &str,
        _result: &str,
        _duration: Duration,
    ) {
        // For now, just track as general operations
        let _metrics = get_metrics();
        // Could extend to track cache-specific metrics
    }

    /// Record security event
    pub fn record_security_event(_event_type: &str, _severity: &str) {
        let _metrics = get_metrics();
        // Could extend to track security-specific metrics
    }

    /// Record authentication event
    pub fn record_auth_event(_event_type: &str, _method: &str, _success: bool) {
        let metrics = get_metrics();
        if _success {
            metrics.record_login_success();
        } else {
            metrics.record_login_failure();
        }
    }

    /// Record API endpoint access
    pub fn record_api_access(
        _endpoint: &str,
        _method: &str,
        _status_code: u16,
        _duration: Duration,
    ) {
        let _metrics = get_metrics();
        // Could extend to track API-specific metrics
    }
}

impl Default for BusinessMetricsHelper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_metrics_creation() {
        let metrics = AuthMetrics::new();
        assert_eq!(metrics.get_active_sessions(), 0);
        assert!(metrics.get_login_attempts().is_empty());
        assert!(metrics.get_token_operations().is_empty());
    }

    #[test]
    fn test_login_tracking() {
        let metrics = AuthMetrics::new();

        metrics.record_login_success();
        metrics.record_login_success();
        metrics.record_login_failure();

        let attempts = metrics.get_login_attempts();
        assert_eq!(attempts.get("success"), Some(&2));
        assert_eq!(attempts.get("failure"), Some(&1));
    }

    #[test]
    fn test_session_tracking() {
        let metrics = AuthMetrics::new();

        metrics.session_started();
        metrics.session_started();
        assert_eq!(metrics.get_active_sessions(), 2);

        metrics.session_ended();
        assert_eq!(metrics.get_active_sessions(), 1);

        // Should not go below 0
        metrics.session_ended();
        metrics.session_ended();
        assert_eq!(metrics.get_active_sessions(), 0);
    }

    #[test]
    fn test_token_operations() {
        let metrics = AuthMetrics::new();

        metrics.record_token_issued();
        metrics.record_token_issued();
        metrics.record_token_revoked();

        let operations = metrics.get_token_operations();
        assert_eq!(operations.get("issued"), Some(&2));
        assert_eq!(operations.get("revoked"), Some(&1));
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = AuthMetrics::new();

        metrics.record_login_success();
        metrics.session_started();
        metrics.record_token_issued();

        metrics.reset();

        assert_eq!(metrics.get_active_sessions(), 0);
        assert!(metrics.get_login_attempts().is_empty());
        assert!(metrics.get_token_operations().is_empty());
    }

    #[test]
    fn test_global_metrics() {
        let metrics = get_metrics();
        metrics.record_login_success();
        assert_eq!(metrics.get_login_attempts().get("success"), Some(&1));
    }
}
