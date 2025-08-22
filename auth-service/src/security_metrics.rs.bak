use once_cell::sync::Lazy;
use prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry};
use std::time::Instant;

/// Security-specific metrics for monitoring and alerting
pub struct SecurityMetrics {
    pub registry: Registry,

    // Authentication metrics
    pub auth_attempts_total: IntCounterVec,
    pub auth_failures_total: IntCounterVec,
    pub auth_success_total: IntCounterVec,

    // Token metrics
    pub tokens_issued_total: IntCounterVec,
    pub tokens_revoked_total: IntCounterVec,
    pub token_binding_violations_total: IntCounter,
    pub token_introspection_total: IntCounterVec,

    // Security event metrics
    pub security_events_total: IntCounterVec,
    pub input_validation_failures_total: IntCounterVec,
    pub rate_limit_hits_total: IntCounterVec,
    pub request_signature_failures_total: IntCounter,

    // MFA metrics
    pub mfa_attempts_total: IntCounterVec,
    pub mfa_failures_total: IntCounterVec,
    pub backup_codes_used_total: IntCounter,

    // System security metrics
    pub active_sessions: IntGauge,
    pub suspicious_activity_total: IntCounterVec,
    pub security_headers_applied_total: IntCounter,

    // Performance security metrics
    pub auth_duration_seconds: HistogramVec,
    pub token_validation_duration_seconds: Histogram,
}

impl SecurityMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let auth_attempts_total = IntCounterVec::new(
            Opts::new("auth_attempts_total", "Total authentication attempts"),
            &["client_id", "method", "result"],
        )?;

        let auth_failures_total = IntCounterVec::new(
            Opts::new("auth_failures_total", "Total authentication failures"),
            &["client_id", "reason", "ip_address"],
        )?;

        let auth_success_total = IntCounterVec::new(
            Opts::new("auth_success_total", "Total successful authentications"),
            &["client_id", "method", "scope"],
        )?;

        let tokens_issued_total = IntCounterVec::new(
            Opts::new("tokens_issued_total", "Total tokens issued"),
            &["token_type", "client_id", "grant_type"],
        )?;

        let tokens_revoked_total = IntCounterVec::new(
            Opts::new("tokens_revoked_total", "Total tokens revoked"),
            &["token_type", "reason", "client_id"],
        )?;

        let token_binding_violations_total = IntCounter::new(
            "token_binding_violations_total",
            "Total token binding violations detected",
        )?;

        let token_introspection_total = IntCounterVec::new(
            Opts::new(
                "token_introspection_total",
                "Total token introspection requests",
            ),
            &["result", "client_id"],
        )?;

        let security_events_total = IntCounterVec::new(
            Opts::new("security_events_total", "Total security events"),
            &["event_type", "severity", "source"],
        )?;

        let input_validation_failures_total = IntCounterVec::new(
            Opts::new(
                "input_validation_failures_total",
                "Total input validation failures",
            ),
            &["endpoint", "validation_type", "client_id"],
        )?;

        let rate_limit_hits_total = IntCounterVec::new(
            Opts::new("rate_limit_hits_total", "Total rate limit hits"),
            &["client_id", "ip_address", "endpoint"],
        )?;

        let request_signature_failures_total = IntCounter::new(
            "request_signature_failures_total",
            "Total request signature validation failures",
        )?;

        let mfa_attempts_total = IntCounterVec::new(
            Opts::new("mfa_attempts_total", "Total MFA attempts"),
            &["method", "client_id", "result"],
        )?;

        let mfa_failures_total = IntCounterVec::new(
            Opts::new("mfa_failures_total", "Total MFA failures"),
            &["method", "reason", "client_id"],
        )?;

        let backup_codes_used_total =
            IntCounter::new("backup_codes_used_total", "Total backup codes used for MFA")?;

        let active_sessions =
            IntGauge::new("active_sessions", "Number of currently active sessions")?;

        let suspicious_activity_total = IntCounterVec::new(
            Opts::new(
                "suspicious_activity_total",
                "Total suspicious activities detected",
            ),
            &["activity_type", "severity", "ip_address"],
        )?;

        let security_headers_applied_total = IntCounter::new(
            "security_headers_applied_total",
            "Total security headers applied to responses",
        )?;

        let auth_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "auth_duration_seconds",
                "Authentication request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ]),
            &["method", "result"],
        )?;

        let token_validation_duration_seconds = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "token_validation_duration_seconds",
                "Token validation duration in seconds",
            )
            .buckets(vec![
                0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
            ]),
        )?;

        // Register all metrics
        registry.register(Box::new(auth_attempts_total.clone()))?;
        registry.register(Box::new(auth_failures_total.clone()))?;
        registry.register(Box::new(auth_success_total.clone()))?;
        registry.register(Box::new(tokens_issued_total.clone()))?;
        registry.register(Box::new(tokens_revoked_total.clone()))?;
        registry.register(Box::new(token_binding_violations_total.clone()))?;
        registry.register(Box::new(token_introspection_total.clone()))?;
        registry.register(Box::new(security_events_total.clone()))?;
        registry.register(Box::new(input_validation_failures_total.clone()))?;
        registry.register(Box::new(rate_limit_hits_total.clone()))?;
        registry.register(Box::new(request_signature_failures_total.clone()))?;
        registry.register(Box::new(mfa_attempts_total.clone()))?;
        registry.register(Box::new(mfa_failures_total.clone()))?;
        registry.register(Box::new(backup_codes_used_total.clone()))?;
        registry.register(Box::new(active_sessions.clone()))?;
        registry.register(Box::new(suspicious_activity_total.clone()))?;
        registry.register(Box::new(security_headers_applied_total.clone()))?;
        registry.register(Box::new(auth_duration_seconds.clone()))?;
        registry.register(Box::new(token_validation_duration_seconds.clone()))?;

        Ok(Self {
            registry,
            auth_attempts_total,
            auth_failures_total,
            auth_success_total,
            tokens_issued_total,
            tokens_revoked_total,
            token_binding_violations_total,
            token_introspection_total,
            security_events_total,
            input_validation_failures_total,
            rate_limit_hits_total,
            request_signature_failures_total,
            mfa_attempts_total,
            mfa_failures_total,
            backup_codes_used_total,
            active_sessions,
            suspicious_activity_total,
            security_headers_applied_total,
            auth_duration_seconds,
            token_validation_duration_seconds,
        })
    }

    /// Record an authentication attempt
    pub fn record_auth_attempt(&self, client_id: &str, method: &str, result: &str) {
        self.auth_attempts_total
            .with_label_values(&[client_id, method, result])
            .inc();
    }

    /// Record an authentication failure
    pub fn record_auth_failure(&self, client_id: &str, reason: &str, ip_address: &str) {
        self.auth_failures_total
            .with_label_values(&[client_id, reason, ip_address])
            .inc();
    }

    /// Record a security event
    pub fn record_security_event(&self, event_type: &str, severity: &str, source: &str) {
        self.security_events_total
            .with_label_values(&[event_type, severity, source])
            .inc();
    }

    /// Record input validation failure
    pub fn record_validation_failure(
        &self,
        endpoint: &str,
        validation_type: &str,
        client_id: &str,
    ) {
        self.input_validation_failures_total
            .with_label_values(&[endpoint, validation_type, client_id])
            .inc();
    }

    /// Record rate limit hit
    pub fn record_rate_limit_hit(&self, client_id: &str, ip_address: &str, endpoint: &str) {
        self.rate_limit_hits_total
            .with_label_values(&[client_id, ip_address, endpoint])
            .inc();
    }

    /// Record token binding violation
    pub fn record_token_binding_violation(&self) {
        self.token_binding_violations_total.inc();
    }

    /// Record suspicious activity
    pub fn record_suspicious_activity(
        &self,
        activity_type: &str,
        severity: &str,
        ip_address: &str,
    ) {
        self.suspicious_activity_total
            .with_label_values(&[activity_type, severity, ip_address])
            .inc();
    }

    /// Time an authentication operation
    pub fn time_auth_operation<F, R>(&self, method: &str, operation: F) -> R
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = operation();
        let duration = start.elapsed().as_secs_f64();

        self.auth_duration_seconds
            .with_label_values(&[method, "success"])
            .observe(duration);

        result
    }
}

impl Default for SecurityMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            tracing::error!("Failed to create default SecurityMetrics: {}", e);
            // Return a minimal metrics instance with default registry
            SecurityMetrics {
                registry: Registry::new(),
                auth_attempts_total: IntCounterVec::new(
                    Opts::new("auth_attempts_total_fallback", "Fallback metric"),
                    &["status"],
                ).unwrap_or_else(|_| IntCounterVec::new(Opts::new("fallback", ""), &[""]).unwrap()),
                auth_failures_total: IntCounterVec::new(
                    Opts::new("auth_failures_total_fallback", "Fallback metric"),
                    &["status"],
                ).unwrap_or_else(|_| IntCounterVec::new(Opts::new("fallback", ""), &[""]).unwrap()),
                auth_success_total: IntCounterVec::new(
                    Opts::new("auth_success_total_fallback", "Fallback metric"),
                    &["status"],
                ).unwrap_or_else(|_| IntCounterVec::new(Opts::new("fallback", ""), &[""]).unwrap()),
                tokens_issued_total: IntCounterVec::new(
                    Opts::new("tokens_issued_total_fallback", "Fallback metric"),
                    &["status"],
                ).unwrap_or_else(|_| IntCounterVec::new(Opts::new("fallback", ""), &[""]).unwrap()),
                tokens_revoked_total: IntCounterVec::new(
                    Opts::new("tokens_revoked_total_fallback", "Fallback metric"),
                    &["status"],
                ).unwrap_or_else(|_| IntCounterVec::new(Opts::new("fallback", ""), &[""]).unwrap()),
                token_binding_violations_total: IntCounter::new("token_binding_violations_total_fallback", "Fallback metric").unwrap(),
                token_introspection_total: IntCounterVec::new(
                    Opts::new("token_introspection_total_fallback", "Fallback metric"),
                    &["status"],
                ).unwrap_or_else(|_| IntCounterVec::new(Opts::new("fallback", ""), &[""]).unwrap()),
                security_events_total: IntCounterVec::new(
                    Opts::new("security_events_total_fallback", "Fallback metric"),
                    &["status"],
                ).unwrap_or_else(|_| IntCounterVec::new(Opts::new("fallback", ""), &[""]).unwrap()),
                input_validation_failures_total: IntCounterVec::new(
                    Opts::new("input_validation_failures_total_fallback", "Fallback metric"),
                    &["status"],
                ).unwrap_or_else(|_| IntCounterVec::new(Opts::new("fallback", ""), &[""]).unwrap()),
                rate_limit_hits_total: IntCounterVec::new(
                    Opts::new("rate_limit_hits_total_fallback", "Fallback metric"),
                    &["status"],
                ).unwrap_or_else(|_| IntCounterVec::new(Opts::new("fallback", ""), &[""]).unwrap()),
                request_signature_failures_total: IntCounter::new("request_signature_failures_total_fallback", "Fallback metric").unwrap(),
                mfa_attempts_total: IntCounterVec::new(
                    Opts::new("mfa_attempts_total_fallback", "Fallback metric"),
                    &["status"],
                ).unwrap_or_else(|_| IntCounterVec::new(Opts::new("fallback", ""), &[""]).unwrap()),
                mfa_failures_total: IntCounterVec::new(
                    Opts::new("mfa_failures_total_fallback", "Fallback metric"),
                    &["status"],
                ).unwrap_or_else(|_| IntCounterVec::new(Opts::new("fallback", ""), &[""]).unwrap()),
                backup_codes_used_total: IntCounter::new("backup_codes_used_total_fallback", "Fallback metric").unwrap(),
                active_sessions: IntGauge::new("active_sessions_fallback", "Fallback metric").unwrap(),
                suspicious_activity_total: IntCounterVec::new(
                    Opts::new("suspicious_activity_total_fallback", "Fallback metric"),
                    &["status"],
                ).unwrap_or_else(|_| IntCounterVec::new(Opts::new("fallback", ""), &[""]).unwrap()),
                security_headers_applied_total: IntCounter::new("security_headers_applied_total_fallback", "Fallback metric").unwrap(),
                auth_duration_seconds: HistogramVec::new(
                    prometheus::HistogramOpts::new("auth_duration_seconds_fallback", "Fallback metric"),
                    &["status"],
                ).unwrap_or_else(|_| HistogramVec::new(prometheus::HistogramOpts::new("fallback", ""), &[""]).unwrap()),
                token_validation_duration_seconds: Histogram::new("token_validation_duration_seconds_fallback".into(), "Fallback metric".into()).unwrap(),
            }
        })
    }
}

/// Global security metrics instance - use Result-based initialization
pub static SECURITY_METRICS: Lazy<SecurityMetrics> =
    Lazy::new(|| SecurityMetrics::default());

/// Helper macro for recording security events
#[macro_export]
macro_rules! record_security_event {
    ($event_type:expr, $severity:expr, $source:expr) => {
        $crate::security_metrics::SECURITY_METRICS.record_security_event(
            $event_type,
            $severity,
            $source,
        );
    };
}

/// Helper macro for recording authentication failures
#[macro_export]
macro_rules! record_auth_failure {
    ($client_id:expr, $reason:expr, $ip:expr) => {
        $crate::security_metrics::SECURITY_METRICS.record_auth_failure($client_id, $reason, $ip);
    };
}
