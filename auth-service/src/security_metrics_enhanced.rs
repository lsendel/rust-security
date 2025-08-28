//! Enhanced Security Metrics for Service Identity and JIT Token Management
//!
//! Provides comprehensive Prometheus metrics for monitoring the new security features
//! and detecting potential OAuth token compromise attempts.

#[cfg(feature = "monitoring")]
use prometheus::{
    register_counter_vec, register_gauge_vec, register_histogram_vec, register_int_counter_vec,
    register_int_gauge_vec, Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec,
    IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};

use once_cell::sync::Lazy;

/// Service Identity Management Metrics
#[cfg(feature = "monitoring")]
pub struct ServiceIdentityMetrics {
    // Identity registration and lifecycle
    pub identities_registered: IntCounterVec,
    pub identities_active: IntGaugeVec,
    pub identities_suspended: IntCounterVec,
    pub credential_rotations: IntCounterVec,
    
    // Token issuance and usage
    pub jit_tokens_issued: IntCounterVec,
    pub jit_tokens_revoked: IntCounterVec,
    pub jit_token_usage: IntCounterVec,
    pub token_request_duration: HistogramVec,
    pub token_lifetime_seconds: HistogramVec,
    
    // Security and monitoring
    pub behavioral_anomalies_detected: IntCounterVec,
    pub baselines_established: IntCounterVec,
    pub risk_scores: GaugeVec,
    pub policy_violations: IntCounterVec,
    pub auto_suspensions: IntCounterVec,
    
    // Performance metrics
    pub identity_lookup_duration: HistogramVec,
    pub baseline_analysis_duration: HistogramVec,
    pub monitoring_queue_size: IntGaugeVec,
}

#[cfg(feature = "monitoring")]
impl ServiceIdentityMetrics {
    fn new() -> Self {
        Self {
            // Identity management metrics
            identities_registered: register_int_counter_vec!(
                "service_identities_registered_total",
                "Total number of service identities registered",
                &["identity_type", "environment"]
            ).unwrap(),
            
            identities_active: register_int_gauge_vec!(
                "service_identities_active",
                "Number of active service identities",
                &["identity_type", "status"]
            ).unwrap(),
            
            identities_suspended: register_int_counter_vec!(
                "service_identities_suspended_total",
                "Total number of service identities suspended",
                &["identity_type", "reason"]
            ).unwrap(),
            
            credential_rotations: register_int_counter_vec!(
                "service_identity_rotations_total",
                "Total credential rotations performed",
                &["identity_type", "trigger"]
            ).unwrap(),
            
            // JIT Token metrics
            jit_tokens_issued: register_int_counter_vec!(
                "jit_tokens_issued_total",
                "Total JIT tokens issued",
                &["identity_type", "scopes_count"]
            ).unwrap(),
            
            jit_tokens_revoked: register_int_counter_vec!(
                "jit_tokens_revoked_total",
                "Total JIT tokens revoked",
                &["identity_type", "reason"]
            ).unwrap(),
            
            jit_token_usage: register_int_counter_vec!(
                "jit_token_usage_total",
                "Total JIT token usage events",
                &["identity_type", "endpoint"]
            ).unwrap(),
            
            token_request_duration: register_histogram_vec!(
                "jit_token_request_duration_seconds",
                "Duration of JIT token requests",
                &["identity_type", "result"],
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
            ).unwrap(),
            
            token_lifetime_seconds: register_histogram_vec!(
                "jit_token_lifetime_seconds",
                "Lifetime of issued JIT tokens",
                &["identity_type"],
                vec![60.0, 300.0, 600.0, 1800.0, 3600.0, 7200.0, 14400.0, 28800.0]
            ).unwrap(),
            
            // Security metrics
            behavioral_anomalies_detected: register_int_counter_vec!(
                "behavioral_anomalies_detected_total",
                "Total behavioral anomalies detected",
                &["identity_type", "anomaly_type", "severity"]
            ).unwrap(),
            
            baselines_established: register_int_counter_vec!(
                "behavioral_baselines_established_total",
                "Total behavioral baselines established",
                &["identity_type", "confidence_level"]
            ).unwrap(),
            
            risk_scores: register_gauge_vec!(
                "service_identity_risk_score",
                "Current risk score for service identities",
                &["identity_id", "identity_type"]
            ).unwrap(),
            
            policy_violations: register_int_counter_vec!(
                "policy_violations_total",
                "Total policy violations detected",
                &["identity_type", "policy_type", "violation_type"]
            ).unwrap(),
            
            auto_suspensions: register_int_counter_vec!(
                "auto_suspensions_total",
                "Total automatic suspensions triggered",
                &["identity_type", "trigger_reason"]
            ).unwrap(),
            
            // Performance metrics
            identity_lookup_duration: register_histogram_vec!(
                "identity_lookup_duration_seconds",
                "Duration of identity lookup operations",
                &["operation", "result"],
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1]
            ).unwrap(),
            
            baseline_analysis_duration: register_histogram_vec!(
                "baseline_analysis_duration_seconds",
                "Duration of behavioral baseline analysis",
                &["identity_type", "analysis_type"],
                vec![0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
            ).unwrap(),
            
            monitoring_queue_size: register_int_gauge_vec!(
                "monitoring_queue_size",
                "Size of monitoring queues",
                &["queue_type", "identity_type"]
            ).unwrap(),
        }
    }
}

/// JIT Token specific metrics
#[cfg(feature = "monitoring")]
pub struct JitTokenMetrics {
    pub tokens_created: IntCounterVec,
    pub tokens_validated: IntCounterVec,
    pub tokens_rejected: IntCounterVec,
    pub token_binding_failures: IntCounterVec,
    pub single_use_tokens: IntCounterVec,
    pub token_usage_exceeded: IntCounterVec,
    pub scope_filtering_events: IntCounterVec,
}

#[cfg(feature = "monitoring")]
impl JitTokenMetrics {
    fn new() -> Self {
        Self {
            tokens_created: register_int_counter_vec!(
                "jit_tokens_created_total",
                "Total JIT tokens created",
                &["identity_type", "single_use"]
            ).unwrap(),
            
            tokens_validated: register_int_counter_vec!(
                "jit_tokens_validated_total",
                "Total JIT token validation attempts",
                &["identity_type", "result"]
            ).unwrap(),
            
            tokens_rejected: register_int_counter_vec!(
                "jit_tokens_rejected_total",
                "Total JIT tokens rejected",
                &["identity_type", "reason"]
            ).unwrap(),
            
            token_binding_failures: register_int_counter_vec!(
                "jit_token_binding_failures_total",
                "Total token binding validation failures",
                &["identity_type", "binding_type"]
            ).unwrap(),
            
            single_use_tokens: register_int_counter_vec!(
                "jit_single_use_tokens_total",
                "Total single-use tokens consumed",
                &["identity_type", "operation"]
            ).unwrap(),
            
            token_usage_exceeded: register_int_counter_vec!(
                "jit_token_usage_exceeded_total",
                "Total tokens that exceeded usage limits",
                &["identity_type"]
            ).unwrap(),
            
            scope_filtering_events: register_int_counter_vec!(
                "jit_scope_filtering_total",
                "Total scope filtering events",
                &["identity_type", "requested_scopes", "granted_scopes"]
            ).unwrap(),
        }
    }
}

/// Non-human monitoring metrics
#[cfg(feature = "monitoring")]
pub struct MonitoringMetrics {
    pub activity_events_processed: IntCounterVec,
    pub anomaly_checks_performed: IntCounterVec,
    pub risk_score_updates: IntCounterVec,
    pub alert_generation_events: IntCounterVec,
    pub baseline_confidence_scores: GaugeVec,
    pub geographic_anomalies: IntCounterVec,
    pub temporal_anomalies: IntCounterVec,
    pub request_rate_anomalies: IntCounterVec,
}

#[cfg(feature = "monitoring")]
impl MonitoringMetrics {
    fn new() -> Self {
        Self {
            activity_events_processed: register_int_counter_vec!(
                "monitoring_activity_events_processed_total",
                "Total activity events processed",
                &["identity_type", "event_type"]
            ).unwrap(),
            
            anomaly_checks_performed: register_int_counter_vec!(
                "monitoring_anomaly_checks_total",
                "Total anomaly checks performed",
                &["identity_type", "check_type", "result"]
            ).unwrap(),
            
            risk_score_updates: register_int_counter_vec!(
                "monitoring_risk_score_updates_total",
                "Total risk score updates",
                &["identity_type", "score_change"]
            ).unwrap(),
            
            alert_generation_events: register_int_counter_vec!(
                "monitoring_alerts_generated_total",
                "Total monitoring alerts generated",
                &["identity_type", "alert_type", "severity"]
            ).unwrap(),
            
            baseline_confidence_scores: register_gauge_vec!(
                "monitoring_baseline_confidence",
                "Confidence scores for behavioral baselines",
                &["identity_id", "identity_type"]
            ).unwrap(),
            
            geographic_anomalies: register_int_counter_vec!(
                "monitoring_geographic_anomalies_total",
                "Total geographic anomalies detected",
                &["identity_type", "source_country", "suspicious"]
            ).unwrap(),
            
            temporal_anomalies: register_int_counter_vec!(
                "monitoring_temporal_anomalies_total",
                "Total temporal pattern anomalies",
                &["identity_type", "hour_of_day", "day_of_week"]
            ).unwrap(),
            
            request_rate_anomalies: register_int_counter_vec!(
                "monitoring_request_rate_anomalies_total",
                "Total request rate anomalies detected",
                &["identity_type", "rate_change_factor"]
            ).unwrap(),
        }
    }
}

/// Global metrics instances
#[cfg(feature = "monitoring")]
pub static SERVICE_IDENTITY_METRICS: Lazy<ServiceIdentityMetrics> = 
    Lazy::new(ServiceIdentityMetrics::new);

#[cfg(feature = "monitoring")]
pub static JIT_TOKEN_METRICS: Lazy<JitTokenMetrics> = 
    Lazy::new(JitTokenMetrics::new);

#[cfg(feature = "monitoring")]
pub static MONITORING_METRICS: Lazy<MonitoringMetrics> = 
    Lazy::new(MonitoringMetrics::new);

// Metric helper functions

/// Record service identity registration
#[cfg(feature = "monitoring")]
pub fn record_identity_registration(identity_type: &str, environment: Option<&str>) {
    SERVICE_IDENTITY_METRICS.identities_registered
        .with_label_values(&[identity_type, environment.unwrap_or("unknown")])
        .inc();
}

/// Update active identity count
#[cfg(feature = "monitoring")]
pub fn update_active_identities(identity_type: &str, status: &str, count: i64) {
    SERVICE_IDENTITY_METRICS.identities_active
        .with_label_values(&[identity_type, status])
        .set(count);
}

/// Record identity suspension
#[cfg(feature = "monitoring")]
pub fn record_identity_suspension(identity_type: &str, reason: &str) {
    SERVICE_IDENTITY_METRICS.identities_suspended
        .with_label_values(&[identity_type, reason])
        .inc();
}

/// Record credential rotation
#[cfg(feature = "monitoring")]
pub fn record_credential_rotation(identity_type: &str, trigger: &str) {
    SERVICE_IDENTITY_METRICS.credential_rotations
        .with_label_values(&[identity_type, trigger])
        .inc();
}

/// Record JIT token issuance
#[cfg(feature = "monitoring")]
pub fn record_jit_token_issued(identity_type: &str, scopes_count: usize, lifetime_seconds: u64) {
    JIT_TOKEN_METRICS.tokens_created
        .with_label_values(&[identity_type, "false"])
        .inc();
    
    SERVICE_IDENTITY_METRICS.jit_tokens_issued
        .with_label_values(&[identity_type, &scopes_count.to_string()])
        .inc();
    
    SERVICE_IDENTITY_METRICS.token_lifetime_seconds
        .with_label_values(&[identity_type])
        .observe(lifetime_seconds as f64);
}

/// Record JIT token validation
#[cfg(feature = "monitoring")]
pub fn record_jit_token_validation(identity_type: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    JIT_TOKEN_METRICS.tokens_validated
        .with_label_values(&[identity_type, result])
        .inc();
}

/// Record token binding failure
#[cfg(feature = "monitoring")]
pub fn record_token_binding_failure(identity_type: &str, binding_type: &str) {
    JIT_TOKEN_METRICS.token_binding_failures
        .with_label_values(&[identity_type, binding_type])
        .inc();
}

/// Record behavioral anomaly detection
#[cfg(feature = "monitoring")]
pub fn record_behavioral_anomaly(identity_type: &str, anomaly_type: &str, severity: &str) {
    SERVICE_IDENTITY_METRICS.behavioral_anomalies_detected
        .with_label_values(&[identity_type, anomaly_type, severity])
        .inc();
    
    MONITORING_METRICS.alert_generation_events
        .with_label_values(&[identity_type, anomaly_type, severity])
        .inc();
}

/// Update risk score
#[cfg(feature = "monitoring")]
pub fn update_risk_score(identity_id: &str, identity_type: &str, score: f64) {
    SERVICE_IDENTITY_METRICS.risk_scores
        .with_label_values(&[identity_id, identity_type])
        .set(score);
}

/// Record baseline establishment
#[cfg(feature = "monitoring")]
pub fn record_baseline_established(identity_type: &str, confidence: f32) {
    let confidence_level = match confidence {
        c if c >= 0.8 => "high",
        c if c >= 0.6 => "medium",
        c if c >= 0.4 => "low",
        _ => "very_low",
    };
    
    SERVICE_IDENTITY_METRICS.baselines_established
        .with_label_values(&[identity_type, confidence_level])
        .inc();
}

/// Record policy violation
#[cfg(feature = "monitoring")]
pub fn record_policy_violation(identity_type: &str, policy_type: &str, violation_type: &str) {
    SERVICE_IDENTITY_METRICS.policy_violations
        .with_label_values(&[identity_type, policy_type, violation_type])
        .inc();
}

/// Record auto suspension
#[cfg(feature = "monitoring")]
pub fn record_auto_suspension(identity_type: &str, trigger_reason: &str) {
    SERVICE_IDENTITY_METRICS.auto_suspensions
        .with_label_values(&[identity_type, trigger_reason])
        .inc();
}

/// Record geographic anomaly
#[cfg(feature = "monitoring")]
pub fn record_geographic_anomaly(identity_type: &str, source_country: &str, suspicious: bool) {
    MONITORING_METRICS.geographic_anomalies
        .with_label_values(&[identity_type, source_country, &suspicious.to_string()])
        .inc();
}

/// Record request rate anomaly
#[cfg(feature = "monitoring")]
pub fn record_request_rate_anomaly(identity_type: &str, rate_change_factor: f64) {
    let factor_bucket = match rate_change_factor {
        f if f >= 10.0 => "10x_or_more",
        f if f >= 5.0 => "5x_to_10x",
        f if f >= 2.0 => "2x_to_5x",
        f if f >= 1.5 => "1.5x_to_2x",
        _ => "less_than_1.5x",
    };
    
    MONITORING_METRICS.request_rate_anomalies
        .with_label_values(&[identity_type, factor_bucket])
        .inc();
}

/// Timing helper for token requests
#[cfg(feature = "monitoring")]
pub struct TokenRequestTimer {
    timer: std::time::Instant,
    identity_type: String,
}

#[cfg(feature = "monitoring")]
impl TokenRequestTimer {
    pub fn start(identity_type: String) -> Self {
        Self {
            timer: std::time::Instant::now(),
            identity_type,
        }
    }
    
    pub fn finish(self, success: bool) {
        let duration = self.timer.elapsed().as_secs_f64();
        let result = if success { "success" } else { "failure" };
        
        SERVICE_IDENTITY_METRICS.token_request_duration
            .with_label_values(&[&self.identity_type, result])
            .observe(duration);
    }
}

/// Timing helper for baseline analysis
#[cfg(feature = "monitoring")]
pub struct BaselineAnalysisTimer {
    timer: std::time::Instant,
    identity_type: String,
    analysis_type: String,
}

#[cfg(feature = "monitoring")]
impl BaselineAnalysisTimer {
    pub fn start(identity_type: String, analysis_type: String) -> Self {
        Self {
            timer: std::time::Instant::now(),
            identity_type,
            analysis_type,
        }
    }
    
    pub fn finish(self) {
        let duration = self.timer.elapsed().as_secs_f64();
        
        SERVICE_IDENTITY_METRICS.baseline_analysis_duration
            .with_label_values(&[&self.identity_type, &self.analysis_type])
            .observe(duration);
    }
}

// Stub implementations for when monitoring feature is disabled
#[cfg(not(feature = "monitoring"))]
pub fn record_identity_registration(_identity_type: &str, _environment: Option<&str>) {}

#[cfg(not(feature = "monitoring"))]
pub fn update_active_identities(_identity_type: &str, _status: &str, _count: i64) {}

#[cfg(not(feature = "monitoring"))]
pub fn record_identity_suspension(_identity_type: &str, _reason: &str) {}

#[cfg(not(feature = "monitoring"))]
pub fn record_credential_rotation(_identity_type: &str, _trigger: &str) {}

#[cfg(not(feature = "monitoring"))]
pub fn record_jit_token_issued(_identity_type: &str, _scopes_count: usize, _lifetime_seconds: u64) {}

#[cfg(not(feature = "monitoring"))]
pub fn record_jit_token_validation(_identity_type: &str, _success: bool) {}

#[cfg(not(feature = "monitoring"))]
pub fn record_token_binding_failure(_identity_type: &str, _binding_type: &str) {}

#[cfg(not(feature = "monitoring"))]
pub fn record_behavioral_anomaly(_identity_type: &str, _anomaly_type: &str, _severity: &str) {}

#[cfg(not(feature = "monitoring"))]
pub fn update_risk_score(_identity_id: &str, _identity_type: &str, _score: f64) {}

#[cfg(not(feature = "monitoring"))]
pub fn record_baseline_established(_identity_type: &str, _confidence: f32) {}

#[cfg(not(feature = "monitoring"))]
pub fn record_policy_violation(_identity_type: &str, _policy_type: &str, _violation_type: &str) {}

#[cfg(not(feature = "monitoring"))]
pub fn record_auto_suspension(_identity_type: &str, _trigger_reason: &str) {}

#[cfg(not(feature = "monitoring"))]
pub fn record_geographic_anomaly(_identity_type: &str, _source_country: &str, _suspicious: bool) {}

#[cfg(not(feature = "monitoring"))]
pub fn record_request_rate_anomaly(_identity_type: &str, _rate_change_factor: f64) {}

#[cfg(not(feature = "monitoring"))]
pub struct TokenRequestTimer;

#[cfg(not(feature = "monitoring"))]
impl TokenRequestTimer {
    pub fn start(_identity_type: String) -> Self { Self }
    pub fn finish(self, _success: bool) {}
}

#[cfg(not(feature = "monitoring"))]
pub struct BaselineAnalysisTimer;

#[cfg(not(feature = "monitoring"))]
impl BaselineAnalysisTimer {
    pub fn start(_identity_type: String, _analysis_type: String) -> Self { Self }
    pub fn finish(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metric_recording() {
        // These tests will only run when monitoring feature is enabled
        #[cfg(feature = "monitoring")]
        {
            record_identity_registration("service_account", Some("production"));
            record_jit_token_issued("service_account", 3, 3600);
            record_behavioral_anomaly("ai_agent", "request_rate", "high");
        }
        
        // Test always passes - metrics recording should not panic
        assert!(true);
    }
    
    #[test]
    fn test_timer_functionality() {
        #[cfg(feature = "monitoring")]
        {
            let timer = TokenRequestTimer::start("test".to_string());
            std::thread::sleep(std::time::Duration::from_millis(1));
            timer.finish(true);
        }
        
        #[cfg(not(feature = "monitoring"))]
        {
            let timer = TokenRequestTimer::start("test".to_string());
            timer.finish(true);
        }
        
        assert!(true);
    }
}