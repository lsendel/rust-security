//! Business Logic Metrics for Auth Service
//!
//! This module provides specialized metrics for tracking business-critical
//! operations, user behavior patterns, and compliance requirements.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Business metrics registry for auth service
pub struct BusinessMetricsRegistry {
    pub registry: Registry,

    // === User Behavior Metrics ===
    /// User session duration tracking
    pub user_session_duration: HistogramVec,
    /// Login frequency by user type and time of day
    pub user_login_frequency: IntCounterVec,
    /// Password change frequency and reasons
    pub password_change_events: IntCounterVec,
    /// MFA adoption and usage patterns
    pub mfa_adoption_metrics: IntCounterVec,

    // === Business Process Metrics ===
    /// OAuth flow completion rates by client and grant type
    pub oauth_flow_completion: IntCounterVec,
    /// API key usage patterns and lifecycle
    pub api_key_usage_metrics: IntCounterVec,
    /// Token refresh patterns and intervals
    pub token_refresh_patterns: HistogramVec,

    // === Compliance and Audit Metrics ===
    /// Data retention compliance events
    pub data_retention_events: IntCounterVec,
    /// Audit log generation and export metrics
    pub audit_events_total: IntCounterVec,
    /// GDPR/Privacy request processing
    pub privacy_request_metrics: IntCounterVec,
    /// Compliance violation events
    pub compliance_violations: IntCounterVec,

    // === Security Posture Metrics ===
    /// Security control effectiveness
    pub security_control_effectiveness: IntCounterVec,
    /// Threat detection accuracy (true/false positives)
    pub threat_detection_accuracy: IntCounterVec,
    /// Security policy enforcement actions
    pub security_policy_enforcement: IntCounterVec,

    // === Revenue and Business Impact Metrics ===
    /// Authentication-gated revenue events
    pub revenue_impact_events: IntCounterVec,
    /// Feature usage by authentication method
    pub feature_usage_by_auth: IntCounterVec,
    /// Customer satisfaction indicators
    pub customer_satisfaction_metrics: IntCounterVec,

    // === Operational Efficiency Metrics ===
    /// Support ticket correlation with auth events
    pub support_correlation_metrics: IntCounterVec,
    /// Onboarding funnel metrics
    pub onboarding_funnel_metrics: IntCounterVec,
    /// Self-service resolution rates
    pub self_service_metrics: IntCounterVec,
}

impl BusinessMetricsRegistry {
    pub fn new() -> Self {
        let registry = Registry::new();

        // User Behavior Metrics
        let user_session_duration = HistogramVec::new(
            HistogramOpts::new(
                "auth_user_session_duration_seconds",
                "Duration of user sessions in seconds",
            )
            .buckets(vec![
                300.0,   // 5 minutes
                1800.0,  // 30 minutes
                3600.0,  // 1 hour
                7200.0,  // 2 hours
                14400.0, // 4 hours
                28800.0, // 8 hours
                86400.0, // 24 hours
            ]),
            &["user_type", "session_type", "client_id"],
        )
        .expect("Failed to create user_session_duration metric");

        let user_login_frequency = IntCounterVec::new(
            Opts::new("auth_user_login_frequency_total", "User login frequency patterns"),
            &["user_type", "hour_of_day", "day_of_week", "login_method"],
        )
        .expect("Failed to create user_login_frequency metric");

        let password_change_events = IntCounterVec::new(
            Opts::new("auth_password_change_events_total", "Password change events"),
            &["reason", "user_type", "complexity_level", "forced"],
        )
        .expect("Failed to create password_change_events metric");

        let mfa_adoption_metrics = IntCounterVec::new(
            Opts::new("auth_mfa_adoption_metrics_total", "MFA adoption and usage metrics"),
            &["event_type", "mfa_method", "user_segment", "enrollment_path"],
        )
        .expect("Failed to create mfa_adoption_metrics metric");

        // Business Process Metrics
        let oauth_flow_completion = IntCounterVec::new(
            Opts::new("auth_oauth_flow_completion_total", "OAuth flow completion tracking"),
            &["client_id", "grant_type", "flow_stage", "result"],
        )
        .expect("Failed to create oauth_flow_completion metric");

        let api_key_usage_metrics = IntCounterVec::new(
            Opts::new("auth_api_key_usage_total", "API key usage and lifecycle metrics"),
            &["key_type", "usage_pattern", "client_category", "lifecycle_stage"],
        )
        .expect("Failed to create api_key_usage_metrics metric");

        let token_refresh_patterns = HistogramVec::new(
            HistogramOpts::new(
                "auth_token_refresh_interval_seconds",
                "Token refresh interval patterns",
            )
            .buckets(vec![
                300.0,   // 5 minutes
                900.0,   // 15 minutes
                1800.0,  // 30 minutes
                3600.0,  // 1 hour
                7200.0,  // 2 hours
                14400.0, // 4 hours
                28800.0, // 8 hours
            ]),
            &["client_type", "token_type", "refresh_trigger"],
        )
        .expect("Failed to create token_refresh_patterns metric");

        // Compliance and Audit Metrics
        let data_retention_events = IntCounterVec::new(
            Opts::new("auth_data_retention_events_total", "Data retention compliance events"),
            &["event_type", "data_category", "retention_period", "result"],
        )
        .expect("Failed to create data_retention_events metric");

        let audit_events_total = IntCounterVec::new(
            Opts::new("auth_audit_events_total", "Audit events generation and processing"),
            &["event_category", "severity", "destination", "format"],
        )
        .expect("Failed to create audit_events_total metric");

        let privacy_request_metrics = IntCounterVec::new(
            Opts::new("auth_privacy_request_total", "Privacy request processing metrics"),
            &["request_type", "user_segment", "processing_stage", "result"],
        )
        .expect("Failed to create privacy_request_metrics metric");

        let compliance_violations = IntCounterVec::new(
            Opts::new("auth_compliance_violations_total", "Compliance violation events"),
            &["violation_type", "regulation", "severity", "remediation_status"],
        )
        .expect("Failed to create compliance_violations metric");

        // Security Posture Metrics
        let security_control_effectiveness = IntCounterVec::new(
            Opts::new(
                "auth_security_control_effectiveness_total",
                "Security control effectiveness tracking",
            ),
            &["control_type", "threat_category", "outcome", "confidence_level"],
        )
        .expect("Failed to create security_control_effectiveness metric");

        let threat_detection_accuracy = IntCounterVec::new(
            Opts::new("auth_threat_detection_accuracy_total", "Threat detection accuracy metrics"),
            &["detection_type", "threat_category", "outcome", "feedback_source"],
        )
        .expect("Failed to create threat_detection_accuracy metric");

        let security_policy_enforcement = IntCounterVec::new(
            Opts::new(
                "auth_security_policy_enforcement_total",
                "Security policy enforcement actions",
            ),
            &["policy_type", "enforcement_action", "user_segment", "override_reason"],
        )
        .expect("Failed to create security_policy_enforcement metric");

        // Revenue and Business Impact Metrics
        let revenue_impact_events = IntCounterVec::new(
            Opts::new("auth_revenue_impact_events_total", "Authentication-gated revenue events"),
            &["event_type", "customer_segment", "revenue_tier", "auth_method"],
        )
        .expect("Failed to create revenue_impact_events metric");

        let feature_usage_by_auth = IntCounterVec::new(
            Opts::new(
                "auth_feature_usage_by_auth_total",
                "Feature usage patterns by authentication method",
            ),
            &["feature_category", "auth_method", "user_tier", "access_pattern"],
        )
        .expect("Failed to create feature_usage_by_auth metric");

        let customer_satisfaction_metrics = IntCounterVec::new(
            Opts::new(
                "auth_customer_satisfaction_total",
                "Customer satisfaction indicators related to auth",
            ),
            &["satisfaction_score", "feedback_type", "user_segment", "auth_journey_stage"],
        )
        .expect("Failed to create customer_satisfaction_metrics metric");

        // Operational Efficiency Metrics
        let support_correlation_metrics = IntCounterVec::new(
            Opts::new(
                "auth_support_correlation_total",
                "Support ticket correlation with auth events",
            ),
            &["ticket_category", "auth_event_type", "resolution_type", "prevention_opportunity"],
        )
        .expect("Failed to create support_correlation_metrics metric");

        let onboarding_funnel_metrics = IntCounterVec::new(
            Opts::new("auth_onboarding_funnel_total", "User onboarding funnel metrics"),
            &["funnel_stage", "conversion_outcome", "user_segment", "onboarding_path"],
        )
        .expect("Failed to create onboarding_funnel_metrics metric");

        let self_service_metrics = IntCounterVec::new(
            Opts::new("auth_self_service_total", "Self-service resolution metrics"),
            &["service_type", "user_segment", "resolution_outcome", "assistance_level"],
        )
        .expect("Failed to create self_service_metrics metric");

        // Register all metrics
        let metrics: Vec<Box<dyn prometheus::core::Collector>> = vec![
            Box::new(user_session_duration.clone()),
            Box::new(user_login_frequency.clone()),
            Box::new(password_change_events.clone()),
            Box::new(mfa_adoption_metrics.clone()),
            Box::new(oauth_flow_completion.clone()),
            Box::new(api_key_usage_metrics.clone()),
            Box::new(token_refresh_patterns.clone()),
            Box::new(data_retention_events.clone()),
            Box::new(audit_events_total.clone()),
            Box::new(privacy_request_metrics.clone()),
            Box::new(compliance_violations.clone()),
            Box::new(security_control_effectiveness.clone()),
            Box::new(threat_detection_accuracy.clone()),
            Box::new(security_policy_enforcement.clone()),
            Box::new(revenue_impact_events.clone()),
            Box::new(feature_usage_by_auth.clone()),
            Box::new(customer_satisfaction_metrics.clone()),
            Box::new(support_correlation_metrics.clone()),
            Box::new(onboarding_funnel_metrics.clone()),
            Box::new(self_service_metrics.clone()),
        ];

        for metric in metrics {
            if let Err(e) = registry.register(metric) {
                error!("Failed to register business metric: {}", e);
            }
        }

        Self {
            registry,
            user_session_duration,
            user_login_frequency,
            password_change_events,
            mfa_adoption_metrics,
            oauth_flow_completion,
            api_key_usage_metrics,
            token_refresh_patterns,
            data_retention_events,
            audit_events_total,
            privacy_request_metrics,
            compliance_violations,
            security_control_effectiveness,
            threat_detection_accuracy,
            security_policy_enforcement,
            revenue_impact_events,
            feature_usage_by_auth,
            customer_satisfaction_metrics,
            support_correlation_metrics,
            onboarding_funnel_metrics,
            self_service_metrics,
        }
    }
}

/// Global business metrics registry
pub static BUSINESS_METRICS: Lazy<BusinessMetricsRegistry> =
    Lazy::new(BusinessMetricsRegistry::new);

/// Business metrics helper functions
pub struct BusinessMetricsHelper;

impl BusinessMetricsHelper {
    /// Record user session completion
    pub fn record_user_session(
        user_type: &str,
        session_type: &str,
        client_id: &str,
        duration: Duration,
    ) {
        BUSINESS_METRICS
            .user_session_duration
            .with_label_values(&[user_type, session_type, client_id])
            .observe(duration.as_secs_f64());
    }

    /// Record login with temporal context
    pub fn record_login_event(user_type: &str, login_method: &str, timestamp: SystemTime) {
        let datetime = timestamp.duration_since(UNIX_EPOCH).unwrap_or_default();
        let hour_of_day = (datetime.as_secs() / 3600) % 24;
        let day_of_week = ((datetime.as_secs() / 86400) + 4) % 7; // Unix epoch was Thursday

        BUSINESS_METRICS
            .user_login_frequency
            .with_label_values(&[
                user_type,
                &hour_of_day.to_string(),
                &day_of_week.to_string(),
                login_method,
            ])
            .inc();
    }

    /// Record OAuth flow progression
    pub fn record_oauth_flow_step(
        client_id: &str,
        grant_type: &str,
        flow_stage: &str,
        result: &str,
    ) {
        BUSINESS_METRICS
            .oauth_flow_completion
            .with_label_values(&[client_id, grant_type, flow_stage, result])
            .inc();
    }

    /// Record MFA adoption event
    pub fn record_mfa_adoption(
        event_type: &str,
        mfa_method: &str,
        user_segment: &str,
        enrollment_path: &str,
    ) {
        BUSINESS_METRICS
            .mfa_adoption_metrics
            .with_label_values(&[event_type, mfa_method, user_segment, enrollment_path])
            .inc();
    }

    /// Record privacy request processing
    pub fn record_privacy_request(
        request_type: &str,
        user_segment: &str,
        processing_stage: &str,
        result: &str,
    ) {
        BUSINESS_METRICS
            .privacy_request_metrics
            .with_label_values(&[request_type, user_segment, processing_stage, result])
            .inc();
    }

    /// Record security control effectiveness
    pub fn record_security_control_outcome(
        control_type: &str,
        threat_category: &str,
        outcome: &str,
        confidence_level: &str,
    ) {
        BUSINESS_METRICS
            .security_control_effectiveness
            .with_label_values(&[control_type, threat_category, outcome, confidence_level])
            .inc();
    }

    /// Record threat detection feedback
    pub fn record_threat_detection_feedback(
        detection_type: &str,
        threat_category: &str,
        outcome: &str, // "true_positive", "false_positive", "true_negative", "false_negative"
        feedback_source: &str,
    ) {
        BUSINESS_METRICS
            .threat_detection_accuracy
            .with_label_values(&[detection_type, threat_category, outcome, feedback_source])
            .inc();
    }

    /// Record revenue impact event
    pub fn record_revenue_impact(
        event_type: &str,
        customer_segment: &str,
        revenue_tier: &str,
        auth_method: &str,
    ) {
        BUSINESS_METRICS
            .revenue_impact_events
            .with_label_values(&[event_type, customer_segment, revenue_tier, auth_method])
            .inc();
    }

    /// Record customer satisfaction feedback
    pub fn record_customer_satisfaction(
        satisfaction_score: &str, // "1-5" or "satisfied/dissatisfied"
        feedback_type: &str,
        user_segment: &str,
        auth_journey_stage: &str,
    ) {
        BUSINESS_METRICS
            .customer_satisfaction_metrics
            .with_label_values(&[
                satisfaction_score,
                feedback_type,
                user_segment,
                auth_journey_stage,
            ])
            .inc();
    }

    /// Record support ticket correlation
    pub fn record_support_correlation(
        ticket_category: &str,
        auth_event_type: &str,
        resolution_type: &str,
        prevention_opportunity: &str,
    ) {
        BUSINESS_METRICS
            .support_correlation_metrics
            .with_label_values(&[
                ticket_category,
                auth_event_type,
                resolution_type,
                prevention_opportunity,
            ])
            .inc();
    }

    /// Record onboarding funnel progression
    pub fn record_onboarding_funnel(
        funnel_stage: &str,
        conversion_outcome: &str,
        user_segment: &str,
        onboarding_path: &str,
    ) {
        BUSINESS_METRICS
            .onboarding_funnel_metrics
            .with_label_values(&[funnel_stage, conversion_outcome, user_segment, onboarding_path])
            .inc();
    }
}

/// User behavior analytics
pub struct UserBehaviorAnalytics {
    session_tracking: Arc<RwLock<HashMap<String, SessionInfo>>>,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub user_id: String,
    pub session_start: SystemTime,
    pub last_activity: SystemTime,
    pub activity_count: u64,
    pub user_type: String,
    pub client_id: String,
}

impl UserBehaviorAnalytics {
    pub fn new() -> Self {
        Self { session_tracking: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Start tracking a new session
    pub async fn start_session(
        &self,
        session_id: String,
        user_id: String,
        user_type: String,
        client_id: String,
    ) {
        let session_info = SessionInfo {
            user_id,
            session_start: SystemTime::now(),
            last_activity: SystemTime::now(),
            activity_count: 1,
            user_type,
            client_id,
        };

        let mut sessions = self.session_tracking.write().await;
        sessions.insert(session_id, session_info);
    }

    /// Update session activity
    pub async fn record_activity(&self, session_id: &str) {
        let mut sessions = self.session_tracking.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_activity = SystemTime::now();
            session.activity_count += 1;
        }
    }

    /// End session and record metrics
    pub async fn end_session(&self, session_id: &str) {
        let mut sessions = self.session_tracking.write().await;
        if let Some(session) = sessions.remove(session_id) {
            let duration =
                session.last_activity.duration_since(session.session_start).unwrap_or_default();

            BusinessMetricsHelper::record_user_session(
                &session.user_type,
                "interactive",
                &session.client_id,
                duration,
            );

            info!(
                user_id = %session.user_id,
                session_duration_seconds = %duration.as_secs(),
                activity_count = %session.activity_count,
                "User session completed"
            );
        }
    }

    /// Cleanup inactive sessions
    pub async fn cleanup_inactive_sessions(&self, timeout: Duration) {
        let now = SystemTime::now();
        let mut sessions = self.session_tracking.write().await;

        sessions.retain(|session_id, session| {
            let inactive_duration = now.duration_since(session.last_activity).unwrap_or_default();

            if inactive_duration > timeout {
                let total_duration =
                    session.last_activity.duration_since(session.session_start).unwrap_or_default();

                BusinessMetricsHelper::record_user_session(
                    &session.user_type,
                    "timeout",
                    &session.client_id,
                    total_duration,
                );

                debug!(
                    session_id = %session_id,
                    user_id = %session.user_id,
                    inactive_duration_seconds = %inactive_duration.as_secs(),
                    "Session cleaned up due to inactivity"
                );
                false
            } else {
                true
            }
        });
    }
}

/// Global user behavior analytics instance
pub static USER_ANALYTICS: Lazy<UserBehaviorAnalytics> = Lazy::new(UserBehaviorAnalytics::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_business_metrics_creation() {
        let metrics = BusinessMetricsRegistry::new();
        assert!(!metrics.registry.gather().is_empty());
    }

    #[tokio::test]
    async fn test_session_tracking() {
        let analytics = UserBehaviorAnalytics::new();

        analytics
            .start_session(
                "session-123".to_string(),
                "user-456".to_string(),
                "premium".to_string(),
                "client-789".to_string(),
            )
            .await;

        analytics.record_activity("session-123").await;
        analytics.end_session("session-123").await;
    }

    #[test]
    fn test_business_metrics_helpers() {
        BusinessMetricsHelper::record_oauth_flow_step(
            "client-123",
            "authorization_code",
            "consent",
            "completed",
        );

        BusinessMetricsHelper::record_mfa_adoption(
            "enrollment",
            "totp",
            "enterprise",
            "admin_required",
        );
    }
}
