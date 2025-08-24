//! Business Logic Metrics for Auth Service
//!
//! This module provides specialized metrics for tracking business-critical
//! operations, user behavior patterns, and compliance requirements.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
#[cfg(feature = "monitoring")]
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Business metrics registry for auth service
#[cfg(feature = "monitoring")]
pub struct BusinessMetricsRegistry {
    pub registry: Registry,

    // === User Behavior Metrics ===
    /// Tracks user session duration in seconds across different user types and clients
    /// Labels: user_type (premium, basic, trial), session_type (interactive, timeout), client_id
    /// Purpose: Monitor user engagement patterns and detect abnormal session behaviors
    pub user_session_duration: HistogramVec,
    
    /// Counts login events by user characteristics and temporal patterns
    /// Labels: user_type, hour_of_day (0-23), day_of_week (0-6), login_method (password, sso, mfa)
    /// Purpose: Identify login patterns, detect unusual access times, plan capacity
    pub user_login_frequency: IntCounterVec,
    
    /// Tracks password change events and their triggers
    /// Labels: reason (expired, security, user_initiated), user_type, complexity_level, forced (true/false)
    /// Purpose: Monitor password hygiene, track security policy compliance
    pub password_change_events: IntCounterVec,
    
    /// Measures MFA adoption rates and usage patterns
    /// Labels: event_type (enrollment, usage, bypass), mfa_method (totp, sms, webauthn), user_segment, enrollment_path
    /// Purpose: Track security adoption, identify MFA gaps, measure security posture improvements
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

#[cfg(feature = "monitoring")]
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
            Opts::new(
                "auth_user_login_frequency_total",
                "User login frequency patterns",
            ),
            &["user_type", "hour_of_day", "day_of_week", "login_method"],
        )
        .expect("Failed to create user_login_frequency metric");

        let password_change_events = IntCounterVec::new(
            Opts::new(
                "auth_password_change_events_total",
                "Password change events",
            ),
            &["reason", "user_type", "complexity_level", "forced"],
        )
        .expect("Failed to create password_change_events metric");

        let mfa_adoption_metrics = IntCounterVec::new(
            Opts::new(
                "auth_mfa_adoption_metrics_total",
                "MFA adoption and usage metrics",
            ),
            &[
                "event_type",
                "mfa_method",
                "user_segment",
                "enrollment_path",
            ],
        )
        .expect("Failed to create mfa_adoption_metrics metric");

        // Business Process Metrics
        let oauth_flow_completion = IntCounterVec::new(
            Opts::new(
                "auth_oauth_flow_completion_total",
                "OAuth flow completion tracking",
            ),
            &["client_id", "grant_type", "flow_stage", "result"],
        )
        .expect("Failed to create oauth_flow_completion metric");

        let api_key_usage_metrics = IntCounterVec::new(
            Opts::new(
                "auth_api_key_usage_total",
                "API key usage and lifecycle metrics",
            ),
            &[
                "key_type",
                "usage_pattern",
                "client_category",
                "lifecycle_stage",
            ],
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
            Opts::new(
                "auth_data_retention_events_total",
                "Data retention compliance events",
            ),
            &["event_type", "data_category", "retention_period", "result"],
        )
        .expect("Failed to create data_retention_events metric");

        let audit_events_total = IntCounterVec::new(
            Opts::new(
                "auth_audit_events_total",
                "Audit events generation and processing",
            ),
            &["event_category", "severity", "destination", "format"],
        )
        .expect("Failed to create audit_events_total metric");

        let privacy_request_metrics = IntCounterVec::new(
            Opts::new(
                "auth_privacy_request_total",
                "Privacy request processing metrics",
            ),
            &["request_type", "user_segment", "processing_stage", "result"],
        )
        .expect("Failed to create privacy_request_metrics metric");

        let compliance_violations = IntCounterVec::new(
            Opts::new(
                "auth_compliance_violations_total",
                "Compliance violation events",
            ),
            &[
                "violation_type",
                "regulation",
                "severity",
                "remediation_status",
            ],
        )
        .expect("Failed to create compliance_violations metric");

        // Security Posture Metrics
        let security_control_effectiveness = IntCounterVec::new(
            Opts::new(
                "auth_security_control_effectiveness_total",
                "Security control effectiveness tracking",
            ),
            &[
                "control_type",
                "threat_category",
                "outcome",
                "confidence_level",
            ],
        )
        .expect("Failed to create security_control_effectiveness metric");

        let threat_detection_accuracy = IntCounterVec::new(
            Opts::new(
                "auth_threat_detection_accuracy_total",
                "Threat detection accuracy metrics",
            ),
            &[
                "detection_type",
                "threat_category",
                "outcome",
                "feedback_source",
            ],
        )
        .expect("Failed to create threat_detection_accuracy metric");

        let security_policy_enforcement = IntCounterVec::new(
            Opts::new(
                "auth_security_policy_enforcement_total",
                "Security policy enforcement actions",
            ),
            &[
                "policy_type",
                "enforcement_action",
                "user_segment",
                "override_reason",
            ],
        )
        .expect("Failed to create security_policy_enforcement metric");

        // Revenue and Business Impact Metrics
        let revenue_impact_events = IntCounterVec::new(
            Opts::new(
                "auth_revenue_impact_events_total",
                "Authentication-gated revenue events",
            ),
            &[
                "event_type",
                "customer_segment",
                "revenue_tier",
                "auth_method",
            ],
        )
        .expect("Failed to create revenue_impact_events metric");

        let feature_usage_by_auth = IntCounterVec::new(
            Opts::new(
                "auth_feature_usage_by_auth_total",
                "Feature usage patterns by authentication method",
            ),
            &[
                "feature_category",
                "auth_method",
                "user_tier",
                "access_pattern",
            ],
        )
        .expect("Failed to create feature_usage_by_auth metric");

        let customer_satisfaction_metrics = IntCounterVec::new(
            Opts::new(
                "auth_customer_satisfaction_total",
                "Customer satisfaction indicators related to auth",
            ),
            &[
                "satisfaction_score",
                "feedback_type",
                "user_segment",
                "auth_journey_stage",
            ],
        )
        .expect("Failed to create customer_satisfaction_metrics metric");

        // Operational Efficiency Metrics
        let support_correlation_metrics = IntCounterVec::new(
            Opts::new(
                "auth_support_correlation_total",
                "Support ticket correlation with auth events",
            ),
            &[
                "ticket_category",
                "auth_event_type",
                "resolution_type",
                "prevention_opportunity",
            ],
        )
        .expect("Failed to create support_correlation_metrics metric");

        let onboarding_funnel_metrics = IntCounterVec::new(
            Opts::new(
                "auth_onboarding_funnel_total",
                "User onboarding funnel metrics",
            ),
            &[
                "funnel_stage",
                "conversion_outcome",
                "user_segment",
                "onboarding_path",
            ],
        )
        .expect("Failed to create onboarding_funnel_metrics metric");

        let self_service_metrics = IntCounterVec::new(
            Opts::new("auth_self_service_total", "Self-service resolution metrics"),
            &[
                "service_type",
                "user_segment",
                "resolution_outcome",
                "assistance_level",
            ],
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

        let mut registration_errors = Vec::new();
        for (i, metric) in metrics.into_iter().enumerate() {
            if let Err(e) = registry.register(metric) {
                let error_msg = format!("Metric #{}: {}", i, e);
                error!("Failed to register business metric: {}", error_msg);
                registration_errors.push(error_msg);
            }
        }
        
        if !registration_errors.is_empty() {
            error!(
                "Business metrics registration completed with {} errors: {:?}",
                registration_errors.len(),
                registration_errors
            );
        } else {
            info!("All {} business metrics registered successfully", 20);
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

    /// Export metrics in Prometheus text format
    pub fn export_metrics(&self) -> Result<String, Box<dyn std::error::Error>> {
        use prometheus::TextEncoder;
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode_to_string(&metric_families)
    }

    /// Get registry statistics
    pub fn get_stats(&self) -> prometheus::proto::MetricFamily {
        let metrics = self.registry.gather();
        let mut stats = prometheus::proto::MetricFamily::new();
        stats.set_name("business_metrics_registry_stats".to_string());
        stats.set_help("Statistics about the business metrics registry".to_string());
        stats.set_field_type(prometheus::proto::MetricType::GAUGE);
        
        let mut metric = prometheus::proto::Metric::new();
        let mut gauge = prometheus::proto::Gauge::new();
        gauge.set_value(metrics.len() as f64);
        metric.set_gauge(gauge);
        
        let mut label = prometheus::proto::LabelPair::new();
        label.set_name("stat".to_string());
        label.set_value("total_metrics".to_string());
        metric.mut_label().push(label);
        
        stats.mut_metric().push(metrics);
        stats
    }
}

/// Global business metrics registry
#[cfg(feature = "monitoring")]
pub static BUSINESS_METRICS: Lazy<BusinessMetricsRegistry> =
    Lazy::new(BusinessMetricsRegistry::new);

/// Business metrics helper functions
pub struct BusinessMetricsHelper;

impl BusinessMetricsHelper {
    /// Validate and sanitize metric labels to prevent injection attacks
    fn sanitize_label(label: &str, max_len: usize) -> String {
        if label.len() > max_len {
            return format!("label_too_long_{}", label.len());
        }
        
        // Remove potential problematic characters
        label.chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
            .collect::<String>()
            .get(..max_len.min(label.len()))
            .unwrap_or("invalid_label")
            .to_string()
    }

    /// Validate metric values to ensure they are within acceptable ranges
    pub fn validate_metric_value(metric_name: &str, value: f64) -> Result<f64, String> {
        match metric_name {
            name if name.contains("duration") => {
                if value < 0.0 || value > 86400.0 {
                    Err(format!("Duration value {} is out of range (0-86400 seconds)", value))
                } else {
                    Ok(value)
                }
            },
            name if name.contains("score") => {
                if value < 0.0 || value > 100.0 {
                    Err(format!("Score value {} is out of range (0-100)", value))
                } else {
                    Ok(value)
                }
            },
            name if name.contains("count") || name.contains("total") => {
                if value < 0.0 {
                    Err(format!("Counter value {} cannot be negative", value))
                } else {
                    Ok(value)
                }
            },
            _ => {
                // General validation for all other metrics
                if value.is_nan() || value.is_infinite() {
                    Err(format!("Invalid metric value: {}", value))
                } else {
                    Ok(value)
                }
            }
        }
    }
}

#[cfg(feature = "monitoring")]
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
            .with_label_values(&[
                funnel_stage,
                conversion_outcome,
                user_segment,
                onboarding_path,
            ])
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
    /// Client IP address for security monitoring
    pub ip_address: Option<String>,
    /// User agent for device tracking and fraud detection
    pub user_agent: Option<String>,
    /// Session security score based on behavior patterns
    pub security_score: u8,
}

impl UserBehaviorAnalytics {
    pub fn new() -> Self {
        Self {
            session_tracking: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start tracking a new session with security validation
    pub async fn start_session(
        &self,
        session_id: String,
        user_id: String,
        user_type: String,
        client_id: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) {
        // Validate session ID format (should be UUID-like or similar secure format)
        if session_id.len() < 16 || session_id.len() > 64 {
            debug!("Invalid session ID length: {}", session_id.len());
            return;
        }
        
        // Validate input lengths for security
        if user_id.len() > 128 || user_type.len() > 32 || client_id.len() > 64 {
            debug!("Invalid input lengths for session tracking");
            return;
        }

        // Calculate initial security score based on available information
        let security_score = calculate_session_security_score(&ip_address, &user_agent);

        let session_info = SessionInfo {
            user_id,
            session_start: SystemTime::now(),
            last_activity: SystemTime::now(),
            activity_count: 1,
            user_type,
            client_id,
            ip_address,
            user_agent,
            security_score,
        };

        let mut sessions = self.session_tracking.write().await;
        
        // Prevent session table from growing unbounded (potential DoS protection)
        if sessions.len() > 10000 {
            debug!("Session table at capacity, cleaning up oldest sessions");
            // Keep only the 8000 most recent sessions
            let mut session_pairs: Vec<_> = sessions.drain().collect();
            session_pairs.sort_by(|a, b| b.1.last_activity.cmp(&a.1.last_activity));
            session_pairs.truncate(8000);
            sessions.extend(session_pairs);
        }
        
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
            let duration = session
                .last_activity
                .duration_since(session.session_start)
                .unwrap_or_default();

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
            let inactive_duration = now
                .duration_since(session.last_activity)
                .unwrap_or_default();

            if inactive_duration > timeout {
                let total_duration = session
                    .last_activity
                    .duration_since(session.session_start)
                    .unwrap_or_default();

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

    /// Record rate limit enforcement with security-safe logging
    pub fn record_rate_limit_enforcement(path: &str, client_key: &str, action: &str, request_type: &str) {
        // Validate input lengths to prevent log injection
        let safe_path = if path.len() > 100 { &path[..100] } else { path };
        let safe_client_key = if client_key.len() > 32 { "key_too_long" } else { client_key };
        let safe_action = if action.len() > 20 { "action_truncated" } else { action };
        let safe_request_type = if request_type.len() > 20 { "type_truncated" } else { request_type };
        
        tracing::info!(
            path = %safe_path,
            client_key = %safe_client_key,
            action = %safe_action,
            request_type = %safe_request_type,
            "Rate limit enforcement"
        );
    }
}

// Stub implementations when monitoring is not enabled
#[cfg(not(feature = "monitoring"))]
impl BusinessMetricsHelper {
    pub fn new() -> Self {
        Self
    }
    
    /// Record user session completion - logs to tracing instead of metrics
    pub fn record_user_session(user_type: &str, session_type: &str, client_id: &str, duration: Duration) {
        tracing::debug!(
            user_type = user_type,
            session_type = session_type,
            client_id = client_id,
            duration_seconds = duration.as_secs(),
            "User session recorded (metrics disabled)"
        );
    }
    
    /// Record login event - logs to tracing instead of metrics
    pub fn record_login_event(user_type: &str, login_method: &str, _timestamp: SystemTime) {
        tracing::info!(
            user_type = user_type,
            login_method = login_method,
            "Login event recorded (metrics disabled)"
        );
    }
    
    /// Record OAuth flow progression - logs to tracing instead of metrics
    pub fn record_oauth_flow_step(client_id: &str, grant_type: &str, flow_stage: &str, result: &str) {
        tracing::debug!(
            client_id = client_id,
            grant_type = grant_type,
            flow_stage = flow_stage,
            result = result,
            "OAuth flow step recorded (metrics disabled)"
        );
    }
    
    /// Record MFA adoption event - logs to tracing instead of metrics
    pub fn record_mfa_adoption(event_type: &str, mfa_method: &str, user_segment: &str, enrollment_path: &str) {
        tracing::info!(
            event_type = event_type,
            mfa_method = mfa_method,
            user_segment = user_segment,
            enrollment_path = enrollment_path,
            "MFA adoption recorded (metrics disabled)"
        );
    }
    
    /// Record privacy request processing - logs to tracing instead of metrics
    pub fn record_privacy_request(request_type: &str, user_segment: &str, processing_stage: &str, result: &str) {
        tracing::info!(
            request_type = request_type,
            user_segment = user_segment,
            processing_stage = processing_stage,
            result = result,
            "Privacy request recorded (metrics disabled)"
        );
    }
    
    /// Record rate limit enforcement - logs to tracing instead of metrics
    pub fn record_rate_limit_enforcement(path: &str, client_key: &str, action: &str, request_type: &str) {
        tracing::warn!(
            path = path,
            client_key = client_key,
            action = action,
            request_type = request_type,
            "Rate limit enforcement recorded (metrics disabled)"
        );
    }
    
    /// Record security control outcome - logs to tracing instead of metrics
    pub fn record_security_control_outcome(control_type: &str, threat_category: &str, outcome: &str, confidence_level: &str) {
        tracing::info!(
            control_type = control_type,
            threat_category = threat_category,
            outcome = outcome,
            confidence_level = confidence_level,
            "Security control outcome recorded (metrics disabled)"
        );
    }
    
    /// Record threat detection feedback - logs to tracing instead of metrics
    pub fn record_threat_detection_feedback(detection_type: &str, threat_category: &str, outcome: &str, feedback_source: &str) {
        tracing::info!(
            detection_type = detection_type,
            threat_category = threat_category,
            outcome = outcome,
            feedback_source = feedback_source,
            "Threat detection feedback recorded (metrics disabled)"
        );
    }
    
    /// Record revenue impact event - logs to tracing instead of metrics
    pub fn record_revenue_impact(event_type: &str, customer_segment: &str, revenue_tier: &str, auth_method: &str) {
        tracing::info!(
            event_type = event_type,
            customer_segment = customer_segment,
            revenue_tier = revenue_tier,
            auth_method = auth_method,
            "Revenue impact recorded (metrics disabled)"
        );
    }
    
    /// Record customer satisfaction feedback - logs to tracing instead of metrics
    pub fn record_customer_satisfaction(satisfaction_score: &str, feedback_type: &str, user_segment: &str, auth_journey_stage: &str) {
        tracing::info!(
            satisfaction_score = satisfaction_score,
            feedback_type = feedback_type,
            user_segment = user_segment,
            auth_journey_stage = auth_journey_stage,
            "Customer satisfaction recorded (metrics disabled)"
        );
    }
    
    /// Record support ticket correlation - logs to tracing instead of metrics
    pub fn record_support_correlation(ticket_category: &str, auth_event_type: &str, resolution_type: &str, prevention_opportunity: &str) {
        tracing::info!(
            ticket_category = ticket_category,
            auth_event_type = auth_event_type,
            resolution_type = resolution_type,
            prevention_opportunity = prevention_opportunity,
            "Support correlation recorded (metrics disabled)"
        );
    }
    
    /// Record onboarding funnel progression - logs to tracing instead of metrics
    pub fn record_onboarding_funnel(funnel_stage: &str, conversion_outcome: &str, user_segment: &str, onboarding_path: &str) {
        tracing::info!(
            funnel_stage = funnel_stage,
            conversion_outcome = conversion_outcome,
            user_segment = user_segment,
            onboarding_path = onboarding_path,
            "Onboarding funnel recorded (metrics disabled)"
        );
    }
    
    /// Validate metric values (stub implementation)
    pub fn validate_metric_value(metric_name: &str, value: f64) -> Result<f64, String> {
        tracing::debug!(
            metric_name = metric_name,
            value = value,
            "Metric validation (metrics disabled)"
        );
        Ok(value)
    }
}

/// Calculate session security score based on available information
fn calculate_session_security_score(ip_address: &Option<String>, user_agent: &Option<String>) -> u8 {
    let mut score = 50; // Base score
    
    // Bonus for having IP address
    if ip_address.is_some() {
        score += 20;
    }
    
    // Bonus for having user agent
    if let Some(ua) = user_agent {
        score += 15;
        
        // Additional checks for suspicious user agents
        let ua_lower = ua.to_lowercase();
        if ua_lower.contains("bot") || ua_lower.contains("crawler") || ua_lower.contains("spider") {
            score -= 30; // Suspicious bot-like user agent
        } else if ua_lower.len() < 10 {
            score -= 20; // Suspiciously short user agent
        } else if ua_lower.len() > 500 {
            score -= 15; // Suspiciously long user agent
        }
    }
    
    // Ensure score stays within bounds
    score.max(0).min(100)
}

/// Global user behavior analytics instance
pub static USER_ANALYTICS: Lazy<UserBehaviorAnalytics> = Lazy::new(UserBehaviorAnalytics::new);

#[cfg(all(test, feature = "monitoring"))]
mod tests {
    use super::*;

    #[test]
    fn test_business_metrics_creation() {
        let metrics = BusinessMetricsRegistry::new();
        assert!(!metrics.registry.gather().is_empty());
    }

    #[test]
    fn test_metrics_registration() {
        let registry = BusinessMetricsRegistry::new();
        let metrics = registry.registry.gather();
        
        // Verify that all expected metrics are registered
        let metric_names: Vec<String> = metrics
            .iter()
            .map(|m| m.get_name().to_string())
            .collect();
        
        assert!(metric_names.contains(&"auth_user_session_duration_seconds".to_string()));
        assert!(metric_names.contains(&"auth_oauth_flow_completion_total".to_string()));
        assert!(metric_names.contains(&"auth_security_control_effectiveness_total".to_string()));
    }

    #[test]
    fn test_label_sanitization() {
        let sanitized = BusinessMetricsHelper::sanitize_label("valid_label-123", 50);
        assert_eq!(sanitized, "valid_label-123");
        
        let sanitized = BusinessMetricsHelper::sanitize_label("invalid@#$%label", 50);
        assert_eq!(sanitized, "invalidlabel");
        
        let sanitized = BusinessMetricsHelper::sanitize_label("toolongabelthatshouldbetruncated", 10);
        assert_eq!(sanitized, "label_too_long_35");
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
                Some("192.168.1.1".to_string()),
                Some("Mozilla/5.0 (compatible; test-agent)".to_string()),
            )
            .await;

        analytics.record_activity("session-123").await;
        analytics.end_session("session-123").await;
    }

    #[test]
    fn test_security_score_calculation() {
        // Test base score with no info
        let score = calculate_session_security_score(&None, &None);
        assert_eq!(score, 50);

        // Test with IP but no user agent
        let score = calculate_session_security_score(&Some("192.168.1.1".to_string()), &None);
        assert_eq!(score, 70);

        // Test with suspicious bot user agent
        let score = calculate_session_security_score(
            &Some("192.168.1.1".to_string()), 
            &Some("bot crawler spider".to_string())
        );
        assert_eq!(score, 55); // 70 + 15 - 30

        // Test with normal user agent
        let score = calculate_session_security_score(
            &Some("192.168.1.1".to_string()), 
            &Some("Mozilla/5.0 (compatible; legitimate-browser)".to_string())
        );
        assert_eq!(score, 85); // 70 + 15
    }

    #[test]
    fn test_metric_validation() {
        // Test duration validation
        assert!(BusinessMetricsHelper::validate_metric_value("auth_duration", 3600.0).is_ok());
        assert!(BusinessMetricsHelper::validate_metric_value("auth_duration", -1.0).is_err());
        assert!(BusinessMetricsHelper::validate_metric_value("auth_duration", 90000.0).is_err());

        // Test score validation
        assert!(BusinessMetricsHelper::validate_metric_value("auth_score", 85.0).is_ok());
        assert!(BusinessMetricsHelper::validate_metric_value("auth_score", -5.0).is_err());
        assert!(BusinessMetricsHelper::validate_metric_value("auth_score", 150.0).is_err());

        // Test counter validation
        assert!(BusinessMetricsHelper::validate_metric_value("auth_total", 100.0).is_ok());
        assert!(BusinessMetricsHelper::validate_metric_value("auth_total", -1.0).is_err());
    }

    #[test]
    fn test_metrics_export() {
        let registry = BusinessMetricsRegistry::new();
        let export_result = registry.export_metrics();
        assert!(export_result.is_ok());
        
        let stats = registry.get_stats();
        assert_eq!(stats.get_name(), "business_metrics_registry_stats");
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
