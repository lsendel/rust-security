//! Comprehensive tracing instrumentation for authentication flows
//! 
//! This module provides detailed tracing for all authentication operations,
//! security events, and performance monitoring with OpenTelemetry integration.

use opentelemetry::{
    trace::{SpanKind, TraceContextExt, Tracer},
    Context, KeyValue,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{error, info, instrument, warn, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use uuid::Uuid;

use crate::{
    error_handling::{SecurityError, SecurityResult},
    observability::{ObservabilityProvider, ServiceMetrics, TracingUtils},
};

/// Authentication flow tracer for detailed operation tracking
pub struct AuthFlowTracer {
    observability: Arc<ObservabilityProvider>,
    flow_id: String,
    user_context: Option<UserContext>,
    security_context: SecurityContext,
    performance_tracker: PerformanceTracker,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub session_id: Option<String>,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: String,
    pub correlation_id: String,
    pub threat_level: ThreatLevel,
    pub geo_location: Option<GeoLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatLevel::Low => write!(f, "LOW"),
            ThreatLevel::Medium => write!(f, "MEDIUM"),
            ThreatLevel::High => write!(f, "HIGH"),
            ThreatLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug)]
pub struct PerformanceTracker {
    start_time: Instant,
    checkpoints: HashMap<String, Instant>,
    metrics: HashMap<String, f64>,
}

impl PerformanceTracker {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            checkpoints: HashMap::new(),
            metrics: HashMap::new(),
        }
    }

    pub fn checkpoint(&mut self, name: &str) {
        self.checkpoints.insert(name.to_string(), Instant::now());
    }

    pub fn record_metric(&mut self, name: &str, value: f64) {
        self.metrics.insert(name.to_string(), value);
    }

    pub fn duration_since_start(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn duration_since_checkpoint(&self, name: &str) -> Option<Duration> {
        self.checkpoints.get(name).map(|&time| time.elapsed())
    }
}

impl AuthFlowTracer {
    pub fn new(observability: Arc<ObservabilityProvider>) -> Self {
        let flow_id = Uuid::new_v4().to_string();
        let security_context = SecurityContext {
            client_ip: None,
            user_agent: None,
            request_id: Uuid::new_v4().to_string(),
            correlation_id: Uuid::new_v4().to_string(),
            threat_level: ThreatLevel::Low,
            geo_location: None,
        };

        Self {
            observability,
            flow_id,
            user_context: None,
            security_context,
            performance_tracker: PerformanceTracker::new(),
        }
    }

    pub fn with_security_context(mut self, context: SecurityContext) -> Self {
        self.security_context = context;
        self
    }

    pub fn with_user_context(mut self, context: UserContext) -> Self {
        self.user_context = Some(context);
        self
    }

    /// Start authentication flow tracing
    #[instrument(skip(self), fields(
        flow_id = %self.flow_id,
        request_id = %self.security_context.request_id,
        correlation_id = %self.security_context.correlation_id
    ))]
    pub async fn start_auth_flow(&mut self, flow_type: &str) -> SecurityResult<AuthFlowSpan> {
        info!("Starting authentication flow: {}", flow_type);

        let span_name = format!("auth_flow_{}", flow_type);
        let tracer = self.observability.tracer()
            .ok_or(SecurityError::Configuration)?;

        let mut span = TracingUtils::create_span(
            tracer,
            &span_name,
            SpanKind::Server,
            vec![
                KeyValue::new("auth.flow_type", flow_type.to_string()),
                KeyValue::new("auth.flow_id", self.flow_id.clone()),
                KeyValue::new("request.id", self.security_context.request_id.clone()),
                KeyValue::new("correlation.id", self.security_context.correlation_id.clone()),
                KeyValue::new("security.threat_level", self.security_context.threat_level.to_string()),
            ],
        );

        // Add security context
        TracingUtils::add_security_context(
            &mut span,
            self.user_context.as_ref().and_then(|ctx| ctx.user_id.as_deref()),
            self.user_context.as_ref().and_then(|ctx| ctx.session_id.as_deref()),
            self.security_context.client_ip.as_deref(),
        );

        // Add additional context attributes
        if let Some(user_agent) = &self.security_context.user_agent {
            span.set_attribute(KeyValue::new("http.user_agent", user_agent.clone()));
        }

        if let Some(user_ctx) = &self.user_context {
            if let Some(client_id) = &user_ctx.client_id {
                span.set_attribute(KeyValue::new("oauth.client_id", client_id.clone()));
            }
            if !user_ctx.scopes.is_empty() {
                span.set_attribute(KeyValue::new("oauth.scopes", user_ctx.scopes.join(",")));
            }
        }

        // Record metrics
        if let Ok(metrics) = self.observability.metrics().read().await {
            metrics.record_auth_attempt(
                flow_type,
                true, // Starting attempt
                self.user_context.as_ref().and_then(|ctx| ctx.user_id.as_deref()),
            );
        }

        self.performance_tracker.checkpoint("auth_flow_start");

        Ok(AuthFlowSpan {
            span,
            flow_id: self.flow_id.clone(),
            observability: Arc::clone(&self.observability),
        })
    }

    /// Trace token validation operation
    #[instrument(skip(self), fields(
        flow_id = %self.flow_id,
        token_type = %token_type
    ))]
    pub async fn trace_token_validation(
        &mut self,
        token_type: &str,
        token_id: Option<&str>,
    ) -> SecurityResult<TokenValidationSpan> {
        info!("Starting token validation: {}", token_type);

        let tracer = self.observability.tracer()
            .ok_or(SecurityError::Configuration)?;

        let mut span = TracingUtils::create_span(
            tracer,
            "token_validation",
            SpanKind::Internal,
            vec![
                KeyValue::new("token.type", token_type.to_string()),
                KeyValue::new("auth.flow_id", self.flow_id.clone()),
                KeyValue::new("operation", "validate".to_string()),
            ],
        );

        if let Some(tid) = token_id {
            span.set_attribute(KeyValue::new("token.id", tid.to_string()));
        }

        // Add security context
        TracingUtils::add_security_context(
            &mut span,
            self.user_context.as_ref().and_then(|ctx| ctx.user_id.as_deref()),
            self.user_context.as_ref().and_then(|ctx| ctx.session_id.as_deref()),
            self.security_context.client_ip.as_deref(),
        );

        self.performance_tracker.checkpoint("token_validation_start");

        Ok(TokenValidationSpan {
            span,
            start_time: Instant::now(),
            observability: Arc::clone(&self.observability),
            token_type: token_type.to_string(),
        })
    }

    /// Trace policy evaluation
    #[instrument(skip(self), fields(
        flow_id = %self.flow_id,
        policy_id = %policy_id
    ))]
    pub async fn trace_policy_evaluation(
        &mut self,
        policy_id: &str,
        resource: &str,
        action: &str,
    ) -> SecurityResult<PolicyEvaluationSpan> {
        info!("Starting policy evaluation: {}", policy_id);

        let tracer = self.observability.tracer()
            .ok_or(SecurityError::Configuration)?;

        let mut span = TracingUtils::create_span(
            tracer,
            "policy_evaluation",
            SpanKind::Internal,
            vec![
                KeyValue::new("policy.id", policy_id.to_string()),
                KeyValue::new("policy.resource", resource.to_string()),
                KeyValue::new("policy.action", action.to_string()),
                KeyValue::new("auth.flow_id", self.flow_id.clone()),
            ],
        );

        // Add security context
        TracingUtils::add_security_context(
            &mut span,
            self.user_context.as_ref().and_then(|ctx| ctx.user_id.as_deref()),
            self.user_context.as_ref().and_then(|ctx| ctx.session_id.as_deref()),
            self.security_context.client_ip.as_deref(),
        );

        self.performance_tracker.checkpoint("policy_evaluation_start");

        // Record policy evaluation metric
        if let Ok(metrics) = self.observability.metrics().read().await {
            metrics.policy_evaluations_total.add(1, &[
                KeyValue::new("policy_id", policy_id.to_string()),
                KeyValue::new("resource", resource.to_string()),
                KeyValue::new("action", action.to_string()),
            ]);
        }

        Ok(PolicyEvaluationSpan {
            span,
            start_time: Instant::now(),
            observability: Arc::clone(&self.observability),
            policy_id: policy_id.to_string(),
        })
    }

    /// Trace database operation
    #[instrument(skip(self), fields(
        flow_id = %self.flow_id,
        operation = %operation,
        table = %table
    ))]
    pub async fn trace_database_operation(
        &mut self,
        operation: &str,
        table: &str,
    ) -> SecurityResult<DatabaseOperationSpan> {
        info!("Starting database operation: {} on {}", operation, table);

        let tracer = self.observability.tracer()
            .ok_or(SecurityError::Configuration)?;

        let mut span = TracingUtils::create_span(
            tracer,
            "db_operation",
            SpanKind::Client,
            vec![
                KeyValue::new("db.operation", operation.to_string()),
                KeyValue::new("db.table", table.to_string()),
                KeyValue::new("db.system", "redis".to_string()),
                KeyValue::new("auth.flow_id", self.flow_id.clone()),
            ],
        );

        self.performance_tracker.checkpoint("db_operation_start");

        // Record database operation metric
        if let Ok(metrics) = self.observability.metrics().read().await {
            metrics.database_operations_total.add(1, &[
                KeyValue::new("operation", operation.to_string()),
                KeyValue::new("table", table.to_string()),
            ]);
        }

        Ok(DatabaseOperationSpan {
            span,
            start_time: Instant::now(),
            observability: Arc::clone(&self.observability),
            operation: operation.to_string(),
        })
    }

    /// Record security event with detailed tracing
    #[instrument(skip(self), fields(
        flow_id = %self.flow_id,
        event_type = %event_type,
        severity = %severity
    ))]
    pub async fn record_security_event(
        &mut self,
        event_type: &str,
        severity: &str,
        description: &str,
        additional_data: Option<HashMap<String, String>>,
    ) {
        warn!(
            target = "security_audit",
            event_type = %event_type,
            severity = %severity,
            flow_id = %self.flow_id,
            request_id = %self.security_context.request_id,
            user_id = ?self.user_context.as_ref().and_then(|ctx| ctx.user_id.as_deref()),
            client_ip = ?self.security_context.client_ip,
            description = %description,
            "Security event recorded"
        );

        // Record security event metric
        if let Ok(metrics) = self.observability.metrics().read().await {
            metrics.record_security_event(
                event_type,
                severity,
                self.security_context.client_ip.as_deref(),
            );
        }

        // Create span for security event
        if let Some(tracer) = self.observability.tracer() {
            let mut span = TracingUtils::create_span(
                tracer,
                "security_event",
                SpanKind::Internal,
                vec![
                    KeyValue::new("security.event_type", event_type.to_string()),
                    KeyValue::new("security.severity", severity.to_string()),
                    KeyValue::new("security.description", description.to_string()),
                    KeyValue::new("auth.flow_id", self.flow_id.clone()),
                ],
            );

            // Add additional data as span attributes
            if let Some(data) = additional_data {
                for (key, value) in data {
                    span.set_attribute(KeyValue::new(format!("security.{}", key), value));
                }
            }

            TracingUtils::add_security_context(
                &mut span,
                self.user_context.as_ref().and_then(|ctx| ctx.user_id.as_deref()),
                self.user_context.as_ref().and_then(|ctx| ctx.session_id.as_deref()),
                self.security_context.client_ip.as_deref(),
            );

            span.end();
        }
    }
}

/// Authentication flow span wrapper
pub struct AuthFlowSpan {
    span: opentelemetry::global::BoxedSpan,
    flow_id: String,
    observability: Arc<ObservabilityProvider>,
}

impl AuthFlowSpan {
    pub fn record_success(&mut self, user_id: &str, session_id: &str) {
        self.span.set_attribute(KeyValue::new("auth.result", "success"));
        self.span.set_attribute(KeyValue::new("auth.user_id", user_id.to_string()));
        self.span.set_attribute(KeyValue::new("auth.session_id", session_id.to_string()));
        
        info!(
            flow_id = %self.flow_id,
            user_id = %user_id,
            session_id = %session_id,
            "Authentication flow completed successfully"
        );
    }

    pub fn record_failure(&mut self, error: &SecurityError, reason: &str) {
        TracingUtils::add_error_to_span(&mut self.span, error);
        self.span.set_attribute(KeyValue::new("auth.result", "failure"));
        self.span.set_attribute(KeyValue::new("auth.failure_reason", reason.to_string()));
        
        error!(
            flow_id = %self.flow_id,
            error_code = %error.error_code(),
            reason = %reason,
            "Authentication flow failed"
        );
    }

    pub fn add_attribute(&mut self, key: &str, value: &str) {
        self.span.set_attribute(KeyValue::new(key.to_string(), value.to_string()));
    }
}

impl Drop for AuthFlowSpan {
    fn drop(&mut self) {
        self.span.end();
    }
}

/// Token validation span wrapper
pub struct TokenValidationSpan {
    span: opentelemetry::global::BoxedSpan,
    start_time: Instant,
    observability: Arc<ObservabilityProvider>,
    token_type: String,
}

impl TokenValidationSpan {
    pub async fn record_success(&mut self, user_id: &str) {
        let duration = self.start_time.elapsed();
        
        self.span.set_attribute(KeyValue::new("token.validation_result", "success"));
        self.span.set_attribute(KeyValue::new("token.user_id", user_id.to_string()));
        self.span.set_attribute(KeyValue::new("token.validation_duration_ms", duration.as_millis() as i64));

        // Record metrics
        if let Ok(metrics) = self.observability.metrics().read().await {
            metrics.token_validation_duration.record(duration.as_secs_f64(), &[
                KeyValue::new("token_type", self.token_type.clone()),
                KeyValue::new("result", "success".to_string()),
            ]);
        }

        info!(
            token_type = %self.token_type,
            user_id = %user_id,
            duration_ms = %duration.as_millis(),
            "Token validation completed successfully"
        );
    }

    pub async fn record_failure(&mut self, error: &SecurityError) {
        let duration = self.start_time.elapsed();
        
        TracingUtils::add_error_to_span(&mut self.span, error);
        self.span.set_attribute(KeyValue::new("token.validation_result", "failure"));
        self.span.set_attribute(KeyValue::new("token.validation_duration_ms", duration.as_millis() as i64));

        // Record metrics
        if let Ok(metrics) = self.observability.metrics().read().await {
            metrics.token_validation_duration.record(duration.as_secs_f64(), &[
                KeyValue::new("token_type", self.token_type.clone()),
                KeyValue::new("result", "failure".to_string()),
            ]);
        }

        error!(
            token_type = %self.token_type,
            error_code = %error.error_code(),
            duration_ms = %duration.as_millis(),
            "Token validation failed"
        );
    }
}

impl Drop for TokenValidationSpan {
    fn drop(&mut self) {
        self.span.end();
    }
}

/// Policy evaluation span wrapper
pub struct PolicyEvaluationSpan {
    span: opentelemetry::global::BoxedSpan,
    start_time: Instant,
    observability: Arc<ObservabilityProvider>,
    policy_id: String,
}

impl PolicyEvaluationSpan {
    pub fn record_decision(&mut self, decision: &str, reason: Option<&str>) {
        let duration = self.start_time.elapsed();
        
        self.span.set_attribute(KeyValue::new("policy.decision", decision.to_string()));
        self.span.set_attribute(KeyValue::new("policy.evaluation_duration_ms", duration.as_millis() as i64));
        
        if let Some(reason) = reason {
            self.span.set_attribute(KeyValue::new("policy.reason", reason.to_string()));
        }

        info!(
            policy_id = %self.policy_id,
            decision = %decision,
            duration_ms = %duration.as_millis(),
            reason = ?reason,
            "Policy evaluation completed"
        );
    }
}

impl Drop for PolicyEvaluationSpan {
    fn drop(&mut self) {
        self.span.end();
    }
}

/// Database operation span wrapper
pub struct DatabaseOperationSpan {
    span: opentelemetry::global::BoxedSpan,
    start_time: Instant,
    observability: Arc<ObservabilityProvider>,
    operation: String,
}

impl DatabaseOperationSpan {
    pub async fn record_success(&mut self, rows_affected: Option<u64>) {
        let duration = self.start_time.elapsed();
        
        self.span.set_attribute(KeyValue::new("db.operation_result", "success"));
        self.span.set_attribute(KeyValue::new("db.duration_ms", duration.as_millis() as i64));
        
        if let Some(rows) = rows_affected {
            self.span.set_attribute(KeyValue::new("db.rows_affected", rows as i64));
        }

        info!(
            operation = %self.operation,
            duration_ms = %duration.as_millis(),
            rows_affected = ?rows_affected,
            "Database operation completed successfully"
        );
    }

    pub fn record_failure(&mut self, error: &SecurityError) {
        let duration = self.start_time.elapsed();
        
        TracingUtils::add_error_to_span(&mut self.span, error);
        self.span.set_attribute(KeyValue::new("db.operation_result", "failure"));
        self.span.set_attribute(KeyValue::new("db.duration_ms", duration.as_millis() as i64));

        error!(
            operation = %self.operation,
            error_code = %error.error_code(),
            duration_ms = %duration.as_millis(),
            "Database operation failed"
        );
    }
}

impl Drop for DatabaseOperationSpan {
    fn drop(&mut self) {
        self.span.end();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::ObservabilityConfig;

    #[tokio::test]
    async fn test_auth_flow_tracer_creation() {
        let config = ObservabilityConfig::default();
        let observability = Arc::new(ObservabilityProvider::new(config).await.unwrap());
        let tracer = AuthFlowTracer::new(observability);
        
        assert!(!tracer.flow_id.is_empty());
        assert!(tracer.user_context.is_none());
    }

    #[test]
    fn test_performance_tracker() {
        let mut tracker = PerformanceTracker::new();
        
        std::thread::sleep(std::time::Duration::from_millis(10));
        tracker.checkpoint("test");
        tracker.record_metric("test_metric", 123.45);
        
        assert!(tracker.duration_since_start().as_millis() >= 10);
        assert!(tracker.duration_since_checkpoint("test").is_some());
        assert_eq!(tracker.metrics.get("test_metric"), Some(&123.45));
    }

    #[test]
    fn test_threat_level_display() {
        assert_eq!(ThreatLevel::Low.to_string(), "LOW");
        assert_eq!(ThreatLevel::Critical.to_string(), "CRITICAL");
    }
}