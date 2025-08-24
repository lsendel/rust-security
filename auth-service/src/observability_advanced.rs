// Advanced Observability and Distributed Tracing
// Comprehensive observability with OpenTelemetry, metrics, and correlation

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use opentelemetry::{
    trace::{TraceContextExt, Tracer, TracerProvider, SpanKind, Status},
    Context, KeyValue,
};
use opentelemetry_sdk::{
    trace::{self, RandomIdGenerator, Sampler},
    Resource,
};
use opentelemetry_jaeger::new_agent_pipeline;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use sha2::{Sha256, Digest};

/// Observability configuration
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    /// Service name for tracing
    pub service_name: String,
    /// Service version
    pub service_version: String,
    /// Environment (dev, staging, prod)
    pub environment: String,
    /// Jaeger endpoint for trace export
    pub jaeger_endpoint: Option<String>,
    /// Sampling rate (0.0 to 1.0)
    pub sampling_rate: f64,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Enable distributed tracing
    pub enable_tracing: bool,
    /// Enable business metrics
    pub enable_business_metrics: bool,
    /// Metrics export interval
    pub metrics_interval: Duration,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            service_name: "rust-security-platform".to_string(),
            service_version: "1.0.0".to_string(),
            environment: "development".to_string(),
            jaeger_endpoint: Some("http://localhost:14268/api/traces".to_string()),
            sampling_rate: 1.0, // 100% sampling in dev
            enable_metrics: true,
            enable_tracing: true,
            enable_business_metrics: true,
            metrics_interval: Duration::from_secs(60),
        }
    }
}

/// Standardized span information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardSpan {
    /// Trace ID for correlation
    pub trace_id: String,
    /// Span ID
    pub span_id: String,
    /// Parent span ID
    pub parent_span_id: Option<String>,
    /// Service name
    pub service_name: String,
    /// Operation name
    pub operation_name: String,
    /// Start timestamp
    pub start_time: SystemTime,
    /// Duration (if completed)
    pub duration: Option<Duration>,
    /// Span status
    pub status: SpanStatus,
    /// Tags/attributes
    pub tags: HashMap<String, String>,
    /// Privacy-safe user identifier hash
    pub user_id_hash: Option<String>,
    /// Request correlation ID
    pub request_id: String,
    /// Session identifier hash
    pub session_id_hash: Option<String>,
    /// Business context
    pub business_context: Option<BusinessContext>,
}

/// Span status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpanStatus {
    Ok,
    Error(String),
    Cancelled,
}

/// Business context for spans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessContext {
    /// Business operation type
    pub operation_type: BusinessOperationType,
    /// Customer/tenant identifier
    pub tenant_id: Option<String>,
    /// Feature flags active during operation
    pub feature_flags: Vec<String>,
    /// A/B test variants
    pub ab_test_variants: HashMap<String, String>,
    /// Business metrics
    pub business_metrics: HashMap<String, f64>,
}

/// Business operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BusinessOperationType {
    Authentication,
    Authorization,
    UserRegistration,
    PasswordReset,
    TokenRefresh,
    PolicyEvaluation,
    SessionManagement,
    AuditLog,
    HealthCheck,
    MetricsCollection,
}

/// Distributed tracing context
#[derive(Debug, Clone)]
pub struct TracingContext {
    /// Trace ID
    pub trace_id: String,
    /// Current span ID
    pub span_id: String,
    /// Parent span ID
    pub parent_span_id: Option<String>,
    /// Baggage items for cross-service context
    pub baggage: HashMap<String, String>,
    /// Sampling decision
    pub sampled: bool,
}

impl TracingContext {
    /// Create new tracing context
    pub fn new() -> Self {
        Self {
            trace_id: generate_trace_id(),
            span_id: generate_span_id(),
            parent_span_id: None,
            baggage: HashMap::new(),
            sampled: true,
        }
    }

    /// Create child context
    pub fn create_child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            span_id: generate_span_id(),
            parent_span_id: Some(self.span_id.clone()),
            baggage: self.baggage.clone(),
            sampled: self.sampled,
        }
    }

    /// Add baggage item
    pub fn add_baggage(&mut self, key: String, value: String) {
        self.baggage.insert(key, value);
    }

    /// Get baggage item
    pub fn get_baggage(&self, key: &str) -> Option<&String> {
        self.baggage.get(key)
    }

    /// Convert to W3C trace context header
    pub fn to_w3c_traceparent(&self) -> String {
        format!("00-{}-{}-{:02x}", 
            self.trace_id, 
            self.span_id, 
            if self.sampled { 1 } else { 0 }
        )
    }

    /// Parse from W3C trace context header
    pub fn from_w3c_traceparent(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 || parts[0] != "00" {
            return None;
        }

        let trace_id = parts[1].to_string();
        let parent_span_id = parts[2].to_string();
        let flags = u8::from_str_radix(parts[3], 16).ok()?;
        let sampled = (flags & 0x01) != 0;

        Some(Self {
            trace_id,
            span_id: generate_span_id(),
            parent_span_id: Some(parent_span_id),
            baggage: HashMap::new(),
            sampled,
        })
    }
}

/// Advanced observability manager
pub struct ObservabilityManager {
    config: ObservabilityConfig,
    tracer: Option<Box<dyn Tracer + Send + Sync>>,
    active_spans: Arc<RwLock<HashMap<String, StandardSpan>>>,
    metrics_collector: Arc<RwLock<MetricsCollector>>,
    business_metrics: Arc<RwLock<BusinessMetricsCollector>>,
}

impl ObservabilityManager {
    /// Create new observability manager
    pub async fn new(config: ObservabilityConfig) -> Result<Self, ObservabilityError> {
        let tracer = if config.enable_tracing {
            Some(Self::setup_tracing(&config).await?)
        } else {
            None
        };

        Ok(Self {
            config,
            tracer,
            active_spans: Arc::new(RwLock::new(HashMap::new())),
            metrics_collector: Arc::new(RwLock::new(MetricsCollector::new())),
            business_metrics: Arc::new(RwLock::new(BusinessMetricsCollector::new())),
        })
    }

    /// Setup distributed tracing
    async fn setup_tracing(config: &ObservabilityConfig) -> Result<Box<dyn Tracer + Send + Sync>, ObservabilityError> {
        #[cfg(feature = "opentelemetry")]
        {
            let tracer = opentelemetry_jaeger::new_agent_pipeline()
                .with_service_name(&config.service_name)
                .with_trace_config(
                    trace::config()
                        .with_sampler(Sampler::TraceIdRatioBased(config.sampling_rate))
                        .with_id_generator(RandomIdGenerator::default())
                        .with_resource(Resource::new(vec![
                            KeyValue::new("service.name", config.service_name.clone()),
                            KeyValue::new("service.version", config.service_version.clone()),
                            KeyValue::new("deployment.environment", config.environment.clone()),
                        ]))
                )
                .install_batch(opentelemetry_sdk::runtime::Tokio)
                .map_err(|e| ObservabilityError::TracingSetupFailed(e.to_string()))?;

            return Ok(Box::new(tracer));
        }

        #[cfg(not(feature = "opentelemetry"))]
        {
            // Provide a no-op tracer when opentelemetry is not enabled
            struct NoopTracer;
            impl Tracer for NoopTracer {}
            return Ok(Box::new(NoopTracer));
        }
    }

    /// Start a new span with comprehensive context
    pub async fn start_span(
        &self,
        operation_name: &str,
        context: Option<TracingContext>,
        business_context: Option<BusinessContext>,
    ) -> SpanHandle {
        let span_id = generate_span_id();
        let trace_id = context.as_ref()
            .map(|c| c.trace_id.clone())
            .unwrap_or_else(generate_trace_id);

        let mut tags = HashMap::new();
        tags.insert("service.name".to_string(), self.config.service_name.clone());
        tags.insert("service.version".to_string(), self.config.service_version.clone());
        tags.insert("environment".to_string(), self.config.environment.clone());

        // Add business context tags
        if let Some(ref biz_ctx) = business_context {
            tags.insert("business.operation_type".to_string(), format!("{:?}", biz_ctx.operation_type));
            if let Some(ref tenant_id) = biz_ctx.tenant_id {
                tags.insert("business.tenant_id".to_string(), tenant_id.clone());
            }
        }

        let standard_span = StandardSpan {
            trace_id: trace_id.clone(),
            span_id: span_id.clone(),
            parent_span_id: context.as_ref().and_then(|c| c.parent_span_id.clone()),
            service_name: self.config.service_name.clone(),
            operation_name: operation_name.to_string(),
            start_time: SystemTime::now(),
            duration: None,
            status: SpanStatus::Ok,
            tags,
            user_id_hash: None,
            request_id: Uuid::new_v4().to_string(),
            session_id_hash: None,
            business_context,
        };

        // Store active span
        {
            let mut spans = self.active_spans.write().await;
            spans.insert(span_id.clone(), standard_span.clone());
        }

        // Create OpenTelemetry span if tracing is enabled
        let otel_span = if let Some(ref tracer) = self.tracer {
            let mut span_builder = tracer.span_builder(operation_name);
            span_builder = span_builder.with_kind(SpanKind::Server);
            
            // Add attributes
            for (key, value) in &standard_span.tags {
                span_builder = span_builder.with_attributes(vec![KeyValue::new(key.clone(), value.clone())]);
            }

            Some(span_builder.start(tracer.as_ref()))
        } else {
            None
        };

        SpanHandle {
            span_id,
            trace_id,
            otel_span,
            manager: Arc::new(self.clone()),
        }
    }

    /// Record business metric
    pub async fn record_business_metric(
        &self,
        metric_name: &str,
        value: f64,
        tags: HashMap<String, String>,
    ) {
        if !self.config.enable_business_metrics {
            return;
        }

        let mut collector = self.business_metrics.write().await;
        collector.record_metric(metric_name, value, tags).await;
    }

    /// Record authentication event
    pub async fn record_authentication_event(
        &self,
        user_id: &str,
        success: bool,
        method: &str,
        duration: Duration,
    ) {
        let mut tags = HashMap::new();
        tags.insert("auth.method".to_string(), method.to_string());
        tags.insert("auth.success".to_string(), success.to_string());
        
        // Privacy-safe user identifier
        let user_hash = hash_user_id(user_id);
        tags.insert("user.id_hash".to_string(), user_hash);

        self.record_business_metric("authentication.attempts", 1.0, tags.clone()).await;
        self.record_business_metric("authentication.duration_ms", duration.as_millis() as f64, tags).await;

        if success {
            let mut success_tags = HashMap::new();
            success_tags.insert("auth.method".to_string(), method.to_string());
            self.record_business_metric("authentication.successes", 1.0, success_tags).await;
        }
    }

    /// Record authorization event
    pub async fn record_authorization_event(
        &self,
        user_id: &str,
        resource: &str,
        action: &str,
        allowed: bool,
        duration: Duration,
    ) {
        let mut tags = HashMap::new();
        tags.insert("authz.resource".to_string(), resource.to_string());
        tags.insert("authz.action".to_string(), action.to_string());
        tags.insert("authz.allowed".to_string(), allowed.to_string());
        
        let user_hash = hash_user_id(user_id);
        tags.insert("user.id_hash".to_string(), user_hash);

        self.record_business_metric("authorization.checks", 1.0, tags.clone()).await;
        self.record_business_metric("authorization.duration_ms", duration.as_millis() as f64, tags).await;
    }

    /// Get observability health status
    pub async fn get_health_status(&self) -> ObservabilityHealth {
        let active_spans_count = self.active_spans.read().await.len();
        let metrics_collector = self.metrics_collector.read().await;
        let business_metrics = self.business_metrics.read().await;

        ObservabilityHealth {
            tracing_enabled: self.config.enable_tracing,
            metrics_enabled: self.config.enable_metrics,
            active_spans: active_spans_count,
            total_metrics_collected: metrics_collector.get_total_metrics(),
            business_metrics_collected: business_metrics.get_total_metrics(),
            last_export_time: metrics_collector.get_last_export_time(),
            health_score: self.calculate_health_score().await,
        }
    }

    /// Calculate overall health score
    async fn calculate_health_score(&self) -> f64 {
        let mut score = 1.0;

        // Reduce score if tracing is not working
        if self.config.enable_tracing && self.tracer.is_none() {
            score *= 0.7;
        }

        // Reduce score if too many active spans (potential memory leak)
        let active_spans = self.active_spans.read().await.len();
        if active_spans > 1000 {
            score *= 0.8;
        }

        score
    }

    /// Export metrics
    pub async fn export_metrics(&self) -> MetricsExport {
        let metrics_collector = self.metrics_collector.read().await;
        let business_metrics = self.business_metrics.read().await;

        MetricsExport {
            timestamp: SystemTime::now(),
            service_name: self.config.service_name.clone(),
            technical_metrics: metrics_collector.export_metrics(),
            business_metrics: business_metrics.export_metrics(),
        }
    }
}

// Clone implementation for ObservabilityManager
impl Clone for ObservabilityManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            tracer: None, // Tracer is not cloneable, but we can work around this
            active_spans: self.active_spans.clone(),
            metrics_collector: self.metrics_collector.clone(),
            business_metrics: self.business_metrics.clone(),
        }
    }
}

/// Span handle for managing span lifecycle
pub struct SpanHandle {
    span_id: String,
    trace_id: String,
    otel_span: Option<opentelemetry::global::BoxedSpan>,
    manager: Arc<ObservabilityManager>,
}

impl SpanHandle {
    /// Add attribute to span
    pub fn add_attribute(&mut self, key: &str, value: &str) {
        if let Some(ref mut span) = self.otel_span {
            span.set_attribute(KeyValue::new(key.to_string(), value.to_string()));
        }
    }

    /// Add user context (privacy-safe)
    pub fn add_user_context(&mut self, user_id: &str) {
        let user_hash = hash_user_id(user_id);
        self.add_attribute("user.id_hash", &user_hash);
    }

    /// Add session context (privacy-safe)
    pub fn add_session_context(&mut self, session_id: &str) {
        let session_hash = hash_session_id(session_id);
        self.add_attribute("session.id_hash", &session_hash);
    }

    /// Record error in span
    pub fn record_error(&mut self, error: &str) {
        if let Some(ref mut span) = self.otel_span {
            span.record_error(error);
            span.set_status(Status::Error {
                description: error.to_string().into(),
            });
        }
    }

    /// Finish span
    pub async fn finish(mut self) {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        // Update stored span
        {
            let mut spans = self.manager.active_spans.write().await;
            if let Some(mut span) = spans.remove(&self.span_id) {
                span.duration = Some(duration);
                // Could store completed spans for analysis
            }
        }

        // Finish OpenTelemetry span
        if let Some(span) = self.otel_span.take() {
            span.end();
        }
    }
}

/// Metrics collector for technical metrics
#[derive(Debug)]
pub struct MetricsCollector {
    metrics: HashMap<String, Vec<MetricPoint>>,
    last_export: Option<SystemTime>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
            last_export: None,
        }
    }

    pub fn record_counter(&mut self, name: &str, value: f64, tags: HashMap<String, String>) {
        let point = MetricPoint {
            timestamp: SystemTime::now(),
            value,
            tags,
            metric_type: MetricType::Counter,
        };

        self.metrics.entry(name.to_string()).or_default().push(point);
    }

    pub fn record_gauge(&mut self, name: &str, value: f64, tags: HashMap<String, String>) {
        let point = MetricPoint {
            timestamp: SystemTime::now(),
            value,
            tags,
            metric_type: MetricType::Gauge,
        };

        self.metrics.entry(name.to_string()).or_default().push(point);
    }

    pub fn get_total_metrics(&self) -> usize {
        self.metrics.values().map(|v| v.len()).sum()
    }

    pub fn get_last_export_time(&self) -> Option<SystemTime> {
        self.last_export
    }

    pub fn export_metrics(&self) -> HashMap<String, Vec<MetricPoint>> {
        self.metrics.clone()
    }
}

/// Business metrics collector
#[derive(Debug)]
pub struct BusinessMetricsCollector {
    metrics: HashMap<String, Vec<BusinessMetricPoint>>,
}

impl BusinessMetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
        }
    }

    pub async fn record_metric(&mut self, name: &str, value: f64, tags: HashMap<String, String>) {
        let point = BusinessMetricPoint {
            timestamp: SystemTime::now(),
            value,
            tags,
        };

        self.metrics.entry(name.to_string()).or_default().push(point);
    }

    pub fn get_total_metrics(&self) -> usize {
        self.metrics.values().map(|v| v.len()).sum()
    }

    pub fn export_metrics(&self) -> HashMap<String, Vec<BusinessMetricPoint>> {
        self.metrics.clone()
    }
}

/// Metric point for technical metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub timestamp: SystemTime,
    pub value: f64,
    pub tags: HashMap<String, String>,
    pub metric_type: MetricType,
}

/// Business metric point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessMetricPoint {
    pub timestamp: SystemTime,
    pub value: f64,
    pub tags: HashMap<String, String>,
}

/// Metric types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

/// Observability health status
#[derive(Debug, Serialize, Deserialize)]
pub struct ObservabilityHealth {
    pub tracing_enabled: bool,
    pub metrics_enabled: bool,
    pub active_spans: usize,
    pub total_metrics_collected: usize,
    pub business_metrics_collected: usize,
    pub last_export_time: Option<SystemTime>,
    pub health_score: f64,
}

/// Metrics export
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsExport {
    pub timestamp: SystemTime,
    pub service_name: String,
    pub technical_metrics: HashMap<String, Vec<MetricPoint>>,
    pub business_metrics: HashMap<String, Vec<BusinessMetricPoint>>,
}

/// Observability errors
#[derive(Debug, thiserror::Error)]
pub enum ObservabilityError {
    #[error("Tracing setup failed: {0}")]
    TracingSetupFailed(String),
    #[error("Metrics export failed: {0}")]
    MetricsExportFailed(String),
    #[error("Span not found: {0}")]
    SpanNotFound(String),
}

// Utility functions
fn generate_trace_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

fn generate_span_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

fn hash_user_id(user_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    hasher.update(b"user_salt"); // Add salt for additional privacy
    format!("{:x}", hasher.finalize())
}

fn hash_session_id(session_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(b"session_salt"); // Add salt for additional privacy
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_observability_manager_creation() {
        let config = ObservabilityConfig::default();
        let manager = ObservabilityManager::new(config).await;
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_span_lifecycle() {
        let config = ObservabilityConfig {
            enable_tracing: false, // Disable for testing
            ..Default::default()
        };
        let manager = ObservabilityManager::new(config).await.unwrap();
        
        let mut span = manager.start_span("test_operation", None, None).await;
        span.add_attribute("test.key", "test.value");
        span.add_user_context("test_user");
        span.finish().await;
    }

    #[test]
    fn test_tracing_context() {
        let context = TracingContext::new();
        assert!(!context.trace_id.is_empty());
        assert!(!context.span_id.is_empty());
        
        let child = context.create_child();
        assert_eq!(child.trace_id, context.trace_id);
        assert_ne!(child.span_id, context.span_id);
        assert_eq!(child.parent_span_id, Some(context.span_id));
    }

    #[test]
    fn test_w3c_trace_context() {
        let context = TracingContext::new();
        let header = context.to_w3c_traceparent();
        
        let parsed = TracingContext::from_w3c_traceparent(&header);
        assert!(parsed.is_some());
        
        let parsed = parsed.unwrap();
        assert_eq!(parsed.trace_id, context.trace_id);
    }

    #[test]
    fn test_privacy_safe_hashing() {
        let user_id = "test_user_123";
        let hash1 = hash_user_id(user_id);
        let hash2 = hash_user_id(user_id);
        
        assert_eq!(hash1, hash2); // Consistent hashing
        assert_ne!(hash1, user_id); // Actually hashed
        assert!(!hash1.contains(user_id)); // No PII leakage
    }
}
