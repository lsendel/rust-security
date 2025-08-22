//! Comprehensive OpenTelemetry observability implementation
//! 
//! This module provides distributed tracing, metrics collection, and logging
//! with correlation across microservices for complete system observability.

use opentelemetry::{
    global,
    metrics::{Counter, Histogram, Meter, MeterProvider, Unit},
    trace::{SpanKind, TraceContextExt, Tracer},
    Context, KeyValue,
};
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::{
    metrics::{MeterProviderBuilder, PeriodicReader, SdkMeterProvider},
    resource::{EnvResourceDetector, TelemetryResourceDetector},
    trace::{Config, TracerProvider},
    Resource,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use uuid::Uuid;

use crate::error_handling::{SecurityError, SecurityResult};

/// Observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Service name for telemetry
    pub service_name: String,
    /// Service version
    pub service_version: String,
    /// Environment (dev, staging, prod)
    pub environment: String,
    /// OTLP exporter endpoint
    pub otlp_endpoint: String,
    /// Enable tracing
    pub tracing_enabled: bool,
    /// Enable metrics
    pub metrics_enabled: bool,
    /// Sampling ratio (0.0 - 1.0)
    pub sampling_ratio: f64,
    /// Batch export timeout
    pub batch_timeout: Duration,
    /// Custom resource attributes
    pub resource_attributes: HashMap<String, String>,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            service_name: "auth-service".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
            otlp_endpoint: std::env::var("OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:4317".to_string()),
            tracing_enabled: true,
            metrics_enabled: true,
            sampling_ratio: 1.0,
            batch_timeout: Duration::from_secs(5),
            resource_attributes: HashMap::new(),
        }
    }
}

/// Comprehensive observability provider
pub struct ObservabilityProvider {
    config: ObservabilityConfig,
    tracer: Option<Tracer>,
    meter: Option<Meter>,
    metrics: Arc<RwLock<ServiceMetrics>>,
}

impl ObservabilityProvider {
    /// Initialize observability with configuration
    pub async fn new(config: ObservabilityConfig) -> SecurityResult<Self> {
        info!("Initializing OpenTelemetry observability");

        let resource = Self::create_resource(&config)?;
        
        let tracer = if config.tracing_enabled {
            Some(Self::init_tracing(&config, resource.clone()).await?)
        } else {
            None
        };

        let meter = if config.metrics_enabled {
            Some(Self::init_metrics(&config, resource).await?)
        } else {
            None
        };

        let metrics = Arc::new(RwLock::new(ServiceMetrics::new(meter.as_ref())?));

        Ok(Self {
            config,
            tracer,
            meter,
            metrics,
        })
    }

    /// Create resource with service information
    fn create_resource(config: &ObservabilityConfig) -> SecurityResult<Resource> {
        let mut resource = Resource::from_detectors(
            Duration::from_secs(3),
            vec![
                Box::new(EnvResourceDetector::new()),
                Box::new(TelemetryResourceDetector),
            ],
        );

        // Add service information
        let service_attrs = vec![
            KeyValue::new("service.name", config.service_name.clone()),
            KeyValue::new("service.version", config.service_version.clone()),
            KeyValue::new("service.environment", config.environment.clone()),
            KeyValue::new("service.instance.id", Uuid::new_v4().to_string()),
            KeyValue::new("telemetry.sdk.name", "opentelemetry-rust"),
            KeyValue::new("telemetry.sdk.language", "rust"),
        ];

        resource = resource.merge(&Resource::new(service_attrs));

        // Add custom attributes
        if !config.resource_attributes.is_empty() {
            let custom_attrs: Vec<KeyValue> = config
                .resource_attributes
                .iter()
                .map(|(k, v)| KeyValue::new(k.clone(), v.clone()))
                .collect();
            resource = resource.merge(&Resource::new(custom_attrs));
        }

        Ok(resource)
    }

    /// Initialize distributed tracing
    async fn init_tracing(
        config: &ObservabilityConfig,
        resource: Resource,
    ) -> SecurityResult<Tracer> {
        info!("Initializing OpenTelemetry tracing");

        let tracer_provider = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(&config.otlp_endpoint)
                    .with_timeout(config.batch_timeout),
            )
            .with_trace_config(
                Config::default()
                    .with_resource(resource)
                    .with_sampler(opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(
                        config.sampling_ratio,
                    )),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)
            .map_err(|e| {
                error!("Failed to initialize tracing: {}", e);
                SecurityError::Configuration
            })?;

        // Set as global tracer provider
        global::set_tracer_provider(tracer_provider.clone());

        // Create tracer
        let tracer = tracer_provider.tracer("auth-service");

        // Initialize tracing subscriber
        Self::init_tracing_subscriber()?;

        info!("OpenTelemetry tracing initialized successfully");
        Ok(tracer)
    }

    /// Initialize metrics collection
    async fn init_metrics(
        config: &ObservabilityConfig,
        resource: Resource,
    ) -> SecurityResult<Meter> {
        info!("Initializing OpenTelemetry metrics");

        let export_config = opentelemetry_otlp::ExportConfig {
            endpoint: config.otlp_endpoint.clone(),
            timeout: config.batch_timeout,
            ..Default::default()
        };

        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_export_config(export_config)
            .build_metrics_exporter(
                Box::new(opentelemetry_sdk::metrics::selectors::simple::inexpensive()),
                Box::new(opentelemetry_sdk::metrics::processors::basic::new(
                    opentelemetry_sdk::metrics::selectors::simple::inexpensive(),
                    opentelemetry_sdk::export::metrics::aggregation::cumulative_temporality_selector(),
                    opentelemetry_sdk::metrics::processors::basic::simple_processor(),
                )),
            )
            .map_err(|e| {
                error!("Failed to create metrics exporter: {}", e);
                SecurityError::Configuration
            })?;

        let reader = PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio)
            .with_interval(Duration::from_secs(30))
            .build();

        let meter_provider = MeterProviderBuilder::default()
            .with_resource(resource)
            .with_reader(reader)
            .build();

        // Set as global meter provider
        global::set_meter_provider(meter_provider.clone());

        let meter = meter_provider.meter("auth-service");

        info!("OpenTelemetry metrics initialized successfully");
        Ok(meter)
    }

    /// Initialize tracing subscriber with OpenTelemetry layer
    fn init_tracing_subscriber() -> SecurityResult<()> {
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

        #[allow(unused_variables)]
        let telemetry_layer = {
            #[cfg(feature = "opentelemetry" )]
            {
                tracing_opentelemetry::layer()
            }
            #[cfg(not(feature = "opentelemetry"))]
            {
                // Fallback no-op layer when feature not enabled
                tracing_subscriber::layer::Identity::new()
            }
        }
            .with_tracer(global::tracer("auth-service"));

        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info,auth_service=debug".into());

        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .with(telemetry_layer)
            .try_init()
            .map_err(|_| SecurityError::Configuration)?;

        Ok(())
    }

    /// Get the tracer instance
    pub fn tracer(&self) -> Option<&Tracer> {
        self.tracer.as_ref()
    }

    /// Get the meter instance
    pub fn meter(&self) -> Option<&Meter> {
        self.meter.as_ref()
    }

    /// Get service metrics
    pub fn metrics(&self) -> Arc<RwLock<ServiceMetrics>> {
        Arc::clone(&self.metrics)
    }

    /// Shutdown observability gracefully
    pub async fn shutdown(&self) -> SecurityResult<()> {
        info!("Shutting down observability");

        if self.tracer.is_some() {
            global::shutdown_tracer_provider();
        }

        if self.meter.is_some() {
            global::shutdown_meter_provider();
        }

        info!("Observability shutdown completed");
        Ok(())
    }
}

/// Service-specific metrics collection
pub struct ServiceMetrics {
    // Request metrics
    pub http_requests_total: Counter<u64>,
    pub http_request_duration: Histogram<f64>,
    pub http_requests_in_flight: opentelemetry::metrics::UpDownCounter<i64>,

    // Authentication metrics
    pub auth_attempts_total: Counter<u64>,
    pub auth_failures_total: Counter<u64>,
    pub token_operations_total: Counter<u64>,
    pub token_validation_duration: Histogram<f64>,

    // Security metrics
    pub rate_limit_violations_total: Counter<u64>,
    pub suspicious_activity_total: Counter<u64>,
    pub security_events_total: Counter<u64>,

    // System metrics
    pub database_operations_total: Counter<u64>,
    pub database_connection_pool_size: opentelemetry::metrics::UpDownCounter<i64>,
    pub memory_usage_bytes: opentelemetry::metrics::UpDownCounter<i64>,

    // Business metrics
    pub active_sessions: opentelemetry::metrics::UpDownCounter<i64>,
    pub user_registrations_total: Counter<u64>,
    pub policy_evaluations_total: Counter<u64>,
}

impl ServiceMetrics {
    pub fn new(meter: Option<&Meter>) -> SecurityResult<Self> {
        let meter = meter.ok_or(SecurityError::Configuration)?;

        Ok(Self {
            // Request metrics
            http_requests_total: meter
                .u64_counter("http_requests_total")
                .with_description("Total number of HTTP requests")
                .init(),
            
            http_request_duration: meter
                .f64_histogram("http_request_duration_seconds")
                .with_description("HTTP request duration in seconds")
                .with_unit(Unit::new("s"))
                .init(),
            
            http_requests_in_flight: meter
                .i64_up_down_counter("http_requests_in_flight")
                .with_description("Number of HTTP requests currently being processed")
                .init(),

            // Authentication metrics
            auth_attempts_total: meter
                .u64_counter("auth_attempts_total")
                .with_description("Total number of authentication attempts")
                .init(),
            
            auth_failures_total: meter
                .u64_counter("auth_failures_total")
                .with_description("Total number of authentication failures")
                .init(),
            
            token_operations_total: meter
                .u64_counter("token_operations_total")
                .with_description("Total number of token operations (issue, refresh, revoke)")
                .init(),
            
            token_validation_duration: meter
                .f64_histogram("token_validation_duration_seconds")
                .with_description("Token validation duration in seconds")
                .with_unit(Unit::new("s"))
                .init(),

            // Security metrics
            rate_limit_violations_total: meter
                .u64_counter("rate_limit_violations_total")
                .with_description("Total number of rate limit violations")
                .init(),
            
            suspicious_activity_total: meter
                .u64_counter("suspicious_activity_total")
                .with_description("Total number of suspicious activities detected")
                .init(),
            
            security_events_total: meter
                .u64_counter("security_events_total")
                .with_description("Total number of security events")
                .init(),

            // System metrics
            database_operations_total: meter
                .u64_counter("database_operations_total")
                .with_description("Total number of database operations")
                .init(),
            
            database_connection_pool_size: meter
                .i64_up_down_counter("database_connection_pool_size")
                .with_description("Current database connection pool size")
                .init(),
            
            memory_usage_bytes: meter
                .i64_up_down_counter("memory_usage_bytes")
                .with_description("Current memory usage in bytes")
                .with_unit(Unit::new("By"))
                .init(),

            // Business metrics
            active_sessions: meter
                .i64_up_down_counter("active_sessions")
                .with_description("Number of active user sessions")
                .init(),
            
            user_registrations_total: meter
                .u64_counter("user_registrations_total")
                .with_description("Total number of user registrations")
                .init(),
            
            policy_evaluations_total: meter
                .u64_counter("policy_evaluations_total")
                .with_description("Total number of policy evaluations")
                .init(),
        })
    }

    /// Record HTTP request
    pub fn record_http_request(
        &self,
        method: &str,
        path: &str,
        status_code: u16,
        duration: Duration,
    ) {
        let labels = &[
            KeyValue::new("method", method.to_string()),
            KeyValue::new("path", path.to_string()),
            KeyValue::new("status_code", status_code.to_string()),
        ];

        self.http_requests_total.add(1, labels);
        self.http_request_duration.record(duration.as_secs_f64(), labels);
    }

    /// Record authentication attempt
    pub fn record_auth_attempt(&self, method: &str, success: bool, user_id: Option<&str>) {
        let mut labels = vec![
            KeyValue::new("method", method.to_string()),
            KeyValue::new("success", success.to_string()),
        ];

        if let Some(uid) = user_id {
            labels.push(KeyValue::new("user_id", uid.to_string()));
        }

        self.auth_attempts_total.add(1, &labels);
        
        if !success {
            self.auth_failures_total.add(1, &labels);
        }
    }

    /// Record token operation
    pub fn record_token_operation(&self, operation: &str, token_type: &str) {
        let labels = &[
            KeyValue::new("operation", operation.to_string()),
            KeyValue::new("token_type", token_type.to_string()),
        ];

        self.token_operations_total.add(1, labels);
    }

    /// Record security event
    pub fn record_security_event(&self, event_type: &str, severity: &str, source_ip: Option<&str>) {
        let mut labels = vec![
            KeyValue::new("event_type", event_type.to_string()),
            KeyValue::new("severity", severity.to_string()),
        ];

        if let Some(ip) = source_ip {
            labels.push(KeyValue::new("source_ip", ip.to_string()));
        }

        self.security_events_total.add(1, &labels);
    }
}

/// Tracing utilities for manual instrumentation
pub struct TracingUtils;

impl TracingUtils {
    /// Create a new span with common attributes
    pub fn create_span(
        tracer: &Tracer,
        name: &str,
        kind: SpanKind,
        attributes: Vec<KeyValue>,
    ) -> opentelemetry::trace::Span {
        tracer
            .span_builder(name)
            .with_kind(kind)
            .with_attributes(attributes)
            .start(tracer)
    }

    /// Add security context to span
    pub fn add_security_context(
        span: &mut opentelemetry::trace::Span,
        user_id: Option<&str>,
        session_id: Option<&str>,
        client_ip: Option<&str>,
    ) {
        if let Some(uid) = user_id {
            span.set_attribute(KeyValue::new("user.id", uid.to_string()));
        }
        
        if let Some(sid) = session_id {
            span.set_attribute(KeyValue::new("session.id", sid.to_string()));
        }
        
        if let Some(ip) = client_ip {
            span.set_attribute(KeyValue::new("client.ip", ip.to_string()));
        }
        
        span.set_attribute(KeyValue::new("service.component", "auth"));
    }

    /// Add error information to span
    pub fn add_error_to_span(span: &mut opentelemetry::trace::Span, error: &SecurityError) {
        span.set_status(opentelemetry::trace::Status::Error {
            description: error.public_message().into(),
        });
        
        span.set_attribute(KeyValue::new("error", true));
        span.set_attribute(KeyValue::new("error.type", error.error_code().to_string()));
        span.set_attribute(KeyValue::new("error.message", error.public_message().to_string()));
    }

    /// Extract trace context from headers
    pub fn extract_trace_context(
        headers: &axum::http::HeaderMap,
    ) -> Context {
        use opentelemetry::propagation::Extractor;
        
        struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);
        
        impl<'a> Extractor for HeaderExtractor<'a> {
            fn get(&self, key: &str) -> Option<&str> {
                self.0.get(key)?.to_str().ok()
            }

            fn keys(&self) -> Vec<&str> {
                self.0.keys().map(|k| k.as_str()).collect()
            }
        }

        global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(headers))
        })
    }

    /// Inject trace context into headers
    pub fn inject_trace_context(
        context: &Context,
    ) -> axum::http::HeaderMap {
        use opentelemetry::propagation::Injector;
        
        struct HeaderInjector(axum::http::HeaderMap);
        
        impl Injector for HeaderInjector {
            fn set(&mut self, key: &str, value: String) {
                if let Ok(header_name) = axum::http::HeaderName::try_from(key) {
                    if let Ok(header_value) = axum::http::HeaderValue::try_from(value) {
                        self.0.insert(header_name, header_value);
                    }
                }
            }
        }

        let mut injector = HeaderInjector(axum::http::HeaderMap::new());
        global::get_text_map_propagator(|propagator| {
            propagator.inject_context(context, &mut injector);
        });

        injector.0
    }
}

/// Middleware for automatic HTTP request tracing
pub async fn tracing_middleware<B>(
    req: axum::http::Request<B>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let start_time = SystemTime::now();
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    
    // Extract trace context from headers
    let parent_context = TracingUtils::extract_trace_context(req.headers());
    
    // Create span for this request
    let tracer = global::tracer("auth-service");
    let mut span = TracingUtils::create_span(
        &tracer,
        &format!("{} {}", method, path),
        SpanKind::Server,
        vec![
            KeyValue::new("http.method", method.clone()),
            KeyValue::new("http.route", path.clone()),
            KeyValue::new("http.scheme", req.uri().scheme_str().unwrap_or("http").to_string()),
        ],
    );

    // Add request headers and client IP
    if let Some(user_agent) = req.headers().get("user-agent") {
        if let Ok(ua_str) = user_agent.to_str() {
            span.set_attribute(KeyValue::new("http.user_agent", ua_str.to_string()));
        }
    }

    // Process request within span context
    let response = {
        let _guard = span.set_active();
        next.run(req).await
    };

    // Record metrics and span completion
    let duration = start_time.elapsed().unwrap_or_default();
    let status_code = response.status().as_u16();
    
    span.set_attribute(KeyValue::new("http.status_code", status_code as i64));
    span.set_attribute(KeyValue::new("http.response_size", 
        response.headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0)
    ));

    // Mark span as error for 4xx/5xx status codes
    if status_code >= 400 {
        span.set_status(opentelemetry::trace::Status::Error {
            description: format!("HTTP {}", status_code).into(),
        });
    }

    span.end();
    
    response
}

/// Custom tracing macros for structured logging
#[macro_export]
macro_rules! trace_security_event {
    ($level:ident, $event_type:expr, $message:expr, $($key:expr => $value:expr),*) => {
        tracing::$level!(
            target = "security_audit",
            event_type = $event_type,
            timestamp = %chrono::Utc::now().to_rfc3339(),
            $($key = %$value,)*
            $message
        );
    };
}

#[macro_export]
macro_rules! trace_performance {
    ($operation:expr, $duration:expr, $($key:expr => $value:expr),*) => {
        tracing::info!(
            target = "performance",
            operation = $operation,
            duration_ms = %$duration.as_millis(),
            $($key = %$value,)*
            "Performance measurement"
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_observability_config_default() {
        let config = ObservabilityConfig::default();
        assert_eq!(config.service_name, "auth-service");
        assert!(config.tracing_enabled);
        assert!(config.metrics_enabled);
    }

    #[tokio::test]
    async fn test_service_metrics_creation() {
        // This test would require a meter instance
        // In practice, you'd create a test meter provider
        let config = ObservabilityConfig::default();
        let meter = opentelemetry::global::meter("test");
        let metrics = ServiceMetrics::new(Some(&meter));
        assert!(metrics.is_ok());
    }

    #[test]
    fn test_trace_context_extraction() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("traceparent", "00-12345678901234567890123456789012-1234567890123456-01".parse().unwrap());
        
        let context = TracingUtils::extract_trace_context(&headers);
        // Verify context contains trace information
        assert!(context.span().span_context().is_valid());
    }

    #[test]
    fn test_security_event_macro() {
        // Test the security event tracing macro
        trace_security_event!(
            warn,
            "authentication_failure",
            "Failed login attempt",
            "user_id" => "test@example.com",
            "client_ip" => "192.168.1.1"
        );
        // This would need assertion against log output in real tests
    }
}