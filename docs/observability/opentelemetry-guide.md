# OpenTelemetry Observability Guide

## Overview

This guide provides comprehensive documentation for the OpenTelemetry observability implementation in the Rust Security Platform. It covers distributed tracing, metrics collection, logging, and monitoring strategies for production environments.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        OpenTelemetry Architecture                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        │
│  │  Auth Service   │    │ Policy Service  │    │  Other Services │        │
│  │                 │    │                 │    │                 │        │
│  │ • Traces        │    │ • Traces        │    │ • Traces        │        │
│  │ • Metrics       │    │ • Metrics       │    │ • Metrics       │        │
│  │ • Logs          │    │ • Logs          │    │ • Logs          │        │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘        │
│           │                       │                       │               │
│           └───────────────────────┼───────────────────────┘               │
│                                   │                                       │
│  ┌─────────────────────────────────────────────────────────────────────── │
│  │                  OpenTelemetry Collector                               │
│  │                                                                         │
│  │ • Receives OTLP data         • Processes and transforms                │
│  │ • Batches for efficiency     • Routes to multiple backends             │
│  │ • Adds metadata              • Provides observability                  │
│  └─────────────────────────────────────────────────────────────────────── │
│           │                       │                       │               │
│           ▼                       ▼                       ▼               │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        │
│  │     Jaeger      │    │   Prometheus    │    │ Elasticsearch   │        │
│  │                 │    │                 │    │                 │        │
│  │ • Trace Storage │    │ • Metrics Store │    │ • Log Storage   │        │
│  │ • Query API     │    │ • Time Series   │    │ • Full Text     │        │
│  │ • UI Dashboard  │    │ • Alerting      │    │ • Search        │        │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘        │
│                                   │                                       │
│                          ┌─────────────────┐                              │
│                          │     Grafana     │                              │
│                          │                 │                              │
│                          │ • Dashboards    │                              │
│                          │ • Visualization │                              │
│                          │ • Alerting      │                              │
│                          └─────────────────┘                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Implementation Components

### 1. OpenTelemetry SDK Integration

The Rust Security Platform integrates OpenTelemetry through the `observability.rs` module:

```rust
use crate::observability::{ObservabilityProvider, ObservabilityConfig};

// Initialize observability
let config = ObservabilityConfig::default();
let observability = ObservabilityProvider::new(config).await?;

// Get tracer and metrics
let tracer = observability.tracer();
let metrics = observability.metrics();
```

### 2. Distributed Tracing

#### Automatic Instrumentation
- HTTP request/response tracing via middleware
- Database operation tracing
- External service call tracing
- Error and exception tracing

#### Manual Instrumentation
```rust
use crate::tracing_instrumentation::AuthFlowTracer;

// Create flow tracer
let mut tracer = AuthFlowTracer::new(observability);

// Start authentication flow
let mut flow_span = tracer.start_auth_flow("oauth_authorization_code").await?;

// Record success/failure
flow_span.record_success(user_id, session_id);
```

#### Trace Context Propagation
- Automatic trace context extraction from HTTP headers
- Context injection for outbound requests
- Cross-service correlation via trace and span IDs

### 3. Metrics Collection

#### Service-Level Metrics
- **Request Metrics**: Rate, duration, error rate
- **Authentication Metrics**: Attempts, failures, success rate
- **Security Metrics**: Rate limits, suspicious activity, violations
- **System Metrics**: Memory, CPU, database connections
- **Business Metrics**: Active sessions, registrations, policy evaluations

#### Custom Metrics Example
```rust
// Record authentication attempt
metrics.record_auth_attempt("oauth", true, Some("user123"));

// Record security event
metrics.record_security_event("failed_login", "medium", Some("192.168.1.1"));

// Record token operation
metrics.record_token_operation("issue", "access_token");
```

### 4. Structured Logging

#### Security Event Logging
```rust
use crate::trace_security_event;

trace_security_event!(
    warn,
    "authentication_failure",
    "Failed login attempt detected",
    "user_id" => user_id,
    "client_ip" => client_ip,
    "failure_reason" => "invalid_credentials"
);
```

#### Performance Logging
```rust
use crate::trace_performance;

trace_performance!(
    "token_validation",
    duration,
    "token_type" => "access_token",
    "user_id" => user_id
);
```

## Configuration

### Environment Variables

```bash
# Service identification
SERVICE_NAME=auth-service
SERVICE_VERSION=1.0.0
ENVIRONMENT=production

# OpenTelemetry configuration
OTLP_ENDPOINT=http://otel-collector.observability:4317
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.observability:4317
OTEL_RESOURCE_ATTRIBUTES="service.name=auth-service,service.version=1.0.0"

# Sampling configuration
OTEL_TRACES_SAMPLER=traceidratio
OTEL_TRACES_SAMPLER_ARG=0.1  # 10% sampling

# Batch configuration
OTEL_BSP_SCHEDULE_DELAY=5000
OTEL_BSP_MAX_EXPORT_BATCH_SIZE=512
OTEL_BSP_EXPORT_TIMEOUT=30000
```

### Application Configuration

```rust
ObservabilityConfig {
    service_name: "auth-service".to_string(),
    service_version: "1.0.0".to_string(),
    environment: "production".to_string(),
    otlp_endpoint: "http://otel-collector.observability:4317".to_string(),
    tracing_enabled: true,
    metrics_enabled: true,
    sampling_ratio: 0.1, // 10% sampling
    batch_timeout: Duration::from_secs(5),
    resource_attributes: HashMap::from([
        ("k8s.cluster.name".to_string(), "rust-security-cluster".to_string()),
        ("k8s.namespace.name".to_string(), "rust-security".to_string()),
    ]),
}
```

## Deployment

### 1. Deploy OpenTelemetry Collector

```bash
kubectl apply -f k8s/observability/opentelemetry-deployment.yaml
```

### 2. Configure Application

Update your application deployment to include observability:

```yaml
env:
- name: OTLP_ENDPOINT
  value: "http://otel-collector.observability:4317"
- name: OTEL_SERVICE_NAME
  value: "auth-service"
- name: OTEL_RESOURCE_ATTRIBUTES
  value: "service.name=auth-service,service.version=1.0.0,k8s.cluster.name=rust-security"
```

### 3. Deploy Grafana Dashboards

```bash
kubectl apply -f k8s/observability/grafana-tracing-dashboards.yaml
```

## Observability Features

### 1. Distributed Tracing

#### Authentication Flow Tracing
- Complete OAuth/OIDC flow tracking
- Token lifecycle management
- Cross-service dependency mapping
- Error propagation and root cause analysis

#### Key Trace Attributes
- `auth.flow_id`: Unique identifier for authentication flows
- `auth.flow_type`: Type of authentication (oauth, saml, etc.)
- `user.id`: User identifier
- `session.id`: Session identifier
- `client.ip`: Client IP address
- `security.threat_level`: Assessed threat level

### 2. Performance Monitoring

#### Response Time Tracking
- P50, P95, P99 latency percentiles
- Operation-specific performance metrics
- Database query performance
- External service call latency

#### Resource Utilization
- Memory usage tracking
- CPU utilization monitoring
- Database connection pool metrics
- Cache hit/miss rates

### 3. Security Observability

#### Security Event Tracking
- Failed authentication attempts
- Rate limit violations
- Suspicious activity detection
- Policy violation monitoring

#### Threat Intelligence
- IP-based threat assessment
- Behavioral anomaly detection
- Attack pattern recognition
- Compliance violation tracking

### 4. Business Metrics

#### User Activity
- Active user sessions
- Registration rates
- Login frequency patterns
- Feature usage statistics

#### System Health
- Service availability
- Error rates by endpoint
- Capacity utilization
- Performance regression detection

## Dashboards and Visualization

### 1. Auth Service Tracing Dashboard
- Authentication flow overview
- Response time percentiles
- Token operation metrics
- Security event monitoring

### 2. Distributed Tracing Overview
- Cross-service trace volume
- Service dependency mapping
- Critical path analysis
- Error propagation visualization

### 3. Security Tracing Dashboard
- Security events by severity
- Failed authentication timeline
- Suspicious activity mapping
- Policy violation tracking

### 4. Performance Tracing Dashboard
- Request latency heatmaps
- Database performance metrics
- Memory and resource usage
- Performance regression alerts

## Alerting and Monitoring

### 1. SLO-Based Alerting

#### Availability SLO (99.9%)
```promql
# Alert if availability drops below 99.9%
(
  sum(rate(http_requests_total{service="auth-service"}[5m])) -
  sum(rate(http_requests_total{service="auth-service",code=~"5.."}[5m]))
) / sum(rate(http_requests_total{service="auth-service"}[5m])) < 0.999
```

#### Latency SLO (P95 < 200ms)
```promql
# Alert if P95 latency exceeds 200ms
histogram_quantile(0.95,
  sum(rate(http_request_duration_seconds_bucket{service="auth-service"}[5m])) by (le)
) * 1000 > 200
```

### 2. Security Alerting

#### Authentication Failure Spike
```promql
# Alert on authentication failure spike
rate(auth_failures_total[5m]) > 5
```

#### Suspicious Activity Detection
```promql
# Alert on suspicious activity
rate(suspicious_activity_total[5m]) > 1
```

### 3. Performance Alerting

#### Memory Usage Alert
```promql
# Alert on high memory usage
memory_usage_bytes / 1024 / 1024 > 1000  # 1GB
```

#### Database Performance Alert
```promql
# Alert on slow database operations
histogram_quantile(0.95,
  sum(rate(database_operation_duration_seconds_bucket[5m])) by (le)
) > 0.1  # 100ms
```

## Best Practices

### 1. Trace Design

#### Span Naming
- Use descriptive, hierarchical names: `auth_flow_oauth_authorization_code`
- Include operation type: `db_query`, `http_request`, `token_validation`
- Avoid high-cardinality values in span names

#### Attribute Guidelines
- Use semantic conventions for standard attributes
- Include business context: user_id, tenant_id, operation_type
- Add security context: threat_level, client_ip, user_agent
- Limit attribute cardinality to prevent explosion

### 2. Sampling Strategy

#### Production Sampling
- Use head-based sampling for initial filtering
- Implement tail-based sampling for error traces
- Sample at 1-10% for high-traffic services
- Always sample error and security-related traces

#### Sampling Configuration
```yaml
# Probabilistic sampling
probabilistic_sampler:
  sampling_percentage: 10.0

# Always sample errors
tail_sampling:
  decision_wait: 10s
  policies:
    - name: error_sampling
      type: status_code
      status_code: {status_codes: [ERROR]}
```

### 3. Performance Optimization

#### Batch Configuration
- Configure appropriate batch sizes (512-1024 spans)
- Set reasonable export timeouts (5-30 seconds)
- Use compression for network efficiency

#### Resource Management
- Set memory limits for collectors
- Configure proper resource requests/limits
- Monitor collector performance metrics

### 4. Security Considerations

#### Data Privacy
- Avoid logging sensitive data in spans
- Implement data sanitization in processors
- Use attribute filtering for PII removal

#### Access Control
- Secure observability infrastructure
- Implement proper RBAC for dashboards
- Encrypt data in transit and at rest

## Troubleshooting

### Common Issues

#### High Cardinality Attributes
```bash
# Check for high cardinality
kubectl logs -n observability otel-collector | grep "high cardinality"

# Solution: Filter attributes in collector config
attributes:
  actions:
    - key: user_id
      action: delete  # Remove high cardinality attributes
```

#### Sampling Issues
```bash
# Check sampling rates
kubectl logs -n observability otel-collector | grep "sampling"

# Verify trace volume
curl http://otel-collector.observability:8889/metrics | grep traces_received
```

#### Performance Problems
```bash
# Check collector resource usage
kubectl top pods -n observability

# Monitor export latency
curl http://otel-collector.observability:8889/metrics | grep export_latency
```

### Debugging Tools

#### Trace Debugging
```bash
# Export debug traces
OTEL_LOG_LEVEL=debug ./auth-service

# Query specific traces
curl "http://jaeger.observability:16686/api/traces?service=auth-service&operation=auth_flow_oauth"
```

#### Metrics Debugging
```bash
# Check metric export
curl http://otel-collector.observability:8889/metrics

# Verify metric ingestion
kubectl logs -n monitoring prometheus | grep "auth-service"
```

## Integration Examples

### 1. HTTP Request Tracing

```rust
#[tracing::instrument(skip(observability))]
async fn handle_login_request(
    observability: Arc<ObservabilityProvider>,
    request: LoginRequest,
) -> Result<LoginResponse, SecurityError> {
    let mut tracer = AuthFlowTracer::new(observability)
        .with_security_context(extract_security_context(&request))
        .with_user_context(extract_user_context(&request));

    let mut flow_span = tracer.start_auth_flow("password_login").await?;
    
    // Token validation
    let mut token_span = tracer.trace_token_validation("password", None).await?;
    let validation_result = validate_credentials(&request.credentials).await;
    
    match validation_result {
        Ok(user) => {
            token_span.record_success(&user.id).await;
            flow_span.record_success(&user.id, &user.session_id);
            Ok(create_login_response(user))
        }
        Err(e) => {
            token_span.record_failure(&e).await;
            flow_span.record_failure(&e, "credential_validation_failed");
            
            tracer.record_security_event(
                "authentication_failure",
                "medium",
                "Invalid credentials provided",
                Some(HashMap::from([
                    ("failure_type".to_string(), "invalid_credentials".to_string()),
                ]))
            ).await;
            
            Err(e)
        }
    }
}
```

### 2. Database Operation Tracing

```rust
#[tracing::instrument(skip(tracer))]
async fn get_user_by_id(
    tracer: &mut AuthFlowTracer,
    user_id: &str,
) -> SecurityResult<User> {
    let mut db_span = tracer.trace_database_operation("SELECT", "users").await?;
    
    let start = Instant::now();
    let result = database::users::find_by_id(user_id).await;
    let duration = start.elapsed();
    
    match result {
        Ok(Some(user)) => {
            db_span.record_success(Some(1)).await;
            trace_performance!("db_query_user", duration, "operation" => "find_by_id");
            Ok(user)
        }
        Ok(None) => {
            db_span.record_success(Some(0)).await;
            Err(SecurityError::NotFound)
        }
        Err(e) => {
            db_span.record_failure(&SecurityError::Internal);
            error!("Database query failed: {}", e);
            Err(SecurityError::Internal)
        }
    }
}
```

This comprehensive OpenTelemetry implementation provides complete observability for the Rust Security Platform, enabling detailed monitoring, debugging, and performance optimization in production environments.