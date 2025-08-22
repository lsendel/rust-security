# Enhanced Observability System

This document describes the comprehensive observability system implemented for the auth-service, providing enterprise-grade monitoring, alerting, and performance tracking.

## Features

### 1. Comprehensive Metrics Collection
- **Request Metrics**: HTTP request rates, latency, error rates with detailed labels
- **Authentication Metrics**: Login attempts, failures, MFA usage, token operations
- **Security Metrics**: Security events, rate limit violations, suspicious activities
- **Business Metrics**: User registrations, session counts, policy evaluations
- **System Metrics**: Database connections, memory usage, performance profiles

### 2. Service Level Indicators/Objectives (SLI/SLO)
- **Availability Monitoring**: Target 99.9% uptime with automatic violation tracking
- **Latency Monitoring**: P95 latency targeting <100ms with alert thresholds
- **Error Rate Monitoring**: Target <0.1% error rate with trend analysis
- **Real-time SLO Dashboard**: Live status updates and historical trends

### 3. Distributed Tracing
- **OpenTelemetry Integration**: OTLP-compliant tracing with correlation IDs
- **Security Context**: User ID, session ID, client IP tracking across spans
- **Performance Profiling**: Automatic bottleneck detection and analysis
- **Cross-Service Correlation**: Request tracing across microservice boundaries

### 4. Health Monitoring
- **Component Health Checks**: Database, Redis, external services monitoring
- **Automated Recovery**: Circuit breaker patterns and degraded mode detection
- **Health Endpoints**: RESTful health check APIs for orchestrators
- **Dependency Monitoring**: Real-time status of critical service dependencies

### 5. Alerting System
- **Multi-Level Alerts**: Critical, Warning, and Info severity levels
- **Smart Thresholds**: Dynamic thresholds based on historical patterns
- **Alert Resolution**: Automatic resolution tracking and notification
- **Integration Ready**: Compatible with PagerDuty, Slack, and email notifications

### 6. Performance Monitoring
- **Operation Profiling**: Per-operation latency and error rate tracking
- **Resource Monitoring**: Memory, CPU, and I/O utilization tracking
- **Bottleneck Detection**: Automatic identification of performance issues
- **Trend Analysis**: Historical performance data and regression detection

## Configuration

### Environment Variables

```bash
# Service Configuration
SERVICE_NAME=auth-service
ENVIRONMENT=production

# SLI/SLO Targets
SLI_AVAILABILITY_TARGET=99.9
SLI_LATENCY_TARGET_MS=100
SLI_ERROR_RATE_TARGET=0.1
SLI_MEASUREMENT_WINDOW_MINUTES=5

# Monitoring Intervals
HEALTH_CHECK_INTERVAL=30
SLO_CALCULATION_INTERVAL=60
METRICS_RETENTION_HOURS=24

# Features
ENABLE_PROFILING=true
ENABLE_ALERTING=true
ENABLE_GRAFANA_EXPORT=true

# Dashboard Configuration
DASHBOARD_REFRESH_INTERVAL=30
CUSTOM_DASHBOARD_PANELS=authentication_flow,token_operations,security_events
```

### OpenTelemetry Configuration

```bash
# OTLP Endpoint (e.g., Jaeger, Zipkin)
OTLP_ENDPOINT=http://localhost:4317

# Tracing Configuration
RUST_LOG=info,auth_service=debug
OTEL_SERVICE_NAME=auth-service
OTEL_SERVICE_VERSION=1.0.0
```

## API Endpoints

### Health and Status
- `GET /health` - Service health check with component status
- `GET /observability/slo` - Current SLO status and metrics
- `GET /observability/profiles` - Performance profiles by operation
- `GET /observability/alerts` - Active alerts and their status

### Metrics Export
- `GET /metrics` - Prometheus-compatible metrics endpoint
- `GET /observability/dashboard` - Grafana dashboard configuration export

## Integration Examples

### Application Code Integration

```rust
use crate::observability_init::ObservabilitySystem;

// Initialize observability system
let observability = ObservabilitySystem::initialize().await?;

// Record authentication event
observability.record_auth_event(
    "password",           // method
    true,                 // success
    Some("user123"),      // user_id
    Duration::from_millis(45), // duration
    Some("192.168.1.1"),  // client_ip
).await;

// Record token operation
observability.record_token_operation(
    "issue",              // operation
    "access_token",       // token_type
    true,                 // success
    Duration::from_millis(12), // duration
).await;
```

### Middleware Integration

```rust
use crate::enhanced_observability::observability_middleware;

let app = Router::new()
    .route("/api/auth", post(authenticate))
    .layer(axum::middleware::from_fn(observability_middleware));
```

## Grafana Dashboard

The system automatically exports Grafana dashboard configurations at `/observability/dashboard`. Key panels include:

1. **SLO Overview**: Availability, latency, and error rate trends
2. **Authentication Flow**: Login success/failure rates and patterns
3. **Token Operations**: Issuance, validation, and revocation metrics
4. **Security Events**: Real-time security incident monitoring
5. **Performance Profiles**: Operation-level performance analysis
6. **System Health**: Component health and dependency status

## Alerting Rules

### Critical Alerts
- **Service Unavailable**: Overall health status is Unhealthy
- **SLO Violation**: Availability drops below 99.9%
- **Security Incident**: Critical security events detected
- **High Error Rate**: Error rate exceeds 1.0%

### Warning Alerts
- **Degraded Performance**: P95 latency exceeds 200ms
- **High Authentication Failures**: Auth failure rate exceeds 5%
- **Resource Pressure**: Memory usage exceeds 80%
- **External Dependency Issues**: External service health degraded

## Monitoring Best Practices

1. **Start with SLOs**: Define clear service level objectives based on user expectations
2. **Monitor User Experience**: Focus on metrics that impact end users
3. **Use Structured Logging**: Include correlation IDs and security context
4. **Alert on Symptoms**: Alert on user-facing issues, not internal metrics
5. **Test Your Monitoring**: Regularly test alert channels and runbooks

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │    │  Observability  │    │   External      │
│     Layer       │───▶│     System      │───▶│   Monitoring    │
│                 │    │                 │    │    Systems      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       ▼                       │
         │              ┌─────────────────┐              │
         │              │    Enhanced     │              │
         └─────────────▶│  Observability  │◀─────────────┘
                        │   Coordinator   │
                        └─────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
           ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
           │   Metrics   │ │   Tracing   │ │   Logging   │
           │ Collection  │ │   System    │ │   System    │
           └─────────────┘ └─────────────┘ └─────────────┘
```

## Security Considerations

- **Metric Data Privacy**: Sensitive data is never included in metrics labels
- **Access Control**: Observability endpoints are protected by authentication
- **Data Retention**: Automatic cleanup of old metrics and trace data
- **Audit Logging**: All observability system access is logged for compliance

## Troubleshooting

### Common Issues

1. **Missing Metrics**: Check that the metrics registry is properly initialized
2. **Trace Not Appearing**: Verify OTLP endpoint configuration and connectivity
3. **High Memory Usage**: Reduce metrics retention period or sampling rate
4. **Alert Fatigue**: Tune alert thresholds based on historical data

### Debug Commands

```bash
# Check health status
curl http://localhost:8080/health | jq

# View current SLO status
curl http://localhost:8080/observability/slo | jq

# Export metrics in Prometheus format
curl http://localhost:8080/metrics
```

This observability system provides comprehensive visibility into the auth-service's performance, security, and operational health, enabling proactive monitoring and rapid incident response.