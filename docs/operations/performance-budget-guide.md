# Performance Budget and Regression Detection Guide

## Overview

This guide covers the comprehensive performance budget system and automated regression detection for the Rust Security Platform. It ensures consistent performance standards, automatically detects regressions, and maintains service quality through continuous monitoring and testing.

## Performance Budget Framework

### Architecture Components

```
┌─────────────────────────────────────────────────────────────┐
│                Performance Budget System                     │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  │  Budget Monitor │    │ Load Test Auto  │    │ Regression Det  │
│  │                 │    │                 │    │                 │
│  │ • Metric Collect│    │ • K6 Tests      │    │ • Baseline Comp │
│  │ • Budget Check  │    │ • Auto Schedule │    │ • Trend Analysis│
│  │ • Compliance    │    │ • Result Analyze│    │ • Alert System │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘
│           │                       │                       │
│           └───────────────────────┼───────────────────────┘
│                                   │
│  ┌─────────────────────────────────────────────────────────────┐
│  │                 Monitoring & Alerting                      │
│  │                                                             │
│  │ • Prometheus Metrics  • Grafana Dashboards                │
│  │ • Alert Rules         • Webhook Notifications             │
│  │ • SLO Tracking        • Performance Reports               │
│  └─────────────────────────────────────────────────────────────┘
└─────────────────────────────────────────────────────────────┘
```

### Key Features

1. **Automated Performance Monitoring**: Continuous tracking of key performance metrics
2. **Budget Compliance Checking**: Real-time validation against performance budgets
3. **Regression Detection**: Statistical analysis to identify performance degradations
4. **Load Testing Automation**: Scheduled and on-demand performance testing
5. **Comprehensive Alerting**: Multi-level alerting for budget violations and regressions
6. **Performance Reporting**: Detailed reports and dashboards for analysis

## Performance Budgets

### Auth Service Budget

```json
{
  "auth-service": {
    "response_time": {
      "p50": {
        "budget_ms": 100,
        "warning_threshold": 0.8,
        "critical_threshold": 1.0,
        "regression_threshold": 0.15
      },
      "p95": {
        "budget_ms": 200,
        "warning_threshold": 0.8,
        "critical_threshold": 1.0,
        "regression_threshold": 0.15
      },
      "p99": {
        "budget_ms": 500,
        "warning_threshold": 0.8,
        "critical_threshold": 1.0,
        "regression_threshold": 0.20
      }
    },
    "throughput": {
      "min_rps": 1000,
      "warning_threshold": 0.9,
      "critical_threshold": 0.8,
      "regression_threshold": 0.10
    },
    "error_rate": {
      "max_percentage": 1.0,
      "warning_threshold": 0.5,
      "critical_threshold": 0.8,
      "regression_threshold": 0.05
    }
  }
}
```

### Policy Service Budget

```json
{
  "policy-service": {
    "response_time": {
      "p95": {
        "budget_ms": 50,
        "warning_threshold": 0.8,
        "critical_threshold": 1.0,
        "regression_threshold": 0.15
      }
    },
    "throughput": {
      "min_decisions_per_sec": 5000,
      "warning_threshold": 0.9,
      "critical_threshold": 0.8,
      "regression_threshold": 0.10
    },
    "cache_hit_rate": {
      "min_percentage": 80,
      "warning_threshold": 0.9,
      "critical_threshold": 0.8,
      "regression_threshold": 0.05
    }
  }
}
```

### Infrastructure Budget

```json
{
  "infrastructure": {
    "cluster_cpu": {
      "max_percentage": 80,
      "warning_threshold": 0.8,
      "critical_threshold": 0.9,
      "regression_threshold": 0.10
    },
    "cluster_memory": {
      "max_percentage": 85,
      "warning_threshold": 0.8,
      "critical_threshold": 0.9,
      "regression_threshold": 0.10
    },
    "node_availability": {
      "min_percentage": 99,
      "warning_threshold": 0.99,
      "critical_threshold": 0.95,
      "regression_threshold": 0.01
    }
  }
}
```

## Performance Budget Monitoring

### Automated Monitoring Setup

The performance budget monitoring system runs automatically:

```bash
# Deploy monitoring infrastructure
kubectl apply -f k8s/monitoring/performance-monitoring.yaml

# Verify deployment
kubectl get cronjob performance-budget-monitor -n rust-security
kubectl get pods -l app.kubernetes.io/name=performance-monitor -n rust-security
```

### Manual Monitoring Commands

```bash
# Run complete performance monitoring
./scripts/performance/performance-budget-monitor.sh monitor

# Monitor specific service
./scripts/performance/performance-budget-monitor.sh collect auth-service

# Check budget compliance
./scripts/performance/performance-budget-monitor.sh check auth-service metrics-file.json

# Detect regressions
./scripts/performance/performance-budget-monitor.sh regression auth-service metrics-file.json

# Generate performance report
./scripts/performance/performance-budget-monitor.sh report
```

### Monitoring Frequency

- **Real-time**: Prometheus metrics collection (15s intervals)
- **Budget Checks**: Every 5 minutes via CronJob
- **Regression Analysis**: Every 15 minutes with 7-day baseline
- **Load Testing**: Daily automated tests + on-demand
- **Reporting**: Weekly comprehensive reports

## Regression Detection

### Statistical Methods

The system uses multiple approaches for regression detection:

1. **Z-Score Analysis**: Detects statistical anomalies (>2 standard deviations)
2. **Percentage Change**: Monitors relative changes against baselines
3. **Trend Analysis**: Identifies negative performance trends over time
4. **Confidence Intervals**: Uses 95% confidence for regression alerts

### Baseline Management

```bash
# Create initial baseline
./scripts/performance/performance-budget-monitor.sh baseline auth-service metrics-file.json

# Update baseline (weekly automated process)
# Baselines are automatically updated if stable for 7 days with <5% variance
```

### Regression Alert Thresholds

| Metric Type | Warning Threshold | Critical Threshold |
|-------------|-------------------|-------------------|
| Response Time | 15% increase | 25% increase |
| Throughput | 10% decrease | 20% decrease |
| Error Rate | 5% increase | 10% increase |
| Resource Usage | 10% increase | 20% increase |

## Load Testing Automation

### Test Profiles

#### Smoke Tests
- **Purpose**: Quick validation after deployments
- **Virtual Users**: 10-20
- **Duration**: 2 minutes
- **Frequency**: After every deployment

#### Baseline Tests
- **Purpose**: Standard performance validation
- **Virtual Users**: 100-200
- **Duration**: 10 minutes
- **Frequency**: Daily scheduled tests

#### Stress Tests
- **Purpose**: Validate performance under high load
- **Virtual Users**: 500-1000
- **Duration**: 15 minutes
- **Frequency**: Weekly scheduled tests

#### Spike Tests
- **Purpose**: Test sudden load increases
- **Virtual Users**: 1000-2000 (rapid ramp-up)
- **Duration**: 5 minutes
- **Frequency**: Monthly scheduled tests

#### Endurance Tests
- **Purpose**: Long-duration performance validation
- **Virtual Users**: 200
- **Duration**: 60 minutes
- **Frequency**: Monthly scheduled tests

### Running Load Tests

```bash
# Create test configurations
./scripts/performance/load-test-automation.sh create-configs
./scripts/performance/load-test-automation.sh create-scripts

# Run specific test
./scripts/performance/load-test-automation.sh run-test auth-service baseline

# Run complete test suite
./scripts/performance/load-test-automation.sh run-suite stress

# Schedule continuous testing
./scripts/performance/load-test-automation.sh schedule "0 2 * * *"
```

### K6 Test Scripts

The system includes comprehensive K6 scripts for:

- **Authentication flows**: Login, token refresh, logout
- **Authorization decisions**: Policy evaluation, cache testing
- **Mixed workloads**: Realistic user behavior patterns
- **Error scenarios**: Testing system resilience

## Alerting and Notifications

### Alert Severity Levels

#### Warning Alerts
- **Trigger**: 80% of budget threshold reached
- **Response Time**: 15 minutes
- **Action**: Monitor and investigate
- **Notification**: Slack, email

#### Critical Alerts
- **Trigger**: 100% of budget threshold exceeded
- **Response Time**: 5 minutes
- **Action**: Immediate investigation required
- **Notification**: PagerDuty, SMS, phone

#### Regression Alerts
- **Trigger**: Statistical regression detected
- **Response Time**: 10 minutes
- **Action**: Analyze recent changes
- **Notification**: Slack, email to team

### Alert Rules

```yaml
# Example Alert Rule
- alert: AuthServiceResponseTimeBudgetViolation
  expr: |
    histogram_quantile(0.95, 
      sum(rate(http_request_duration_seconds_bucket{service="auth-service"}[5m])) by (le)
    ) * 1000 > 200
  for: 2m
  labels:
    severity: warning
    service: auth-service
    budget_type: response_time
  annotations:
    summary: "Auth Service P95 response time budget violation"
    description: "Auth Service P95 response time is {{ $value }}ms, exceeding budget of 200ms"
    runbook_url: "https://docs.example.com/runbooks/performance-budget-violation"
```

## Performance Dashboards

### Grafana Dashboard Features

1. **Budget Compliance Overview**
   - Service availability status
   - Budget violation alerts
   - Performance trend graphs

2. **Response Time Monitoring**
   - P50, P95, P99 latency trends
   - Budget threshold lines
   - Regression indicators

3. **Throughput Analysis**
   - Requests per second
   - Decisions per second
   - Capacity utilization

4. **Error Rate Tracking**
   - Service error rates
   - Budget compliance
   - Error trend analysis

5. **Resource Utilization**
   - CPU and memory usage
   - Budget thresholds
   - Scaling indicators

6. **Regression Detection**
   - Active regression alerts
   - Performance baselines
   - Trend comparisons

### Dashboard Access

```bash
# Get Grafana URL
kubectl get ingress grafana -n monitoring

# Default credentials (change in production)
# Username: admin
# Password: [from secret]
kubectl get secret grafana-admin-password -n monitoring -o jsonpath='{.data.password}' | base64 -d
```

## Performance Budget Integration

### CI/CD Integration

```yaml
# Example GitHub Actions workflow step
- name: Performance Budget Check
  run: |
    # Deploy to staging
    helm upgrade --install auth-service-staging ./helm/auth-service
    
    # Wait for deployment
    kubectl rollout status deployment/auth-service -n staging
    
    # Run smoke test
    ./scripts/performance/load-test-automation.sh run-test auth-service smoke
    
    # Check performance budget
    ./scripts/performance/performance-budget-monitor.sh monitor
    
    # Fail build if budget violated
    if [ $? -ne 0 ]; then
      echo "Performance budget violation detected"
      exit 1
    fi
```

### Deployment Gates

Performance budgets can serve as deployment gates:

1. **Pre-deployment**: Validate current performance
2. **Post-deployment**: Confirm no regression introduced
3. **Canary**: Monitor performance during gradual rollout
4. **Rollback**: Automatic rollback on critical violations

## Troubleshooting Performance Issues

### Common Performance Problems

#### High Response Time
```bash
# Investigate high latency
kubectl top pods -n rust-security --sort-by=cpu
kubectl logs -l app=auth-service --tail=100

# Check resource constraints
kubectl describe pods -l app=auth-service | grep -A 5 "Limits\|Requests"

# Analyze slow queries (if applicable)
./scripts/performance/performance-budget-monitor.sh collect auth-service 1m
```

#### Low Throughput
```bash
# Check HPA status
kubectl get hpa -n rust-security

# Verify resource availability
kubectl describe nodes | grep -A 5 "Allocated resources"

# Check service mesh configuration
kubectl get virtualservice -n rust-security
```

#### High Error Rate
```bash
# Check service logs
kubectl logs -l app=auth-service --since=1h | grep ERROR

# Verify service dependencies
kubectl get endpoints -n rust-security

# Check external service connectivity
kubectl exec -it auth-service-xxx -- curl -I https://external-service.com
```

### Performance Optimization Strategies

#### Response Time Optimization
1. **Database Query Optimization**: Analyze and optimize slow queries
2. **Caching Strategy**: Implement appropriate caching layers
3. **Connection Pooling**: Optimize database and external service connections
4. **Code Profiling**: Use profiling tools to identify bottlenecks

#### Throughput Optimization
1. **Horizontal Scaling**: Increase pod replicas
2. **Resource Tuning**: Adjust CPU and memory allocations
3. **Load Balancing**: Optimize traffic distribution
4. **Asynchronous Processing**: Use async patterns for I/O operations

#### Resource Optimization
1. **Right-sizing**: Adjust resource requests and limits
2. **Vertical Scaling**: Use VPA for automatic resource tuning
3. **Node Optimization**: Ensure appropriate node types and sizes
4. **Cluster Autoscaling**: Enable automatic node scaling

## Best Practices

### Performance Budget Definition

1. **Business-Aligned**: Budgets should reflect business requirements
2. **Realistic**: Based on actual capacity and user expectations
3. **Measurable**: Use metrics that can be reliably collected
4. **Actionable**: Include clear thresholds for alerts and actions

### Monitoring and Alerting

1. **Layered Approach**: Multiple alert levels (warning, critical)
2. **Context-Aware**: Include relevant metadata in alerts
3. **Actionable Alerts**: Each alert should have a clear response
4. **Alert Fatigue Prevention**: Tune thresholds to avoid noise

### Testing Strategy

1. **Regular Testing**: Automated daily tests with manual deep dives
2. **Realistic Scenarios**: Test patterns that match production usage
3. **Environment Parity**: Ensure test environments mirror production
4. **Baseline Management**: Maintain stable baselines for comparison

### Regression Detection

1. **Statistical Rigor**: Use appropriate statistical methods
2. **Multiple Metrics**: Don't rely on single indicators
3. **Context Consideration**: Account for external factors
4. **Rapid Response**: Quick detection and notification systems

## Compliance and Reporting

### Performance SLA Reporting

Generate monthly reports showing:
- Budget compliance percentages
- Performance trends and improvements
- Regression incidents and resolutions
- Capacity planning recommendations

### Audit Requirements

Maintain records for:
- Performance budget definitions and changes
- Monitoring configuration and alert history
- Load test results and analysis
- Incident response and resolution

This comprehensive performance budget system ensures the Rust Security Platform maintains optimal performance while automatically detecting and alerting on any degradations, supporting both operational excellence and business continuity.