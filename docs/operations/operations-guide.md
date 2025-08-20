# Operations Guide

## Overview

This comprehensive operations guide provides everything needed to successfully operate the Rust Security Platform in production. It covers operational processes, best practices, tooling, and procedures for maintaining a reliable, secure, and performant service.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Service Operations](#service-operations)
3. [Monitoring and Observability](#monitoring-and-observability)
4. [Incident Management](#incident-management)
5. [Change Management](#change-management)
6. [Security Operations](#security-operations)
7. [Performance Management](#performance-management)
8. [Disaster Recovery](#disaster-recovery)
9. [Operational Excellence](#operational-excellence)

## Getting Started

### Prerequisites

Before operating the Rust Security Platform, ensure you have:

#### Required Access
- Kubernetes cluster admin access
- Prometheus/Grafana monitoring access
- CI/CD pipeline access
- Secret management system access
- Log aggregation system access

#### Required Tools
```bash
# Install required CLI tools
# Kubernetes
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"

# Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Prometheus CLI
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz

# Grafana CLI
curl -L https://grafana.com/api/dashboards/12927/revisions/2/download | jq . > dashboard.json
```

#### Environment Setup
```bash
# Set up environment variables
export NAMESPACE="rust-security"
export CLUSTER_NAME="rust-security-prod"
export MONITORING_NAMESPACE="monitoring"

# Configure kubectl context
kubectl config use-context $CLUSTER_NAME

# Verify access
kubectl get nodes
kubectl get pods -n $NAMESPACE
```

### Initial Health Check

Run this comprehensive health check before starting operations:

```bash
#!/bin/bash
# health-check.sh - Comprehensive system health verification

set -e

NAMESPACE="rust-security"
MONITORING_NS="monitoring"

echo "=== Rust Security Platform Health Check ==="
echo "Timestamp: $(date)"
echo "Cluster: $(kubectl config current-context)"
echo

# Check namespace
echo "1. Checking namespace..."
kubectl get namespace $NAMESPACE || exit 1
echo "✓ Namespace exists"

# Check services
echo
echo "2. Checking services..."
SERVICES=("auth-service" "policy-service" "redis")
for service in "${SERVICES[@]}"; do
    if kubectl get service $service -n $NAMESPACE >/dev/null 2>&1; then
        echo "✓ $service service exists"
    else
        echo "✗ $service service missing"
        exit 1
    fi
done

# Check pod health
echo
echo "3. Checking pod health..."
READY_PODS=$(kubectl get pods -n $NAMESPACE --no-headers | grep -c " 1/1.*Running")
TOTAL_PODS=$(kubectl get pods -n $NAMESPACE --no-headers | wc -l)
echo "Ready pods: $READY_PODS/$TOTAL_PODS"

if [ $READY_PODS -lt $TOTAL_PODS ]; then
    echo "✗ Not all pods are ready"
    kubectl get pods -n $NAMESPACE
    exit 1
fi
echo "✓ All pods are ready"

# Check ingress
echo
echo "4. Checking ingress..."
if kubectl get ingress -n $NAMESPACE >/dev/null 2>&1; then
    echo "✓ Ingress configured"
else
    echo "⚠ No ingress found"
fi

# Check external connectivity
echo
echo "5. Checking external connectivity..."
AUTH_URL=$(kubectl get ingress auth-service-ingress -n $NAMESPACE -o jsonpath='{.spec.rules[0].host}')
if curl -s -o /dev/null -w "%{http_code}" https://$AUTH_URL/health | grep -q "200"; then
    echo "✓ External connectivity working"
else
    echo "✗ External connectivity failed"
    exit 1
fi

# Check monitoring
echo
echo "6. Checking monitoring..."
if kubectl get pods -n $MONITORING_NS | grep -q prometheus; then
    echo "✓ Prometheus running"
else
    echo "✗ Prometheus not found"
fi

if kubectl get pods -n $MONITORING_NS | grep -q grafana; then
    echo "✓ Grafana running"
else
    echo "✗ Grafana not found"
fi

# Check metrics
echo
echo "7. Checking metrics..."
PROM_URL="http://prometheus.monitoring.svc.cluster.local:9090"
kubectl run metrics-check --rm -i --tty --image=curlimages/curl -- \
    curl -s "$PROM_URL/api/v1/query?query=up{job=\"kubernetes-pods\"}" | \
    grep -q '"status":"success"' && echo "✓ Metrics available" || echo "✗ Metrics unavailable"

echo
echo "=== Health Check Complete ==="
```

## Service Operations

### Service Lifecycle Management

#### Startup Sequence
1. **Infrastructure dependencies** (Redis, monitoring)
2. **Policy Service** (authorization engine)
3. **Auth Service** (authentication service)
4. **Load balancer and ingress** (traffic routing)

```bash
# Controlled startup script
#!/bin/bash
startup_service() {
    local service=$1
    local namespace=$2
    local timeout=${3:-300}
    
    echo "Starting $service..."
    kubectl scale deployment $service --replicas=3 -n $namespace
    
    echo "Waiting for $service to be ready..."
    kubectl wait --for=condition=available --timeout=${timeout}s deployment/$service -n $namespace
    
    echo "Verifying $service health..."
    kubectl get pods -l app=$service -n $namespace
}

# Start services in order
startup_service "redis" "$NAMESPACE" 60
startup_service "policy-service" "$NAMESPACE" 120
startup_service "auth-service" "$NAMESPACE" 120

echo "Startup complete!"
```

#### Shutdown Sequence
1. **Stop accepting new traffic** (ingress/load balancer)
2. **Drain existing connections** (graceful shutdown)
3. **Stop application services** (auth, policy)
4. **Stop infrastructure services** (Redis, monitoring)

```bash
# Graceful shutdown script
#!/bin/bash
shutdown_service() {
    local service=$1
    local namespace=$2
    
    echo "Stopping traffic to $service..."
    kubectl patch service $service -p='{"spec":{"selector":{"shutdown":"true"}}}' -n $namespace
    
    echo "Waiting for connections to drain..."
    sleep 30
    
    echo "Scaling down $service..."
    kubectl scale deployment $service --replicas=0 -n $namespace
    
    echo "Waiting for pods to terminate..."
    kubectl wait --for=delete pod -l app=$service --timeout=120s -n $namespace
}

# Shutdown in reverse order
shutdown_service "auth-service" "$NAMESPACE"
shutdown_service "policy-service" "$NAMESPACE"
shutdown_service "redis" "$NAMESPACE"

echo "Shutdown complete!"
```

### Configuration Management

#### Configuration Validation
```bash
# validate-config.sh - Validate configuration before deployment
#!/bin/bash

CONFIG_DIR="k8s/config"
SCHEMA_DIR="schemas"

echo "Validating configuration files..."

# Validate Kubernetes manifests
for file in $CONFIG_DIR/*.yaml; do
    echo "Validating $file..."
    kubectl apply --dry-run=client -f "$file" || exit 1
done

# Validate Helm values
helm template auth-service helm/auth-service \
    --values helm/auth-service/values.yaml \
    --dry-run || exit 1

echo "✓ All configurations valid"
```

#### Configuration Deployment
```bash
# deploy-config.sh - Deploy configuration changes
#!/bin/bash

CONFIG_VERSION=$1
if [[ -z "$CONFIG_VERSION" ]]; then
    echo "Usage: $0 <config-version>"
    exit 1
fi

echo "Deploying configuration version: $CONFIG_VERSION"

# Backup current configuration
kubectl get configmaps -n $NAMESPACE -o yaml > "backups/configmaps-$(date +%Y%m%d-%H%M%S).yaml"

# Apply new configuration
kubectl apply -f "k8s/config/v$CONFIG_VERSION/"

# Restart affected services
kubectl rollout restart deployment/auth-service -n $NAMESPACE
kubectl rollout restart deployment/policy-service -n $NAMESPACE

# Wait for rollout to complete
kubectl rollout status deployment/auth-service -n $NAMESPACE
kubectl rollout status deployment/policy-service -n $NAMESPACE

echo "Configuration deployment complete!"
```

## Monitoring and Observability

### Key Performance Indicators (KPIs)

#### Service Level Indicators
- **Availability**: Percentage of successful requests
- **Latency**: Response time percentiles (P50, P95, P99)
- **Throughput**: Requests per second
- **Error Rate**: Percentage of failed requests

#### Business Metrics
- **Authentication Success Rate**: Successful logins vs attempts
- **Authorization Accuracy**: Correct authorization decisions
- **User Activity**: Active users and session patterns
- **API Usage**: Endpoint usage patterns and trends

### Monitoring Stack

#### Prometheus Configuration
```yaml
# prometheus-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
    
    rule_files:
      - "/etc/prometheus/rules/*.yml"
    
    scrape_configs:
      - job_name: 'kubernetes-pods'
        kubernetes_sd_configs:
        - role: pod
        relabel_configs:
        - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
          action: keep
          regex: true
        - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
          action: replace
          target_label: __metrics_path__
          regex: (.+)
        - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
          action: replace
          regex: ([^:]+)(?::\d+)?;(\d+)
          replacement: $1:$2
          target_label: __address__
      
      - job_name: 'auth-service'
        static_configs:
        - targets: ['auth-service:8080']
        metrics_path: /metrics
        scrape_interval: 10s
      
      - job_name: 'policy-service'
        static_configs:
        - targets: ['policy-service:8080']
        metrics_path: /metrics
        scrape_interval: 10s
```

#### Grafana Dashboards
```json
{
  "dashboard": {
    "id": null,
    "title": "Rust Security Platform",
    "tags": ["rust-security"],
    "timezone": "browser",
    "panels": [
      {
        "title": "Service Availability",
        "type": "stat",
        "targets": [
          {
            "expr": "avg(up{job=\"auth-service\"}) * 100",
            "legendFormat": "Auth Service"
          },
          {
            "expr": "avg(up{job=\"policy-service\"}) * 100",
            "legendFormat": "Policy Service"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percent",
            "min": 0,
            "max": 100,
            "thresholds": {
              "steps": [
                {"color": "red", "value": 0},
                {"color": "yellow", "value": 95},
                {"color": "green", "value": 99}
              ]
            }
          }
        }
      },
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "sum(rate(http_requests_total[5m])) by (service)",
            "legendFormat": "{{service}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, service))",
            "legendFormat": "P95 {{service}}"
          },
          {
            "expr": "histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, service))",
            "legendFormat": "P99 {{service}}"
          }
        ]
      }
    ]
  }
}
```

### Alerting Rules

#### Critical Alerts
```yaml
# critical-alerts.yml
groups:
  - name: critical
    rules:
      - alert: ServiceDown
        expr: up{job=~"auth-service|policy-service"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service {{ $labels.job }} is down"
          description: "Service {{ $labels.job }} has been down for more than 1 minute"
      
      - alert: HighErrorRate
        expr: rate(http_requests_total{code=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | humanizePercentage }} for {{ $labels.service }}"
      
      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High latency detected"
          description: "95th percentile latency is {{ $value }}s for {{ $labels.service }}"
```

## Incident Management

### Incident Classification

#### Severity Matrix
| Impact | Low | Medium | High |
|--------|-----|--------|------|
| **Low** | P4 | P3 | P2 |
| **Medium** | P3 | P2 | P1 |
| **High** | P2 | P1 | P0 |

Where:
- **P0**: Complete outage, security breach
- **P1**: Major functionality impacted
- **P2**: Some functionality impacted
- **P3**: Minor issues
- **P4**: Cosmetic issues

### Incident Response Process

#### Incident Commander Role
The Incident Commander (IC) is responsible for:
- Overall incident coordination
- Communication with stakeholders
- Decision making and escalation
- Post-incident review coordination

#### Response Team Structure
```
Incident Commander
├── Technical Lead (diagnosis and resolution)
├── Communications Lead (stakeholder updates)
├── Customer Success (user impact assessment)
└── Security Lead (if security incident)
```

#### Response Timeline
```
0-5 min:   Initial assessment and team formation
5-15 min:  Problem diagnosis and immediate mitigation
15-60 min: Root cause analysis and resolution
1-4 hours: Validation and monitoring
24 hours:  Post-incident review
```

### Communication Templates

#### Incident Notification
```
🚨 INCIDENT ALERT 🚨

Incident ID: INC-$(date +%Y%m%d-%H%M%S)
Severity: P1
Service: Auth Service
Status: Investigating

Description: High error rates detected on authentication endpoint

Impact: Users unable to log in
ETA: Under investigation

Incident Commander: @john.doe
Next Update: 15 minutes

War Room: #incident-$(date +%Y%m%d)
```

#### Status Update
```
📈 INCIDENT UPDATE 📈

Incident ID: INC-20240820-143000
Status: Identified → Mitigating

Update: Root cause identified as Redis connection pool exhaustion. 
Implementing connection pool scaling.

Actions Taken:
✅ Scaled Redis cluster
✅ Increased connection pool size
🔄 Rolling restart of auth service

ETA: 10 minutes
Next Update: 10 minutes
```

#### Resolution Notification
```
✅ INCIDENT RESOLVED ✅

Incident ID: INC-20240820-143000
Duration: 45 minutes
Status: Resolved

Resolution: Redis connection pool scaling resolved authentication failures

Actions Completed:
✅ Scaled Redis cluster from 3 to 6 nodes
✅ Increased connection pool size to 100
✅ Validated authentication functionality
✅ Monitoring for stability

Post-Mortem: Scheduled for tomorrow 2 PM
```

## Change Management

### Change Categories

#### Standard Changes
- **Definition**: Pre-approved, low-risk changes
- **Examples**: Configuration updates, scaling adjustments
- **Approval**: Automated or team lead approval
- **Process**: Standard deployment pipeline

#### Normal Changes
- **Definition**: Medium-risk changes requiring review
- **Examples**: Feature deployments, dependency updates
- **Approval**: Change Advisory Board (CAB)
- **Process**: Full testing and rollback plan required

#### Emergency Changes
- **Definition**: Urgent changes for incident resolution
- **Examples**: Security patches, critical bug fixes
- **Approval**: Incident Commander or on-call manager
- **Process**: Expedited with post-change review

### Change Process

#### Change Request Template
```yaml
change_request:
  id: CHG-$(date +%Y%m%d)-001
  type: normal  # standard, normal, emergency
  title: "Update Auth Service to v1.3.0"
  
  description: |
    Deploy Auth Service v1.3.0 with improved rate limiting
    and performance optimizations.
  
  business_justification: |
    Addresses customer complaints about slow login times
    and prepares for expected 50% traffic increase.
  
  technical_details:
    components: ["auth-service"]
    environments: ["staging", "production"]
    deployment_method: "rolling_update"
    rollback_plan: "kubectl rollout undo deployment/auth-service"
  
  testing:
    unit_tests: "✅ Passed"
    integration_tests: "✅ Passed"
    performance_tests: "✅ Passed"
    security_scan: "✅ Passed"
  
  schedule:
    planned_start: "2024-08-20T14:00:00Z"
    planned_duration: "30 minutes"
    maintenance_window: "2024-08-20T14:00:00Z to 2024-08-20T15:00:00Z"
  
  approvals:
    technical_lead: "approved"
    security_team: "approved"
    business_owner: "approved"
```

#### Pre-Change Checklist
```bash
# pre-change-checklist.sh
#!/bin/bash

CHANGE_ID=$1
SERVICE=$2

echo "=== Pre-Change Checklist for $CHANGE_ID ==="

# 1. Backup current state
echo "1. Creating backup..."
kubectl get deployment $SERVICE -o yaml > "backups/${SERVICE}-${CHANGE_ID}.yaml"

# 2. Verify monitoring
echo "2. Verifying monitoring..."
curl -s "http://prometheus:9090/api/v1/query?query=up{job=\"$SERVICE\"}" | grep -q '"status":"success"'

# 3. Check resource availability
echo "3. Checking resource availability..."
kubectl describe nodes | grep -A 5 "Allocated resources"

# 4. Verify rollback capability
echo "4. Verifying rollback capability..."
kubectl rollout history deployment/$SERVICE

# 5. Notify stakeholders
echo "5. Sending change notification..."
# Send notification to stakeholders

echo "✓ Pre-change checklist complete"
```

## Security Operations

### Security Monitoring

#### Security Metrics
- **Authentication failures** per minute
- **Brute force attack** detection
- **Privilege escalation** attempts
- **Unauthorized access** attempts
- **Certificate expiry** warnings

#### Security Alerts
```yaml
# security-alerts.yml
groups:
  - name: security
    rules:
      - alert: BruteForceAttack
        expr: increase(authentication_failures_total[5m]) > 100
        for: 2m
        labels:
          severity: critical
          category: security
        annotations:
          summary: "Potential brute force attack detected"
          description: "{{ $value }} authentication failures in 5 minutes"
      
      - alert: UnauthorizedAccess
        expr: increase(authorization_denied_total[10m]) > 50
        for: 5m
        labels:
          severity: warning
          category: security
        annotations:
          summary: "High number of authorization denials"
          description: "{{ $value }} authorization denials in 10 minutes"
      
      - alert: CertificateExpiring
        expr: (cert_expiry_timestamp - time()) / 86400 < 30
        for: 1h
        labels:
          severity: warning
          category: security
        annotations:
          summary: "Certificate expiring soon"
          description: "Certificate {{ $labels.subject }} expires in {{ $value }} days"
```

### Security Incident Response

#### Security Incident Playbook
```bash
# security-incident-response.sh
#!/bin/bash

INCIDENT_TYPE=$1  # brute_force, unauthorized_access, data_breach
SEVERITY=$2       # low, medium, high, critical

echo "=== Security Incident Response ==="
echo "Type: $INCIDENT_TYPE"
echo "Severity: $SEVERITY"
echo "Timestamp: $(date)"

case $INCIDENT_TYPE in
  "brute_force")
    echo "Implementing brute force protections..."
    # Block source IPs
    kubectl apply -f security/rate-limiting-strict.yaml
    # Increase monitoring
    kubectl patch deployment auth-service -p='{"spec":{"template":{"spec":{"containers":[{"name":"auth-service","env":[{"name":"LOG_LEVEL","value":"debug"}]}]}}}}'
    ;;
  
  "unauthorized_access")
    echo "Investigating unauthorized access..."
    # Enhanced logging
    kubectl patch deployment auth-service -p='{"spec":{"template":{"spec":{"containers":[{"name":"auth-service","env":[{"name":"AUDIT_LOG_LEVEL","value":"verbose"}]}]}}}}'
    # Review recent access patterns
    kubectl logs -l app=auth-service | grep "unauthorized"
    ;;
  
  "data_breach")
    echo "CRITICAL: Data breach response..."
    # Immediate containment
    kubectl patch service auth-service -p='{"spec":{"selector":{"emergency":"isolate"}}}'
    # Alert all stakeholders
    echo "🚨 SECURITY BREACH DETECTED 🚨" | mail -s "URGENT: Security Incident" security-team@company.com
    ;;
esac

echo "Security response actions completed"
```

## Performance Management

### Performance Optimization

#### Performance Monitoring
```bash
# performance-monitoring.sh
#!/bin/bash

echo "=== Performance Monitoring Report ==="
echo "Generated: $(date)"

# Response time analysis
echo "1. Response Time Analysis:"
curl -s "http://prometheus:9090/api/v1/query?query=histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))" | \
  jq -r '.data.result[] | "\(.metric.service): \(.value[1])s"'

# Throughput analysis
echo "2. Throughput Analysis:"
curl -s "http://prometheus:9090/api/v1/query?query=sum(rate(http_requests_total[5m])) by (service)" | \
  jq -r '.data.result[] | "\(.metric.service): \(.value[1]) RPS"'

# Resource utilization
echo "3. Resource Utilization:"
kubectl top pods -n rust-security --sort-by=cpu

# Error rate analysis
echo "4. Error Rate Analysis:"
curl -s "http://prometheus:9090/api/v1/query?query=rate(http_requests_total{code=~\"5..\"}[5m]) / rate(http_requests_total[5m])" | \
  jq -r '.data.result[] | "\(.metric.service): \(.value[1] | tonumber * 100 | round)%"'
```

#### Performance Tuning
```bash
# performance-tuning.sh
#!/bin/bash

SERVICE=$1
TARGET_IMPROVEMENT=$2  # cpu, memory, latency, throughput

echo "Performance tuning for $SERVICE - Target: $TARGET_IMPROVEMENT"

case $TARGET_IMPROVEMENT in
  "cpu")
    # Optimize CPU usage
    kubectl patch deployment $SERVICE -p='{"spec":{"template":{"spec":{"containers":[{"name":"'$SERVICE'","resources":{"requests":{"cpu":"500m"},"limits":{"cpu":"2000m"}}}]}}}}'
    ;;
  
  "memory")
    # Optimize memory usage
    kubectl patch deployment $SERVICE -p='{"spec":{"template":{"spec":{"containers":[{"name":"'$SERVICE'","resources":{"requests":{"memory":"512Mi"},"limits":{"memory":"2Gi"}}}]}}}}'
    ;;
  
  "latency")
    # Optimize for latency
    kubectl patch deployment $SERVICE -p='{"spec":{"template":{"spec":{"containers":[{"name":"'$SERVICE'","env":[{"name":"CACHE_SIZE","value":"1000"},{"name":"POOL_SIZE","value":"50"}]}]}}}}'
    ;;
  
  "throughput")
    # Optimize for throughput
    kubectl scale deployment $SERVICE --replicas=10
    kubectl patch hpa $SERVICE -p='{"spec":{"maxReplicas":20,"targetCPUUtilizationPercentage":60}}'
    ;;
esac

echo "Performance tuning applied"
```

## Disaster Recovery

### Backup Strategy

#### Automated Backup
```bash
# automated-backup.sh
#!/bin/bash

BACKUP_DIR="/backups/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

echo "Starting automated backup - $(date)"

# 1. Application data backup
echo "Backing up Redis data..."
kubectl exec redis-master-0 -- redis-cli BGSAVE
kubectl cp redis-master-0:/data/dump.rdb "$BACKUP_DIR/redis-$(date +%H%M%S).rdb"

# 2. Configuration backup
echo "Backing up configurations..."
kubectl get configmaps -n rust-security -o yaml > "$BACKUP_DIR/configmaps.yaml"
kubectl get secrets -n rust-security -o yaml > "$BACKUP_DIR/secrets.yaml"

# 3. Policy data backup
echo "Backing up policy data..."
kubectl exec -it policy-service-xxx -- tar czf - /etc/policies > "$BACKUP_DIR/policies.tar.gz"

# 4. Kubernetes state backup
echo "Backing up Kubernetes state..."
kubectl get all -n rust-security -o yaml > "$BACKUP_DIR/kubernetes-state.yaml"

# 5. Upload to cloud storage
echo "Uploading to cloud storage..."
aws s3 sync $BACKUP_DIR s3://rust-security-backups/$(date +%Y%m%d)/

echo "Backup completed - $(date)"
```

#### Recovery Procedures
```bash
# disaster-recovery.sh
#!/bin/bash

BACKUP_DATE=$1
RECOVERY_TYPE=$2  # full, partial, config_only

if [[ -z "$BACKUP_DATE" ]]; then
    echo "Usage: $0 <backup-date> [recovery-type]"
    echo "Example: $0 20240820 full"
    exit 1
fi

BACKUP_DIR="/backups/$BACKUP_DATE"
RECOVERY_TYPE=${RECOVERY_TYPE:-full}

echo "=== Disaster Recovery Procedure ==="
echo "Backup Date: $BACKUP_DATE"
echo "Recovery Type: $RECOVERY_TYPE"
echo "Started: $(date)"

case $RECOVERY_TYPE in
  "full")
    echo "Performing full recovery..."
    
    # 1. Restore infrastructure
    kubectl apply -f "$BACKUP_DIR/kubernetes-state.yaml"
    
    # 2. Restore configurations
    kubectl apply -f "$BACKUP_DIR/configmaps.yaml"
    kubectl apply -f "$BACKUP_DIR/secrets.yaml"
    
    # 3. Restore application data
    kubectl cp "$BACKUP_DIR/redis-*.rdb" redis-master-0:/data/dump.rdb
    kubectl exec redis-master-0 -- redis-cli DEBUG RESTART
    
    # 4. Restore policy data
    kubectl cp "$BACKUP_DIR/policies.tar.gz" policy-service-xxx:/tmp/
    kubectl exec policy-service-xxx -- tar xzf /tmp/policies.tar.gz -C /
    
    # 5. Restart services
    kubectl rollout restart deployment/auth-service
    kubectl rollout restart deployment/policy-service
    ;;
    
  "partial")
    echo "Performing partial recovery (data only)..."
    # Restore only application data
    kubectl cp "$BACKUP_DIR/redis-*.rdb" redis-master-0:/data/dump.rdb
    kubectl exec redis-master-0 -- redis-cli DEBUG RESTART
    ;;
    
  "config_only")
    echo "Performing configuration recovery..."
    # Restore only configurations
    kubectl apply -f "$BACKUP_DIR/configmaps.yaml"
    kubectl apply -f "$BACKUP_DIR/secrets.yaml"
    kubectl rollout restart deployment/auth-service
    kubectl rollout restart deployment/policy-service
    ;;
esac

echo "Recovery completed - $(date)"
echo "Verifying service health..."
./health-check.sh
```

## Operational Excellence

### Continuous Improvement

#### Monthly Operations Review
```yaml
# monthly-ops-review.yml
review_agenda:
  - incident_analysis:
    - Review all incidents from past month
    - Identify patterns and trends
    - Action items for prevention
  
  - performance_analysis:
    - SLO compliance review
    - Performance trends analysis
    - Capacity planning updates
  
  - security_review:
    - Security incidents analysis
    - Vulnerability assessment updates
    - Compliance status review
  
  - process_improvement:
    - Runbook updates
    - Automation opportunities
    - Tool optimization
  
  - team_development:
    - Training needs assessment
    - Knowledge sharing sessions
    - Cross-training planning
```

#### Operations Metrics Dashboard
```json
{
  "operations_dashboard": {
    "reliability_metrics": {
      "mttr": "Mean Time To Recovery",
      "mtbf": "Mean Time Between Failures", 
      "availability": "Service Availability %",
      "slo_compliance": "SLO Compliance %"
    },
    "performance_metrics": {
      "deployment_frequency": "Deployments per week",
      "deployment_success_rate": "Successful deployments %",
      "rollback_frequency": "Rollbacks per month",
      "change_failure_rate": "Change failure rate %"
    },
    "operational_metrics": {
      "alert_volume": "Alerts per day",
      "false_positive_rate": "False alert rate %",
      "incident_response_time": "Average response time",
      "automation_coverage": "Automated tasks %"
    }
  }
}
```

### Knowledge Management

#### Documentation Standards
- **Runbooks**: Step-by-step operational procedures
- **Playbooks**: Incident response procedures
- **Architecture Diagrams**: System design documentation
- **Configuration Guides**: Setup and configuration procedures
- **Troubleshooting Guides**: Common issues and solutions

#### Training Program
```yaml
training_curriculum:
  foundation:
    - Kubernetes fundamentals
    - Monitoring and observability
    - Incident response basics
    - Security fundamentals
  
  intermediate:
    - Advanced troubleshooting
    - Performance optimization
    - Automation development
    - Security operations
  
  advanced:
    - Chaos engineering
    - Disaster recovery
    - System design
    - Leadership skills
  
  certifications:
    - CKA (Certified Kubernetes Administrator)
    - Prometheus monitoring
    - Security clearances
    - Cloud platform certifications
```

This comprehensive operations guide provides everything needed to successfully operate the Rust Security Platform, ensuring high availability, security, and performance while maintaining operational excellence.