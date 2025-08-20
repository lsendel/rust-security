#!/bin/bash
# Configuration Migration v2: Enhanced security and monitoring configurations
# Purpose: Add advanced security settings, external secrets integration, and enhanced monitoring

set -euo pipefail

# Migration metadata
MIGRATION_NAME="Enhanced Security and Monitoring Configurations"
MIGRATION_DESCRIPTION="Add external secrets integration, advanced security settings, and comprehensive monitoring"

echo "=== Configuration Migration v2: $MIGRATION_NAME ==="
echo "Description: $MIGRATION_DESCRIPTION"
echo "Timestamp: $(date)"

# Verify namespace and previous migration
if ! kubectl get namespace rust-security >/dev/null 2>&1; then
    echo "ERROR: Namespace 'rust-security' does not exist"
    exit 1
fi

if ! kubectl get configmap migration-tracker -n rust-security >/dev/null 2>&1; then
    echo "ERROR: Previous migration (v1) not found. Please run configuration migration v1 first."
    exit 1
fi

echo "✓ Prerequisites verified"

# Create External Secrets configuration
echo "Creating External Secrets configuration..."

kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: external-secrets-config
  namespace: rust-security
  labels:
    app.kubernetes.io/name: external-secrets
    app.kubernetes.io/part-of: rust-security
    config.rust-security/version: "2"
data:
  # External Secrets Operator configuration
  refresh_interval: "15m"
  secret_store_type: "vault"
  
  # Vault configuration
  vault_server: "https://vault.example.com"
  vault_path: "secret"
  vault_version: "v2"
  vault_mount_path: "auth/kubernetes"
  vault_role: "rust-security-role"
  
  # AWS Secrets Manager configuration (alternative)
  aws_region: "us-west-2"
  aws_secrets_prefix: "rust-security/"
  
  # GCP Secret Manager configuration (alternative)
  gcp_project_id: "rust-security-project"
  gcp_secrets_prefix: "rust-security-"
  
  # Secret mapping configuration
  secret_mappings: |
    auth-service:
      jwt-secret: "auth-service/jwt/secret"
      client-credentials: "auth-service/clients/credentials"
      request-signing-secret: "auth-service/signing/secret"
      google-client-secret: "auth-service/oauth/google/client_secret"
    policy-service:
      policy-signing-key: "policy-service/signing/key"
      cedar-validation-key: "policy-service/cedar/validation_key"
    redis:
      password: "redis/password"
    monitoring:
      grafana-admin-password: "monitoring/grafana/admin_password"
      alertmanager-webhook-url: "monitoring/alertmanager/webhook_url"
EOF

echo "✓ External Secrets configuration created"

# Enhanced Auth Service security configuration
echo "Enhancing Auth Service security configuration..."

kubectl patch configmap auth-service-config -n rust-security --patch "$(cat <<EOF
data:
  # Enhanced security settings
  security_headers_enabled: "true"
  hsts_enabled: "true"
  hsts_max_age: "31536000"
  csp_enabled: "true"
  csp_policy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
  
  # Advanced rate limiting
  rate_limit_adaptive: "true"
  rate_limit_per_endpoint: "true"
  rate_limit_whitelist: "127.0.0.1,::1"
  rate_limit_sliding_window: "true"
  
  # Password policy enhancements
  password_max_length: "128"
  password_min_entropy: "3.0"
  password_check_common: "true"
  password_check_breach: "true"
  password_history_count: "5"
  
  # Account security
  account_lockout_progressive: "true"
  suspicious_activity_detection: "true"
  geo_location_tracking: "true"
  device_fingerprinting: "true"
  
  # JWT enhancements
  jwt_key_rotation_enabled: "true"
  jwt_key_rotation_interval_hours: "168"
  jwt_audience_validation: "strict"
  jwt_issuer_validation: "strict"
  jwt_not_before_skew_seconds: "30"
  
  # Session security
  session_secure_cookies: "true"
  session_http_only: "true"
  session_same_site: "strict"
  session_domain_validation: "true"
  
  # Audit logging enhancements
  audit_log_level: "detailed"
  audit_log_include_ip: "true"
  audit_log_include_user_agent: "true"
  audit_log_include_request_id: "true"
  audit_log_retention_days: "90"
  
  # Monitoring and alerting
  metrics_detailed: "true"
  metrics_include_labels: "true"
  health_check_detailed: "true"
  performance_monitoring: "true"
EOF
)"

echo "✓ Auth Service security configuration enhanced"

# Enhanced Policy Service configuration
echo "Enhancing Policy Service configuration..."

kubectl patch configmap policy-service-config -n rust-security --patch "$(cat <<EOF
data:
  # Enhanced Cedar engine settings
  cedar_policy_validation: "strict"
  cedar_schema_validation: "enabled"
  cedar_policy_optimization: "true"
  cedar_concurrent_evaluations: "true"
  cedar_evaluation_cache: "true"
  
  # Policy management
  policy_versioning_enabled: "true"
  policy_rollback_enabled: "true"
  policy_approval_required: "true"
  policy_testing_mode: "dry-run"
  policy_conflict_detection: "true"
  
  # Enhanced security
  policy_encryption_at_rest: "true"
  policy_digital_signatures: "true"
  policy_access_logging: "true"
  policy_change_notifications: "true"
  
  # Performance optimizations
  evaluation_parallel_processing: "true"
  evaluation_result_caching: "true"
  entity_prefetching: "true"
  query_optimization: "true"
  
  # Monitoring and debugging
  policy_evaluation_tracing: "true"
  decision_explanation_enabled: "true"
  performance_profiling: "true"
  slow_evaluation_threshold_ms: "50"
  
  # Multi-tenancy support
  tenant_isolation: "strict"
  tenant_policy_separation: "true"
  cross_tenant_validation: "enabled"
  
  # External integrations
  external_entity_sources: "ldap,scim"
  entity_sync_interval_minutes: "30"
  entity_cache_warming: "true"
EOF
)"

echo "✓ Policy Service configuration enhanced"

# Create comprehensive monitoring configuration
echo "Creating comprehensive monitoring configuration..."

kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-rules
  namespace: rust-security
  labels:
    app.kubernetes.io/name: prometheus
    app.kubernetes.io/part-of: rust-security
    config.rust-security/version: "2"
data:
  auth-service.yml: |
    groups:
      - name: auth-service
        rules:
          # SLI metrics
          - record: auth_service:availability_5m
            expr: |
              (
                sum(rate(http_requests_total{service="auth-service",code!~"5.."}[5m])) /
                sum(rate(http_requests_total{service="auth-service"}[5m]))
              ) * 100
          
          - record: auth_service:latency_p95_5m
            expr: |
              histogram_quantile(0.95,
                sum(rate(http_request_duration_seconds_bucket{service="auth-service"}[5m])) by (le)
              )
          
          - record: auth_service:error_rate_5m
            expr: |
              (
                sum(rate(http_requests_total{service="auth-service",code=~"5.."}[5m])) /
                sum(rate(http_requests_total{service="auth-service"}[5m]))
              ) * 100
          
          # Business metrics
          - record: auth_service:login_success_rate_5m
            expr: |
              (
                sum(rate(authentication_attempts_total{service="auth-service",result="success"}[5m])) /
                sum(rate(authentication_attempts_total{service="auth-service"}[5m]))
              ) * 100
          
          - record: auth_service:active_sessions
            expr: |
              sum(active_sessions{service="auth-service"})
          
          # Security metrics
          - record: auth_service:failed_login_rate_5m
            expr: |
              sum(rate(authentication_attempts_total{service="auth-service",result="failed"}[5m]))
          
          - record: auth_service:suspicious_activity_5m
            expr: |
              sum(rate(security_events_total{service="auth-service",type="suspicious"}[5m]))

  policy-service.yml: |
    groups:
      - name: policy-service
        rules:
          # SLI metrics
          - record: policy_service:availability_5m
            expr: |
              (
                sum(rate(authorization_requests_total{service="policy-service",result!="error"}[5m])) /
                sum(rate(authorization_requests_total{service="policy-service"}[5m]))
              ) * 100
          
          - record: policy_service:decision_latency_p95_5m
            expr: |
              histogram_quantile(0.95,
                sum(rate(authorization_duration_seconds_bucket{service="policy-service"}[5m])) by (le)
              )
          
          - record: policy_service:decision_accuracy_5m
            expr: |
              (
                sum(rate(authorization_decisions_total{service="policy-service",accuracy="correct"}[5m])) /
                sum(rate(authorization_decisions_total{service="policy-service"}[5m]))
              ) * 100
          
          # Performance metrics
          - record: policy_service:cache_hit_rate_5m
            expr: |
              (
                sum(rate(policy_cache_hits_total{service="policy-service"}[5m])) /
                sum(rate(policy_cache_requests_total{service="policy-service"}[5m]))
              ) * 100
          
          - record: policy_service:policy_evaluation_rate_5m
            expr: |
              sum(rate(policy_evaluations_total{service="policy-service"}[5m]))

  infrastructure.yml: |
    groups:
      - name: infrastructure
        rules:
          # Cluster health
          - record: cluster:node_availability
            expr: |
              (
                count(up{job="kubernetes-nodes"} == 1) /
                count(up{job="kubernetes-nodes"})
              ) * 100
          
          - record: cluster:cpu_utilization
            expr: |
              (
                sum(rate(container_cpu_usage_seconds_total{container!="POD",container!=""}[5m])) /
                sum(machine_cpu_cores)
              ) * 100
          
          - record: cluster:memory_utilization
            expr: |
              (
                sum(container_memory_usage_bytes{container!="POD",container!=""}) /
                sum(machine_memory_bytes)
              ) * 100
          
          # Service discovery
          - record: cluster:services_healthy
            expr: |
              count(up{job=~"auth-service|policy-service"} == 1)
EOF

echo "✓ Comprehensive monitoring rules created"

# Create alerting configuration
echo "Creating alerting configuration..."

kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: alerting-rules
  namespace: rust-security
  labels:
    app.kubernetes.io/name: alertmanager
    app.kubernetes.io/part-of: rust-security
    config.rust-security/version: "2"
data:
  critical-alerts.yml: |
    groups:
      - name: critical
        rules:
          - alert: ServiceDown
            expr: up{job=~"auth-service|policy-service"} == 0
            for: 1m
            labels:
              severity: critical
              service: "{{ \$labels.job }}"
            annotations:
              summary: "Service {{ \$labels.job }} is down"
              description: "Service {{ \$labels.job }} has been down for more than 1 minute"
              runbook_url: "https://docs.example.com/runbooks/service-down"
          
          - alert: HighErrorRate
            expr: auth_service:error_rate_5m > 5
            for: 5m
            labels:
              severity: critical
              service: auth-service
            annotations:
              summary: "High error rate detected in Auth Service"
              description: "Error rate is {{ \$value | humanizePercentage }} for Auth Service"
              runbook_url: "https://docs.example.com/runbooks/high-error-rate"
          
          - alert: AuthenticationFailureSpike
            expr: auth_service:failed_login_rate_5m > 10
            for: 2m
            labels:
              severity: critical
              category: security
            annotations:
              summary: "Authentication failure spike detected"
              description: "{{ \$value }} failed logins per second in the last 5 minutes"
              runbook_url: "https://docs.example.com/runbooks/auth-failure-spike"

  warning-alerts.yml: |
    groups:
      - name: warning
        rules:
          - alert: HighLatency
            expr: auth_service:latency_p95_5m > 0.5
            for: 10m
            labels:
              severity: warning
              service: auth-service
            annotations:
              summary: "High latency detected in Auth Service"
              description: "95th percentile latency is {{ \$value }}s"
              runbook_url: "https://docs.example.com/runbooks/high-latency"
          
          - alert: PolicyDecisionLatency
            expr: policy_service:decision_latency_p95_5m > 0.1
            for: 5m
            labels:
              severity: warning
              service: policy-service
            annotations:
              summary: "High decision latency in Policy Service"
              description: "95th percentile decision latency is {{ \$value }}s"
              runbook_url: "https://docs.example.com/runbooks/policy-latency"
          
          - alert: LowCacheHitRate
            expr: policy_service:cache_hit_rate_5m < 80
            for: 15m
            labels:
              severity: warning
              service: policy-service
            annotations:
              summary: "Low cache hit rate in Policy Service"
              description: "Cache hit rate is {{ \$value | humanizePercentage }}"
              runbook_url: "https://docs.example.com/runbooks/low-cache-hit-rate"

  infrastructure-alerts.yml: |
    groups:
      - name: infrastructure
        rules:
          - alert: HighCPUUtilization
            expr: cluster:cpu_utilization > 80
            for: 10m
            labels:
              severity: warning
              category: capacity
            annotations:
              summary: "High CPU utilization detected"
              description: "Cluster CPU utilization is {{ \$value | humanizePercentage }}"
              runbook_url: "https://docs.example.com/runbooks/high-cpu"
          
          - alert: HighMemoryUtilization
            expr: cluster:memory_utilization > 85
            for: 10m
            labels:
              severity: warning
              category: capacity
            annotations:
              summary: "High memory utilization detected"
              description: "Cluster memory utilization is {{ \$value | humanizePercentage }}"
              runbook_url: "https://docs.example.com/runbooks/high-memory"
          
          - alert: NodeDown
            expr: cluster:node_availability < 100
            for: 5m
            labels:
              severity: critical
              category: infrastructure
            annotations:
              summary: "One or more nodes are down"
              description: "Node availability is {{ \$value | humanizePercentage }}"
              runbook_url: "https://docs.example.com/runbooks/node-down"
EOF

echo "✓ Alerting configuration created"

# Create security monitoring configuration
echo "Creating security monitoring configuration..."

kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: security-monitoring-config
  namespace: rust-security
  labels:
    app.kubernetes.io/name: security-monitoring
    app.kubernetes.io/part-of: rust-security
    config.rust-security/version: "2"
data:
  # Security event monitoring
  security_events_enabled: "true"
  security_log_level: "info"
  security_alert_webhook: "https://security-team.example.com/webhook"
  
  # Threat detection
  brute_force_threshold: "10"
  brute_force_window_minutes: "5"
  suspicious_ip_tracking: "true"
  geo_anomaly_detection: "true"
  
  # Compliance monitoring
  compliance_frameworks: "SOC2,GDPR,CCPA"
  audit_log_retention_days: "2555"  # 7 years
  data_classification_tracking: "true"
  
  # Incident response
  automated_response_enabled: "true"
  incident_escalation_enabled: "true"
  security_team_notifications: "true"
  
  # Vulnerability scanning
  container_scanning_enabled: "true"
  dependency_scanning_enabled: "true"
  config_scanning_enabled: "true"
  scan_schedule: "0 2 * * *"  # Daily at 2 AM
  
  # Security policies
  network_policy_enforcement: "strict"
  pod_security_standards: "restricted"
  service_mesh_mtls: "strict"
  secret_encryption: "enabled"
EOF

echo "✓ Security monitoring configuration created"

# Create performance monitoring configuration
echo "Creating performance monitoring configuration..."

kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: performance-monitoring-config
  namespace: rust-security
  labels:
    app.kubernetes.io/name: performance-monitoring
    app.kubernetes.io/part-of: rust-security
    config.rust-security/version: "2"
data:
  # Performance tracking
  performance_profiling_enabled: "true"
  apm_enabled: "true"
  distributed_tracing_enabled: "true"
  
  # SLO monitoring
  slo_monitoring_enabled: "true"
  error_budget_tracking: "true"
  slo_alert_thresholds: "50,75,90"  # Percentages of error budget consumption
  
  # Capacity monitoring
  capacity_planning_enabled: "true"
  growth_rate_tracking: "true"
  resource_forecasting: "true"
  
  # Load testing
  load_test_enabled: "true"
  load_test_schedule: "0 3 * * 0"  # Weekly on Sunday at 3 AM
  performance_regression_detection: "true"
  
  # Optimization
  auto_scaling_optimization: "true"
  resource_right_sizing: "true"
  performance_budget_enforcement: "true"
EOF

echo "✓ Performance monitoring configuration created"

# Update migration tracker
echo "Updating migration tracker..."

kubectl patch configmap migration-tracker -n rust-security --patch "$(cat <<EOF
data:
  version: "2"
  created: "$(kubectl get configmap migration-tracker -n rust-security -o jsonpath='{.data.created}')"
  description: "Migration tracking for configuration changes"
  migrations_applied: "config-v1,config-v2"
  last_migration: "config-v2"
  last_migration_date: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  v2_features: "external-secrets,enhanced-security,comprehensive-monitoring,alerting,security-monitoring,performance-monitoring"
  v2_configmaps_added: "external-secrets-config,prometheus-rules,alerting-rules,security-monitoring-config,performance-monitoring-config"
EOF
)"

echo "✓ Migration tracker updated"

# Verify all new configurations
echo "Verifying migration..."

# Check new ConfigMaps
echo "Checking new ConfigMaps:"
NEW_CONFIG_MAPS=("external-secrets-config" "prometheus-rules" "alerting-rules" "security-monitoring-config" "performance-monitoring-config")
for cm in "${NEW_CONFIG_MAPS[@]}"; do
    if kubectl get configmap "$cm" -n rust-security >/dev/null 2>&1; then
        echo "  ✓ $cm exists"
    else
        echo "  ✗ $cm missing"
        exit 1
    fi
done

# Verify patches were applied
echo "Verifying configuration patches:"
if kubectl get configmap auth-service-config -n rust-security -o yaml | grep -q "security_headers_enabled"; then
    echo "  ✓ Auth Service security enhancements applied"
else
    echo "  ✗ Auth Service security enhancements missing"
    exit 1
fi

if kubectl get configmap policy-service-config -n rust-security -o yaml | grep -q "cedar_policy_validation"; then
    echo "  ✓ Policy Service enhancements applied"
else
    echo "  ✗ Policy Service enhancements missing"
    exit 1
fi

# Check migration version
CURRENT_VERSION=$(kubectl get configmap migration-tracker -n rust-security -o jsonpath='{.data.version}')
if [[ "$CURRENT_VERSION" == "2" ]]; then
    echo "  ✓ Migration version correctly updated to 2"
else
    echo "  ✗ Migration version not updated correctly"
    exit 1
fi

echo "✓ Configuration migration v2 completed successfully"
echo "Summary:"
echo "  - Added External Secrets Operator integration configuration"
echo "  - Enhanced Auth Service with advanced security settings"
echo "  - Enhanced Policy Service with Cedar engine optimizations"
echo "  - Created comprehensive Prometheus monitoring rules"
echo "  - Set up detailed alerting for critical, warning, and infrastructure events"
echo "  - Added security monitoring with threat detection capabilities"
echo "  - Configured performance monitoring with SLO tracking"
echo "  - All configurations support multi-tenant isolation"
echo "  - Enhanced audit logging and compliance tracking"

exit 0