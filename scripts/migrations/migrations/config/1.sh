#!/bin/bash
# Configuration Migration v1: Initialize base configurations
# Purpose: Set up initial ConfigMaps and Secrets with proper structure

set -euo pipefail

# Migration metadata
MIGRATION_NAME="Initialize Base Configurations"
MIGRATION_DESCRIPTION="Set up initial ConfigMaps and Secrets with proper versioning and structure"

echo "=== Configuration Migration v1: $MIGRATION_NAME ==="
echo "Description: $MIGRATION_DESCRIPTION"
echo "Timestamp: $(date)"

# Verify namespace exists
if ! kubectl get namespace rust-security >/dev/null 2>&1; then
    echo "ERROR: Namespace 'rust-security' does not exist"
    exit 1
fi

echo "✓ Namespace verification completed"

# Create migration tracking ConfigMap
echo "Creating migration tracking ConfigMap..."

kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: migration-tracker
  namespace: rust-security
  labels:
    app.kubernetes.io/name: migration-tracker
    app.kubernetes.io/part-of: rust-security
    migration.rust-security/version: "1"
data:
  version: "1"
  created: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  description: "Migration tracking for configuration changes"
  migrations_applied: "config-v1"
EOF

echo "✓ Migration tracker created"

# Create base Auth Service configuration
echo "Creating Auth Service base configuration..."

kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-service-config
  namespace: rust-security
  labels:
    app.kubernetes.io/name: auth-service
    app.kubernetes.io/part-of: rust-security
    config.rust-security/version: "1"
data:
  # Server configuration
  bind_addr: "0.0.0.0:8080"
  log_level: "info"
  environment: "production"
  
  # Token configuration
  token_expiry_seconds: "3600"
  refresh_token_expiry_seconds: "86400"
  
  # Rate limiting
  rate_limit_requests_per_minute: "120"
  rate_limit_burst: "10"
  
  # CORS configuration
  allowed_origins: "https://app.example.com,https://admin.example.com"
  allowed_methods: "GET,POST,PUT,DELETE,OPTIONS"
  allowed_headers: "Content-Type,Authorization,X-Requested-With"
  
  # Redis configuration
  redis_url: "redis://redis-master:6379"
  redis_db_sessions: "0"
  redis_db_rate_limits: "1"
  redis_db_cache: "2"
  redis_db_tokens: "3"
  
  # External services
  jaeger_endpoint: "http://jaeger-collector:14268/api/traces"
  prometheus_metrics: "true"
  prometheus_metrics_path: "/metrics"
  
  # Security settings
  jwt_algorithm: "RS256"
  password_min_length: "8"
  password_require_special: "true"
  password_require_numbers: "true"
  max_login_attempts: "5"
  lockout_duration_minutes: "15"
  
  # Session configuration
  session_timeout_minutes: "30"
  session_cleanup_interval_minutes: "10"
  
  # OAuth settings
  google_redirect_uri: "https://auth.example.com/oauth/google/callback"
  oauth_state_timeout_minutes: "10"
EOF

echo "✓ Auth Service configuration created"

# Create base Policy Service configuration
echo "Creating Policy Service base configuration..."

kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: policy-service-config
  namespace: rust-security
  labels:
    app.kubernetes.io/name: policy-service
    app.kubernetes.io/part-of: rust-security
    config.rust-security/version: "1"
data:
  # Server configuration
  bind_addr: "0.0.0.0:8080"
  log_level: "info"
  environment: "production"
  
  # Policy engine configuration
  policy_reload_interval_seconds: "300"
  policy_cache_size: "1000"
  policy_cache_ttl_seconds: "3600"
  
  # Authorization settings
  default_decision: "deny"
  authorization_timeout_ms: "100"
  max_policy_depth: "10"
  
  # Cedar engine settings
  cedar_log_level: "warn"
  cedar_validation_mode: "strict"
  cedar_max_entities: "10000"
  
  # External services
  jaeger_endpoint: "http://jaeger-collector:14268/api/traces"
  prometheus_metrics: "true"
  prometheus_metrics_path: "/metrics"
  
  # Entity resolution
  entity_cache_size: "5000"
  entity_cache_ttl_seconds: "1800"
  entity_resolution_timeout_ms: "50"
  
  # Audit logging
  audit_log_enabled: "true"
  audit_log_level: "info"
  audit_log_include_entity_data: "false"
  
  # Performance settings
  worker_threads: "4"
  blocking_threads: "16"
  thread_stack_size: "2048"
EOF

echo "✓ Policy Service configuration created"

# Create base monitoring configuration
echo "Creating monitoring base configuration..."

kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: monitoring-config
  namespace: rust-security
  labels:
    app.kubernetes.io/name: monitoring
    app.kubernetes.io/part-of: rust-security
    config.rust-security/version: "1"
data:
  # Prometheus configuration
  scrape_interval: "15s"
  evaluation_interval: "15s"
  scrape_timeout: "10s"
  
  # Metrics retention
  retention_time: "15d"
  retention_size: "10GB"
  
  # Alerting configuration
  alert_evaluation_interval: "10s"
  alert_resolve_timeout: "5m"
  
  # Service discovery
  service_discovery_refresh_interval: "30s"
  
  # Recording rules
  recording_rules_enabled: "true"
  
  # External labels
  cluster_name: "rust-security-cluster"
  environment: "production"
EOF

echo "✓ Monitoring configuration created"

# Create networking configuration
echo "Creating networking configuration..."

kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: networking-config
  namespace: rust-security
  labels:
    app.kubernetes.io/name: networking
    app.kubernetes.io/part-of: rust-security
    config.rust-security/version: "1"
data:
  # Ingress configuration
  ingress_class: "nginx"
  tls_enabled: "true"
  force_ssl_redirect: "true"
  
  # Load balancer settings
  proxy_connect_timeout: "5"
  proxy_send_timeout: "60"
  proxy_read_timeout: "60"
  proxy_buffer_size: "4k"
  proxy_buffers: "8 4k"
  
  # Rate limiting (nginx level)
  rate_limit_requests_per_second: "10"
  rate_limit_burst: "20"
  rate_limit_connections_per_ip: "10"
  
  # SSL configuration
  ssl_protocols: "TLSv1.2 TLSv1.3"
  ssl_ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
  ssl_prefer_server_ciphers: "on"
  
  # Security headers
  enable_hsts: "true"
  hsts_max_age: "31536000"
  hsts_include_subdomains: "true"
  enable_csp: "true"
  csp_default_src: "'self'"
  csp_script_src: "'self' 'unsafe-inline'"
  csp_style_src: "'self' 'unsafe-inline'"
EOF

echo "✓ Networking configuration created"

# Create initial secrets structure (empty, will be populated by external secrets)
echo "Creating initial secrets structure..."

kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: auth-service-secrets
  namespace: rust-security
  labels:
    app.kubernetes.io/name: auth-service
    app.kubernetes.io/part-of: rust-security
    secret.rust-security/version: "1"
  annotations:
    secret.rust-security/managed-by: "external-secrets"
    secret.rust-security/last-updated: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
type: Opaque
data:
  # Placeholder data - will be overwritten by External Secrets
  jwt-secret: $(echo "placeholder-jwt-secret" | base64 -w 0)
  client-credentials: $(echo "placeholder-client-credentials" | base64 -w 0)
  request-signing-secret: $(echo "placeholder-request-signing-secret" | base64 -w 0)
EOF

kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: policy-service-secrets
  namespace: rust-security
  labels:
    app.kubernetes.io/name: policy-service
    app.kubernetes.io/part-of: rust-security
    secret.rust-security/version: "1"
  annotations:
    secret.rust-security/managed-by: "external-secrets"
    secret.rust-security/last-updated: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
type: Opaque
data:
  # Placeholder data - will be overwritten by External Secrets
  policy-signing-key: $(echo "placeholder-policy-signing-key" | base64 -w 0)
EOF

kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: redis-secrets
  namespace: rust-security
  labels:
    app.kubernetes.io/name: redis
    app.kubernetes.io/part-of: rust-security
    secret.rust-security/version: "1"
  annotations:
    secret.rust-security/managed-by: "external-secrets"
    secret.rust-security/last-updated: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
type: Opaque
data:
  # Placeholder data - will be overwritten by External Secrets
  password: $(echo "placeholder-redis-password" | base64 -w 0)
EOF

echo "✓ Initial secrets structure created"

# Create service-specific configurations
echo "Creating service-specific configurations..."

# Redis configuration
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: redis-config
  namespace: rust-security
  labels:
    app.kubernetes.io/name: redis
    app.kubernetes.io/part-of: rust-security
    config.rust-security/version: "1"
data:
  redis.conf: |
    # Network
    bind 0.0.0.0
    port 6379
    tcp-backlog 511
    timeout 300
    tcp-keepalive 60
    
    # General
    daemonize no
    supervised no
    pidfile /var/run/redis_6379.pid
    loglevel notice
    logfile ""
    databases 16
    
    # Snapshotting
    save 900 1
    save 300 10
    save 60 10000
    stop-writes-on-bgsave-error yes
    rdbcompression yes
    rdbchecksum yes
    dbfilename dump.rdb
    dir /data
    
    # Security
    requirepass PLACEHOLDER_PASSWORD
    
    # Memory Management
    maxmemory 256mb
    maxmemory-policy allkeys-lru
    
    # Lazy freeing
    lazyfree-lazy-eviction yes
    lazyfree-lazy-expire yes
    lazyfree-lazy-server-del yes
    
    # Append only file
    appendonly yes
    appendfilename "appendonly.aof"
    appendfsync everysec
    no-appendfsync-on-rewrite no
    auto-aof-rewrite-percentage 100
    auto-aof-rewrite-min-size 64mb
    
    # Slow log
    slowlog-log-slower-than 10000
    slowlog-max-len 128
    
    # Client management
    maxclients 10000
EOF

echo "✓ Service-specific configurations created"

# Verify all configurations
echo "Verifying migration..."

# Check ConfigMaps
echo "Checking ConfigMaps:"
CONFIG_MAPS=("migration-tracker" "auth-service-config" "policy-service-config" "monitoring-config" "networking-config" "redis-config")
for cm in "${CONFIG_MAPS[@]}"; do
    if kubectl get configmap "$cm" -n rust-security >/dev/null 2>&1; then
        echo "  ✓ $cm exists"
    else
        echo "  ✗ $cm missing"
        exit 1
    fi
done

# Check Secrets
echo "Checking Secrets:"
SECRETS=("auth-service-secrets" "policy-service-secrets" "redis-secrets")
for secret in "${SECRETS[@]}"; do
    if kubectl get secret "$secret" -n rust-security >/dev/null 2>&1; then
        echo "  ✓ $secret exists"
    else
        echo "  ✗ $secret missing"
        exit 1
    fi
done

# Update migration tracker
echo "Updating migration tracker..."
kubectl patch configmap migration-tracker -n rust-security --patch "$(cat <<EOF
data:
  version: "1"
  created: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  description: "Migration tracking for configuration changes"
  migrations_applied: "config-v1"
  last_migration: "config-v1"
  last_migration_date: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  configmaps_created: "$(echo "${CONFIG_MAPS[@]}" | tr ' ' ',')"
  secrets_created: "$(echo "${SECRETS[@]}" | tr ' ' ',')"
EOF
)"

echo "✓ Configuration migration v1 completed successfully"
echo "Summary:"
echo "  - Created migration tracking ConfigMap"
echo "  - Set up base Auth Service configuration with security defaults"
echo "  - Set up base Policy Service configuration with Cedar engine settings"
echo "  - Created monitoring and networking configurations"
echo "  - Initialized secrets structure for External Secrets management"
echo "  - Created Redis configuration with performance optimizations"
echo "  - All configurations are labeled and versioned for tracking"

exit 0