# Operations Runbook

## Overview

This runbook provides step-by-step procedures for operating, monitoring, and troubleshooting the Rust Security Platform in production environments. Use this guide for incident response, maintenance, and routine operational tasks.

## Emergency Response

### 🚨 Service Outage Response

#### Immediate Actions (First 5 Minutes)
```bash
# 1. Check service status
./validate-services.sh

# 2. Check system resources
kubectl top nodes
kubectl top pods -n rust-security

# 3. Check recent deployments
kubectl rollout history deployment/auth-service -n rust-security
kubectl rollout history deployment/policy-service -n rust-security

# 4. Quick service restart if needed
kubectl rollout restart deployment/auth-service -n rust-security
```

#### Investigation Steps (5-15 Minutes)
```bash
# 1. Check service logs (last 10 minutes)
kubectl logs --since=10m deployment/auth-service -n rust-security
kubectl logs --since=10m deployment/policy-service -n rust-security

# 2. Check infrastructure dependencies
kubectl get pods -n rust-security
kubectl describe pod -l app=postgres -n rust-security

# 3. Check network connectivity
kubectl exec deployment/auth-service -n rust-security -- nc -zv postgres 5432
kubectl exec deployment/auth-service -n rust-security -- nc -zv redis 6379

# 4. Review metrics (if Prometheus is available)
curl -s "http://prometheus:9090/api/v1/query?query=up{job='auth-service'}"
```

#### Recovery Actions
```bash
# Database connectivity issues
kubectl exec -it deployment/postgres -n rust-security -- pg_isready

# Scale up services for immediate relief
kubectl scale deployment/auth-service --replicas=5 -n rust-security

# Emergency rollback if needed
kubectl rollout undo deployment/auth-service -n rust-security

# Clear Redis cache if corrupted
kubectl exec deployment/redis -n rust-security -- redis-cli FLUSHDB
```

### 🔒 Security Incident Response

#### High Failed Login Rate Alert
```bash
# 1. Check current failed login metrics
curl -s http://auth-service:8080/metrics | grep auth_failed_logins_total

# 2. Review authentication logs
kubectl logs deployment/auth-service -n rust-security | grep "authentication_failed" | tail -50

# 3. Identify attack sources
kubectl logs deployment/auth-service -n rust-security | \
  grep "authentication_failed" | \
  grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
  sort | uniq -c | sort -nr

# 4. Block suspicious IPs (temporary measure)
kubectl exec deployment/nginx -n rust-security -- \
  nginx -s reload -c /etc/nginx/blocked-ips.conf
```

#### JWT Token Compromise
```bash
# 1. Rotate JWT signing key immediately
kubectl create secret generic new-jwt-secret -n rust-security \
  --from-literal=jwt-secret="$(openssl rand -base64 32)"

# 2. Update deployments to use new secret
kubectl patch deployment auth-service -n rust-security \
  --type='merge' -p='{"spec":{"template":{"spec":{"containers":[{"name":"auth-service","env":[{"name":"JWT_SECRET","valueFrom":{"secretKeyRef":{"name":"new-jwt-secret","key":"jwt-secret"}}}]}]}}}}'

# 3. Force restart to apply new key
kubectl rollout restart deployment/auth-service -n rust-security

# 4. Monitor for authentication anomalies
kubectl logs -f deployment/auth-service -n rust-security | grep -E "(jwt|token)"
```

## Routine Maintenance

### Daily Operations Checklist

#### Morning Health Check (09:00)
```bash
#!/bin/bash
# scripts/daily-health-check.sh

echo "=== Daily Health Check $(date) ==="

# Service health
echo "Checking service health..."
for service in auth-service policy-service; do
  status=$(kubectl get deployment $service -n rust-security -o jsonpath='{.status.readyReplicas}/{.status.replicas}')
  echo "$service: $status ready"
done

# Database health  
echo "Checking database..."
kubectl exec deployment/postgres -n rust-security -- pg_isready

# Redis health
echo "Checking Redis..."
kubectl exec deployment/redis -n rust-security -- redis-cli ping

# Disk space
echo "Checking disk space..."
kubectl exec deployment/postgres -n rust-security -- df -h /var/lib/postgresql/data

# Certificate expiry (if using cert-manager)
echo "Checking certificates..."
kubectl get certificates -n rust-security

echo "=== Health check complete ==="
```

#### Evening Metrics Review (17:00)
```bash
#!/bin/bash
# scripts/evening-metrics-review.sh

echo "=== Evening Metrics Review $(date) ==="

# Authentication metrics (last 24h)
echo "Authentication requests (24h):"
kubectl exec deployment/auth-service -n rust-security -- \
  curl -s localhost:8080/metrics | grep auth_requests_total

# Error rates
echo "Error rates (24h):"  
kubectl exec deployment/auth-service -n rust-security -- \
  curl -s localhost:8080/metrics | grep -E "(error|failed)"

# Performance metrics
echo "Response times (24h):"
kubectl exec deployment/auth-service -n rust-security -- \
  curl -s localhost:8080/metrics | grep duration

# Database connections
echo "Database connection usage:"
kubectl exec deployment/postgres -n rust-security -- \
  psql -U auth_service -d auth_service -c "SELECT count(*) as active_connections FROM pg_stat_activity;"

echo "=== Metrics review complete ==="
```

### Weekly Maintenance

#### Database Maintenance (Sunday 02:00)
```bash
#!/bin/bash
# scripts/weekly-db-maintenance.sh

echo "=== Weekly Database Maintenance $(date) ==="

# Backup database
./scripts/backup-database.sh

# Update table statistics
kubectl exec deployment/postgres -n rust-security -- \
  psql -U auth_service -d auth_service -c "ANALYZE;"

# Reindex if needed
kubectl exec deployment/postgres -n rust-security -- \
  psql -U auth_service -d auth_service -c "REINDEX DATABASE auth_service;"

# Cleanup old logs (keep 30 days)
kubectl exec deployment/postgres -n rust-security -- \
  find /var/log -name "*.log" -mtime +30 -delete

# Vacuum full (monthly, during maintenance window)
if [ "$(date +%d)" -le 7 ]; then
  kubectl exec deployment/postgres -n rust-security -- \
    psql -U auth_service -d auth_service -c "VACUUM FULL;"
fi

echo "=== Database maintenance complete ==="
```

#### Security Review (Friday 16:00)
```bash
#!/bin/bash  
# scripts/weekly-security-review.sh

echo "=== Weekly Security Review $(date) ==="

# Check for failed logins
echo "Failed login summary (7 days):"
kubectl logs --since=168h deployment/auth-service -n rust-security | \
  grep "authentication_failed" | \
  grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
  sort | uniq -c | sort -nr | head -10

# JWT token usage
echo "JWT token statistics (7 days):"
kubectl exec deployment/auth-service -n rust-security -- \
  curl -s localhost:8080/metrics | grep jwt_tokens_issued_total

# Certificate status
echo "Certificate expiry status:"
kubectl get certificates -n rust-security -o custom-columns=NAME:.metadata.name,READY:.status.conditions[0].status,EXPIRY:.status.notAfter

# Security patch status
echo "Container image updates needed:"
kubectl get pods -n rust-security -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'

echo "=== Security review complete ==="
```

### Monthly Maintenance

#### Capacity Planning Review
```bash
#!/bin/bash
# scripts/monthly-capacity-review.sh

echo "=== Monthly Capacity Review $(date) ==="

# Resource usage trends
echo "CPU usage (30 days):"
kubectl top pods -n rust-security --sort-by=cpu

echo "Memory usage (30 days):"  
kubectl top pods -n rust-security --sort-by=memory

# Database growth
echo "Database size growth:"
kubectl exec deployment/postgres -n rust-security -- \
  psql -U auth_service -d auth_service -c "
    SELECT 
      schemaname,
      tablename,
      pg_size_pretty(pg_total_relation_size(tablename::regclass)) as size
    FROM pg_tables 
    WHERE schemaname = 'public' 
    ORDER BY pg_total_relation_size(tablename::regclass) DESC;"

# Request volume trends
echo "Request volume (30 days):"
kubectl exec deployment/auth-service -n rust-security -- \
  curl -s localhost:8080/metrics | grep auth_requests_total

echo "=== Capacity review complete ==="
```

## Monitoring and Alerting

### Key Metrics to Monitor

#### Application Metrics
```bash
# Authentication success rate
rate(auth_requests_total{status="success"}[5m]) / rate(auth_requests_total[5m])

# Response time percentiles
histogram_quantile(0.95, auth_request_duration_seconds)
histogram_quantile(0.99, auth_request_duration_seconds)

# Error rates  
rate(auth_requests_total{status="error"}[5m])

# Active sessions
auth_active_sessions

# JWT token validation errors
rate(auth_jwt_validation_errors_total[5m])
```

#### Infrastructure Metrics
```bash
# CPU usage
rate(container_cpu_usage_seconds_total[5m])

# Memory usage
container_memory_usage_bytes / container_spec_memory_limit_bytes

# Database connections
pg_stat_database_numbackends

# Redis memory usage
redis_memory_used_bytes
```

### Alert Configuration

#### Critical Alerts (Immediate Response)
```yaml
# monitoring/alerts/critical.yml
groups:
- name: critical-alerts
  rules:
  - alert: ServiceDown
    expr: up{job=~"auth-service|policy-service"} == 0
    for: 30s
    labels:
      severity: critical
      oncall: true
    annotations:
      summary: "{{ $labels.job }} service is down"
      runbook: "Check service logs and restart if necessary"
      
  - alert: DatabaseDown
    expr: up{job="postgres"} == 0
    for: 1m
    labels:
      severity: critical
      oncall: true
    annotations:
      summary: "PostgreSQL database is down"
      runbook: "Check database logs and restore from backup if necessary"
      
  - alert: HighErrorRate
    expr: rate(auth_requests_total{status="error"}[5m]) > 0.1
    for: 2m
    labels:
      severity: critical
      oncall: true
    annotations:
      summary: "High error rate: {{ $value }}/sec"
      runbook: "Check application logs for errors"
```

#### Warning Alerts (Business Hours Response)
```yaml
# monitoring/alerts/warnings.yml
groups:
- name: warning-alerts
  rules:
  - alert: HighResponseTime
    expr: histogram_quantile(0.95, auth_request_duration_seconds) > 2
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "95th percentile response time is {{ $value }}s"
      runbook: "Check for database performance issues"
      
  - alert: HighMemoryUsage
    expr: container_memory_usage_bytes / container_spec_memory_limit_bytes > 0.8
    for: 10m  
    labels:
      severity: warning
    annotations:
      summary: "Memory usage is {{ $value }}%"
      runbook: "Consider scaling up or optimizing memory usage"
      
  - alert: DiskSpaceWarning
    expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) < 0.2
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Disk space is {{ $value }}% full"
      runbook: "Clean up old logs or expand storage"
```

### Escalation Procedures

#### Level 1: Automated Resolution
- Service restart for transient failures
- Container recycling for memory leaks
- Basic configuration reload

#### Level 2: On-Call Engineer
- Service outages lasting >5 minutes
- Database connectivity issues  
- Security incidents (high failed login rates)
- Performance degradation

#### Level 3: Senior Engineer/Team Lead
- Data corruption or loss
- Security breaches
- Extended outages >30 minutes
- Multi-service failures

#### Level 4: Engineering Manager
- Customer-facing impacts >1 hour
- Regulatory compliance issues
- Major security incidents

## Performance Optimization

### Database Optimization

#### Query Performance Analysis
```bash
# Enable query logging
kubectl exec deployment/postgres -n rust-security -- \
  psql -U auth_service -d auth_service -c "
    ALTER SYSTEM SET log_statement = 'all';
    ALTER SYSTEM SET log_min_duration_statement = 1000;
    SELECT pg_reload_conf();"

# Analyze slow queries
kubectl exec deployment/postgres -n rust-security -- \
  psql -U auth_service -d auth_service -c "
    SELECT query, calls, total_time, mean_time, rows
    FROM pg_stat_statements 
    ORDER BY mean_time DESC 
    LIMIT 10;"

# Check table sizes and indexing
kubectl exec deployment/postgres -n rust-security -- \
  psql -U auth_service -d auth_service -c "
    SELECT 
      schemaname,
      tablename,
      attname,
      n_distinct,
      correlation
    FROM pg_stats 
    WHERE schemaname = 'public'
    ORDER BY n_distinct DESC;"
```

#### Connection Pool Optimization
```rust
// Database pool configuration
#[derive(Clone)]
pub struct DatabaseConfig {
    pub max_connections: u32,      // 20 for production
    pub min_connections: u32,      // 5 for production  
    pub acquire_timeout: Duration, // 30s
    pub idle_timeout: Duration,    // 600s
    pub max_lifetime: Duration,    // 1800s
}

// Connection pool monitoring
async fn monitor_connection_pool(pool: &PgPool) {
    let status = pool.status();
    info!(
        "DB Pool - Size: {}, Idle: {}, Available: {}",
        status.size, status.idle, status.available
    );
}
```

### Application Optimization

#### Memory Usage Optimization
```bash
# Monitor memory allocation patterns
kubectl exec deployment/auth-service -n rust-security -- \
  curl -s localhost:8080/metrics | grep process_resident_memory_bytes

# Check for memory leaks
kubectl top pod -n rust-security --sort-by=memory

# Analyze heap usage (if profiling enabled)
kubectl port-forward deployment/auth-service 6060:6060 -n rust-security
curl http://localhost:6060/debug/pprof/heap > heap.pprof
```

#### CPU Optimization  
```rust
// Async task optimization
use tokio::task;

// CPU-intensive operations should be offloaded
async fn hash_password(password: &str) -> Result<String> {
    let password = password.to_owned();
    task::spawn_blocking(move || {
        argon2::hash_encoded(
            password.as_bytes(),
            &salt,
            &Config::default()
        )
    }).await?
}

// Use connection pooling for Redis
#[derive(Clone)]
pub struct RedisPool {
    pool: deadpool_redis::Pool,
}

impl RedisPool {
    pub async fn get_connection(&self) -> Result<Connection> {
        self.pool.get().await.map_err(Into::into)
    }
}
```

### Caching Strategy

#### Redis Configuration
```bash
# Redis memory optimization
kubectl exec deployment/redis -n rust-security -- \
  redis-cli CONFIG SET maxmemory 1gb
kubectl exec deployment/redis -n rust-security -- \
  redis-cli CONFIG SET maxmemory-policy allkeys-lru

# Monitor Redis performance
kubectl exec deployment/redis -n rust-security -- \
  redis-cli INFO memory

# Cache hit ratio monitoring
kubectl exec deployment/redis -n rust-security -- \
  redis-cli INFO stats | grep -E "(hits|misses)"
```

#### Application-Level Caching
```rust
// JWT validation cache
use std::collections::HashMap;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct JwtCache {
    cache: Arc<RwLock<HashMap<String, (Claims, Instant)>>>,
    ttl: Duration,
}

impl JwtCache {
    pub async fn get_claims(&self, token: &str) -> Option<Claims> {
        let cache = self.cache.read().await;
        if let Some((claims, timestamp)) = cache.get(token) {
            if timestamp.elapsed() < self.ttl {
                return Some(claims.clone());
            }
        }
        None
    }
    
    pub async fn insert_claims(&self, token: String, claims: Claims) {
        let mut cache = self.cache.write().await;
        cache.insert(token, (claims, Instant::now()));
    }
}
```

## Backup and Recovery

### Database Backup Procedures

#### Automated Daily Backups
```bash
#!/bin/bash
# scripts/automated-backup.sh

set -euo pipefail

BACKUP_DIR="/backups"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup
kubectl exec deployment/postgres -n rust-security -- \
  pg_dump -U auth_service -d auth_service \
    --format=custom \
    --compress=9 \
    --no-owner \
    --no-privileges \
    > "${BACKUP_DIR}/auth_service_${TIMESTAMP}.backup"

# Encrypt backup
gpg --cipher-algo AES256 \
    --compress-algo 2 \
    --symmetric \
    --passphrase-file /etc/backup-passphrase \
    --output "${BACKUP_DIR}/auth_service_${TIMESTAMP}.backup.gpg" \
    "${BACKUP_DIR}/auth_service_${TIMESTAMP}.backup"

# Remove unencrypted backup
rm "${BACKUP_DIR}/auth_service_${TIMESTAMP}.backup"

# Upload to cloud storage (AWS S3 example)
aws s3 cp "${BACKUP_DIR}/auth_service_${TIMESTAMP}.backup.gpg" \
  s3://company-backups/rust-security/daily/

# Cleanup old backups
find "${BACKUP_DIR}" -name "*.backup.gpg" -mtime +${RETENTION_DAYS} -delete

# Verify backup integrity
pg_restore --list "${BACKUP_DIR}/auth_service_${TIMESTAMP}.backup.gpg" > /dev/null

echo "Backup completed successfully: auth_service_${TIMESTAMP}.backup.gpg"
```

#### Point-in-Time Recovery
```bash
#!/bin/bash
# scripts/point-in-time-recovery.sh

RECOVERY_TIME="$1"  # Format: 2024-01-15 14:30:00
BACKUP_FILE="$2"

echo "Starting point-in-time recovery to: $RECOVERY_TIME"

# Stop application services
kubectl scale deployment/auth-service --replicas=0 -n rust-security
kubectl scale deployment/policy-service --replicas=0 -n rust-security

# Create recovery database
kubectl exec deployment/postgres -n rust-security -- \
  createdb -U auth_service auth_service_recovery

# Restore from backup
kubectl exec -i deployment/postgres -n rust-security -- \
  pg_restore -U auth_service -d auth_service_recovery \
    --clean --if-exists < "$BACKUP_FILE"

# Apply WAL logs up to recovery point
kubectl exec deployment/postgres -n rust-security -- \
  pg_ctl -D /var/lib/postgresql/data \
    -o "-c recovery_target_time='$RECOVERY_TIME'" \
    restart

echo "Point-in-time recovery completed"
```

### Configuration Backups
```bash
# Backup Kubernetes configurations
kubectl get all -n rust-security -o yaml > k8s-backup-$(date +%Y%m%d).yaml
kubectl get secrets -n rust-security -o yaml > secrets-backup-$(date +%Y%m%d).yaml
kubectl get configmaps -n rust-security -o yaml > configmaps-backup-$(date +%Y%m%d).yaml

# Backup application configurations
tar -czf config-backup-$(date +%Y%m%d).tar.gz config/ monitoring/ scripts/
```

## Security Operations

### Log Analysis

#### Security Event Monitoring
```bash
# Failed authentication attempts
kubectl logs deployment/auth-service -n rust-security | \
  grep -E "(authentication_failed|invalid_token|unauthorized)" | \
  tail -100

# Suspicious IP addresses
kubectl logs deployment/auth-service -n rust-security | \
  grep -E "authentication_failed" | \
  grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
  sort | uniq -c | sort -nr | head -20

# Token validation errors
kubectl logs deployment/auth-service -n rust-security | \
  grep -E "jwt_validation_error" | \
  tail -50
```

#### Audit Log Review
```bash
# Daily audit log analysis
kubectl logs deployment/auth-service -n rust-security | \
  grep -E "(admin_action|privilege_escalation|configuration_change)" | \
  jq -r '[.timestamp, .user_id, .action, .resource] | @tsv'

# Unusual access patterns
kubectl logs deployment/auth-service -n rust-security | \
  grep -E "unusual_access_pattern" | \
  jq -r '[.timestamp, .user_id, .ip_address, .risk_score] | @tsv'
```

### Compliance Reporting

#### Monthly Security Report
```bash
#!/bin/bash
# scripts/monthly-security-report.sh

MONTH=$(date +%Y-%m)
REPORT_FILE="security-report-${MONTH}.md"

cat > "$REPORT_FILE" << EOF
# Security Report - $MONTH

## Authentication Metrics
- Total authentication attempts: $(kubectl logs --since=720h deployment/auth-service -n rust-security | grep -c "authentication_attempt")
- Failed authentication attempts: $(kubectl logs --since=720h deployment/auth-service -n rust-security | grep -c "authentication_failed")
- Success rate: $(echo "scale=2; ($(kubectl logs --since=720h deployment/auth-service -n rust-security | grep -c "authentication_success") / $(kubectl logs --since=720h deployment/auth-service -n rust-security | grep -c "authentication_attempt")) * 100" | bc)%

## Security Incidents
- Blocked IP addresses: $(kubectl logs --since=720h deployment/auth-service -n rust-security | grep "ip_blocked" | wc -l)
- JWT validation errors: $(kubectl logs --since=720h deployment/auth-service -n rust-security | grep "jwt_validation_error" | wc -l)
- Unusual access patterns: $(kubectl logs --since=720h deployment/auth-service -n rust-security | grep "unusual_access_pattern" | wc -l)

## System Health
- Uptime: $(kubectl get pods -n rust-security --no-headers | awk '{print $4}' | head -1)
- Average response time: $(kubectl exec deployment/auth-service -n rust-security -- curl -s localhost:8080/metrics | grep auth_request_duration_seconds_sum)
- Error rate: $(kubectl exec deployment/auth-service -n rust-security -- curl -s localhost:8080/metrics | grep auth_requests_total | grep error)

## Compliance Status
- Data retention policy: ✅ Implemented (30-day log retention)
- Access logging: ✅ Enabled (all authentication events logged)
- Encryption: ✅ TLS 1.3 for all communications
- Backup schedule: ✅ Daily automated backups
EOF

echo "Security report generated: $REPORT_FILE"
```

## Disaster Recovery Procedures

### Complete System Recovery

#### Recovery Time Objectives (RTO)
- **Database Recovery**: 30 minutes
- **Application Services**: 15 minutes  
- **Full System**: 45 minutes
- **Data Loss (RPO)**: 1 hour maximum

#### Step-by-Step Recovery
```bash
#!/bin/bash
# scripts/disaster-recovery.sh

echo "=== DISASTER RECOVERY PROCEDURE ==="
echo "Starting at: $(date)"

# Step 1: Assess damage
echo "Step 1: Assessing system state..."
kubectl get nodes
kubectl get pods -n rust-security

# Step 2: Restore from backup if needed
if [ "$1" = "full-restore" ]; then
    echo "Step 2: Restoring from backup..."
    ./scripts/restore-from-backup.sh "$2"
fi

# Step 3: Deploy core infrastructure
echo "Step 3: Deploying infrastructure..."
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/redis.yaml

# Wait for infrastructure
kubectl wait --for=condition=ready pod -l app=postgres -n rust-security --timeout=300s
kubectl wait --for=condition=ready pod -l app=redis -n rust-security --timeout=300s

# Step 4: Deploy application services
echo "Step 4: Deploying application services..."
kubectl apply -f k8s/auth-service.yaml
kubectl apply -f k8s/policy-service.yaml

# Wait for applications
kubectl wait --for=condition=ready pod -l app=auth-service -n rust-security --timeout=300s
kubectl wait --for=condition=ready pod -l app=policy-service -n rust-security --timeout=300s

# Step 5: Validate functionality
echo "Step 5: Validating system functionality..."
./validate-services.sh

# Step 6: Resume monitoring
echo "Step 6: Resuming monitoring..."
kubectl apply -f k8s/monitoring.yaml

echo "=== DISASTER RECOVERY COMPLETE ==="
echo "Completed at: $(date)"
```

### Communication Templates

#### Incident Communication
```markdown
# Incident Status Update

**Status**: [INVESTIGATING/IDENTIFIED/MONITORING/RESOLVED]
**Severity**: [LOW/MEDIUM/HIGH/CRITICAL]
**Started**: YYYY-MM-DD HH:MM UTC
**Duration**: X minutes

## Impact
- Services affected: [List services]
- User impact: [Describe impact]
- Estimated affected users: [Number or percentage]

## Current Status
[Description of current situation and actions being taken]

## Next Update
Next update will be provided in [X] minutes or when status changes.

**Incident Commander**: [Name]
**Communication Lead**: [Name]
```

#### Post-Incident Report Template
```markdown
# Post-Incident Report

**Incident ID**: INC-YYYY-NNNN
**Date**: YYYY-MM-DD
**Duration**: X hours Y minutes
**Severity**: [CRITICAL/HIGH/MEDIUM/LOW]

## Executive Summary
[Brief description of what happened and impact]

## Timeline
- **HH:MM** - Issue first detected
- **HH:MM** - Investigation started
- **HH:MM** - Root cause identified
- **HH:MM** - Fix implemented
- **HH:MM** - Service restored
- **HH:MM** - Monitoring resumed

## Root Cause
[Detailed explanation of what caused the incident]

## Impact
- **Users Affected**: X users (Y% of total)
- **Services Impacted**: [List]
- **Data Loss**: None/[Description]
- **Financial Impact**: $X (estimated)

## Resolution
[Description of how the issue was resolved]

## Action Items
1. [ ] [Action item 1] - Owner: [Name] - Due: [Date]
2. [ ] [Action item 2] - Owner: [Name] - Due: [Date]

## Lessons Learned
- [Lesson 1]
- [Lesson 2]

## Prevention Measures
- [Measure 1]
- [Measure 2]
```

This comprehensive operations runbook provides the essential procedures, scripts, and templates needed to maintain, monitor, and recover the Rust Security Platform in production environments.