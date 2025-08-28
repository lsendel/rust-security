# Troubleshooting Guide

## Overview

This comprehensive troubleshooting guide helps diagnose and resolve common issues encountered when deploying, operating, and integrating with the Rust Security Platform. Each section provides symptoms, root causes, and step-by-step resolution procedures.

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Service-Specific Issues](#service-specific-issues)
3. [Integration Issues](#integration-issues)
4. [Performance Issues](#performance-issues)
5. [Monitoring and Alerting Issues](#monitoring-and-alerting-issues)
6. [Recovery Procedures](#recovery-procedures)

## Quick Diagnostics

### Health Check Script
```bash
#!/bin/bash
# scripts/quick-diagnostics.sh

echo "=== Rust Security Platform Diagnostics ==="
echo "Started at: $(date)"
echo

# Check service availability
check_service_health() {
    local service="$1"
    local url="$2"
    
    echo -n "Checking $service... "
    if curl -f -s -m 10 "$url" > /dev/null; then
        echo "✅ OK"
        return 0
    else
        echo "❌ FAILED"
        return 1
    fi
}

# Basic health checks
echo "=== Service Health ==="
check_service_health "Auth Service" "http://localhost:8080/health"
check_service_health "Policy Service" "http://localhost:8081/health"
check_service_health "Dashboard" "http://localhost:3000"

# Database connectivity
echo
echo "=== Database Connectivity ==="
if command -v psql &> /dev/null; then
    echo -n "PostgreSQL connection... "
    if psql "$DATABASE_URL" -c "SELECT 1;" > /dev/null 2>&1; then
        echo "✅ OK"
    else
        echo "❌ FAILED"
    fi
else
    echo "psql not available, skipping database check"
fi

# Redis connectivity
echo -n "Redis connection... "
if redis-cli ping > /dev/null 2>&1; then
    echo "✅ OK"
else
    echo "❌ FAILED"
fi

# Port availability
echo
echo "=== Port Status ==="
for port in 8080 8081 5432 6379; do
    echo -n "Port $port... "
    if lsof -i :$port > /dev/null 2>&1; then
        echo "✅ OPEN"
    else
        echo "❌ CLOSED"
    fi
done

# Log recent errors
echo
echo "=== Recent Errors ==="
if [ -f /var/log/auth-service.log ]; then
    echo "Recent auth service errors:"
    tail -10 /var/log/auth-service.log | grep -i error || echo "No recent errors"
else
    echo "Auth service log not found"
fi

echo
echo "Diagnostics completed at: $(date)"
```

### System Information Collection
```bash
#!/bin/bash
# scripts/collect-system-info.sh

REPORT_DIR="diagnostics-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$REPORT_DIR"

echo "Collecting system information in: $REPORT_DIR"

# System information
uname -a > "$REPORT_DIR/system-info.txt"
cat /etc/os-release >> "$REPORT_DIR/system-info.txt"

# Resource usage
top -b -n 1 > "$REPORT_DIR/top-output.txt"
free -h > "$REPORT_DIR/memory-usage.txt"
df -h > "$REPORT_DIR/disk-usage.txt"

# Network information
netstat -tlnp > "$REPORT_DIR/network-ports.txt"
ss -tlnp >> "$REPORT_DIR/network-ports.txt"

# Process information
ps aux | grep -E "(auth-service|policy-service|postgres|redis)" > "$REPORT_DIR/processes.txt"

# Service logs (last 100 lines)
if [ -f /var/log/auth-service.log ]; then
    tail -100 /var/log/auth-service.log > "$REPORT_DIR/auth-service.log"
fi
if [ -f /var/log/policy-service.log ]; then
    tail -100 /var/log/policy-service.log > "$REPORT_DIR/policy-service.log"
fi

# Configuration files (sanitized)
if [ -f .env ]; then
    grep -v -E "(SECRET|PASSWORD|KEY)" .env > "$REPORT_DIR/config-sanitized.txt"
fi

# Docker/Kubernetes information
if command -v docker &> /dev/null; then
    docker ps > "$REPORT_DIR/docker-containers.txt"
    docker stats --no-stream >> "$REPORT_DIR/docker-containers.txt"
fi

if command -v kubectl &> /dev/null; then
    kubectl get pods -n rust-security > "$REPORT_DIR/k8s-pods.txt"
    kubectl get services -n rust-security >> "$REPORT_DIR/k8s-services.txt"
    kubectl describe pods -n rust-security >> "$REPORT_DIR/k8s-pod-details.txt"
fi

echo "System information collected in: $REPORT_DIR"
```

## Service-Specific Issues

### Authentication Service Issues

#### Issue: Service Won't Start
**Symptoms:**
- Service exits immediately after startup
- "Connection refused" errors when accessing endpoints
- Process not visible in `ps aux`

**Common Causes & Solutions:**

1. **Configuration Issues**
```bash
# Check configuration
cat .env | grep -E "(DATABASE_URL|REDIS_URL|JWT_SECRET)"

# Validate environment variables
echo "DATABASE_URL: ${DATABASE_URL}"
echo "REDIS_URL: ${REDIS_URL}" 
echo "JWT_SECRET length: ${#JWT_SECRET}"

# Common fixes:
# - Ensure JWT_SECRET is at least 32 characters
# - Verify database connection string format
# - Check Redis URL format
export JWT_SECRET="$(openssl rand -base64 32)"
export DATABASE_URL="postgres://user:password@localhost:5432/dbname"
export REDIS_URL="redis://localhost:6379"
```

2. **Port Already in Use**
```bash
# Check what's using port 8080
sudo lsof -i :8080
sudo netstat -tlnp | grep :8080

# Kill process using the port
sudo kill -9 $(sudo lsof -ti:8080)

# Or use different port
export PORT=8081
cargo run --bin auth-service
```

3. **Database Connection Issues**
```bash
# Test database connectivity
psql "$DATABASE_URL" -c "SELECT version();"

# Check if database exists
psql -h localhost -U postgres -l | grep auth_service

# Create database if missing
createdb auth_service

# Run migrations
cd auth-service
sqlx migrate run
```

#### Issue: High Memory Usage
**Symptoms:**
- Service consuming >4GB RAM
- System swapping heavily
- OOM (Out of Memory) killer terminating service

**Diagnosis & Solutions:**

1. **Check Memory Usage**
```bash
# Monitor memory usage
top -p $(pgrep auth-service)
sudo cat /proc/$(pgrep auth-service)/status | grep -E "(VmSize|VmRSS|VmData)"

# Check for memory leaks
valgrind --tool=memcheck --leak-check=yes ./target/debug/auth-service
```

2. **Database Connection Pool Tuning**
```rust
// In config.rs - reduce connection pool size
#[derive(Deserialize, Clone)]
pub struct DatabaseConfig {
    pub max_connections: u32,      // Reduce from 20 to 10
    pub min_connections: u32,      // Reduce from 5 to 2
    pub acquire_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}
```

3. **JWT Token Cache Optimization**
```rust
// Implement token cache cleanup
impl JwtCache {
    pub async fn cleanup_expired(&self) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();
        
        cache.retain(|_, (_, timestamp)| {
            now.duration_since(*timestamp) < self.ttl
        });
    }
    
    // Run cleanup periodically
    pub fn start_cleanup_task(&self) {
        let cache = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                cache.cleanup_expired().await;
            }
        });
    }
}
```

#### Issue: Slow Response Times
**Symptoms:**
- API responses taking >2 seconds
- High CPU usage during requests
- Database query timeouts

**Performance Optimization:**

1. **Database Query Analysis**
```sql
-- Enable slow query logging
ALTER SYSTEM SET log_min_duration_statement = 1000; -- Log queries > 1s
SELECT pg_reload_conf();

-- Check slow queries
SELECT query, calls, total_time, mean_time, rows 
FROM pg_stat_statements 
ORDER BY mean_time DESC LIMIT 10;

-- Add missing indexes
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_sessions_user_id ON sessions(user_id);
CREATE INDEX CONCURRENTLY idx_sessions_expires_at ON sessions(expires_at);
```

2. **Connection Pool Optimization**
```rust
// Optimize database pool configuration
impl DatabaseConfig {
    pub fn production() -> Self {
        Self {
            max_connections: 20,
            min_connections: 5,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),     // 10 minutes
            max_lifetime: Duration::from_secs(1800),    // 30 minutes
        }
    }
}
```

### Policy Service Issues

#### Issue: Policy Evaluation Errors
**Symptoms:**
- 500 errors on `/authorize` endpoint
- "Policy evaluation failed" in logs
- Requests timing out

**Troubleshooting Steps:**

1. **Validate Policy Syntax**
```bash
# Check Cedar policy syntax
cedar validate --policies policy-service/policies.cedar --schema policy-service/schema.json

# Test policy with sample data
cedar authorize \
  --policies policy-service/policies.cedar \
  --entities policy-service/entities.json \
  --principal 'User::"alice"' \
  --action 'Action::"read"' \
  --resource 'Document::"doc123"'
```

2. **Debug Policy Evaluation**
```rust
// Add detailed logging to policy evaluation
impl PolicyService {
    pub async fn evaluate_policy(&self, request: &AuthorizationRequest) -> Result<Decision> {
        debug!("Evaluating policy for: {:?}", request);
        
        let start_time = Instant::now();
        
        match self.authorizer.is_authorized(&request.principal, &request.action, &request.resource, &self.entities) {
            Ok(decision) => {
                let duration = start_time.elapsed();
                info!("Policy evaluation completed in {:?}: {:?}", duration, decision);
                Ok(decision)
            }
            Err(e) => {
                error!("Policy evaluation failed: {:?}", e);
                error!("Request details: {:?}", request);
                Err(PolicyError::EvaluationFailed(e.to_string()))
            }
        }
    }
}
```

### Database Issues

#### Issue: Connection Pool Exhaustion
**Symptoms:**
- "Connection pool exhausted" errors
- Long wait times for database operations
- Service becomes unresponsive

**Solutions:**

1. **Monitor Connection Usage**
```sql
-- Check active connections
SELECT count(*) as active_connections 
FROM pg_stat_activity 
WHERE state = 'active' AND backend_type = 'client backend';

-- Check connection by application
SELECT application_name, count(*) as connections
FROM pg_stat_activity 
WHERE backend_type = 'client backend'
GROUP BY application_name;

-- Check long-running queries
SELECT pid, now() - pg_stat_activity.query_start AS duration, query 
FROM pg_stat_activity 
WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes'
AND state = 'active';
```

2. **Optimize Connection Pool Settings**
```rust
// Adjust pool configuration based on load
pub fn configure_db_pool(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(50)           // Increase max connections
        .min_connections(10)           // Maintain minimum connections
        .acquire_timeout(Duration::from_secs(60)) // Increase timeout
        .idle_timeout(Some(Duration::from_secs(300))) // Close idle connections
        .max_lifetime(Some(Duration::from_secs(1800))) // Recycle connections
        .test_before_acquire(true)     // Validate connections
        .connect(database_url)
        .await
}
```

## Integration Issues

### JWT Token Issues

#### Issue: Token Validation Failures
**Symptoms:**
- "Invalid token" errors in client applications
- Authentication working in auth service but failing in downstream services
- Intermittent token validation failures

**Debugging Steps:**

1. **Validate Token Structure**
```bash
# Decode JWT token (without verification)
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." | cut -d'.' -f2 | base64 -d | jq .

# Check token expiration
TOKEN="your_jwt_token_here"
PAYLOAD=$(echo $TOKEN | cut -d'.' -f2 | base64 -d)
EXPIRY=$(echo $PAYLOAD | jq -r '.exp')
CURRENT=$(date +%s)
echo "Token expires at: $(date -d @$EXPIRY)"
echo "Current time: $(date -d @$CURRENT)"
if [ $EXPIRY -lt $CURRENT ]; then
    echo "❌ Token expired"
else
    echo "✅ Token valid"
fi
```

2. **JWKS Endpoint Validation**
```bash
# Check JWKS endpoint
curl -s https://auth.company.com/.well-known/jwks.json | jq .

# Validate key ID matches
TOKEN_HEADER=$(echo $TOKEN | cut -d'.' -f1 | base64 -d)
TOKEN_KID=$(echo $TOKEN_HEADER | jq -r '.kid')
JWKS_KIDS=$(curl -s https://auth.company.com/.well-known/jwks.json | jq -r '.keys[].kid')

echo "Token KID: $TOKEN_KID"
echo "Available KIDs: $JWKS_KIDS"
```

3. **Clock Skew Issues**
```rust
// Add clock skew tolerance
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

pub fn create_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["https://auth.company.com"]);
    validation.set_audience(&["your-audience"]);
    validation.leeway = 60; // 60 seconds clock skew tolerance
    validation
}
```

#### Issue: CORS Problems
**Symptoms:**
- Browser blocking requests to auth service
- "Access-Control-Allow-Origin" errors
- Authentication working in backend but failing in frontend

**Solutions:**

1. **Configure CORS Properly**
```rust
use tower_http::cors::{CorsLayer, Any};
use axum::http::{HeaderValue, Method};

pub fn create_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin([
            "https://app.company.com".parse::<HeaderValue>().unwrap(),
            "https://admin.company.com".parse::<HeaderValue>().unwrap(),
            "http://localhost:3000".parse::<HeaderValue>().unwrap(), // Development
        ])
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([
            "Authorization",
            "Content-Type",
            "X-Requested-With",
        ])
        .allow_credentials(true)
        .max_age(Duration::from_secs(3600))
}
```

## Performance Issues

### High CPU Usage

#### Diagnosis
```bash
# Monitor CPU usage by process
top -p $(pgrep -d, auth-service)

# Detailed CPU profiling
perf record -g ./target/release/auth-service
perf report

# Rust-specific profiling
cargo install flamegraph
sudo flamegraph --bin auth-service
```

#### Common Causes & Solutions

1. **Expensive Cryptographic Operations**
```rust
// Use async for CPU-intensive operations
pub async fn hash_password(&self, password: &str) -> Result<String> {
    let password = password.to_owned();
    let config = self.config.clone();
    
    tokio::task::spawn_blocking(move || {
        argon2::hash_encoded(password.as_bytes(), &[0; 16], &config)
    }).await?
}
```

### Memory Leaks

#### Detection
```bash
# Monitor memory usage over time
while true; do
    ps -p $(pgrep auth-service) -o pid,vsz,rss,pmem,time,comm
    sleep 60
done

# Use Valgrind for detailed analysis
valgrind --tool=memcheck --leak-check=full ./target/debug/auth-service
```

#### Common Leak Sources
```rust
// Fix: Properly clean up async tasks
pub struct TaskManager {
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl TaskManager {
    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let handle = tokio::spawn(future);
        self.tasks.lock().unwrap().push(handle);
        handle
    }
    
    pub async fn shutdown(&self) {
        let mut tasks = self.tasks.lock().unwrap();
        for task in tasks.drain(..) {
            task.abort();
            let _ = task.await; // Ignore cancellation errors
        }
    }
}
```

## Monitoring and Alerting Issues

### Metrics Not Being Collected

#### Issue: Prometheus Not Scraping Metrics
**Symptoms:**
- Missing metrics in Prometheus
- "Targets down" in Prometheus UI
- Grafana dashboards showing no data

**Solutions:**

1. **Check Service Discovery**
```bash
# Verify Prometheus can reach the service
curl http://auth-service:8080/metrics

# Check Prometheus configuration
kubectl get configmap prometheus-config -o yaml

# Check service endpoints
kubectl get endpoints auth-service
```

2. **Fix Metrics Endpoint**
```rust
// Ensure metrics endpoint is properly configured
use axum::{routing::get, Router};
use prometheus::{Encoder, TextEncoder, gather};

pub async fn metrics_handler() -> Result<String, AppError> {
    let encoder = TextEncoder::new();
    let metric_families = gather();
    
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)
        .map_err(|e| AppError::MetricsError(e.to_string()))?;
    
    String::from_utf8(buffer)
        .map_err(|e| AppError::MetricsError(e.to_string()))
}

// Add to router
let app = Router::new()
    .route("/metrics", get(metrics_handler))
    .route("/health", get(health_check));
```

## Recovery Procedures

### Service Recovery
```bash
#!/bin/bash
# Emergency service recovery script

SERVICE="$1"
case "$SERVICE" in
    "auth-service")
        echo "Recovering auth service..."
        # Restart service
        systemctl restart auth-service
        
        # Wait for health check
        for i in {1..30}; do
            if curl -f http://localhost:8080/health; then
                echo "✅ Auth service recovered"
                break
            fi
            echo "Waiting for service... ($i/30)"
            sleep 5
        done
        ;;
        
    "database")
        echo "Recovering database..."
        # Check if PostgreSQL is running
        if ! pg_isready; then
            systemctl restart postgresql
        fi
        
        # Check for corruption
        sudo -u postgres pg_checksums -D /var/lib/postgresql/data
        ;;
        
    "redis")
        echo "Recovering Redis..."
        systemctl restart redis
        redis-cli ping
        ;;
        
    *)
        echo "Usage: $0 {auth-service|database|redis}"
        exit 1
        ;;
esac
```

### Data Recovery
```bash
#!/bin/bash
# Database recovery from backup

BACKUP_FILE="$1"
RECOVERY_TIME="$2"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file> [recovery_time]"
    exit 1
fi

echo "Starting database recovery..."

# Stop services that use the database
systemctl stop auth-service policy-service

# Create recovery database
createdb auth_service_recovery

# Restore from backup
if [[ "$BACKUP_FILE" == *.sql ]]; then
    psql auth_service_recovery < "$BACKUP_FILE"
elif [[ "$BACKUP_FILE" == *.backup ]]; then
    pg_restore -d auth_service_recovery "$BACKUP_FILE"
else
    echo "Unsupported backup format"
    exit 1
fi

# Point-in-time recovery if specified
if [ -n "$RECOVERY_TIME" ]; then
    echo "Applying point-in-time recovery to: $RECOVERY_TIME"
    # This requires WAL files and PostgreSQL archive recovery
fi

# Swap databases
psql -c "ALTER DATABASE auth_service RENAME TO auth_service_old;"
psql -c "ALTER DATABASE auth_service_recovery RENAME TO auth_service;"

# Restart services
systemctl start auth-service policy-service

echo "Database recovery completed"
```

This comprehensive troubleshooting guide should help resolve the vast majority of issues encountered when operating the Rust Security Platform. For issues not covered here, collect diagnostic information using the provided scripts and consult the development team.