# Rust Security Platform - Production Deployment Checklist

## Pre-deployment Security Validation

### 1. Code Security Review
- [ ] **Dependency Audit**: Run `cargo audit` to check for known vulnerabilities
- [ ] **License Compliance**: Verify all dependencies have compatible licenses
- [ ] **Static Analysis**: Run Clippy with security lints enabled
- [ ] **Secret Scanning**: Ensure no hardcoded secrets in codebase

```bash
# Security validation commands
cargo audit
cargo clippy -- -D warnings
grep -r "password\|secret\|key" --include="*.rs" . | grep -v "test"
```

### 2. Security Configuration Validation
- [ ] **Environment Variables**: All required security environment variables set
- [ ] **TLS Configuration**: TLS 1.3 enforced, secure cipher suites configured
- [ ] **CORS Settings**: Allowed origins explicitly configured (no wildcards)
- [ ] **Rate Limiting**: Production-appropriate rate limits configured

### 3. Cryptographic Standards
- [ ] **RSA Key Size**: Minimum 4096-bit RSA keys for JWT signing
- [ ] **EdDSA Migration**: JWT signing configured to use EdDSA where possible
- [ ] **Password Policy**: Strong password requirements enforced
- [ ] **Token TTL**: Production-appropriate token expiration times

## Environment Configuration Requirements

### Essential Environment Variables

```bash
# Required for Production
export ENVIRONMENT=production
export FORCE_HTTPS=true
export DATABASE_URL=postgresql://auth_service:${DB_PASSWORD}@${DB_HOST}:5432/auth_db
export REDIS_URL=redis://:${REDIS_PASSWORD}@${REDIS_HOST}:6379
export REQUEST_SIGNING_SECRET=${STRONG_SECRET_32_CHARS_MIN}

# Security Configuration
export ALLOWED_ORIGINS=https://yourdomain.com,https://api.yourdomain.com
export JWT_ACCESS_TOKEN_TTL_SECONDS=600        # 10 minutes
export JWT_REFRESH_TOKEN_TTL_SECONDS=86400     # 24 hours
export SESSION_TTL_SECONDS=1800                # 30 minutes
export SESSION_ROTATION_INTERVAL_SECONDS=600   # 10 minutes

# Rate Limiting (Production Strict)
export RATE_LIMIT_REQUESTS_PER_MINUTE_GLOBAL=1000
export RATE_LIMIT_REQUESTS_PER_MINUTE_PER_IP=60
export OAUTH_REQUESTS_PER_MINUTE=5
export ADMIN_REQUESTS_PER_MINUTE=2

# TLS Configuration
export TLS_MIN_VERSION=1.3
export TLS_CERT_PATH=/etc/ssl/certs/auth-service.pem
export TLS_KEY_PATH=/etc/ssl/private/auth-service.key

# Monitoring
export PROMETHEUS_METRICS_ENABLED=true
export OPENTELEMETRY_ENABLED=true
export JAEGER_ENDPOINT=http://jaeger:14268/api/traces
export LOG_LEVEL=info
export SECURITY_LOG_LEVEL=warn

# Feature Flags (Production Defaults)
export MFA_ENABLED=true
export WEBAUTHN_ENABLED=false                  # Until fully tested
export OAUTH_DYNAMIC_REGISTRATION=false
export ADMIN_API_ENABLED=false                 # Enable only when needed
export DEBUG_ENDPOINTS_ENABLED=false           # Never in production
```

### Configuration Validation Script

```bash
#!/bin/bash
# config-validation.sh

echo "=== Rust Security Platform Configuration Validation ==="

# Check required environment variables
required_vars=(
    "ENVIRONMENT" "DATABASE_URL" "REDIS_URL" "REQUEST_SIGNING_SECRET"
    "ALLOWED_ORIGINS" "FORCE_HTTPS"
)

for var in "${required_vars[@]}"; do
    if [[ -z "${!var}" ]]; then
        echo "❌ Missing required environment variable: $var"
        exit 1
    else
        echo "✅ $var is set"
    fi
done

# Validate secret strength
if [[ ${#REQUEST_SIGNING_SECRET} -lt 32 ]]; then
    echo "❌ REQUEST_SIGNING_SECRET must be at least 32 characters"
    exit 1
fi

# Validate HTTPS enforcement
if [[ "$ENVIRONMENT" == "production" && "$FORCE_HTTPS" != "true" ]]; then
    echo "❌ HTTPS must be enforced in production"
    exit 1
fi

# Validate CORS origins
if [[ "$ALLOWED_ORIGINS" == *"*"* ]]; then
    echo "❌ Wildcard CORS origins not allowed in production"
    exit 1
fi

echo "✅ Configuration validation passed"
```

## Database Setup and Migration Steps

### 1. Database Preparation

```bash
# Create database user and database
sudo -u postgres psql << EOF
CREATE USER auth_service WITH PASSWORD '${DB_PASSWORD}';
CREATE DATABASE auth_db OWNER auth_service;
GRANT ALL PRIVILEGES ON DATABASE auth_db TO auth_service;

# Enable required extensions
\c auth_db
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
EOF
```

### 2. Connection Pool Configuration

```bash
# Database connection pool settings
export DB_MAX_CONNECTIONS_AUTH=30      # High throughput for auth
export DB_MAX_CONNECTIONS_SESSION=15   # Moderate for sessions
export DB_MAX_CONNECTIONS_AUDIT=10     # Moderate for audit

export DB_ACQUIRE_TIMEOUT=100          # 100ms for auth operations
export DB_MAX_LIFETIME=1800            # 30 minutes
export DB_IDLE_TIMEOUT=600             # 10 minutes
```

### 3. Run Database Migrations

```bash
# Install sqlx-cli if not present
cargo install sqlx-cli --features postgres

# Run migrations
cd auth-service
sqlx migrate run --database-url $DATABASE_URL

# Verify schema
sqlx migrate info --database-url $DATABASE_URL
```

### 4. Database Performance Optimization

```sql
-- Apply these settings to the database
ALTER SYSTEM SET work_mem = '64MB';
ALTER SYSTEM SET maintenance_work_mem = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;
SELECT pg_reload_conf();
```

### 5. Database Validation

```bash
# Test database connectivity
psql $DATABASE_URL -c "SELECT version();"

# Validate schema
psql $DATABASE_URL -c "SELECT table_name FROM information_schema.tables WHERE table_schema='public';"

# Test cleanup function
psql $DATABASE_URL -c "SELECT cleanup_expired_data();"
```

## Security Feature Activation

### 1. JWT Security Configuration

```bash
# Verify JWT signing algorithm preference
export JWT_ALGORITHM_PREFERENCE=EdDSA,RS256,HS256

# Generate or import signing keys
openssl genpkey -algorithm Ed25519 -out jwt_ed25519_private.pem
openssl pkey -in jwt_ed25519_private.pem -pubout -out jwt_ed25519_public.pem

# For RSA fallback (4096-bit minimum)
openssl genpkey -algorithm RSA -pkcs8 -pkeyopt rsa_keygen_bits:4096 -out jwt_rsa_private.pem
openssl rsa -in jwt_rsa_private.pem -pubout -out jwt_rsa_public.pem
```

### 2. CSRF Protection

```bash
# CSRF is enabled by default in production
export CSRF_ENABLED=true
export CSRF_TOKEN_TTL=3600  # 1 hour
export CSRF_HEADER=X-CSRF-Token
export CSRF_COOKIE=csrf_token
```

### 3. Rate Limiting Configuration

```bash
# Global rate limits
export RATE_LIMITING_ENABLED=true
export ENABLE_ADAPTIVE_LIMITING=true
export SUSPICIOUS_ACTIVITY_THRESHOLD=3
export BAN_THRESHOLD=5
export BAN_DURATION_MINUTES=15

# IP allowlist/blocklist (comma-separated)
export ALLOWLIST_IPS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
export BLOCKLIST_IPS=  # Set known malicious IPs
```

### 4. Security Headers

```bash
# Security headers are enforced by default
export HSTS_MAX_AGE=31536000  # 1 year
export CSP_POLICY="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'none';"
```

### 5. Request Validation

```bash
export INPUT_VALIDATION_ENABLED=true
export MAX_REQUEST_BODY_SIZE=1048576  # 1MB
export REQUEST_TIMESTAMP_WINDOW_SECONDS=300  # 5 minutes
```

## Performance Optimization Settings

### 1. Connection Pool Tuning

```bash
# Optimized for high-concurrency production workloads
export CONNECTION_POOL_PREPARED_STATEMENTS=true
export CONNECTION_POOL_HEALTH_CHECK_INTERVAL=60

# Pool-specific configurations
export AUTH_POOL_MIN_CONNECTIONS=5
export AUTH_POOL_MAX_CONNECTIONS=30
export SESSION_POOL_MIN_CONNECTIONS=2
export SESSION_POOL_MAX_CONNECTIONS=15
export AUDIT_POOL_MIN_CONNECTIONS=2
export AUDIT_POOL_MAX_CONNECTIONS=10
```

### 2. Caching Configuration

```bash
# Redis caching settings
export REDIS_MAX_CONNECTIONS=20
export REDIS_CONNECTION_TIMEOUT=5000    # 5 seconds
export REDIS_RESPONSE_TIMEOUT=10000     # 10 seconds
export REDIS_MIN_IDLE=5
export REDIS_MAX_IDLE=15

# Cache TTL settings
export CACHE_USER_SESSIONS_TTL=1800     # 30 minutes
export CACHE_OAUTH_CODES_TTL=600        # 10 minutes
export CACHE_RATE_LIMIT_WINDOW=60       # 1 minute
```

### 3. HTTP Server Optimization

```bash
# Server performance tuning
export SERVER_WORKER_THREADS=0          # Auto-detect CPU cores
export SERVER_MAX_CONNECTIONS=10000
export SERVER_KEEPALIVE_TIMEOUT=75      # 75 seconds
export SERVER_REQUEST_TIMEOUT=30        # 30 seconds
export SERVER_GRACEFUL_SHUTDOWN_TIMEOUT=30  # 30 seconds
```

## Monitoring and Alerting Configuration

### 1. Prometheus Metrics

```bash
export PROMETHEUS_METRICS_ENABLED=true
export METRICS_SCRAPE_INTERVAL_SECONDS=30
export PROMETHEUS_ENDPOINT=0.0.0.0:9090
```

### 2. OpenTelemetry Tracing

```bash
export OPENTELEMETRY_ENABLED=true
export OTEL_SERVICE_NAME=rust-auth-service
export OTEL_SERVICE_VERSION=1.0.0
export JAEGER_ENDPOINT=http://jaeger:14268/api/traces
export OTEL_EXPORTER_JAEGER_TIMEOUT=30
```

### 3. Security Monitoring

```bash
export SECURITY_MONITORING_ENABLED=true
export AUDIT_LOGGING_ENABLED=true
export PERFORMANCE_MONITORING_ENABLED=true

# Alert thresholds
export ALERT_FAILED_LOGIN_THRESHOLD=10
export ALERT_RATE_LIMIT_HIT_THRESHOLD=100
export ALERT_SUSPICIOUS_ACTIVITY_THRESHOLD=5
export ALERT_DATABASE_CONNECTION_FAILURE=true
```

### 4. Structured Logging

```bash
export RUST_LOG=info
export RUST_LOG_FORMAT=json
export LOG_LEVEL=info
export SECURITY_LOG_LEVEL=warn

# Log destinations
export LOG_FILE=/var/log/auth-service/app.log
export SECURITY_LOG_FILE=/var/log/auth-service/security.log
export AUDIT_LOG_FILE=/var/log/auth-service/audit.log
```

## Post-deployment Verification Steps

### 1. Health Checks

```bash
#!/bin/bash
# health-check.sh

API_BASE_URL="${API_BASE_URL:-https://auth-service:8080}"

echo "=== Post-Deployment Health Checks ==="

# Basic health endpoint
echo "Testing health endpoint..."
response=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE_URL/health")
if [[ "$response" == "200" ]]; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed (HTTP $response)"
    exit 1
fi

# Database connectivity
echo "Testing database connectivity..."
response=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE_URL/health/database")
if [[ "$response" == "200" ]]; then
    echo "✅ Database connectivity check passed"
else
    echo "❌ Database connectivity check failed"
    exit 1
fi

# Redis connectivity
echo "Testing Redis connectivity..."
response=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE_URL/health/redis")
if [[ "$response" == "200" ]]; then
    echo "✅ Redis connectivity check passed"
else
    echo "❌ Redis connectivity check failed"
    exit 1
fi
```

### 2. Security Header Validation

```bash
#!/bin/bash
# security-headers-check.sh

API_BASE_URL="${API_BASE_URL:-https://auth-service:8080}"

echo "=== Security Headers Validation ==="

# Check security headers
headers=$(curl -s -I "$API_BASE_URL/health")

required_headers=(
    "Strict-Transport-Security"
    "X-Content-Type-Options: nosniff"
    "X-Frame-Options: DENY"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Referrer-Policy"
)

for header in "${required_headers[@]}"; do
    if echo "$headers" | grep -qi "$header"; then
        echo "✅ $header present"
    else
        echo "❌ $header missing"
        exit 1
    fi
done
```

### 3. OAuth Flow Testing

```bash
#!/bin/bash
# oauth-flow-test.sh

API_BASE_URL="${API_BASE_URL:-https://auth-service:8080}"
CLIENT_ID="${TEST_CLIENT_ID}"
REDIRECT_URI="${TEST_REDIRECT_URI:-https://example.com/callback}"

echo "=== OAuth Flow Testing ==="

# Test authorization endpoint
auth_url="$API_BASE_URL/oauth/authorize?client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&response_type=code&scope=openid"
response=$(curl -s -o /dev/null -w "%{http_code}" "$auth_url")

if [[ "$response" == "302" || "$response" == "200" ]]; then
    echo "✅ OAuth authorization endpoint accessible"
else
    echo "❌ OAuth authorization endpoint failed (HTTP $response)"
    exit 1
fi

# Test OpenID Connect discovery
discovery_response=$(curl -s "$API_BASE_URL/.well-known/openid-configuration")
if echo "$discovery_response" | jq -e '.issuer' > /dev/null 2>&1; then
    echo "✅ OpenID Connect discovery endpoint working"
else
    echo "❌ OpenID Connect discovery endpoint failed"
    exit 1
fi
```

### 4. Performance Testing

```bash
#!/bin/bash
# performance-test.sh

API_BASE_URL="${API_BASE_URL:-https://auth-service:8080}"

echo "=== Performance Testing ==="

# Load test with curl (basic)
echo "Running basic load test..."
for i in {1..10}; do
    response_time=$(curl -s -o /dev/null -w "%{time_total}" "$API_BASE_URL/health")
    echo "Request $i: ${response_time}s"
    
    # Fail if response time > 5 seconds
    if (( $(echo "$response_time > 5.0" | bc -l) )); then
        echo "❌ Response time too high: ${response_time}s"
        exit 1
    fi
done

echo "✅ Basic performance test passed"
```

### 5. Rate Limiting Verification

```bash
#!/bin/bash
# rate-limit-test.sh

API_BASE_URL="${API_BASE_URL:-https://auth-service:8080}"

echo "=== Rate Limiting Testing ==="

# Test rate limiting (should get 429 after hitting limit)
success_count=0
rate_limited=false

for i in {1..70}; do  # Test above per-minute IP limit
    response=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE_URL/health")
    
    if [[ "$response" == "200" ]]; then
        ((success_count++))
    elif [[ "$response" == "429" ]]; then
        rate_limited=true
        break
    fi
    
    sleep 0.1  # Small delay between requests
done

if [[ "$rate_limited" == true ]]; then
    echo "✅ Rate limiting is working (got 429 after $success_count requests)"
else
    echo "❌ Rate limiting may not be working correctly"
fi
```

## Rollback Procedures

### 1. Quick Rollback Script

```bash
#!/bin/bash
# rollback.sh

set -e

BACKUP_VERSION="${1:-previous}"
API_BASE_URL="${API_BASE_URL:-https://auth-service:8080}"

echo "=== Emergency Rollback Procedure ==="
echo "Rolling back to version: $BACKUP_VERSION"

# 1. Stop the current service
echo "Stopping current service..."
systemctl stop auth-service

# 2. Restore previous binary
echo "Restoring previous binary..."
cp "/opt/auth-service/backups/auth-service-$BACKUP_VERSION" /opt/auth-service/auth-service
chmod +x /opt/auth-service/auth-service

# 3. Restore previous configuration if needed
if [[ -f "/opt/auth-service/backups/config-$BACKUP_VERSION.env" ]]; then
    echo "Restoring previous configuration..."
    cp "/opt/auth-service/backups/config-$BACKUP_VERSION.env" /opt/auth-service/config.env
fi

# 4. Database rollback (if needed)
if [[ -f "/opt/auth-service/backups/rollback-$BACKUP_VERSION.sql" ]]; then
    echo "Rolling back database changes..."
    psql $DATABASE_URL -f "/opt/auth-service/backups/rollback-$BACKUP_VERSION.sql"
fi

# 5. Start the service
echo "Starting rolled-back service..."
systemctl start auth-service

# 6. Verify rollback success
echo "Verifying rollback..."
sleep 10  # Wait for startup

response=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE_URL/health")
if [[ "$response" == "200" ]]; then
    echo "✅ Rollback successful"
else
    echo "❌ Rollback verification failed"
    exit 1
fi
```

### 2. Database Rollback Templates

```sql
-- rollback-template.sql
-- Template for database rollbacks

BEGIN;

-- Example: Rollback table changes
-- DROP TABLE IF EXISTS new_table_added_in_version;

-- Example: Rollback column additions
-- ALTER TABLE users DROP COLUMN IF EXISTS new_column;

-- Example: Rollback index changes
-- DROP INDEX IF EXISTS idx_new_index;

-- Add specific rollback steps here

COMMIT;
```

### 3. Configuration Rollback

```bash
# Backup current configuration before deployment
cp /opt/auth-service/config.env "/opt/auth-service/backups/config-$(date +%Y%m%d-%H%M%S).env"

# Rollback configuration
rollback_config() {
    local backup_config="$1"
    if [[ -f "$backup_config" ]]; then
        cp "$backup_config" /opt/auth-service/config.env
        systemctl restart auth-service
        echo "Configuration rolled back to $backup_config"
    else
        echo "Backup configuration not found: $backup_config"
        exit 1
    fi
}
```

### 4. Service Recovery

```bash
#!/bin/bash
# service-recovery.sh

echo "=== Service Recovery Procedure ==="

# Check if service is running
if ! systemctl is-active --quiet auth-service; then
    echo "Service is not running, attempting to start..."
    systemctl start auth-service
    sleep 5
fi

# Check health endpoint
if curl -s -f "$API_BASE_URL/health" > /dev/null; then
    echo "✅ Service is healthy"
else
    echo "❌ Service health check failed, checking logs..."
    journalctl -u auth-service --lines=50 --no-pager
    
    echo "Attempting service restart..."
    systemctl restart auth-service
    sleep 10
    
    if curl -s -f "$API_BASE_URL/health" > /dev/null; then
        echo "✅ Service recovered after restart"
    else
        echo "❌ Service recovery failed, manual intervention required"
        exit 1
    fi
fi
```

## Summary

This deployment checklist ensures:

- **Security-first approach** with hardened defaults
- **Production-ready configuration** with environment-specific settings
- **Comprehensive validation** of all critical components
- **Monitoring and observability** for ongoing operations
- **Emergency procedures** for quick recovery

**Key Security Features Activated:**
- TLS 1.3 enforcement
- Strong JWT security with EdDSA preference
- Comprehensive rate limiting
- CSRF protection
- Security headers
- Input validation
- Audit logging

**Performance Optimizations:**
- Optimized database connection pools (auth_pool, session_pool, audit_pool)
- Redis caching with appropriate TTL settings
- Prepared statement caching
- Database performance tuning

**Monitoring Coverage:**
- Prometheus metrics
- OpenTelemetry tracing
- Security event monitoring
- Performance monitoring
- Health checks

Run each section's validation scripts after deployment to ensure all systems are operating correctly and securely.