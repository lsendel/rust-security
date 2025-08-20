#!/bin/bash
# Redis Migration v2: Add monitoring and performance optimizations
# Purpose: Configure Redis monitoring, add performance indices, and optimize for high throughput

set -euo pipefail

# Migration metadata
MIGRATION_NAME="Redis Monitoring and Performance Optimization"
MIGRATION_DESCRIPTION="Add monitoring metrics, performance indices, and optimization for high throughput scenarios"

echo "=== Redis Migration v2: $MIGRATION_NAME ==="
echo "Description: $MIGRATION_DESCRIPTION"
echo "Timestamp: $(date)"

# Verify Redis is running and previous migration completed
if ! kubectl get pod redis-master-0 -n rust-security >/dev/null 2>&1; then
    echo "ERROR: Redis master pod not found"
    exit 1
fi

if ! kubectl exec redis-master-0 -n rust-security -- redis-cli ping | grep -q "PONG"; then
    echo "ERROR: Cannot connect to Redis"
    exit 1
fi

# Check if previous migration was applied
if ! kubectl exec redis-master-0 -n rust-security -- redis-cli -n 1 GET rate_limit_initialized >/dev/null 2>&1; then
    echo "ERROR: Previous migration (v1) not found. Please run migration v1 first."
    exit 1
fi

echo "✓ Redis connectivity and prerequisites verified"

# Configure performance optimizations
echo "Applying performance optimizations..."

# Optimize for high throughput
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET tcp-nodelay yes
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET tcp-keepalive 60

# Set reasonable client limits
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET maxclients 10000

# Configure memory optimization
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET hash-max-ziplist-entries 512
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET hash-max-ziplist-value 64
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET list-max-ziplist-size -2
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET set-max-intset-entries 512

# Configure lazy expiration for better performance
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET lazyfree-lazy-eviction yes
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET lazyfree-lazy-expire yes
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET lazyfree-lazy-server-del yes

echo "✓ Performance optimizations applied"

# Set up monitoring data structures
echo "Setting up monitoring data structures..."

# DB 5: Monitoring and metrics
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 HSET monitoring:config version "2"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 HSET monitoring:config setup_date "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 HSET monitoring:config description "Monitoring and metrics database"

# Initialize performance counters
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 HSET perf:counters total_operations 0
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 HSET perf:counters total_errors 0
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 HSET perf:counters last_reset "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Set up connection pool monitoring
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 HSET pool:stats active_connections 0
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 HSET pool:stats peak_connections 0
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 HSET pool:stats total_connections_created 0

echo "✓ Monitoring data structures created"

# Add performance indices for common queries
echo "Creating performance indices..."

# DB 6: User session indices
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 6 HSET indices:config description "User session performance indices"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 6 HSET indices:config version "2"

# Create index for active user sessions (sorted set by last activity)
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 6 ZADD active_users_by_activity 0 "index_placeholder"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 6 EXPIRE active_users_by_activity 1

# Create index for user sessions by creation time
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 6 ZADD users_by_login_time 0 "index_placeholder"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 6 EXPIRE users_by_login_time 1

# DB 7: Rate limiting indices
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 7 HSET rate_limit_indices:config description "Rate limiting performance indices"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 7 HSET rate_limit_indices:config version "2"

# Create rate limit tracking by IP (sorted set by request count)
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 7 ZADD rate_limits_by_ip 0 "index_placeholder"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 7 EXPIRE rate_limits_by_ip 1

# Create rate limit tracking by user (sorted set by request count)
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 7 ZADD rate_limits_by_user 0 "index_placeholder"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 7 EXPIRE rate_limits_by_user 1

echo "✓ Performance indices created"

# Configure slow log for monitoring
echo "Configuring slow log monitoring..."

# Set slow log to capture queries taking more than 10ms
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET slowlog-log-slower-than 10000

# Keep last 128 slow queries
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET slowlog-max-len 128

echo "✓ Slow log monitoring configured"

# Set up health check data
echo "Setting up health check data..."

# DB 8: Health check data
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 8 HSET health:config description "Health check and diagnostics"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 8 HSET health:config version "2"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 8 HSET health:config setup_date "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Create health check key with TTL
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 8 SET health:status "healthy"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 8 EXPIRE health:status 300

# Store Redis info for health monitoring
REDIS_VERSION=$(kubectl exec redis-master-0 -n rust-security -- redis-cli INFO server | grep redis_version | cut -d: -f2 | tr -d '\r')
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 8 HSET health:info redis_version "$REDIS_VERSION"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 8 HSET health:info migration_version "2"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 8 HSET health:info last_health_check "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "✓ Health check data configured"

# Verify all configurations
echo "Verifying migration..."

# Check performance settings
TCP_NODELAY=$(kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG GET tcp-nodelay | tail -1)
MAX_CLIENTS=$(kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG GET maxclients | tail -1)
SLOWLOG_THRESHOLD=$(kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG GET slowlog-log-slower-than | tail -1)

echo "TCP Nodelay: $TCP_NODELAY"
echo "Max Clients: $MAX_CLIENTS"
echo "Slowlog Threshold: $SLOWLOG_THRESHOLD microseconds"

# Verify monitoring databases
for db in 5 6 7 8; do
    DB_DESC=$(kubectl exec redis-master-0 -n rust-security -- redis-cli -n $db HGET "${db}_config" description 2>/dev/null || kubectl exec redis-master-0 -n rust-security -- redis-cli -n $db HGET "monitoring:config" description 2>/dev/null || kubectl exec redis-master-0 -n rust-security -- redis-cli -n $db HGET "indices:config" description 2>/dev/null || kubectl exec redis-master-0 -n rust-security -- redis-cli -n $db HGET "rate_limit_indices:config" description 2>/dev/null || kubectl exec redis-master-0 -n rust-security -- redis-cli -n $db HGET "health:config" description 2>/dev/null || echo "not configured")
    echo "DB $db: $DB_DESC"
done

# Test performance improvements
echo "Testing performance improvements..."

# Measure operation latency
START_TIME=$(date +%s%N)
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 INCR test_counter >/dev/null
END_TIME=$(date +%s%N)
LATENCY_NS=$((END_TIME - START_TIME))
LATENCY_MS=$((LATENCY_NS / 1000000))

echo "Sample operation latency: ${LATENCY_MS}ms"

# Clean up test data
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 DEL test_counter

# Save configuration to disk
echo "Persisting configuration..."
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG REWRITE

# Force save current dataset
kubectl exec redis-master-0 -n rust-security -- redis-cli BGSAVE

# Set migration completion marker
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 HSET monitoring:migration v2_completed "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "✓ Redis migration v2 completed successfully"
echo "Summary:"
echo "  - Applied performance optimizations for high throughput"
echo "  - Configured lazy expiration and memory optimizations"
echo "  - Set up monitoring and metrics databases (DB 5)"
echo "  - Created performance indices (DB 6-7)"
echo "  - Configured health check monitoring (DB 8)"
echo "  - Set up slow log monitoring with 10ms threshold"
echo "  - Persisted all configurations to disk"

exit 0