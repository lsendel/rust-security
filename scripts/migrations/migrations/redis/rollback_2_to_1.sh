#!/bin/bash
# Redis Rollback: v2 to v1
# Purpose: Rollback Redis from v2 (monitoring/performance) to v1 (basic configuration)

set -euo pipefail

# Migration metadata
ROLLBACK_NAME="Redis Rollback v2 to v1"
ROLLBACK_DESCRIPTION="Remove v2 monitoring and performance features, restore v1 basic configuration"

echo "=== Redis Rollback: $ROLLBACK_NAME ==="
echo "Description: $ROLLBACK_DESCRIPTION"
echo "Timestamp: $(date)"

# Verify Redis is running
if ! kubectl get pod redis-master-0 -n rust-security >/dev/null 2>&1; then
    echo "ERROR: Redis master pod not found"
    exit 1
fi

if ! kubectl exec redis-master-0 -n rust-security -- redis-cli ping | grep -q "PONG"; then
    echo "ERROR: Cannot connect to Redis"
    exit 1
fi

echo "✓ Redis connectivity verified"

# Check if v2 migration was applied
if ! kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 HGET monitoring:migration v2_completed >/dev/null 2>&1; then
    echo "ERROR: v2 migration not found or not completed. Cannot rollback."
    exit 1
fi

echo "✓ v2 migration detected, proceeding with rollback"

# Remove v2 monitoring data structures
echo "Removing v2 monitoring data structures..."

# Clear monitoring database (DB 5)
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 FLUSHDB

# Clear performance indices (DB 6-7)
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 6 FLUSHDB
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 7 FLUSHDB

# Clear health check data (DB 8)
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 8 FLUSHDB

echo "✓ v2 data structures removed"

# Revert performance optimizations to v1 settings
echo "Reverting performance optimizations..."

# Revert TCP settings to v1 defaults
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET tcp-nodelay no
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET maxclients 4064

# Revert memory optimizations to v1 defaults
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET hash-max-ziplist-entries 512
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET hash-max-ziplist-value 64
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET list-max-ziplist-size -2
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET set-max-intset-entries 512

# Disable lazy expiration (v2 feature)
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET lazyfree-lazy-eviction no
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET lazyfree-lazy-expire no
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET lazyfree-lazy-server-del no

echo "✓ Performance settings reverted to v1"

# Revert slow log to v1 settings (less aggressive monitoring)
echo "Reverting slow log settings..."

# Set slow log to capture queries taking more than 100ms (v1 default)
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET slowlog-log-slower-than 100000

# Keep last 32 slow queries (v1 default)
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET slowlog-max-len 32

echo "✓ Slow log settings reverted"

# Restore v1 data structure markers
echo "Restoring v1 data structure markers..."

# Restore v1 markers in databases 1-3
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 1 SET rate_limit_initialized "true"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 1 EXPIRE rate_limit_initialized 86400

kubectl exec redis-master-0 -n rust-security -- redis-cli -n 2 SET cache_initialized "true"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 2 EXPIRE cache_initialized 86400

kubectl exec redis-master-0 -n rust-security -- redis-cli -n 3 SET token_blacklist_initialized "true"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 3 EXPIRE token_blacklist_initialized 86400

echo "✓ v1 data structure markers restored"

# Clear v2 migration markers
echo "Clearing v2 migration markers..."

# Remove any remaining v2 markers
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 DEL monitoring:migration 2>/dev/null || true
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 5 DEL monitoring:config 2>/dev/null || true

echo "✓ v2 migration markers cleared"

# Verify rollback
echo "Verifying rollback..."

# Check that v1 settings are in place
TCP_NODELAY=$(kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG GET tcp-nodelay | tail -1)
MAX_CLIENTS=$(kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG GET maxclients | tail -1)
SLOWLOG_THRESHOLD=$(kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG GET slowlog-log-slower-than | tail -1)
LAZYFREE_EVICTION=$(kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG GET lazyfree-lazy-eviction | tail -1)

echo "TCP Nodelay: $TCP_NODELAY (should be 'no')"
echo "Max Clients: $MAX_CLIENTS (should be '4064')"
echo "Slowlog Threshold: $SLOWLOG_THRESHOLD microseconds (should be '100000')"
echo "Lazyfree Eviction: $LAZYFREE_EVICTION (should be 'no')"

# Verify v1 databases still have their initialization markers
echo "Verifying v1 database markers:"
for db in 1 2 3; do
    case $db in
        1) KEY_NAME="rate_limit_initialized" ;;
        2) KEY_NAME="cache_initialized" ;;
        3) KEY_NAME="token_blacklist_initialized" ;;
    esac
    
    if kubectl exec redis-master-0 -n rust-security -- redis-cli -n $db GET "$KEY_NAME" >/dev/null 2>&1; then
        echo "  ✓ DB $db: $KEY_NAME exists"
    else
        echo "  ✗ DB $db: $KEY_NAME missing"
    fi
done

# Verify v2 databases are cleared
echo "Verifying v2 databases are cleared:"
for db in 5 6 7 8; do
    KEY_COUNT=$(kubectl exec redis-master-0 -n rust-security -- redis-cli -n $db DBSIZE)
    echo "  DB $db: $KEY_COUNT keys (should be 0)"
done

# Test basic Redis functionality
echo "Testing basic Redis functionality..."

# Test SET/GET
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 1 SET rollback_test "v1_restored"
ROLLBACK_TEST=$(kubectl exec redis-master-0 -n rust-security -- redis-cli -n 1 GET rollback_test)

if [[ "$ROLLBACK_TEST" == "v1_restored" ]]; then
    echo "✓ Basic Redis operations working"
else
    echo "✗ Basic Redis operations failed"
    exit 1
fi

# Clean up test data
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 1 DEL rollback_test

# Save configuration to disk
echo "Persisting rollback configuration..."
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG REWRITE

# Force save current dataset
kubectl exec redis-master-0 -n rust-security -- redis-cli BGSAVE

# Create rollback completion marker
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 1 HSET rollback:status v2_to_v1_completed "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 1 HSET rollback:status description "Rolled back from v2 to v1 configuration"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 1 EXPIRE rollback:status 86400

echo "✓ Redis rollback v2→v1 completed successfully"
echo "Summary:"
echo "  - Removed v2 monitoring data structures (DB 5-8)"
echo "  - Reverted performance optimizations to v1 settings"
echo "  - Disabled lazy expiration features added in v2"
echo "  - Restored v1 slow log configuration (100ms threshold)"
echo "  - Verified v1 database markers are intact"
echo "  - Persisted rollback configuration to disk"
echo "  - Basic Redis functionality validated"
echo ""
echo "Redis is now restored to v1 configuration state."

exit 0