#!/bin/bash
# Redis Migration v1: Initialize Redis configuration for Auth Service
# Purpose: Set up initial Redis configuration with proper memory settings and persistence

set -euo pipefail

# Migration metadata
MIGRATION_NAME="Initialize Redis Configuration"
MIGRATION_DESCRIPTION="Set up Redis with optimized configuration for Auth Service"

echo "=== Redis Migration v1: $MIGRATION_NAME ==="
echo "Description: $MIGRATION_DESCRIPTION"
echo "Timestamp: $(date)"

# Verify Redis is running
if ! kubectl get pod redis-master-0 -n rust-security >/dev/null 2>&1; then
    echo "ERROR: Redis master pod not found"
    exit 1
fi

# Check Redis connectivity
if ! kubectl exec redis-master-0 -n rust-security -- redis-cli ping | grep -q "PONG"; then
    echo "ERROR: Cannot connect to Redis"
    exit 1
fi

echo "✓ Redis connectivity verified"

# Configure Redis settings
echo "Configuring Redis settings..."

# Set memory policy for LRU eviction
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET maxmemory-policy allkeys-lru

# Set reasonable memory limit (adjust based on available memory)
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET maxmemory 256mb

# Enable persistence
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET save "900 1 300 10 60 10000"

# Set database count (we'll use multiple databases for different purposes)
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET databases 16

# Configure connection settings
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET timeout 300
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET tcp-keepalive 60

# Set log level
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG SET loglevel notice

echo "✓ Redis configuration applied"

# Create initial data structure for Auth Service
echo "Setting up initial data structures..."

# Database allocation:
# DB 0: User sessions
# DB 1: Rate limiting data
# DB 2: Cache data
# DB 3: Token blacklist
# DB 4: User preferences
# DB 5-15: Reserved for future use

# Switch to DB 1 and set up rate limiting structure
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 1 SET rate_limit_initialized "true"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 1 EXPIRE rate_limit_initialized 86400

# Switch to DB 2 and set up cache structure
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 2 SET cache_initialized "true"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 2 EXPIRE cache_initialized 86400

# Switch to DB 3 and set up token blacklist
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 3 SET token_blacklist_initialized "true"
kubectl exec redis-master-0 -n rust-security -- redis-cli -n 3 EXPIRE token_blacklist_initialized 86400

echo "✓ Initial data structures created"

# Verify configuration
echo "Verifying configuration..."

# Check memory settings
MEMORY_POLICY=$(kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG GET maxmemory-policy | tail -1)
MEMORY_LIMIT=$(kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG GET maxmemory | tail -1)

echo "Memory policy: $MEMORY_POLICY"
echo "Memory limit: $MEMORY_LIMIT"

# Check persistence settings
SAVE_CONFIG=$(kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG GET save | tail -1)
echo "Save configuration: $SAVE_CONFIG"

# Test database switching
DB_COUNT=$(kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG GET databases | tail -1)
echo "Database count: $DB_COUNT"

# Verify data structures
echo "Verifying data structures..."
for db in 1 2 3; do
    INIT_STATUS=$(kubectl exec redis-master-0 -n rust-security -- redis-cli -n $db GET "${db}_initialized" || echo "not found")
    echo "DB $db initialized: $INIT_STATUS"
done

# Save configuration to disk
echo "Persisting configuration..."
kubectl exec redis-master-0 -n rust-security -- redis-cli CONFIG REWRITE

# Force save current dataset
kubectl exec redis-master-0 -n rust-security -- redis-cli BGSAVE

echo "✓ Redis migration v1 completed successfully"
echo "Summary:"
echo "  - Configured memory management with LRU eviction"
echo "  - Set up persistence with reasonable save intervals"
echo "  - Initialized database structure for Auth Service"
echo "  - Configured connection and logging settings"
echo "  - Persisted configuration to disk"

exit 0