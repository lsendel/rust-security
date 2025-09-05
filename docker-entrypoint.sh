#!/bin/bash
set -e

# Auth-as-a-Service MVP Docker Entrypoint
# Provides configuration validation and startup

echo "🚀 Starting Auth-as-a-Service MVP"
echo "Version: 1.0.0-mvp"
echo "Features: security-essential"

# Validate required environment variables
if [ -z "$JWT_SECRET" ] || [ ${#JWT_SECRET} -lt 32 ]; then
    echo "❌ Error: JWT_SECRET must be set and at least 32 characters long"
    exit 1
fi

echo "✅ Configuration validated"

# Show startup configuration (without secrets)
echo "🔧 Configuration:"
echo "  - Bind Address: ${BIND_ADDRESS:-0.0.0.0:8080}"
echo "  - Log Level: ${RUST_LOG:-info}"
echo "  - External URL: ${EXTERNAL_BASE_URL:-http://localhost:8080}"
echo "  - Features:"
echo "    - Redis Sessions: ${ENABLE_REDIS_SESSIONS:-false}"
echo "    - PostgreSQL: ${ENABLE_POSTGRES:-false}"
echo "    - Metrics: ${ENABLE_METRICS:-true}"
echo "    - API Keys: ${ENABLE_API_KEYS:-true}"
echo "    - Rate Limiting: ${RATE_LIMIT_ENABLED:-true}"

if [ "$ENABLE_REDIS_SESSIONS" = "true" ] && [ -z "$REDIS_URL" ]; then
    echo "⚠️  Warning: Redis sessions enabled but REDIS_URL not set, falling back to in-memory"
fi

if [ "$ENABLE_POSTGRES" = "true" ] && [ -z "$DATABASE_URL" ]; then
    echo "⚠️  Warning: PostgreSQL enabled but DATABASE_URL not set, falling back to SQLite"
fi

echo "🎯 Starting Auth-as-a-Service MVP..."
exec "$@"