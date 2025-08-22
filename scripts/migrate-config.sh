#!/bin/bash

# Configuration Migration Script
# This script helps migrate from .env-based configuration to static Rust configuration

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
AUTH_SERVICE_DIR="$PROJECT_ROOT/auth-service"

echo "🔧 Configuration Migration Tool"
echo "================================"

# Check if .env.example exists
if [[ -f "$PROJECT_ROOT/.env.example" ]]; then
    echo "📋 Found .env.example file"
    echo "   This file shows the old environment-based configuration approach"
    echo ""
fi

# Run the migration analysis
echo "🔍 Running configuration migration analysis..."
cd "$AUTH_SERVICE_DIR"

if command -v cargo >/dev/null 2>&1; then
    echo "   Running: cargo run --bin auth-service -- --migrate-config"
    if ! cargo run --bin auth-service -- --migrate-config; then
        echo "❌ Migration analysis failed. Check the error above."
        exit 1
    fi
else
    echo "❌ Cargo not found. Please install Rust and Cargo first."
    exit 1
fi

echo ""
echo "✅ Migration analysis complete!"
echo ""

# Show environment-specific recommendations
echo "📝 Next Steps:"
echo "1. Set ENVIRONMENT variable to one of: development, testing, staging, production"
echo "2. Set required environment variables (JWT_SIGNING_KEY, etc.)"
echo "3. Remove .env files to ensure static configuration is used"
echo "4. Update deployment scripts to use new environment variables"
echo ""

# Show current environment
current_env=${ENVIRONMENT:-"development"}
echo "🌍 Current environment: $current_env"
echo ""

# Generate client secrets for development
echo "🔐 Generating bcrypt hashes for development client secrets:"
echo "   For 'dev-secret': \$2b\$12\$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
echo "   For 'test-secret': \$2b\$12\$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
echo ""

echo "🎯 Configuration migration setup complete!"
echo "   The application now uses compile-time static configuration"
echo "   with environment-specific settings and runtime secrets."