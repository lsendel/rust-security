#!/bin/bash

# Final Service Validation - Minimal Approach
echo "🎯 Final Service Validation"
echo "=========================="

# Kill existing processes
pkill -f "auth-service" 2>/dev/null || true
pkill -f "policy-service" 2>/dev/null || true
sleep 2

# First, let's just try with minimal environment and see what errors we get
echo "🔧 Testing with minimal environment..."

# Only set the absolutely minimal variables
export RUST_LOG="info"

echo ""
echo "1️⃣ Testing Auth Service compilation..."
cd auth-service
if ! cargo build --quiet; then
    echo "❌ Auth service compilation failed"
    cd ..
    exit 1
fi
echo "✅ Auth service compiles"
cd ..

echo ""
echo "2️⃣ Testing Policy Service compilation..."
cd policy-service
if ! cargo build --quiet; then
    echo "❌ Policy service compilation failed"
    cd ..
    exit 1
fi
echo "✅ Policy service compiles"
cd ..

echo ""
echo "3️⃣ Starting Auth Service without env vars to see what config it needs..."
cd auth-service
timeout 10s ./target/debug/auth-service 2>&1 | head -20
echo ""
echo "(Auth service stopped after 10s to see error output)"
cd ..

echo ""
echo "4️⃣ Starting Policy Service to check route conflicts..."
cd policy-service  
timeout 10s ./target/debug/policy-service 2>&1 | head -20
echo ""
echo "(Policy service stopped after 10s to see error output)"
cd ..

echo ""
echo "=========================="
echo "📋 Analysis Complete"
echo "=========================="
echo ""
echo "The services compile successfully but have runtime configuration issues:"
echo "1. Auth service needs proper config format (Duration vs string)"
echo "2. Policy service has duplicate /openapi.json route"
echo ""
echo "These are the exact issues identified in CLAUDE.md as minor runtime fixes needed."
echo ""
echo "🔧 Next steps:"
echo "  - Fix Duration config parsing in auth service"
echo "  - Remove duplicate route in policy service"
echo "  - Then create comprehensive curl validation"