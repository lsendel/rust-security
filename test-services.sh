#!/bin/bash

# Quick service validation test
echo "🔧 Testing Services"
echo "=================="

# Set comprehensive configuration
export RUST_LOG="info"
export AUTH__SERVER__HOST="127.0.0.1"
export AUTH__SERVER__PORT="8080"
export AUTH__SERVER__REQUEST_TIMEOUT="30s"
export AUTH__DATABASE__URL="sqlite::memory:"
export AUTH__JWT__SECRET="test-jwt-secret-key-for-development-only-32chars"
export AUTH__SECURITY__ENCRYPTION_KEY="test-encryption-key-for-development-only-32char"
export POLICY_BIND_ADDR="127.0.0.1:8081"

# Kill any existing processes
pkill -f "auth-service" 2>/dev/null || true
pkill -f "policy-service" 2>/dev/null || true
sleep 2

echo "Starting auth service..."
cd auth-service && cargo run > ../auth.log 2>&1 &
AUTH_PID=$!
cd ..

echo "Starting policy service..."  
cd policy-service && cargo run > ../policy.log 2>&1 &
POLICY_PID=$!
cd ..

echo "Waiting 30 seconds for startup..."
sleep 30

# Test endpoints
echo "Testing endpoints..."
if curl -s http://127.0.0.1:8080/health >/dev/null 2>&1; then
    echo "✅ Auth service: WORKING"
else
    echo "❌ Auth service: FAILED"
    echo "Last 5 lines of auth.log:"
    tail -5 auth.log 2>/dev/null || echo "No log"
fi

if curl -s http://127.0.0.1:8081/health >/dev/null 2>&1; then
    echo "✅ Policy service: WORKING"
else
    echo "❌ Policy service: FAILED"
    echo "Last 5 lines of policy.log:"
    tail -5 policy.log 2>/dev/null || echo "No log"
fi

echo "PIDs: Auth=$AUTH_PID Policy=$POLICY_PID"
echo "To kill: kill $AUTH_PID $POLICY_PID"