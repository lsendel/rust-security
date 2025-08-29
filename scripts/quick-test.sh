#!/bin/bash

# Quick Service Test with Configuration Fix
set -e

echo "🔧 Quick Service Test"
echo "=================="

# Clean up any running processes
pkill -f "auth-service" 2>/dev/null || true
pkill -f "policy-service" 2>/dev/null || true
sleep 2

# Set comprehensive configuration to fix the missing fields
export RUST_LOG="info"

# Server configuration (fixing the missing request_timeout field)
export AUTH__SERVER__HOST="127.0.0.1"
export AUTH__SERVER__PORT="8080"
export AUTH__SERVER__BIND_ADDR="127.0.0.1:8080"
export AUTH__SERVER__MAX_CONNECTIONS="1000"
export AUTH__SERVER__REQUEST_TIMEOUT="30s"
export AUTH__SERVER__SHUTDOWN_TIMEOUT="30s"

# Database configuration
export AUTH__DATABASE__URL="sqlite::memory:"

# Security configuration
export AUTH__JWT__SECRET="test-jwt-secret-key-for-development-only-32chars"
export AUTH__JWT__EXPIRY="1h"
export AUTH__JWT__ALGORITHM="HS256"
export AUTH__SECURITY__ENCRYPTION_KEY="test-encryption-key-for-development-only-32char"
export AUTH__SECURITY__TOKEN_EXPIRY="1h"

# Feature flags
export AUTH__FEATURES__USER_REGISTRATION="true"
export AUTH__FEATURES__OAUTH2_FLOWS="true"
export AUTH__FEATURES__JWT_AUTHENTICATION="true"

echo "✅ Configuration set"

# Start auth service
echo ""
echo "🔐 Testing Auth Service compilation and startup..."
cd auth-service
if cargo run > ../auth-test.log 2>&1 &
then
    AUTH_PID=$!
    echo "Auth Service PID: $AUTH_PID"
else
    echo "❌ Failed to start auth service"
    exit 1
fi
cd ..

# Start policy service
echo ""
echo "📋 Testing Policy Service..."
export POLICY_BIND_ADDR="127.0.0.1:8081"
cd policy-service
if cargo run > ../policy-test.log 2>&1 &
then
    POLICY_PID=$!
    echo "Policy Service PID: $POLICY_PID"
else
    echo "❌ Failed to start policy service"
    kill $AUTH_PID 2>/dev/null || true
    exit 1
fi
cd ..

echo ""
echo "⏳ Waiting for services (60 seconds max)..."

# Test auth service
for i in {1..60}; do
    if curl -s -f http://127.0.0.1:8080/health >/dev/null 2>&1; then
        echo "✅ Auth service is responding!"
        AUTH_OK=1
        break
    fi
    sleep 1
done

# Test policy service
for i in {1..60}; do
    if curl -s -f http://127.0.0.1:8081/health >/dev/null 2>&1; then
        echo "✅ Policy service is responding!"
        POLICY_OK=1
        break
    fi
    sleep 1
done

echo ""
echo "=================="
echo "📊 Results:"
echo "=================="

if [ "${AUTH_OK:-0}" == "1" ] && [ "${POLICY_OK:-0}" == "1" ]; then
    echo "🎉 SUCCESS! Both services are working!"
    echo ""
    echo "📋 Quick Tests:"
    echo "curl http://localhost:8080/health"
    curl -s http://localhost:8080/health
    echo ""
    echo "curl http://localhost:8081/health"
    curl -s http://localhost:8081/health
    echo ""
    echo "✅ READY FOR DOCUMENTATION VALIDATION"
    echo ""
    echo "To stop: kill $AUTH_PID $POLICY_PID"
    
    # Save PIDs
    echo $AUTH_PID > .auth-test.pid
    echo $POLICY_PID > .policy-test.pid
    
else
    echo "❌ FAILED - Check logs:"
    echo "  Auth service log: tail auth-test.log"
    echo "  Policy service log: tail policy-test.log"
    echo ""
    if [ "${AUTH_OK:-0}" != "1" ]; then
        echo "Auth service error (last 10 lines):"
        tail -10 auth-test.log 2>/dev/null || echo "No auth log found"
    fi
    if [ "${POLICY_OK:-0}" != "1" ]; then
        echo "Policy service error (last 10 lines):"
        tail -10 policy-test.log 2>/dev/null || echo "No policy log found"
    fi
    
    kill $AUTH_PID $POLICY_PID 2>/dev/null || true
    exit 1
fi