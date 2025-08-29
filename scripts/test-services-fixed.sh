#!/bin/bash

# Test Services with Configuration Fixes Applied
echo "🎯 Testing Services with Configuration Fixes"
echo "============================================"

# Kill any existing processes
pkill -f "auth-service" 2>/dev/null || true
pkill -f "policy-service" 2>/dev/null || true
sleep 2

# Set up comprehensive configuration with proper Duration formats
export RUST_LOG="info"

# Auth service configuration
export AUTH__SERVER__HOST="127.0.0.1"
export AUTH__SERVER__PORT="8080"
export AUTH__SERVER__REQUEST_TIMEOUT="30s"
export AUTH__SERVER__SHUTDOWN_TIMEOUT="30s"
export AUTH__DATABASE__URL="sqlite::memory:"
export AUTH__JWT__SECRET="test-jwt-secret-key-for-development-only-32chars"
export AUTH__JWT__ISSUER="http://localhost:8080"
export AUTH__JWT__ACCESS_TOKEN_TTL="1h"
export AUTH__JWT__REFRESH_TOKEN_TTL="7d"
export AUTH__SECURITY__ENCRYPTION_KEY="test-encryption-key-for-development-only-32char"
export AUTH__SECURITY__LOCKOUT_DURATION="15m"
export AUTH__FEATURES__USER_REGISTRATION="true"
export AUTH__FEATURES__OAUTH2_FLOWS="true"
export AUTH__FEATURES__JWT_AUTHENTICATION="true"

# Policy service configuration
export POLICY_BIND_ADDR="127.0.0.1:8081"

echo "✅ Configuration set with proper Duration string formats"

# Start auth service
echo ""
echo "🔐 Starting Auth Service..."
./target/debug/auth-service > auth-fixed.log 2>&1 &
AUTH_PID=$!
echo "Auth Service PID: $AUTH_PID"

# Start policy service
echo ""
echo "📋 Starting Policy Service..."
./target/debug/policy-service > policy-fixed.log 2>&1 &
POLICY_PID=$!
echo "Policy Service PID: $POLICY_PID"

echo ""
echo "⏳ Waiting for services to start (60 seconds max)..."

# Wait for auth service
AUTH_OK=0
for i in {1..60}; do
    if curl -s -f http://127.0.0.1:8080/health >/dev/null 2>&1; then
        echo "✅ Auth service is responding!"
        AUTH_OK=1
        break
    fi
    
    # Check if process is still running
    if ! kill -0 $AUTH_PID 2>/dev/null; then
        echo "❌ Auth service process died, checking logs..."
        echo "Last 5 lines of auth-fixed.log:"
        tail -5 auth-fixed.log 2>/dev/null || echo "No log available"
        break
    fi
    
    if [ $((i % 10)) -eq 0 ]; then
        echo "   Still waiting for auth service... ($i/60)"
    fi
    sleep 1
done

# Wait for policy service
POLICY_OK=0
for i in {1..60}; do
    if curl -s -f http://127.0.0.1:8081/health >/dev/null 2>&1; then
        echo "✅ Policy service is responding!"
        POLICY_OK=1
        break
    fi
    
    # Check if process is still running
    if ! kill -0 $POLICY_PID 2>/dev/null; then
        echo "❌ Policy service process died, checking logs..."
        echo "Last 5 lines of policy-fixed.log:"
        tail -5 policy-fixed.log 2>/dev/null || echo "No log available"
        break
    fi
    
    if [ $((i % 10)) -eq 0 ]; then
        echo "   Still waiting for policy service... ($i/60)"
    fi
    sleep 1
done

echo ""
echo "============================================"
echo "🎯 Configuration Fix Results:"
echo "============================================"

if [ $AUTH_OK -eq 1 ] && [ $POLICY_OK -eq 1 ]; then
    echo "🎉 SUCCESS! Both configuration issues have been FIXED!"
    echo ""
    echo "✅ Auth Service: Duration parsing working correctly"
    echo "✅ Policy Service: Duplicate route conflict resolved"
    echo ""
    echo "🧪 Quick endpoint tests:"
    echo "Auth Service Health:"
    curl -s http://localhost:8080/health | head -100
    echo ""
    echo "Policy Service Health:"
    curl -s http://localhost:8081/health | head -100
    echo ""
    echo "🚀 READY FOR FULL CURL VALIDATION!"
    echo ""
    echo "📋 Service Information:"
    echo "  Auth Service:   http://localhost:8080"
    echo "  Policy Service: http://localhost:8081"
    echo "  Auth PID: $AUTH_PID"
    echo "  Policy PID: $POLICY_PID"
    echo ""
    echo "🛑 To stop services: kill $AUTH_PID $POLICY_PID"
    
    # Save PIDs for further testing
    echo $AUTH_PID > .auth-fixed.pid
    echo $POLICY_PID > .policy-fixed.pid
    
else
    echo "❌ Issues remain:"
    echo ""
    if [ $AUTH_OK -eq 0 ]; then
        echo "Auth Service Status: FAILED"
        if kill -0 $AUTH_PID 2>/dev/null; then
            echo "  Process still running but not responding"
        else
            echo "  Process died - check auth-fixed.log"
        fi
    else
        echo "Auth Service Status: ✅ WORKING"
    fi
    
    if [ $POLICY_OK -eq 0 ]; then
        echo "Policy Service Status: FAILED"
        if kill -0 $POLICY_PID 2>/dev/null; then
            echo "  Process still running but not responding"
        else
            echo "  Process died - check policy-fixed.log"
        fi
    else
        echo "Policy Service Status: ✅ WORKING"
    fi
    
    echo ""
    echo "🧹 Cleaning up..."
    kill $AUTH_PID $POLICY_PID 2>/dev/null || true
    exit 1
fi