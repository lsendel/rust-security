#!/bin/bash

# Final Test with Complete Configuration
echo "🎯 Final Test with Complete Configuration"
echo "========================================"

# Kill any existing processes
pkill -f "auth-service" 2>/dev/null || true
pkill -f "policy-service" 2>/dev/null || true
sleep 2

# Complete configuration with all required fields
export RUST_LOG="info"

# Server config
export AUTH__SERVER__HOST="127.0.0.1"
export AUTH__SERVER__PORT="8080"
export AUTH__SERVER__REQUEST_TIMEOUT="30s"
export AUTH__SERVER__SHUTDOWN_TIMEOUT="30s"

# Database config
export AUTH__DATABASE__URL="sqlite::memory:"

# JWT config (add missing audience field)
export AUTH__JWT__SECRET="test-jwt-secret-key-for-development-only-32chars"
export AUTH__JWT__ISSUER="http://localhost:8080"
export AUTH__JWT__AUDIENCE="auth-service,test-client"
export AUTH__JWT__ACCESS_TOKEN_TTL="1h"
export AUTH__JWT__REFRESH_TOKEN_TTL="7d"
export AUTH__JWT__ALGORITHM="HS256"
export AUTH__JWT__KEY_ROTATION_INTERVAL="24h"
export AUTH__JWT__LEEWAY="30s"

# Security config
export AUTH__SECURITY__ENCRYPTION_KEY="test-encryption-key-for-development-only-32char"
export AUTH__SECURITY__LOCKOUT_DURATION="15m"
export AUTH__SECURITY__BCRYPT_COST="12"

# Features
export AUTH__FEATURES__USER_REGISTRATION="true"
export AUTH__FEATURES__OAUTH2_FLOWS="true"
export AUTH__FEATURES__JWT_AUTHENTICATION="true"

# Policy service
export POLICY_BIND_ADDR="127.0.0.1:8081"

echo "✅ Complete configuration set"

# Start services
echo ""
echo "🔐 Starting Auth Service..."
./target/debug/auth-service > auth-final.log 2>&1 &
AUTH_PID=$!

echo "📋 Starting Policy Service..."
./target/debug/policy-service > policy-final.log 2>&1 &
POLICY_PID=$!

echo "Auth PID: $AUTH_PID, Policy PID: $POLICY_PID"
echo ""
echo "⏳ Waiting for startup (45 seconds)..."

# Wait for both services
AUTH_OK=0
POLICY_OK=0

for i in {1..45}; do
    # Check auth service
    if [ $AUTH_OK -eq 0 ] && curl -s -f http://127.0.0.1:8080/health >/dev/null 2>&1; then
        echo "✅ Auth service is responding!"
        AUTH_OK=1
    fi
    
    # Check policy service
    if [ $POLICY_OK -eq 0 ] && curl -s -f http://127.0.0.1:8081/health >/dev/null 2>&1; then
        echo "✅ Policy service is responding!"
        POLICY_OK=1
    fi
    
    # Exit early if both are working
    if [ $AUTH_OK -eq 1 ] && [ $POLICY_OK -eq 1 ]; then
        break
    fi
    
    # Check if processes died
    if [ $AUTH_OK -eq 0 ] && ! kill -0 $AUTH_PID 2>/dev/null; then
        echo "❌ Auth service process died"
        echo "Last lines of auth-final.log:"
        tail -10 auth-final.log 2>/dev/null || echo "No log"
        break
    fi
    
    if [ $POLICY_OK -eq 0 ] && ! kill -0 $POLICY_PID 2>/dev/null; then
        echo "❌ Policy service process died"
        echo "Last lines of policy-final.log:"
        tail -10 policy-final.log 2>/dev/null || echo "No log"
        break
    fi
    
    if [ $((i % 10)) -eq 0 ]; then
        echo "   Waiting... ($i/45)"
    fi
    sleep 1
done

echo ""
echo "========================================"
echo "🎯 FINAL RESULTS:"
echo "========================================"

if [ $AUTH_OK -eq 1 ] && [ $POLICY_OK -eq 1 ]; then
    echo "🎉🎉🎉 COMPLETE SUCCESS! 🎉🎉🎉"
    echo ""
    echo "✅ Auth Service: WORKING (configuration fixes applied)"
    echo "✅ Policy Service: WORKING (duplicate route fix applied)"
    echo ""
    echo "🧪 Quick validation:"
    echo "Auth health: $(curl -s http://localhost:8080/health | head -50)"
    echo "Policy health: $(curl -s http://localhost:8081/health | head -50)"
    echo ""
    echo "🚀 SYSTEM IS FULLY OPERATIONAL!"
    echo "📋 Ready for comprehensive curl validation"
    echo ""
    echo "Service URLs:"
    echo "  Auth Service:   http://localhost:8080"
    echo "  Policy Service: http://localhost:8081"
    echo ""
    echo "🛑 To stop: kill $AUTH_PID $POLICY_PID"
    
    # Save PIDs
    echo $AUTH_PID > .auth-final.pid
    echo $POLICY_PID > .policy-final.pid
    
else
    echo "❌ Not fully operational yet:"
    echo "Auth Service: $([ $AUTH_OK -eq 1 ] && echo '✅ WORKING' || echo '❌ FAILED')"
    echo "Policy Service: $([ $POLICY_OK -eq 1 ] && echo '✅ WORKING' || echo '❌ FAILED')"
    echo ""
    if [ $AUTH_OK -eq 0 ]; then
        echo "Auth service issues - check auth-final.log"
    fi
    if [ $POLICY_OK -eq 0 ]; then
        echo "Policy service issues - check policy-final.log"  
    fi
    
    kill $AUTH_PID $POLICY_PID 2>/dev/null || true
    exit 1
fi