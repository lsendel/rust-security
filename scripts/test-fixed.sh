#!/bin/bash

# Comprehensive Service Test with Full Configuration
echo "🔧 Comprehensive Service Test"
echo "============================="

# Kill existing processes
pkill -f "auth-service" 2>/dev/null || true
pkill -f "policy-service" 2>/dev/null || true  
sleep 2

# Set comprehensive environment configuration
export RUST_LOG="info"

# Server configuration
export AUTH__SERVER__HOST="127.0.0.1"
export AUTH__SERVER__PORT="8080"
export AUTH__SERVER__BIND_ADDR="127.0.0.1:8080"
export AUTH__SERVER__MAX_CONNECTIONS="1000"
export AUTH__SERVER__REQUEST_TIMEOUT="30s"
export AUTH__SERVER__SHUTDOWN_TIMEOUT="30s"

# Database configuration  
export AUTH__DATABASE__URL="sqlite::memory:"

# JWT and Security configuration
export AUTH__JWT__SECRET="test-jwt-secret-key-for-development-only-32chars"
export AUTH__JWT__EXPIRY="1h"
export AUTH__JWT__ALGORITHM="HS256"
export AUTH__JWT__ISSUER="http://localhost:8080"
export AUTH__SECURITY__ENCRYPTION_KEY="test-encryption-key-for-development-only-32char"

# OAuth configuration
export AUTH__OAUTH__AUTHORIZATION_CODE_EXPIRY="10m"
export AUTH__OAUTH__ACCESS_TOKEN_EXPIRY="1h"
export AUTH__OAUTH__REFRESH_TOKEN_EXPIRY="7d"

# Rate limiting
export AUTH__RATE_LIMITING__REQUESTS_PER_MINUTE="60"
export AUTH__RATE_LIMITING__BURST_SIZE="10"

# Session configuration
export AUTH__SESSION__DURATION="1h"
export AUTH__SESSION__SECURE_COOKIES="false"

# Feature flags
export AUTH__FEATURES__USER_REGISTRATION="true"
export AUTH__FEATURES__OAUTH2_FLOWS="true"
export AUTH__FEATURES__JWT_AUTHENTICATION="true"

# Monitoring
export AUTH__MONITORING__METRICS_ENABLED="true"
export AUTH__MONITORING__TRACING_ENABLED="true"

# Policy service
export POLICY_BIND_ADDR="127.0.0.1:8081"

echo "✅ Configuration set with all required fields"
echo ""

# Test auth service compilation first
echo "🔍 Testing auth service compilation..."
cd auth-service
if cargo check --quiet; then
    echo "✅ Auth service compiles successfully"
else
    echo "❌ Auth service compilation failed"
    cd ..
    exit 1
fi

# Start auth service
echo "🔐 Starting auth service..."
cargo run > ../auth-comprehensive.log 2>&1 &
AUTH_PID=$!
echo "Auth Service PID: $AUTH_PID"
cd ..

# Test policy service compilation
echo "🔍 Testing policy service compilation..."
cd policy-service
if cargo check --quiet; then
    echo "✅ Policy service compiles successfully"
else
    echo "❌ Policy service compilation failed"
    kill $AUTH_PID 2>/dev/null || true
    cd ..
    exit 1
fi

# Start policy service
echo "📋 Starting policy service..."
cargo run > ../policy-comprehensive.log 2>&1 &
POLICY_PID=$!
echo "Policy Service PID: $POLICY_PID"
cd ..

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
        echo "❌ Auth service process died"
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
        echo "❌ Policy service process died" 
        break
    fi
    
    if [ $((i % 10)) -eq 0 ]; then
        echo "   Still waiting for policy service... ($i/60)"
    fi
    sleep 1
done

echo ""
echo "============================="
echo "📊 Final Results:"
echo "============================="

if [ $AUTH_OK -eq 1 ] && [ $POLICY_OK -eq 1 ]; then
    echo "🎉 SUCCESS! Both services are working!"
    echo ""
    echo "🧪 Testing endpoints:"
    echo "curl http://localhost:8080/health"
    curl -s http://localhost:8080/health | head -100
    echo ""
    echo "curl http://localhost:8081/health"
    curl -s http://localhost:8081/health | head -100
    echo ""
    echo "✅ READY FOR FULL CURL VALIDATION"
    echo ""
    echo "🛑 To stop services: kill $AUTH_PID $POLICY_PID"
    
    # Save PIDs
    echo $AUTH_PID > .auth-comprehensive.pid
    echo $POLICY_PID > .policy-comprehensive.pid
    
else
    echo "❌ FAILED"
    echo ""
    if [ $AUTH_OK -eq 0 ]; then
        echo "Auth service failed. Last 10 lines:"
        tail -10 auth-comprehensive.log 2>/dev/null || echo "No auth log"
        echo ""
    fi
    
    if [ $POLICY_OK -eq 0 ]; then
        echo "Policy service failed. Last 10 lines:"
        tail -10 policy-comprehensive.log 2>/dev/null || echo "No policy log"
        echo ""
    fi
    
    echo "🧹 Cleaning up..."
    kill $AUTH_PID $POLICY_PID 2>/dev/null || true
    exit 1
fi