#!/bin/bash

# Fixed Service Startup Script with Proper Configuration
# Addresses configuration loading issues

set -e

echo "🔧 Starting Rust Security Platform (Configuration Fixed)"
echo "======================================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Kill any existing processes
echo "🧹 Cleaning up existing processes..."
pkill -f "auth-service" 2>/dev/null || true
pkill -f "policy-service" 2>/dev/null || true
pkill -f "cargo run" 2>/dev/null || true
sleep 2

# Set comprehensive environment configuration
echo "⚙️  Setting up configuration..."
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

# Redis configuration  
export AUTH__REDIS__URL="redis://localhost:6379"
export AUTH__REDIS__POOL_SIZE="10"
export AUTH__REDIS__CONNECTION_TIMEOUT="5s"
export AUTH__REDIS__COMMAND_TIMEOUT="1s"

# Security configuration
export AUTH__JWT__SECRET="test-jwt-secret-key-for-development-only-32chars"
export AUTH__JWT__EXPIRY="1h" 
export AUTH__JWT__ALGORITHM="HS256"
export AUTH__SECURITY__ENCRYPTION_KEY="test-encryption-key-for-development-only-32char"
export AUTH__SECURITY__TOKEN_EXPIRY="1h"
export AUTH__SECURITY__REFRESH_TOKEN_EXPIRY="7d"
export AUTH__SECURITY__PASSWORD_HASH_COST="12"
export AUTH__SECURITY__MAX_FAILED_ATTEMPTS="5"
export AUTH__SECURITY__LOCKOUT_DURATION="15m"

# OAuth configuration
export AUTH__OAUTH__AUTHORIZATION_CODE_EXPIRY="10m"
export AUTH__OAUTH__ACCESS_TOKEN_EXPIRY="1h"
export AUTH__OAUTH__REFRESH_TOKEN_EXPIRY="7d"

# Rate limiting
export AUTH__RATE_LIMITING__REQUESTS_PER_MINUTE="60"
export AUTH__RATE_LIMITING__BURST_SIZE="10"
export AUTH__RATE_LIMITING__WINDOW_SIZE="1m"
export AUTH__RATE_LIMITING__CLEANUP_INTERVAL="5m"

# Session configuration
export AUTH__SESSION__DURATION="1h"
export AUTH__SESSION__CLEANUP_INTERVAL="30m"
export AUTH__SESSION__SECURE_COOKIES="false"

# Monitoring
export AUTH__MONITORING__METRICS_ENABLED="true"
export AUTH__MONITORING__TRACING_ENABLED="true"
export AUTH__MONITORING__HEALTH_CHECK_INTERVAL="30s"

# Feature flags
export AUTH__FEATURES__USER_REGISTRATION="true"
export AUTH__FEATURES__OAUTH2_FLOWS="true" 
export AUTH__FEATURES__JWT_AUTHENTICATION="true"
export AUTH__FEATURES__SESSION_MANAGEMENT="true"
export AUTH__FEATURES__RATE_LIMITING="true"

echo -e "${GREEN}✅ Configuration set${NC}"

# Policy service configuration
export POLICY_BIND_ADDR="127.0.0.1:8081"
export RUST_LOG="info"

# Check ports
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${RED}❌ Port $1 is in use, killing process${NC}"
        kill $(lsof -t -i:$1) 2>/dev/null || true
        sleep 1
    fi
    echo -e "${GREEN}✅ Port $1 is available${NC}"
}

check_port 8080
check_port 8081

# Start services individually with proper error handling
echo ""
echo "🔐 Starting Auth Service..."
cd auth-service
timeout 60 cargo run > ../auth-service.log 2>&1 &
AUTH_PID=$!
cd ..
echo "Auth Service PID: $AUTH_PID"

echo ""
echo "📋 Starting Policy Service..."
cd policy-service  
timeout 60 cargo run > ../policy-service.log 2>&1 &
POLICY_PID=$!
cd ..
echo "Policy Service PID: $POLICY_PID"

# Wait and test services
echo ""
echo "⏳ Waiting for services to start..."

wait_and_test() {
    local url=$1
    local name=$2
    local max_attempts=60
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -s -f "$url/health" > /dev/null 2>&1; then
            echo -e "${GREEN}✅ $name is ready!${NC}"
            return 0
        fi
        
        if [ $((attempt % 10)) -eq 0 ] && [ $attempt -gt 0 ]; then
            echo -e "${YELLOW}   Still waiting for $name... (${attempt}/${max_attempts})${NC}"
            # Check if process is still running
            if ! kill -0 $3 2>/dev/null; then
                echo -e "${RED}❌ $name process died, check logs${NC}"
                return 1
            fi
        fi
        
        sleep 1
        attempt=$((attempt + 1))
    done
    
    echo -e "${RED}❌ $name failed to start in time${NC}"
    return 1
}

# Test services
if wait_and_test "http://127.0.0.1:8080" "Auth Service" $AUTH_PID; then
    AUTH_STATUS="✅ READY"
else
    AUTH_STATUS="❌ FAILED"
fi

if wait_and_test "http://127.0.0.1:8081" "Policy Service" $POLICY_PID; then
    POLICY_STATUS="✅ READY" 
else
    POLICY_STATUS="❌ FAILED"
fi

# Results
echo ""
echo "======================================================="
echo "📊 Service Status:"
echo "======================================================="
echo -e "Auth Service (8080):   $AUTH_STATUS"
echo -e "Policy Service (8081): $POLICY_STATUS"
echo ""

if [[ "$AUTH_STATUS" == *"READY"* ]] && [[ "$POLICY_STATUS" == *"READY"* ]]; then
    echo -e "${GREEN}🎉 SUCCESS! Both services are running${NC}"
    echo ""
    echo "📋 Quick Tests:"
    echo "  curl http://localhost:8080/health"
    echo "  curl http://localhost:8081/health"
    echo ""
    echo "📖 Full validation:"
    echo "  ./validate-services.sh"
    echo "  cat VALIDATION_PLAN.md"
    echo ""
    echo "📝 Logs:"
    echo "  tail -f auth-service.log"
    echo "  tail -f policy-service.log"
    echo ""
    echo "🛑 To stop:"
    echo "  kill $AUTH_PID $POLICY_PID"
    echo ""
    
    # Save PIDs
    echo $AUTH_PID > .auth-service.pid
    echo $POLICY_PID > .policy-service.pid
    
    # Keep running
    echo "Press Ctrl+C to stop services..."
    wait
else
    echo -e "${RED}❌ FAILED: Some services did not start${NC}"
    echo ""
    echo "🔍 Check logs:"
    echo "  tail auth-service.log"
    echo "  tail policy-service.log"
    echo ""
    echo "🧹 Cleanup:"
    echo "  kill $AUTH_PID $POLICY_PID 2>/dev/null || true"
    
    exit 1
fi