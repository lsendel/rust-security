#!/bin/bash

# Simple Working Startup Script (macOS compatible)
set -e

echo "🚀 Starting Rust Security Platform (Simple Version)"
echo "=================================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Clean up
echo "🧹 Cleaning up..."
pkill -f "auth-service" 2>/dev/null || true
pkill -f "policy-service" 2>/dev/null || true  
pkill -f "cargo run" 2>/dev/null || true
sleep 1

# Configuration via environment
echo "⚙️  Setting configuration..."
export RUST_LOG="info"
export AUTH__SERVER__HOST="127.0.0.1"
export AUTH__SERVER__PORT="8080"
export AUTH__SERVER__BIND_ADDR="127.0.0.1:8080"
export AUTH__SERVER__MAX_CONNECTIONS="1000"
export AUTH__DATABASE__URL="sqlite::memory:"
export AUTH__JWT__SECRET="test-jwt-secret-key-for-development-only-32chars"
export AUTH__SECURITY__ENCRYPTION_KEY="test-encryption-key-for-development-only-32char"
export POLICY_BIND_ADDR="127.0.0.1:8081"

echo -e "${GREEN}✅ Configuration set${NC}"

# Start services
echo ""
echo "🔐 Starting Auth Service..."
cd auth-service
cargo run > ../auth-service.log 2>&1 &
AUTH_PID=$!
echo "Auth Service PID: $AUTH_PID"
cd ..

echo ""
echo "📋 Starting Policy Service..."
cd policy-service
cargo run > ../policy-service.log 2>&1 &
POLICY_PID=$!
echo "Policy Service PID: $POLICY_PID"
cd ..

echo ""
echo "⏳ Waiting for services (this may take 30-60 seconds)..."

# Simple wait function
wait_for_service() {
    local url=$1
    local name=$2
    local max_wait=60
    local count=0
    
    while [ $count -lt $max_wait ]; do
        if curl -s -f "$url" >/dev/null 2>&1; then
            echo -e "${GREEN}✅ $name is ready!${NC}"
            return 0
        fi
        
        if [ $((count % 10)) -eq 0 ] && [ $count -gt 0 ]; then
            echo -e "${YELLOW}   Still waiting... (${count}s)${NC}"
        fi
        
        sleep 1
        count=$((count + 1))
    done
    
    echo -e "${RED}❌ $name timed out${NC}"
    return 1
}

# Test services
echo ""
if wait_for_service "http://127.0.0.1:8080/health" "Auth Service"; then
    AUTH_OK=1
else
    AUTH_OK=0
fi

if wait_for_service "http://127.0.0.1:8081/health" "Policy Service"; then
    POLICY_OK=1
else
    POLICY_OK=0
fi

# Results
echo ""
echo "=================================================="
echo "📊 Results:"
echo "=================================================="

if [ $AUTH_OK -eq 1 ] && [ $POLICY_OK -eq 1 ]; then
    echo -e "${GREEN}🎉 SUCCESS! Both services are running${NC}"
    echo ""
    echo "🔗 Service URLs:"
    echo "  Auth Service:   http://localhost:8080"
    echo "  Policy Service: http://localhost:8081"
    echo ""
    echo "🧪 Quick Test Commands:"
    echo "  curl http://localhost:8080/health"
    echo "  curl http://localhost:8081/health"
    echo ""
    echo "📋 PIDs (to kill later):"
    echo "  Auth: $AUTH_PID"
    echo "  Policy: $POLICY_PID"
    echo ""
    echo "📝 Logs:"
    echo "  tail -f auth-service.log"
    echo "  tail -f policy-service.log"
    echo ""
    
    # Save PIDs
    echo $AUTH_PID > .auth-service.pid
    echo $POLICY_PID > .policy-service.pid
    
    echo -e "${GREEN}✅ READY FOR TESTING!${NC}"
    echo "Press Ctrl+C to stop services..."
    wait
    
else
    echo -e "${RED}❌ FAILED: Services did not start properly${NC}"
    echo ""
    echo "🔍 Debug info:"
    echo "  Auth PID: $AUTH_PID"
    echo "  Policy PID: $POLICY_PID"
    echo ""
    echo "  Check logs:"
    echo "    tail -f auth-service.log"
    echo "    tail -f policy-service.log"
    echo ""
    echo "  Kill processes:"
    echo "    kill $AUTH_PID $POLICY_PID 2>/dev/null"
    
    exit 1
fi