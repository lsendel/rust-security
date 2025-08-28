#!/bin/bash

# Rust Security Platform - Service Startup Script
# This script starts all services required for OpenAPI endpoint testing

set -e

echo "🚀 Starting Rust Security Platform Services..."
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if a port is available
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${RED}❌ Port $1 is already in use${NC}"
        return 1
    else
        echo -e "${GREEN}✅ Port $1 is available${NC}"
        return 0
    fi
}

# Function to wait for service to be ready
wait_for_service() {
    local url=$1
    local service_name=$2
    local max_attempts=30
    local attempt=0
    
    echo -e "${YELLOW}⏳ Waiting for $service_name to be ready...${NC}"
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -s -o /dev/null -w "%{http_code}" "$url/health" | grep -q "200\|204"; then
            echo -e "${GREEN}✅ $service_name is ready!${NC}"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    
    echo -e "${RED}❌ $service_name failed to start after $max_attempts attempts${NC}"
    return 1
}

# Check required ports
echo "📍 Checking port availability..."
check_port 8080 || { echo "Please stop the service on port 8080"; exit 1; }
check_port 8081 || { echo "Please stop the service on port 8081"; exit 1; }

# Create necessary environment variables
export RUST_LOG=info
export DATABASE_URL="sqlite::memory:"
export JWT_SECRET="test-jwt-secret-key-for-development-only-32chars"
export ENCRYPTION_KEY="test-encryption-key-for-development-only-32char"

# Start Auth Service
echo ""
echo "🔐 Starting Auth Service on port 8080..."
cd auth-service
cargo run --release > ../auth-service.log 2>&1 &
AUTH_PID=$!
echo "Auth Service PID: $AUTH_PID"
cd ..

# Start Policy Service
echo ""
echo "📋 Starting Policy Service on port 8081..."
cd policy-service
cargo run --release > ../policy-service.log 2>&1 &
POLICY_PID=$!
echo "Policy Service PID: $POLICY_PID"
cd ..

# Wait for services to be ready
echo ""
wait_for_service "http://127.0.0.1:8080" "Auth Service"
wait_for_service "http://127.0.0.1:8081" "Policy Service"

echo ""
echo "================================================"
echo -e "${GREEN}✅ All services started successfully!${NC}"
echo ""
echo "Service Status:"
echo "  Auth Service:   http://127.0.0.1:8080 (PID: $AUTH_PID)"
echo "  Policy Service: http://127.0.0.1:8081 (PID: $POLICY_PID)"
echo ""
echo "Logs:"
echo "  Auth Service:   ./auth-service.log"
echo "  Policy Service: ./policy-service.log"
echo ""
echo "To stop services:"
echo "  kill $AUTH_PID $POLICY_PID"
echo ""
echo "To run endpoint tests:"
echo "  cargo test --test openapi_endpoints_test"
echo "================================================"

# Save PIDs to file for cleanup
echo "$AUTH_PID" > .auth-service.pid
echo "$POLICY_PID" > .policy-service.pid

# Keep script running to maintain services
echo ""
echo "Press Ctrl+C to stop all services..."
wait