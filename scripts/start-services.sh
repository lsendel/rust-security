#!/bin/bash

# Rust Security Platform - Service Startup Script
# This script starts all services required for OpenAPI endpoint testing

set -e

# Check for demo mode
DEMO_MODE=false
if [ "$1" = "--demo" ]; then
    DEMO_MODE=true
    echo "🎯 Starting in DEMO mode with pre-configured test data..."
else
    echo "🚀 Starting Rust Security Platform Services..."
fi
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
    local max_attempts=60
    local attempt=0
    
    echo -e "${YELLOW}⏳ Waiting for $service_name to be ready...${NC}"
    
    while [ $attempt -lt $max_attempts ]; do
        # Check if the service responds to health check
        if curl -s -f "$url/health" > /dev/null 2>&1; then
            echo -e "${GREEN}✅ $service_name is ready!${NC}"
            return 0
        fi
        
        # Show progress every 10 attempts
        if [ $((attempt % 10)) -eq 0 ] && [ $attempt -gt 0 ]; then
            echo -e "${YELLOW}   Still waiting... (${attempt}/${max_attempts})${NC}"
        fi
        
        attempt=$((attempt + 1))
        sleep 1
    done
    
    echo -e "${RED}❌ $service_name failed to start after $max_attempts seconds${NC}"
    echo "Check the log file for errors:"
    echo "  tail -f auth-service.log"
    return 1
}

# Check required ports
echo "📍 Checking port availability..."
check_port 8080 || { echo "Please stop the service on port 8080"; exit 1; }

# Check Redis connection (optional but recommended)
echo "📡 Checking Redis connection..."
if redis-cli ping > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Redis is available${NC}"
else
    echo -e "${YELLOW}⚠️  Redis not running - using in-memory fallback${NC}"
    export AUTH__REDIS__URL="redis://localhost:6379"
    # Try to start Redis if available
    if command -v redis-server >/dev/null 2>&1; then
        echo "  Starting Redis server..."
        redis-server --daemonize yes --port 6379 --save "" --appendonly no >/dev/null 2>&1 || echo "  Redis start failed, continuing with fallback"
        sleep 1
    fi
fi

# Create necessary environment variables
export RUST_LOG=info
export DATABASE_URL="sqlite::memory:"
export AUTH__DATABASE__URL="sqlite::memory:"
export JWT_SECRET="test-jwt-secret-key-for-development-only-32chars"
export ENCRYPTION_KEY="test-encryption-key-for-development-only-32char"

# Demo mode specific configuration
if [ "$DEMO_MODE" = true ]; then
    echo "⚙️  Setting up demo configuration..."
    export DEMO_USER_EMAIL="demo@company.com"
    export DEMO_USER_PASSWORD="SecurePass123!"
    export OAUTH_CLIENT_ID="demo-client"
    export OAUTH_CLIENT_SECRET="demo-secret"
    export ENABLE_DEMO_DATA="true"
    echo "  📧 Demo user: $DEMO_USER_EMAIL"
    echo "  🔑 OAuth client: $OAUTH_CLIENT_ID"
fi

# Build services first to avoid file lock conflicts
echo ""
echo "🔨 Building services..."
echo "  Building Auth Service..."
cd auth-service
cargo build --release --quiet
cd ..


# Start Auth Service
echo ""
echo "🔐 Starting Auth Service on port 8080..."
cd auth-service
cargo run --release > ../auth-service.log 2>&1 &
AUTH_PID=$!
echo "Auth Service PID: $AUTH_PID"
cd ..


# Wait for services to be ready
echo ""
wait_for_service "http://127.0.0.1:8080" "Auth Service"

echo ""
echo "================================================"
echo -e "${GREEN}✅ All services started successfully!${NC}"
echo ""
echo "Service Status:"
echo "  Auth Service:   http://127.0.0.1:8080 (PID: $AUTH_PID)"
echo ""
if [ "$DEMO_MODE" = true ]; then
    echo "Demo Configuration:"
    echo "  📧 Demo user: $DEMO_USER_EMAIL / $DEMO_USER_PASSWORD"
    echo "  🔑 OAuth client: $OAUTH_CLIENT_ID / $OAUTH_CLIENT_SECRET"
    echo ""
fi
echo "Logs:"
echo "  Auth Service:   ./auth-service.log"
echo ""
echo "Available endpoints:"
echo "  GET  http://127.0.0.1:8080/health         - Auth service health"
echo "  GET  http://127.0.0.1:8080/api/v1/status  - Auth service status"
echo "  POST http://127.0.0.1:8080/api/v1/auth/register - Register user"
echo "  POST http://127.0.0.1:8080/api/v1/auth/login    - Login user"
echo ""
echo "To stop services:"
echo "  kill $AUTH_PID"
echo ""
echo "To validate endpoints:"
echo "  ./validate-services.sh"
echo "================================================"

# Save PIDs to file for cleanup
echo "$AUTH_PID" > .auth-service.pid

# Keep script running to maintain services
echo ""
echo "Press Ctrl+C to stop all services..."
wait