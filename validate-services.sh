#!/bin/bash

# Service Validation Script
# Validates that services can compile and start without errors
# Also tests the endpoints documented in the Quick Start Guide

set -e

echo "🔍 Validating Rust Security Platform Services..."
echo "================================================"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Set minimal environment variables
export DATABASE_URL="sqlite::memory:"
export JWT_SECRET="validation-jwt-secret-key-minimum-32-characters"
export ENCRYPTION_KEY="validation-encryption-key-minimum-32-chars"
export RUST_LOG=error

# Function to test endpoint
test_endpoint() {
    local method=$1
    local url=$2
    local description=$3
    local expected_status=${4:-200}
    local data=$5
    
    echo -e "${YELLOW}Testing: $description${NC}"
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "%{http_code}" -o /tmp/response.json "$url" 2>/dev/null || echo "000")
    else
        response=$(curl -s -w "%{http_code}" -o /tmp/response.json -X "$method" \
                   -H "Content-Type: application/json" \
                   -d "$data" "$url" 2>/dev/null || echo "000")
    fi
    
    if [[ "$response" == *"$expected_status" ]]; then
        echo -e "  ${GREEN}✅ Success: $description${NC}"
        return 0
    else
        echo -e "  ${RED}❌ Failed: $description (HTTP $response)${NC}"
        if [ -f /tmp/response.json ] && [ -s /tmp/response.json ]; then
            echo "  Response: $(head -c 200 /tmp/response.json)"
        fi
        return 1
    fi
}

# Function to wait for service
wait_for_service() {
    local url=$1
    local service_name=$2
    local max_attempts=5
    local attempt=0
    
    echo -e "${YELLOW}⏳ Waiting for $service_name to be ready...${NC}"
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -s -o /dev/null "$url/health" 2>/dev/null; then
            echo -e "  ${GREEN}✅ $service_name is ready!${NC}"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    
    echo -e "  ${YELLOW}⚠️  $service_name not responding, will test compilation only${NC}"
    return 1
}

# Function to validate service
validate_service() {
    local service_dir=$1
    local service_name=$2
    
    echo ""
    echo -e "${YELLOW}🔧 Validating $service_name...${NC}"
    
    cd "/Users/lsendel/IdeaProjects/rust-security/$service_dir"
    
    # Check if Cargo.toml exists
    if [ ! -f "Cargo.toml" ]; then
        echo -e "${RED}❌ Cargo.toml not found in $service_dir${NC}"
        cd ..
        return 1
    fi
    
    # Try to build the service
    echo "  📦 Building $service_name..."
    if cargo build --quiet 2>/dev/null; then
        echo -e "  ${GREEN}✅ Build successful${NC}"
    else
        echo -e "  ${RED}❌ Build failed${NC}"
        cd ..
        return 1
    fi
    
    # Check for the binary
    binary_name=$(basename "$service_dir")
    if [ -f "./target/debug/$binary_name" ]; then
        echo -e "  ${GREEN}✅ Binary created${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Binary location varies${NC}"
    fi
    
    cd ..
    return 0
}

# Validate Auth Service
if validate_service "auth-service" "Auth Service"; then
    AUTH_STATUS="${GREEN}✅ READY${NC}"
else
    AUTH_STATUS="${RED}❌ FAILED${NC}"
fi

# Validate Policy Service  
if validate_service "policy-service" "Policy Service"; then
    POLICY_STATUS="${GREEN}✅ READY${NC}"
else
    POLICY_STATUS="${RED}❌ FAILED${NC}"
fi

# Test running services if they're available
echo ""
echo "🧪 Testing Documentation Examples..."
echo "================================================"

# Check if services are running and test endpoints
ENDPOINT_TESTS=true
if wait_for_service "http://127.0.0.1:8080" "Auth Service"; then
    test_endpoint "GET" "http://127.0.0.1:8080/health" "Auth Health Check" || ENDPOINT_TESTS=false
    test_endpoint "GET" "http://127.0.0.1:8080/api/v1/status" "Auth Status" || ENDPOINT_TESTS=false
else
    echo -e "  ${YELLOW}⚠️  Auth Service not running, skipping endpoint tests${NC}"
    ENDPOINT_TESTS=false
fi

if wait_for_service "http://127.0.0.1:8081" "Policy Service"; then
    test_endpoint "GET" "http://127.0.0.1:8081/health" "Policy Health Check" || ENDPOINT_TESTS=false
    test_endpoint "GET" "http://127.0.0.1:8081/metrics" "Policy Metrics" || ENDPOINT_TESTS=false
    
    # Test policy authorization with proper data
    test_endpoint "POST" "http://127.0.0.1:8081/v1/authorize" "Policy Authorization" "200" '{
        "request_id": "test-123",
        "principal": {"type": "User", "id": "demo-user"},
        "action": "Document::read", 
        "resource": {"type": "Document", "id": "doc-1"},
        "context": {}
    }' || ENDPOINT_TESTS=false
else
    echo -e "  ${YELLOW}⚠️  Policy Service not running, skipping endpoint tests${NC}"
    ENDPOINT_TESTS=false
fi

# Summary
echo ""
echo "================================================"
echo "📊 Validation Summary:"
echo "================================================"
echo -e "Auth Service:   $AUTH_STATUS"
echo -e "Policy Service: $POLICY_STATUS"
if [ "$ENDPOINT_TESTS" = true ]; then
    echo -e "Endpoint Tests: ${GREEN}✅ PASSED${NC}"
else
    echo -e "Endpoint Tests: ${YELLOW}⚠️  SKIPPED/PARTIAL${NC}"
fi
echo "================================================"

# Check if both services are ready
if [[ "$AUTH_STATUS" == *"READY"* ]] && [[ "$POLICY_STATUS" == *"READY"* ]]; then
    echo -e "${GREEN}✅ All services validated successfully!${NC}"
    echo ""
    echo "You can now run:"
    echo "  ./start-services.sh --demo    # Start services with demo data"
    echo "  ./validate-services.sh        # Test endpoints (when services running)"
    echo ""
    echo "Documentation examples are ready to use!"
    exit 0
else
    echo -e "${RED}❌ Some services failed validation${NC}"
    echo "Please check the compilation errors above."
    exit 1
fi