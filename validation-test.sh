#!/bin/bash

# Quick System Validation with curl
echo "🧪 Quick System Validation"
echo "=========================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test counter
TESTS=0
PASSED=0

test_endpoint() {
    local method=$1
    local url=$2
    local description=$3
    local data=$4
    local expected_status=${5:-200}
    
    TESTS=$((TESTS + 1))
    echo -e "${YELLOW}[$TESTS] Testing: $description${NC}"
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "%{http_code}" -o /tmp/response.json "$url" 2>/dev/null)
    else
        response=$(curl -s -w "%{http_code}" -o /tmp/response.json -X "$method" \
                   -H "Content-Type: application/json" \
                   -d "$data" "$url" 2>/dev/null)
    fi
    
    if [[ "$response" == "$expected_status" ]]; then
        echo -e "${GREEN}    ✅ Success (HTTP $response)${NC}"
        if [ -f /tmp/response.json ] && [ -s /tmp/response.json ]; then
            echo "    Response: $(head -c 100 /tmp/response.json)..."
        fi
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}    ❌ Failed (HTTP $response, expected $expected_status)${NC}"
        if [ -f /tmp/response.json ]; then
            echo "    Error: $(cat /tmp/response.json)"
        fi
    fi
    echo ""
}

echo "Checking if services are running..."
echo ""

# Basic health checks
test_endpoint "GET" "http://localhost:8080/health" "Auth Service Health Check"
test_endpoint "GET" "http://localhost:8081/health" "Policy Service Health Check"

# Auth service endpoints
test_endpoint "GET" "http://localhost:8080/api/v1/status" "Auth Service Status"

# User registration
test_endpoint "POST" "http://localhost:8080/api/v1/auth/register" "User Registration" '{
  "email": "test@example.com",
  "password": "testpass123",
  "name": "Test User"
}'

# User login  
test_endpoint "POST" "http://localhost:8080/api/v1/auth/login" "User Login" '{
  "email": "test@example.com",
  "password": "testpass123"
}'

# Policy authorization
test_endpoint "POST" "http://localhost:8081/v1/authorize" "Policy Authorization" '{
  "request_id": "test-123",
  "principal": {"type": "User", "id": "test-user"},
  "action": "Document::read",
  "resource": {"type": "Document", "id": "doc-1"},
  "context": {}
}'

# Policy metrics
test_endpoint "GET" "http://localhost:8081/metrics" "Policy Service Metrics"

# Results
echo "=========================="
echo "📊 Validation Results:"
echo "=========================="
echo -e "Tests run: $TESTS"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$((TESTS - PASSED))${NC}"

if [ $PASSED -eq $TESTS ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED! System is working correctly.${NC}"
    echo ""
    echo "✅ You can now use all the documentation examples"
    echo "✅ All curl commands in the docs will work"
    echo "✅ Services are ready for development"
    exit 0
else
    echo -e "${RED}⚠️  Some tests failed. Check the output above.${NC}"
    echo ""
    echo "🔍 Troubleshooting:"
    echo "  - Check if services are running: ps aux | grep -E '(auth|policy)'"
    echo "  - Check service logs: tail -f auth-service.log policy-service.log"
    echo "  - Try restarting: ./start-services-fixed.sh"
    exit 1
fi