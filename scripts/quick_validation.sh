#!/bin/bash

# Quick Validation Test - Fast smoke test for immediate feedback
# Tests core functionality without full regression suite

set -e

AUTH_URL="${1:-http://localhost:8080}"
POLICY_URL="${2:-http://localhost:8081}"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🚀 Quick Validation Test - Rust Security Workspace${NC}"
echo "Auth Service: $AUTH_URL"
echo "Policy Service: $POLICY_URL"
echo "=" $(printf '=%.0s' {1..60})

# Test 1: Health Checks
echo -n "Health Checks ... "
if curl -s -f "$AUTH_URL/health" > /dev/null && curl -s -f "$POLICY_URL/health" > /dev/null; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    exit 1
fi

# Test 2: OAuth Token Generation
echo -n "OAuth Token Generation ... "
TOKEN_RESPONSE=$(curl -s -X POST "$AUTH_URL/oauth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=read")

if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
    echo -e "${GREEN}✅ PASS${NC}"
    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
else
    echo -e "${RED}❌ FAIL${NC}"
    exit 1
fi

# Test 3: Token Introspection
echo -n "Token Introspection ... "
INTROSPECT_RESPONSE=$(curl -s -X POST "$AUTH_URL/oauth/introspect" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$ACCESS_TOKEN\"}")

if echo "$INTROSPECT_RESPONSE" | grep -q '"active":true'; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    exit 1
fi

# Test 4: Policy Evaluation
echo -n "Policy Evaluation ... "
POLICY_RESPONSE=$(curl -s -X POST "$POLICY_URL/v1/authorize" \
    -H "Content-Type: application/json" \
    -d '{
        "request_id": "quick_test",
        "principal": {"type": "User", "id": "test_user"},
        "action": "orders:read",
        "resource": {"type": "Order", "id": "order123"},
        "context": {}
    }')

if echo "$POLICY_RESPONSE" | grep -q '"decision"'; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    exit 1
fi

# Test 5: JWKS Endpoint
echo -n "JWKS Endpoint ... "
if curl -s -f "$AUTH_URL/jwks.json" | grep -q '"keys"'; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    exit 1
fi

# Test 6: Metrics Endpoint
echo -n "Metrics Endpoint ... "
if curl -s -f "$AUTH_URL/metrics" | grep -q "http_requests_total"; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    exit 1
fi

echo "=" $(printf '=%.0s' {1..60})
echo -e "${GREEN}🎉 All quick validation tests passed!${NC}"
echo -e "${BLUE}💡 Run full regression tests with: ./scripts/run_regression_tests.sh${NC}"
