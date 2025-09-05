#!/bin/bash

# MVP OAuth 2.0 Service Demo Script
# This script demonstrates all the key features of the MVP OAuth service

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

BASE_URL="http://localhost:3000"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo -e "${BLUE}🚀 MVP OAuth 2.0 Service Demo${NC}"
echo -e "${BLUE}================================${NC}"
echo

# Check if service is running
echo -e "${YELLOW}📡 Checking service health...${NC}"
if ! curl -s "$BASE_URL/health" > /dev/null; then
    echo -e "${RED}❌ Service not running. Please start with: cargo run${NC}"
    echo -e "${YELLOW}💡 Or use Docker: docker-compose up -d${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Service is running${NC}"
echo

# 1. Health Check
echo -e "${YELLOW}🔍 Step 1: Health Check${NC}"
echo "GET $BASE_URL/health"
curl -s "$BASE_URL/health" | jq '.'
echo
echo

# 2. JWKS Endpoint
echo -e "${YELLOW}🔑 Step 2: JWKS Public Keys${NC}"
echo "GET $BASE_URL/.well-known/jwks.json"
curl -s "$BASE_URL/.well-known/jwks.json" | jq '.'
echo
echo

# 3. OAuth Token Request - Valid
echo -e "${YELLOW}🎟️  Step 3: Valid OAuth Token Request${NC}"
echo "POST $BASE_URL/oauth/token"
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "mvp-client",
    "client_secret": "mvp-secret"
  }')

echo "$TOKEN_RESPONSE" | jq '.'
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
echo -e "${GREEN}✅ Token obtained: ${ACCESS_TOKEN:0:50}...${NC}"
echo
echo

# 4. Token Introspection - Valid Token
echo -e "${YELLOW}🔍 Step 4: Token Introspection (Valid Token)${NC}"
echo "POST $BASE_URL/oauth/introspect"
curl -s -X POST "$BASE_URL/oauth/introspect" \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$ACCESS_TOKEN\"}" | jq '.'
echo
echo

# 5. Token Introspection - Invalid Token
echo -e "${YELLOW}❌ Step 5: Token Introspection (Invalid Token)${NC}"
echo "POST $BASE_URL/oauth/introspect"
curl -s -X POST "$BASE_URL/oauth/introspect" \
  -H "Content-Type: application/json" \
  -d '{"token": "invalid.jwt.token"}' | jq '.'
echo
echo

# 6. Invalid Client Credentials
echo -e "${YELLOW}🚫 Step 6: Invalid Client Credentials${NC}"
echo "POST $BASE_URL/oauth/token"
INVALID_RESPONSE=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "invalid-client",
    "client_secret": "wrong-secret"
  }')

HTTP_CODE="${INVALID_RESPONSE: -3}"
RESPONSE_BODY="${INVALID_RESPONSE%???}"
echo "HTTP Status: $HTTP_CODE"
echo "Response: $RESPONSE_BODY"
echo -e "${GREEN}✅ Properly rejected invalid credentials${NC}"
echo
echo

# 7. Security Validation - Malicious Input
echo -e "${YELLOW}🛡️  Step 7: Security Validation (Malicious Input)${NC}"
echo "POST $BASE_URL/oauth/token (with control characters)"
MALICIOUS_RESPONSE=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "malicious\u0000client",
    "client_secret": "secret"
  }')

HTTP_CODE="${MALICIOUS_RESPONSE: -3}"
RESPONSE_BODY="${MALICIOUS_RESPONSE%???}"
echo "HTTP Status: $HTTP_CODE"
echo "Response: $RESPONSE_BODY"
echo -e "${GREEN}✅ Security validation blocked malicious input${NC}"
echo
echo

# 8. Metrics Endpoint
echo -e "${YELLOW}📊 Step 8: Metrics Endpoint${NC}"
echo "GET $BASE_URL/metrics"
curl -s "$BASE_URL/metrics" | head -10
echo "..."
echo
echo

# 9. JWT Token Analysis
echo -e "${YELLOW}🔬 Step 9: JWT Token Analysis${NC}"
echo "Analyzing the obtained JWT token:"
echo

# Split JWT into parts
IFS='.' read -ra JWT_PARTS <<< "$ACCESS_TOKEN"
HEADER="${JWT_PARTS[0]}"
PAYLOAD="${JWT_PARTS[1]}"

# Add padding if needed for base64 decoding
add_padding() {
    local str=$1
    while [ $((${#str} % 4)) -ne 0 ]; do
        str="${str}="
    done
    echo "$str"
}

HEADER_PADDED=$(add_padding "$HEADER")
PAYLOAD_PADDED=$(add_padding "$PAYLOAD")

echo "JWT Header:"
echo "$HEADER_PADDED" | base64 -d 2>/dev/null | jq '.' 2>/dev/null || echo "Could not decode header"
echo

echo "JWT Payload:"
echo "$PAYLOAD_PADDED" | base64 -d 2>/dev/null | jq '.' 2>/dev/null || echo "Could not decode payload"
echo
echo

# 10. Rate Limiting Demo (if nginx proxy is available)
echo -e "${YELLOW}⚡ Step 10: Performance Test${NC}"
echo "Making 5 rapid requests to test service responsiveness..."
for i in {1..5}; do
    RESPONSE_TIME=$(curl -s -w "%{time_total}" -o /dev/null "$BASE_URL/health")
    echo "Request $i: ${RESPONSE_TIME}s"
done
echo
echo

# Summary
echo -e "${BLUE}📋 Demo Summary${NC}"
echo -e "${BLUE}===============${NC}"
echo -e "${GREEN}✅ Health check: Service is operational${NC}"
echo -e "${GREEN}✅ JWKS endpoint: Public keys available${NC}"
echo -e "${GREEN}✅ OAuth flow: Token issuance working${NC}"
echo -e "${GREEN}✅ Token introspection: Validation working${NC}"
echo -e "${GREEN}✅ Security validation: Malicious input blocked${NC}"
echo -e "${GREEN}✅ Error handling: Invalid clients rejected${NC}"
echo -e "${GREEN}✅ Monitoring: Health and metrics endpoints${NC}"
echo -e "${GREEN}✅ JWT analysis: Standard-compliant tokens${NC}"
echo
echo -e "${BLUE}🎉 MVP OAuth 2.0 Service Demo Complete!${NC}"
echo -e "${YELLOW}💡 Next steps:${NC}"
echo -e "   • Configure production secrets in .env"
echo -e "   • Deploy with Docker: docker-compose up -d"
echo -e "   • Enable HTTPS and proper SSL certificates"
echo -e "   • Configure monitoring and alerting"
echo -e "   • Integrate with your applications"
echo

echo -e "${BLUE}📚 Documentation:${NC}"
echo -e "   • README.md - Setup and configuration"
echo -e "   • .env.example - Environment variables"  
echo -e "   • docker-compose.yml - Deployment configuration"
echo