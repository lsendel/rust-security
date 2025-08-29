#!/bin/bash

# OAuth 2.0 Server Testing Script
# This script demonstrates how to test the auth-core server

echo "🔐 OAuth 2.0 Server Testing Script"
echo "=================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Server configuration
SERVER_URL="http://localhost:8080"
CLIENT_ID="demo-client"
CLIENT_SECRET="demo-secret"

echo "📋 Server Info:"
echo "  URL: $SERVER_URL"
echo "  Client ID: $CLIENT_ID"
echo "  Client Secret: $CLIENT_SECRET"
echo ""

# Test 1: Health Check
echo "🏥 Test 1: Health Check"
echo "------------------------"
echo "curl -s $SERVER_URL/health"
echo ""

# Test 2: OAuth Token Request
echo "🎫 Test 2: Request OAuth Token"
echo "------------------------------"
echo "curl -X POST $SERVER_URL/oauth/token \\"
echo "     -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "     -d 'grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET'"
echo ""

# Test 3: Invalid Client
echo "❌ Test 3: Invalid Client Test"
echo "------------------------------"
echo "curl -X POST $SERVER_URL/oauth/token \\"
echo "     -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "     -d 'grant_type=client_credentials&client_id=invalid&client_secret=invalid'"
echo ""

# Test 4: Token Introspection (if supported)
echo "🔍 Test 4: Token Introspection"
echo "------------------------------"
echo "# First get a token, then introspect it:"
echo "TOKEN=\$(curl -s -X POST $SERVER_URL/oauth/token \\"
echo "         -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "         -d 'grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET' | jq -r '.access_token')"
echo ""
echo "curl -X POST $SERVER_URL/oauth/introspect \\"
echo "     -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "     -d \"token=\$TOKEN&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET\""
echo ""

# Interactive mode
echo "🚀 Interactive Testing"
echo "====================="
echo ""
echo "To run these tests interactively:"
echo ""
echo "1. Start the server:"
echo -e "${YELLOW}   cd auth-core && cargo run --example minimal_server --features=\"client-credentials,jwt\"${NC}"
echo ""
echo "2. In another terminal, run the tests:"
echo ""
echo -e "${GREEN}# Health check${NC}"
echo "curl -s http://localhost:8080/health"
echo ""
echo -e "${GREEN}# Get OAuth token${NC}"
echo "curl -X POST http://localhost:8080/oauth/token \\"
echo "     -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "     -d 'grant_type=client_credentials&client_id=demo-client&client_secret=demo-secret'"
echo ""
echo -e "${GREEN}# Test invalid credentials${NC}"  
echo "curl -X POST http://localhost:8080/oauth/token \\"
echo "     -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "     -d 'grant_type=client_credentials&client_id=invalid&client_secret=wrong'"
echo ""

# Automated test function
echo "🤖 Automated Testing Function"
echo "============================="
echo ""
echo "Run: ./test-server.sh auto"
echo ""

if [ "$1" = "auto" ]; then
    echo "Running automated tests..."
    echo ""
    
    # Check if server is running
    echo "Checking server status..."
    if curl -s --connect-timeout 5 "$SERVER_URL/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Server is running${NC}"
    else
        echo -e "${RED}❌ Server is not running. Please start it first.${NC}"
        echo "Start server with: cd auth-core && cargo run --example minimal_server --features=\"client-credentials,jwt\""
        exit 1
    fi
    
    echo ""
    echo "🏥 Testing health endpoint..."
    HEALTH_RESPONSE=$(curl -s "$SERVER_URL/health")
    echo "Response: $HEALTH_RESPONSE"
    
    echo ""
    echo "🎫 Testing OAuth token endpoint..."
    TOKEN_RESPONSE=$(curl -s -X POST "$SERVER_URL/oauth/token" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET")
    echo "Response: $TOKEN_RESPONSE"
    
    # Try to extract token if jq is available
    if command -v jq > /dev/null 2>&1; then
        TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')
        if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
            echo -e "${GREEN}✅ Token generated successfully${NC}"
            echo "Token: $TOKEN"
        else
            echo -e "${YELLOW}⚠️  No token in response (might be due to simplified implementation)${NC}"
        fi
    fi
    
    echo ""
    echo "❌ Testing invalid credentials..."
    INVALID_RESPONSE=$(curl -s -X POST "$SERVER_URL/oauth/token" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d "grant_type=client_credentials&client_id=invalid&client_secret=wrong")
    echo "Response: $INVALID_RESPONSE"
    
    echo ""
    echo -e "${GREEN}🎉 Automated testing complete!${NC}"
fi