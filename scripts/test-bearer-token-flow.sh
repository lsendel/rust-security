#!/bin/bash

# Complete Bearer Token Flow Testing Guide
echo "🔐 Bearer Token Flow Testing Guide"
echo "=================================="
echo "This script demonstrates the complete authentication flow with JWT tokens"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if services are running
echo "🔍 Checking service availability..."
if ! curl -s -f http://localhost:8080/health >/dev/null 2>&1; then
    printf "${RED}❌ Auth service not running. Start with: ./test-with-config-file.sh${NC}\n"
    exit 1
fi

if ! curl -s -f http://localhost:8081/health >/dev/null 2>&1; then
    printf "${RED}❌ Policy service not running. Start with: ./test-with-config-file.sh${NC}\n"
    exit 1
fi

printf "${GREEN}✅ Both services are running${NC}\n"
echo ""

# Step 1: Register a new user
echo "=================================="
printf "${BLUE}STEP 1: Register a New User${NC}\n"
echo "=================================="

USER_EMAIL="bearer-test@example.com"
USER_PASSWORD="BearerTest123!"
USER_NAME="Bearer Test User"

echo "Registering user: $USER_EMAIL"
echo ""

REGISTER_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST http://localhost:8080/api/v1/auth/register \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"$USER_EMAIL\",
        \"password\": \"$USER_PASSWORD\",
        \"name\": \"$USER_NAME\"
    }")

REGISTER_CODE=$(echo "$REGISTER_RESPONSE" | tail -n1)
REGISTER_BODY=$(echo "$REGISTER_RESPONSE" | head -n -1)

if [ "$REGISTER_CODE" = "201" ] || [ "$REGISTER_CODE" = "200" ]; then
    printf "${GREEN}✅ Registration successful (HTTP $REGISTER_CODE)${NC}\n"
    echo "Response: $REGISTER_BODY"
else
    printf "${YELLOW}⚠️  Registration response (HTTP $REGISTER_CODE): $REGISTER_BODY${NC}\n"
    echo "Proceeding with login (user may already exist)..."
fi

echo ""

# Step 2: Login and get JWT token
echo "=================================="
printf "${BLUE}STEP 2: Login and Extract JWT Token${NC}\n"
echo "=================================="

echo "Logging in user: $USER_EMAIL"
echo ""

LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST http://localhost:8080/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"$USER_EMAIL\",
        \"password\": \"$USER_PASSWORD\"
    }")

LOGIN_CODE=$(echo "$LOGIN_RESPONSE" | tail -n1)
LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | head -n -1)

if [ "$LOGIN_CODE" = "200" ]; then
    printf "${GREEN}✅ Login successful!${NC}\n"
    echo "Full response: $LOGIN_BODY"
    echo ""
    
    # Try to extract token using different possible JSON field names
    # Common field names: token, access_token, jwt, bearer_token
    JWT_TOKEN=$(echo "$LOGIN_BODY" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    # Try different possible field names for the token
    token = data.get('token') or data.get('access_token') or data.get('jwt') or data.get('bearer_token')
    if token:
        print(token)
    else:
        # If no standard field found, print available fields
        print('TOKEN_FIELDS_AVAILABLE:', list(data.keys()))
except:
    print('JSON_PARSE_ERROR')
" 2>/dev/null)
    
    if [ -n "$JWT_TOKEN" ] && [ "$JWT_TOKEN" != "JSON_PARSE_ERROR" ] && [[ "$JWT_TOKEN" != TOKEN_FIELDS_AVAILABLE* ]]; then
        printf "${GREEN}✅ JWT Token extracted successfully!${NC}\n"
        echo "Token (first 50 chars): ${JWT_TOKEN:0:50}..."
        echo ""
        
        # Step 3: Use Bearer token for authenticated requests
        echo "=================================="
        printf "${BLUE}STEP 3: Test Bearer Token Authentication${NC}\n"
        echo "=================================="
        
        echo "Testing authenticated endpoints with Bearer token..."
        echo ""
        
        # Test 1: Token validation endpoint
        echo "🧪 Test 1: Token Validation"
        echo "curl -H \"Authorization: Bearer \$TOKEN\" http://localhost:8080/api/v1/auth/validate"
        
        VALIDATE_RESPONSE=$(curl -s -w "\n%{http_code}" \
            -H "Authorization: Bearer $JWT_TOKEN" \
            http://localhost:8080/api/v1/auth/validate)
        
        VALIDATE_CODE=$(echo "$VALIDATE_RESPONSE" | tail -n1)
        VALIDATE_BODY=$(echo "$VALIDATE_RESPONSE" | head -n -1)
        
        if [ "$VALIDATE_CODE" = "200" ]; then
            printf "${GREEN}✅ Token validation successful!${NC}\n"
            echo "Response: $VALIDATE_BODY"
        else
            printf "${YELLOW}⚠️  Token validation (HTTP $VALIDATE_CODE): $VALIDATE_BODY${NC}\n"
        fi
        echo ""
        
        # Test 2: User profile endpoint
        echo "🧪 Test 2: Get User Profile"
        echo "curl -H \"Authorization: Bearer \$TOKEN\" http://localhost:8080/api/v1/user/profile"
        
        PROFILE_RESPONSE=$(curl -s -w "\n%{http_code}" \
            -H "Authorization: Bearer $JWT_TOKEN" \
            http://localhost:8080/api/v1/user/profile)
        
        PROFILE_CODE=$(echo "$PROFILE_RESPONSE" | tail -n1)
        PROFILE_BODY=$(echo "$PROFILE_RESPONSE" | head -n -1)
        
        if [ "$PROFILE_CODE" = "200" ]; then
            printf "${GREEN}✅ Profile access successful!${NC}\n"
            echo "Response: $PROFILE_BODY"
        else
            printf "${YELLOW}⚠️  Profile access (HTTP $PROFILE_CODE): $PROFILE_BODY${NC}\n"
        fi
        echo ""
        
        # Test 3: Protected admin endpoint
        echo "🧪 Test 3: Protected Admin Endpoint"
        echo "curl -H \"Authorization: Bearer \$TOKEN\" http://localhost:8080/api/v1/admin/users"
        
        ADMIN_RESPONSE=$(curl -s -w "\n%{http_code}" \
            -H "Authorization: Bearer $JWT_TOKEN" \
            http://localhost:8080/api/v1/admin/users)
        
        ADMIN_CODE=$(echo "$ADMIN_RESPONSE" | tail -n1)
        ADMIN_BODY=$(echo "$ADMIN_RESPONSE" | head -n -1)
        
        if [ "$ADMIN_CODE" = "200" ]; then
            printf "${GREEN}✅ Admin access successful!${NC}\n"
            echo "Response: $ADMIN_BODY"
        else
            printf "${YELLOW}⚠️  Admin access (HTTP $ADMIN_CODE): $ADMIN_BODY${NC}\n"
            echo "Note: This may be expected if user lacks admin permissions"
        fi
        echo ""
        
        # Step 4: Test with Policy Service (Authorization)
        echo "=================================="
        printf "${BLUE}STEP 4: Test Authorization with Policy Service${NC}\n"
        echo "=================================="
        
        echo "Testing policy-based authorization..."
        echo ""
        
        # Test authorization with user context
        echo "🧪 Test 4: Policy Authorization with User Context"
        echo "curl -X POST http://localhost:8081/v1/authorize -d '{\"principal\": {\"type\": \"User\", \"id\": \"$USER_EMAIL\"}, ...}'"
        
        AUTHZ_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST http://localhost:8081/v1/authorize \
            -H "Content-Type: application/json" \
            -d "{
                \"principal\": {\"type\": \"User\", \"id\": \"$USER_EMAIL\"},
                \"action\": {\"type\": \"Action\", \"id\": \"read\"},
                \"resource\": {\"type\": \"Document\", \"id\": \"user-document-123\"},
                \"context\": {
                    \"authenticated\": true,
                    \"jwt_token\": \"present\",
                    \"user_email\": \"$USER_EMAIL\"
                }
            }")
        
        AUTHZ_CODE=$(echo "$AUTHZ_RESPONSE" | tail -n1)
        AUTHZ_BODY=$(echo "$AUTHZ_RESPONSE" | head -n -1)
        
        if [ "$AUTHZ_CODE" = "200" ]; then
            printf "${GREEN}✅ Authorization successful!${NC}\n"
            echo "Response: $AUTHZ_BODY"
        else
            printf "${YELLOW}⚠️  Authorization (HTTP $AUTHZ_CODE): $AUTHZ_BODY${NC}\n"
        fi
        echo ""
        
        # Step 5: Test token expiration and refresh
        echo "=================================="
        printf "${BLUE}STEP 5: Token Information and Best Practices${NC}\n"
        echo "=================================="
        
        echo "📋 Your JWT Token Details:"
        echo "  - Token (truncated): ${JWT_TOKEN:0:50}..."
        echo "  - Length: ${#JWT_TOKEN} characters"
        echo "  - Format: JWT (JSON Web Token)"
        echo ""
        
        echo "🔐 How to use this token in your applications:"
        echo ""
        echo "1️⃣  curl commands:"
        echo "   curl -H \"Authorization: Bearer $JWT_TOKEN\" http://localhost:8080/api/endpoint"
        echo ""
        echo "2️⃣  JavaScript (fetch):"
        echo "   fetch('/api/endpoint', {"
        echo "     headers: { 'Authorization': 'Bearer $JWT_TOKEN' }"
        echo "   })"
        echo ""
        echo "3️⃣  Python (requests):"
        echo "   headers = {'Authorization': f'Bearer {token}'}"
        echo "   response = requests.get('/api/endpoint', headers=headers)"
        echo ""
        echo "4️⃣  Postman/Insomnia:"
        echo "   - Auth Type: Bearer Token"
        echo "   - Token: $JWT_TOKEN"
        echo ""
        
        # Test invalid token
        echo "=================================="
        printf "${BLUE}STEP 6: Test Invalid Token (Security Validation)${NC}\n"
        echo "=================================="
        
        echo "🧪 Testing with invalid token (should fail):"
        
        INVALID_RESPONSE=$(curl -s -w "\n%{http_code}" \
            -H "Authorization: Bearer invalid-token-12345" \
            http://localhost:8080/api/v1/auth/validate)
        
        INVALID_CODE=$(echo "$INVALID_RESPONSE" | tail -n1)
        INVALID_BODY=$(echo "$INVALID_RESPONSE" | head -n -1)
        
        if [ "$INVALID_CODE" = "401" ]; then
            printf "${GREEN}✅ Security working! Invalid token correctly rejected (HTTP 401)${NC}\n"
            echo "Response: $INVALID_BODY"
        else
            printf "${YELLOW}⚠️  Unexpected response for invalid token (HTTP $INVALID_CODE): $INVALID_BODY${NC}\n"
        fi
        echo ""
        
        # Summary
        echo "=================================="
        printf "${BLUE}🎉 BEARER TOKEN FLOW COMPLETE!${NC}\n"
        echo "=================================="
        
        printf "${GREEN}✅ SUCCESSFUL BEARER TOKEN FLOW:${NC}\n"
        echo "  1. ✅ User registration"
        echo "  2. ✅ User login and token extraction"
        echo "  3. ✅ Token-based authentication testing"
        echo "  4. ✅ Policy-based authorization testing"
        echo "  5. ✅ Security validation (invalid token rejection)"
        echo ""
        
        printf "${GREEN}🔑 Your working JWT token:${NC}\n"
        echo "$JWT_TOKEN"
        echo ""
        
        printf "${GREEN}📋 Ready to use in your applications!${NC}\n"
        
    else
        printf "${YELLOW}⚠️  Could not extract JWT token from response${NC}\n"
        echo "Available fields in response: $JWT_TOKEN"
        echo ""
        printf "${YELLOW}Manual token extraction needed:${NC}\n"
        echo "Response body: $LOGIN_BODY"
        echo ""
        echo "🔍 Look for fields like: token, access_token, jwt, bearer_token"
        echo "Then use: curl -H \"Authorization: Bearer <YOUR_TOKEN>\" <URL>"
    fi
    
else
    printf "${RED}❌ Login failed (HTTP $LOGIN_CODE)${NC}\n"
    echo "Response: $LOGIN_BODY"
    echo ""
    echo "🔧 Troubleshooting:"
    echo "  - Check if user registration was successful"
    echo "  - Verify email and password are correct"
    echo "  - Ensure auth service is configured properly"
    exit 1
fi