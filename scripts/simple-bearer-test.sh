#!/bin/bash

# Simple Bearer Token Test
echo "🔐 Simple Bearer Token Test"
echo "=========================="

# Check services
if ! curl -s -f http://localhost:8080/health >/dev/null; then
    echo "❌ Auth service not running. Start with: ./test-with-config-file.sh"
    exit 1
fi

echo "✅ Auth service is running"
echo ""

# Test user credentials
USER_EMAIL="simple-test@example.com"
USER_PASSWORD="SimpleTest123!"

echo "🔹 Step 1: Register user"
echo "========================"
echo "curl -X POST http://localhost:8080/api/v1/auth/register \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\",\"name\":\"Simple Test\"}'"
echo ""

curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\",\"name\":\"Simple Test\"}" \
  -w "\nHTTP_CODE: %{http_code}\n"

echo ""
echo "🔹 Step 2: Login user and get response"
echo "======================================"
echo "curl -X POST http://localhost:8080/api/v1/auth/login \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\"}'"
echo ""

echo "Full login response:"
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\"}" \
  -w "\nHTTP_CODE: %{http_code}")

echo "$LOGIN_RESPONSE"
echo ""

# Extract HTTP code
HTTP_CODE=$(echo "$LOGIN_RESPONSE" | grep "HTTP_CODE:" | cut -d' ' -f2)
RESPONSE_BODY=$(echo "$LOGIN_RESPONSE" | grep -v "HTTP_CODE:")

echo "🔹 Step 3: Analyze Response"
echo "=========================="
echo "HTTP Status Code: $HTTP_CODE"
echo "Response Body: $RESPONSE_BODY"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Login successful!"
    echo ""
    echo "🔍 Looking for JWT token in response..."
    
    # Check if response has content
    if [ -n "$RESPONSE_BODY" ] && [ "$RESPONSE_BODY" != "" ]; then
        echo "Response contains data. Look for token fields:"
        echo "$RESPONSE_BODY" | sed 's/,/,\n/g'
    else
        echo "⚠️  Response body is empty."
        echo ""
        echo "This might mean:"
        echo "1. Login creates session cookies instead of returning JWT"
        echo "2. Token is in response headers"
        echo "3. Different authentication mechanism is used"
    fi
    
    echo ""
    echo "🔹 Step 4: Test different authentication methods"
    echo "=============================================="
    
    echo "Method 1: Test if cookies are used for authentication"
    echo "curl -c cookies.txt -X POST http://localhost:8080/api/v1/auth/login ..."
    
    # Login with cookie jar
    curl -c /tmp/auth_cookies.txt -s -X POST http://localhost:8080/api/v1/auth/login \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\"}" > /dev/null
    
    echo "Cookies saved. Testing with cookies:"
    echo "curl -b cookies.txt http://localhost:8080/api/v1/auth/validate"
    
    COOKIE_TEST=$(curl -b /tmp/auth_cookies.txt -s -w "HTTP_CODE: %{http_code}" \
      http://localhost:8080/api/v1/auth/validate)
    
    echo "Cookie authentication test: $COOKIE_TEST"
    echo ""
    
    echo "Method 2: Check for JWT in response headers"
    echo "curl -I -X POST http://localhost:8080/api/v1/auth/login ..."
    
    HEADER_RESPONSE=$(curl -I -s -X POST http://localhost:8080/api/v1/auth/login \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\"}")
    
    echo "Response headers:"
    echo "$HEADER_RESPONSE"
    echo ""
    
    echo "Method 3: Test session-based access"
    echo "Some systems use session cookies instead of JWT tokens."
    echo ""
    
    # Test various endpoints that might reveal authentication method
    echo "🔹 Step 5: Test available authenticated endpoints"
    echo "=============================================="
    
    echo "Testing various endpoints to understand authentication..."
    echo ""
    
    # Test with cookies
    echo "With cookies:"
    curl -b /tmp/auth_cookies.txt -s -w " (HTTP: %{http_code})" http://localhost:8080/api/v1/user/profile
    echo ""
    curl -b /tmp/auth_cookies.txt -s -w " (HTTP: %{http_code})" http://localhost:8080/api/v1/auth/validate
    echo ""
    
    # List possible endpoints
    echo ""
    echo "📋 Common endpoints to test for JWT tokens:"
    echo "  - POST /api/v1/auth/token (token endpoint)"
    echo "  - GET  /api/v1/auth/me (user info)"
    echo "  - POST /api/v1/oauth/token (OAuth token)"
    echo "  - GET  /.well-known/openid-configuration (OIDC config)"
    
else
    echo "❌ Login failed with HTTP $HTTP_CODE"
    echo "Response: $RESPONSE_BODY"
    echo ""
    echo "🔧 Troubleshooting:"
    echo "1. Check if user was registered successfully"
    echo "2. Verify credentials are correct"
    echo "3. Check service logs for errors"
fi

echo ""
echo "🔹 Manual Bearer Token Testing Template"
echo "======================================"
echo ""
echo "If you obtain a JWT token, test it like this:"
echo ""
echo "# Set your token (replace with actual JWT)"
echo "export JWT_TOKEN=\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\""
echo ""
echo "# Test token validation"  
echo "curl -H \"Authorization: Bearer \$JWT_TOKEN\" \\"
echo "  http://localhost:8080/api/v1/auth/validate"
echo ""
echo "# Test protected endpoint"
echo "curl -H \"Authorization: Bearer \$JWT_TOKEN\" \\"
echo "  http://localhost:8080/api/v1/user/profile"
echo ""
echo "# Test policy authorization with user context"
echo "curl -X POST http://localhost:8081/v1/authorize \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{"
echo "    \"principal\": {\"type\": \"User\", \"id\": \"'$USER_EMAIL'\"},"
echo "    \"action\": {\"type\": \"Action\", \"id\": \"read\"},"
echo "    \"resource\": {\"type\": \"Document\", \"id\": \"doc1\"},"
echo "    \"context\": {\"authenticated\": true}"
echo "  }'"

# Cleanup
rm -f /tmp/auth_cookies.txt

echo ""
echo "✅ Bearer token flow testing complete!"
echo "📋 See BEARER_TOKEN_FLOW_GUIDE.md for detailed documentation"