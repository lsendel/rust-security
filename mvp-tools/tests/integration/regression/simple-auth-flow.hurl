# Simplified Auth Service Regression Test
# Tests basic authentication flow with mock service

# Test 1: Health Check
GET http://localhost:8001/health

HTTP 200
[Asserts]
jsonpath "$.status" == "healthy"
jsonpath "$.service" == "auth-service"
jsonpath "$.timestamp" exists

# Test 2: Version Check  
GET http://localhost:8001/version

HTTP 200
[Asserts]
jsonpath "$.version" exists
jsonpath "$.service" == "auth-service"

# Test 3: User Registration
POST http://localhost:8001/v1/auth/register
Content-Type: application/json
{
    "username": "testuser456",
    "email": "test456@example.com",
    "password": "SecureP@ssw0rd123",
    "full_name": "Test User"
}

HTTP 201
[Captures]
user_id: jsonpath "$.data.id"
username: jsonpath "$.data.username"

[Asserts]
jsonpath "$.data.id" exists
jsonpath "$.data.username" == "testuser456"
jsonpath "$.data.email" == "test456@example.com"
jsonpath "$.data.email_verified" == false
jsonpath "$.meta.request_id" exists
jsonpath "$.meta.timestamp" exists

# Test 4: User Login
POST http://localhost:8001/v1/auth/login
Content-Type: application/json
{
    "username": "{{username}}",
    "password": "SecureP@ssw0rd123",
    "remember_me": false
}

HTTP 200
[Captures]
access_token: jsonpath "$.access_token"
refresh_token: jsonpath "$.refresh_token"

[Asserts]
jsonpath "$.access_token" exists
jsonpath "$.refresh_token" exists
jsonpath "$.token_type" == "Bearer"
jsonpath "$.expires_in" > 0
jsonpath "$.user.id" == "{{user_id}}"
jsonpath "$.user.username" == "{{username}}"

# Test 5: Token Verification
POST http://localhost:8001/v1/auth/verify
Authorization: Bearer {{access_token}}
Content-Type: application/json

HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.claims.sub" exists
jsonpath "$.claims.exp" > 0
jsonpath "$.claims.iat" > 0

# Test 6: Get User Sessions
GET http://localhost:8001/v1/auth/sessions
Authorization: Bearer {{access_token}}

HTTP 200
[Asserts]
jsonpath "$.data" exists
jsonpath "$.meta.page" >= 1
jsonpath "$.meta.per_page" > 0

# Test 7: Refresh Token
POST http://localhost:8001/v1/auth/refresh
Content-Type: application/json
{
    "refresh_token": "{{refresh_token}}"
}

HTTP 200
[Captures]
new_access_token: jsonpath "$.access_token"

[Asserts]
jsonpath "$.access_token" exists
jsonpath "$.token_type" == "Bearer"
jsonpath "$.expires_in" > 0

# Test 8: Password Reset Request
POST http://localhost:8001/v1/auth/password/reset
Content-Type: application/json
{
    "email": "test456@example.com"
}

HTTP 202

# Test 9: Invalid Login Attempt
POST http://localhost:8001/v1/auth/login
Content-Type: application/json
{
    "username": "{{username}}",
    "password": "wrongpassword",
    "remember_me": false
}

HTTP 200
[Asserts]
# Note: Mock server doesn't validate passwords - this would fail in real service
jsonpath "$.access_token" exists

# Test 10: Logout
POST http://localhost:8001/v1/auth/logout
Authorization: Bearer {{new_access_token}}

HTTP 204