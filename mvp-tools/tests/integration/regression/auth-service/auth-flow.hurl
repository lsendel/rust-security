# Auth Service Regression Tests - Complete Authentication Flow
# This file tests the main authentication scenarios

# Test 1: User Registration
POST http://localhost:8001/v1/auth/register
Content-Type: application/json
{
    "username": "testuser123",
    "email": "test123@example.com", 
    "password": "SecureP@ssw0rd123",
    "full_name": "Test User"
}

HTTP 201
[Captures]
user_id: jsonpath "$.data.id"
username: jsonpath "$.data.username"

[Asserts]
jsonpath "$.data.id" matches "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
jsonpath "$.data.username" exists
jsonpath "$.data.email" exists
jsonpath "$.data.email_verified" == false
jsonpath "$.data.two_factor_enabled" == false
jsonpath "$.meta.request_id" exists
jsonpath "$.meta.timestamp" matches "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"

# Test 2: User Login with Valid Credentials
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

# Test 3: Token Verification
POST http://localhost:8001/v1/auth/verify
Authorization: Bearer {{access_token}}
Content-Type: application/json

HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.claims.sub" exists
jsonpath "$.claims.exp" > 0
jsonpath "$.claims.iat" > 0

# Test 4: Get User Sessions
GET http://localhost:8001/v1/auth/sessions
Authorization: Bearer {{access_token}}

HTTP 200
[Asserts]
jsonpath "$.data" exists
jsonpath "$.data" exists
jsonpath "$.meta.page" >= 1
jsonpath "$.meta.per_page" > 0

# Test 5: Refresh Token
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

# Test 6: Password Reset Request
POST http://localhost:8001/v1/auth/password/reset
Content-Type: application/json
{
    "email": "test123@example.com"
}

HTTP 202
[Asserts]
# Password reset should always return 202 regardless of email existence (security)

# Test 7: Invalid Login Attempt
POST http://localhost:8001/v1/auth/login
Content-Type: application/json
{
    "username": "{{username}}",
    "password": "wrongpassword",
    "remember_me": false
}

HTTP 401
[Asserts]
jsonpath "$.error.code" exists
jsonpath "$.error.message" exists
jsonpath "$.meta.request_id" exists

# Test 8: Access Protected Endpoint Without Token
GET http://localhost:8001/v1/auth/sessions

HTTP 401
[Asserts]
jsonpath "$.error.code" exists
jsonpath "$.error.message" exists

# Test 9: Access Protected Endpoint With Invalid Token
GET http://localhost:8001/v1/auth/sessions  
Authorization: Bearer invalid.jwt.token

HTTP 401
[Asserts]
jsonpath "$.error.code" exists
jsonpath "$.error.message" exists

# Test 10: Logout
POST http://localhost:8001/v1/auth/logout
Authorization: Bearer {{new_access_token}}

HTTP 204

# Test 11: Verify Token After Logout (should fail)
POST http://localhost:8001/v1/auth/verify
Authorization: Bearer {{new_access_token}}

HTTP 401
[Asserts]
jsonpath "$.error.code" exists

# Test 12: Rate Limiting Test - Multiple Login Attempts
POST http://localhost:8001/v1/auth/login
Content-Type: application/json
{
    "username": "ratelimituser",
    "password": "wrongpassword"
}

HTTP 401

POST http://localhost:8001/v1/auth/login
Content-Type: application/json
{
    "username": "ratelimituser", 
    "password": "wrongpassword"
}

HTTP 401

POST http://localhost:8001/v1/auth/login
Content-Type: application/json
{
    "username": "ratelimituser",
    "password": "wrongpassword"
}

HTTP 401

POST http://localhost:8001/v1/auth/login
Content-Type: application/json
{
    "username": "ratelimituser",
    "password": "wrongpassword"
}

HTTP 401

POST http://localhost:8001/v1/auth/login
Content-Type: application/json
{
    "username": "ratelimituser",
    "password": "wrongpassword"
}

HTTP 401

# This should trigger rate limiting
POST http://localhost:8001/v1/auth/login
Content-Type: application/json
{
    "username": "ratelimituser",
    "password": "wrongpassword"
}

HTTP 429
[Asserts]
header "X-RateLimit-Limit" exists
header "X-RateLimit-Remaining" exists
header "X-RateLimit-Reset" exists
jsonpath "$.error.code" exists