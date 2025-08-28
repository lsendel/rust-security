# Auth Service Smoke Tests
# Quick health checks to ensure basic functionality

# Test 1: Health Check
GET http://localhost:8001/health

HTTP 200
[Asserts]
jsonpath "$.status" == "healthy"
jsonpath "$.service" == "auth-service"
jsonpath "$.timestamp" exists

# Test 2: API Version Check
GET http://localhost:8001/version

HTTP 200
[Asserts]
jsonpath "$.version" matches "^[0-9]+\\.[0-9]+\\.[0-9]+"
jsonpath "$.service" == "auth-service"

# Test 3: Basic Registration (Smoke)
POST http://localhost:8001/v1/auth/register
Content-Type: application/json
{
    "username": "smoketest123",
    "email": "smoke123@test.com",
    "password": "SmokeTest123!",
    "full_name": "Smoke Test User"
}

HTTP 201
[Captures]
smoke_username: jsonpath "$.data.username"

[Asserts]
jsonpath "$.data.id" exists
jsonpath "$.data.email" exists

# Test 4: Basic Login (Smoke)
POST http://localhost:8001/v1/auth/login
Content-Type: application/json
{
    "username": "{{smoke_username}}",
    "password": "SmokeTest123!"
}

HTTP 200
[Captures]
smoke_token: jsonpath "$.access_token"

[Asserts]
jsonpath "$.access_token" exists
jsonpath "$.token_type" == "Bearer"

# Test 5: Token Verification (Smoke)
POST http://localhost:8001/v1/auth/verify
Authorization: Bearer {{smoke_token}}

HTTP 200
[Asserts]
jsonpath "$.valid" == true

# Test 6: Protected Endpoint Access (Smoke)
GET http://localhost:8001/v1/auth/sessions
Authorization: Bearer {{smoke_token}}

HTTP 200
[Asserts]
jsonpath "$.data" exists

# Test 7: Logout (Smoke)
POST http://localhost:8001/v1/auth/logout
Authorization: Bearer {{smoke_token}}

HTTP 204