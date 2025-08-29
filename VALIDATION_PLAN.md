# System Validation Plan

## 🎯 Objective
Validate the Rust Security Platform is working correctly using curl, httpie, and other tools.

## 📋 Phase 1: Quick Configuration Fix & Startup

### Step 1: Fix Configuration Issue
The current error shows missing `server` field. Let's set the proper environment variables:

```bash
# Set all required configuration via environment variables
export AUTH__SERVER__HOST="127.0.0.1"
export AUTH__SERVER__PORT="8080"
export AUTH__SERVER__BIND_ADDR="127.0.0.1:8080"
export AUTH__SERVER__MAX_CONNECTIONS="1000"
export AUTH__JWT__SECRET="test-jwt-secret-key-for-development-only-32chars"
export AUTH__SECURITY__ENCRYPTION_KEY="test-encryption-key-for-development-only-32char"
export AUTH__DATABASE__URL="sqlite::memory:"
export AUTH__REDIS__URL="redis://localhost:6379"
export RUST_LOG="info"
```

### Step 2: Start Individual Services (Manual Testing)
```bash
# Terminal 1: Start Auth Service
cd auth-service
cargo run

# Terminal 2: Start Policy Service  
cd policy-service
cargo run
```

## 📋 Phase 2: Service Validation with Multiple Tools

### Option A: Using curl (Standard HTTP client)

#### 1. Health Checks
```bash
# Auth Service Health
curl -v http://localhost:8080/health

# Policy Service Health
curl -v http://localhost:8081/health

# Expected: HTTP 200 with JSON response
```

#### 2. Auth Service Endpoints
```bash
# User Registration
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "testpass123",
    "name": "Test User"
  }' | jq

# User Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "testpass123"
  }' | jq

# Save the access_token from response for next requests
export ACCESS_TOKEN="<token_from_login_response>"

# User Profile
curl -X GET http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq
```

#### 3. Policy Service Endpoints
```bash
# Policy Authorization
curl -X POST http://localhost:8081/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "test-123",
    "principal": {"type": "User", "id": "test-user"},
    "action": "Document::read",
    "resource": {"type": "Document", "id": "doc-1"},
    "context": {}
  }' | jq

# Metrics
curl http://localhost:8081/metrics
```

### Option B: Using HTTPie (More User-Friendly)

Install HTTPie:
```bash
# macOS
brew install httpie

# Ubuntu
sudo apt install httpie

# Python pip
pip install httpie
```

#### HTTPie Commands:
```bash
# Health checks
http GET http://localhost:8080/health
http GET http://localhost:8081/health

# User registration
http POST http://localhost:8080/api/v1/auth/register \
  email=test@example.com \
  password=testpass123 \
  name="Test User"

# User login
http POST http://localhost:8080/api/v1/auth/login \
  email=test@example.com \
  password=testpass123

# Policy authorization
http POST http://localhost:8081/v1/authorize \
  request_id=test-123 \
  principal:='{"type": "User", "id": "test-user"}' \
  action="Document::read" \
  resource:='{"type": "Document", "id": "doc-1"}' \
  context:='{}'
```

### Option C: Using Postman/Insomnia

1. Import the OpenAPI specs:
   - Auth Service: `http://localhost:8080/swagger-ui` (if available)
   - Policy Service: `http://localhost:8081/swagger-ui`

2. Or manually create requests with the curl examples above

## 📋 Phase 3: Automated Validation Script

### Create Comprehensive Test Script:

```bash
#!/bin/bash
# validation-test.sh

echo "🧪 Running Comprehensive Service Validation"
echo "==========================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test function
test_endpoint() {
    local method=$1
    local url=$2
    local description=$3
    local data=$4
    
    echo -e "${YELLOW}Testing: $description${NC}"
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "%{http_code}" -o response.json "$url")
    else
        response=$(curl -s -w "%{http_code}" -o response.json -X "$method" \
                   -H "Content-Type: application/json" \
                   -d "$data" "$url")
    fi
    
    if [[ "$response" == "200" ]]; then
        echo -e "${GREEN}✅ Success${NC}"
        cat response.json | jq '.' 2>/dev/null || cat response.json
    else
        echo -e "${RED}❌ Failed (HTTP $response)${NC}"
        cat response.json
    fi
    echo ""
}

# Run tests
test_endpoint "GET" "http://localhost:8080/health" "Auth Service Health"
test_endpoint "GET" "http://localhost:8081/health" "Policy Service Health"

test_endpoint "POST" "http://localhost:8080/api/v1/auth/register" "User Registration" '{
  "email": "validation@example.com",
  "password": "validpass123",
  "name": "Validation User"
}'

test_endpoint "POST" "http://localhost:8080/api/v1/auth/login" "User Login" '{
  "email": "validation@example.com",
  "password": "validpass123"
}'

test_endpoint "POST" "http://localhost:8081/v1/authorize" "Policy Authorization" '{
  "request_id": "validation-test",
  "principal": {"type": "User", "id": "validation-user"},
  "action": "Document::read",
  "resource": {"type": "Document", "id": "doc-validation"},
  "context": {}
}'

echo "==========================================="
echo -e "${GREEN}✅ Validation Complete${NC}"
```

## 📋 Phase 4: Alternative Testing Tools

### 1. K6 Load Testing
```bash
# Install k6
brew install k6

# Create load test
cat > load-test.js << 'EOF'
import http from 'k6/http';
import { check } from 'k6';

export default function() {
  // Health check
  let response = http.get('http://localhost:8080/health');
  check(response, {
    'status is 200': (r) => r.status === 200,
  });
  
  // Policy check
  response = http.post('http://localhost:8081/v1/authorize', JSON.stringify({
    request_id: 'k6-test',
    principal: {type: 'User', id: 'k6-user'},
    action: 'Document::read',
    resource: {type: 'Document', id: 'doc-1'},
    context: {}
  }), {
    headers: { 'Content-Type': 'application/json' },
  });
  check(response, {
    'policy status is 200': (r) => r.status === 200,
  });
}
EOF

# Run load test
k6 run --duration 30s --vus 10 load-test.js
```

### 2. Hurl (HTTP Testing)
```bash
# Install Hurl
brew install hurl

# Create test file
cat > test.hurl << 'EOF'
# Test auth service health
GET http://localhost:8080/health
HTTP 200
[Asserts]
jsonpath "$.status" == "healthy"

# Test policy service health  
GET http://localhost:8081/health
HTTP 200

# Test user registration
POST http://localhost:8080/api/v1/auth/register
Content-Type: application/json
{
  "email": "hurl@example.com",
  "password": "hurlpass123", 
  "name": "Hurl User"
}
HTTP 200

# Test policy authorization
POST http://localhost:8081/v1/authorize
Content-Type: application/json
{
  "request_id": "hurl-test",
  "principal": {"type": "User", "id": "hurl-user"},
  "action": "Document::read",
  "resource": {"type": "Document", "id": "doc-1"}, 
  "context": {}
}
HTTP 200
[Asserts]
jsonpath "$.decision" exists
EOF

# Run Hurl tests
hurl --test test.hurl
```

### 3. Newman (Postman CLI)
```bash
# Install Newman
npm install -g newman

# Export collection from Postman or create JSON manually
# Run tests
newman run collection.json
```

## 📋 Success Criteria

### ✅ Service Health
- [ ] Auth Service returns 200 on `/health`
- [ ] Policy Service returns 200 on `/health`
- [ ] Both services show proper JSON responses

### ✅ Authentication Flow
- [ ] User registration works
- [ ] User login returns access token
- [ ] Protected endpoints accept valid tokens

### ✅ Authorization Flow  
- [ ] Policy service evaluates requests
- [ ] Returns Allow/Deny decisions
- [ ] Handles malformed requests gracefully

### ✅ Performance
- [ ] Response times < 100ms for health checks
- [ ] Response times < 500ms for auth operations
- [ ] Can handle concurrent requests

## 🔧 Troubleshooting Commands

```bash
# Check service logs
tail -f auth-service.log
tail -f policy-service.log

# Check what's running on ports
lsof -i :8080
lsof -i :8081

# Test network connectivity
telnet localhost 8080
telnet localhost 8081

# Check service status
curl -I http://localhost:8080/health
curl -I http://localhost:8081/health
```

This comprehensive validation plan ensures the system works correctly using multiple tools and approaches!