# 🧪 Testing Guide for OAuth 2.0 Server

This guide shows you multiple ways to test that your OAuth 2.0 server is working correctly.

## 🚀 Quick Start Testing

### 1. Start the Server

```bash
cd auth-core
cargo run --example minimal_server --features="client-credentials,jwt"
```

You should see output like:
```
🚀 Starting minimal OAuth 2.0 server...
📋 Available endpoints:
  Health check:  http://localhost:8080/health
  Token endpoint: http://localhost:8080/oauth/token
🚀 Server listening on 0.0.0.0:8080
✅ Server would be serving requests...
```

### 2. Test with curl (in another terminal)

```bash
# Test health endpoint
curl -s http://localhost:8080/health

# Test OAuth token request
curl -X POST http://localhost:8080/oauth/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=client_credentials&client_id=demo-client&client_secret=demo-secret"

# Test invalid credentials
curl -X POST http://localhost:8080/oauth/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=client_credentials&client_id=invalid&client_secret=wrong"
```

## 🛠️ Automated Testing Methods

### Method 1: Shell Script

Run the provided test script:

```bash
# View test commands
./test-server.sh

# Run automated tests (server must be running)
./test-server.sh auto
```

### Method 2: Python Client

```bash
# Install requests if needed
pip install requests

# Run Python test client
python3 test-client.py
```

### Method 3: Unit Tests

```bash
# Run the test suite
cargo test --package auth-core

# Run with output
cargo test --package auth-core -- --nocapture
```

## 🔍 What Each Test Verifies

### 1. Health Check Test
- **URL:** `GET /health`
- **Purpose:** Verify server is running and responding
- **Expected:** HTTP 200 with health status

### 2. OAuth Token Request Test
- **URL:** `POST /oauth/token`
- **Purpose:** Test valid OAuth 2.0 client credentials flow
- **Data:** `grant_type=client_credentials&client_id=demo-client&client_secret=demo-secret`
- **Expected:** HTTP 200 with access token (if fully implemented)

### 3. Invalid Credentials Test
- **URL:** `POST /oauth/token`
- **Purpose:** Verify server rejects invalid credentials
- **Data:** Invalid client_id and client_secret
- **Expected:** HTTP 400/401 with error response

### 4. Token Introspection Test
- **URL:** `POST /oauth/introspect`
- **Purpose:** Validate issued tokens
- **Data:** Token + client credentials
- **Expected:** HTTP 200 with token info (if implemented)

## 🎯 Expected Responses

### Successful Token Request
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Invalid Credentials
```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

### Health Check
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": "5m 32s"
}
```

## 🐛 Troubleshooting

### Server Won't Start
- Check if port 8080 is already in use: `lsof -i :8080`
- Try different port: modify the example code
- Check Rust/Cargo installation: `cargo --version`

### Connection Refused
```bash
# Check if server is listening
netstat -an | grep 8080

# Test local connectivity
telnet localhost 8080
```

### Compilation Errors
```bash
# Clean and rebuild
cargo clean
cargo build --example minimal_server --features="client-credentials,jwt"
```

## 🔧 Advanced Testing

### Load Testing with Apache Bench
```bash
# Install ab (apache2-utils on Ubuntu)
apt-get install apache2-utils

# Test health endpoint
ab -n 1000 -c 10 http://localhost:8080/health

# Test OAuth endpoint (POST request)
echo "grant_type=client_credentials&client_id=demo-client&client_secret=demo-secret" > /tmp/oauth_data
ab -n 100 -c 5 -p /tmp/oauth_data -T "application/x-www-form-urlencoded" http://localhost:8080/oauth/token
```

### Integration with Postman

1. Import this collection:
```json
{
  "info": { "name": "OAuth 2.0 Server Tests" },
  "item": [
    {
      "name": "Health Check",
      "request": {
        "method": "GET",
        "url": "http://localhost:8080/health"
      }
    },
    {
      "name": "Get Token",
      "request": {
        "method": "POST",
        "url": "http://localhost:8080/oauth/token",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/x-www-form-urlencoded"
          }
        ],
        "body": {
          "mode": "urlencoded",
          "urlencoded": [
            { "key": "grant_type", "value": "client_credentials" },
            { "key": "client_id", "value": "demo-client" },
            { "key": "client_secret", "value": "demo-secret" }
          ]
        }
      }
    }
  ]
}
```

## ✅ Success Criteria

Your server is working correctly if:

1. ✅ Health endpoint returns HTTP 200
2. ✅ Valid OAuth requests don't crash the server  
3. ✅ Invalid credentials are properly rejected
4. ✅ Server handles multiple concurrent requests
5. ✅ All unit tests pass

## 🚀 Next Steps

Once basic testing passes, you can:

1. **Add Real HTTP Handling**: Implement actual token generation and validation
2. **Database Integration**: Store clients and tokens persistently  
3. **Security Hardening**: Add rate limiting, HTTPS, proper JWT validation
4. **Performance Testing**: Load test with realistic traffic patterns
5. **Integration Testing**: Test with real OAuth 2.0 clients

## 📞 Need Help?

- Check server logs for error messages
- Verify your OAuth 2.0 flow understanding at [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- Review the auth-core documentation and examples
- Run `cargo test` to ensure all components are working