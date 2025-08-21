# Basic Testing Guide for OAuth 2.0 Server

## Quick Test Commands

### 1. Run All Tests
```bash
cargo test --package auth-core
```

### 2. Check Compilation
```bash
cargo check --package auth-core
```

### 3. Run Benchmarks
```bash
cargo bench --package auth-core --no-run
```

## Manual Server Testing

### Start the Server
```bash
# In one terminal
cargo run --example minimal_server
```

### Test Health Endpoint
```bash
curl http://localhost:8080/health
```
Expected response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": 1693420800
}
```

### Test OAuth Token Request
```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=demo&client_secret=demo-secret"
```

Expected response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Test Invalid Credentials
```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=invalid&client_secret=invalid"
```

Expected response (401):
```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

## Automated Testing Scripts

### Shell Script Test
Use the provided test script:
```bash
./test-server.sh
```

### Python Test Client
```bash
python3 test-client.py
```

## Unit Test Coverage

Current test coverage includes:
- ✅ Server creation and building
- ✅ Builder pattern methods
- ✅ Compatibility methods
- ✅ Property-based testing for client credentials
- ✅ Version verification
- ✅ Documentation examples

## Expected Test Results

All tests should pass:
```
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Troubleshooting

### Common Issues:

1. **Port already in use**: Change port in examples
2. **Missing dependencies**: Run `cargo build` first
3. **Test failures**: Check logs for specific error details

### Debug Mode:
```bash
RUST_LOG=debug cargo run --example minimal_server
```