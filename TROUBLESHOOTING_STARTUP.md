# Troubleshooting Service Startup Issues

## Quick Fix: Use Development Mode

For the fastest startup, use the development script instead:

```bash
./start-services-dev.sh --demo
```

This uses debug builds which compile much faster than release builds.

## Common Issues & Solutions

### 1. Services Won't Start / Hang on "Waiting for service to be ready"

**Cause**: Usually compilation issues or missing dependencies

**Solutions**:

```bash
# Option A: Use debug builds (faster)
./start-services-dev.sh --demo

# Option B: Pre-compile release builds
cargo build --release --workspace
./start-services.sh --demo

# Option C: Check compilation status
tail -f auth-service.log
tail -f policy-service.log
```

### 2. File Lock Issues

**Cause**: Multiple cargo processes trying to build simultaneously

**Solution**:
```bash
# Kill any stuck processes
pkill -f "cargo run"
pkill -f "cargo build" 

# Try again
./start-services.sh --demo
```

### 3. Port Already in Use

**Cause**: Previous services still running

**Solution**:
```bash
# Check what's using the ports
lsof -i :8080
lsof -i :8081

# Kill processes on those ports
kill $(lsof -t -i:8080)
kill $(lsof -t -i:8081)
```

### 4. Redis Connection Issues

**Symptoms**: Services start but health checks fail

**Solutions**:
```bash
# Install Redis (macOS)
brew install redis
brew services start redis

# Install Redis (Ubuntu)
sudo apt install redis-server
sudo systemctl start redis

# Or continue without Redis (uses in-memory fallback)
export AUTH__REDIS__URL=""
```

### 5. Config Loading Issues

**Symptoms**: Configuration errors in logs

**Solution**:
```bash
# Set required environment variables
export JWT_SECRET="test-jwt-secret-key-for-development-only-32chars"
export ENCRYPTION_KEY="test-encryption-key-for-development-only-32char"
export AUTH__DATABASE__URL="sqlite::memory:"
```

## Step-by-Step Debugging

1. **Check compilation first**:
   ```bash
   cd auth-service
   cargo check
   cd ../policy-service  
   cargo check
   cd ..
   ```

2. **Try manual start**:
   ```bash
   # Terminal 1
   cd auth-service
   RUST_LOG=info cargo run
   
   # Terminal 2  
   cd policy-service
   RUST_LOG=info cargo run
   ```

3. **Test endpoints**:
   ```bash
   curl http://localhost:8080/health
   curl http://localhost:8081/health
   ```

## Fast Development Workflow

For the quickest development experience:

```bash
# 1. Use debug builds
./start-services-dev.sh --demo

# 2. In another terminal, validate 
./validate-services.sh

# 3. Test the documentation examples
./test-documentation-samples.sh
```

## Success Indicators

You should see:
- ✅ Services compile without errors
- ✅ Health endpoints return 200 OK
- ✅ Policy authorization works
- ✅ Demo user can be created/logged in

## Getting Help

If issues persist:

1. Check the log files:
   ```bash
   tail -f auth-service.log
   tail -f policy-service.log
   ```

2. Verify your environment:
   ```bash
   cargo --version  # Should be 1.80+
   rustc --version
   ```

3. Try a clean build:
   ```bash
   cargo clean
   ./start-services-dev.sh --demo
   ```