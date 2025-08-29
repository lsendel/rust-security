#!/bin/bash

# Manual Service Testing - Minimal Configuration Approach
echo "🔬 Manual Service Testing"
echo "========================"

# Clean up
pkill -f "auth-service" 2>/dev/null || true
pkill -f "policy-service" 2>/dev/null || true
sleep 1

# Test auth service in minimal mode
echo "1. Testing Auth Service compilation..."
cd auth-service
if cargo build --quiet 2>/dev/null; then
    echo "✅ Auth service compiles"
else
    echo "❌ Auth service compilation failed"
    cd ..
    exit 1
fi
cd ..

# Test policy service
echo "2. Testing Policy Service compilation..."  
cd policy-service
if cargo build --quiet 2>/dev/null; then
    echo "✅ Policy service compiles"
else
    echo "❌ Policy service compilation failed"
    cd ..
    exit 1
fi
cd ..

echo ""
echo "3. Starting services manually..."

# Start auth service with minimal env
export RUST_LOG=error
cd auth-service
cargo run > ../test-auth.log 2>&1 &
AUTH_PID=$!
echo "Auth Service PID: $AUTH_PID"
cd ..

# Start policy service
cd policy-service
cargo run > ../test-policy.log 2>&1 &
POLICY_PID=$!
echo "Policy Service PID: $POLICY_PID"
cd ..

# Wait and test
echo ""
echo "4. Waiting for startup (30s max)..."
sleep 5

# Test with curl
for i in {1..25}; do
    echo "Testing attempt $i/25..."
    
    # Test auth service
    if curl -s -f http://localhost:8080/health >/dev/null 2>&1; then
        echo "✅ Auth service is responding!"
        AUTH_OK=1
        break
    fi
    
    sleep 1
done

if [ "${AUTH_OK:-0}" != "1" ]; then
    echo "❌ Auth service failed to start"
    echo "Last 10 lines of auth log:"
    tail -10 test-auth.log
fi

# Test policy service
for i in {1..25}; do  
    if curl -s -f http://localhost:8081/health >/dev/null 2>&1; then
        echo "✅ Policy service is responding!"
        POLICY_OK=1
        break
    fi
    sleep 1
done

if [ "${POLICY_OK:-0}" != "1" ]; then
    echo "❌ Policy service failed to start"
    echo "Last 10 lines of policy log:"
    tail -10 test-policy.log
fi

# Results
echo ""
echo "========================"
echo "📊 Test Results:"
echo "========================"

if [ "${AUTH_OK:-0}" == "1" ] && [ "${POLICY_OK:-0}" == "1" ]; then
    echo "🎉 SUCCESS! Both services are working!"
    echo ""
    echo "Quick validation:"
    echo "curl http://localhost:8080/health"
    curl -s http://localhost:8080/health | head -100
    echo ""
    echo "curl http://localhost:8081/health"  
    curl -s http://localhost:8081/health | head -100
    echo ""
    echo "✅ READY FOR DOCUMENTATION TESTING"
    echo ""
    echo "To kill services: kill $AUTH_PID $POLICY_PID"
    
    # Save PIDs
    echo $AUTH_PID > .test-auth.pid
    echo $POLICY_PID > .test-policy.pid
    
else
    echo "❌ FAILED - Check logs:"
    echo "  tail -f test-auth.log"
    echo "  tail -f test-policy.log"
    echo ""
    echo "Cleaning up..."
    kill $AUTH_PID $POLICY_PID 2>/dev/null || true
    exit 1
fi