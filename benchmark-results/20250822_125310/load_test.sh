#!/bin/bash
# Simple load test using curl
echo "Starting load test..."

# Start auth-core server in background
../auth-core/target/release/auth-core --port 8080 &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Run load test
echo "Running concurrent requests..."
for i in {1..100}; do
    curl -s -X POST http://localhost:8080/oauth/token \
        -d "grant_type=client_credentials&client_id=test&client_secret=secret" \
        -H "Content-Type: application/x-www-form-urlencoded" &
done

wait

# Stop server
kill $SERVER_PID 2>/dev/null || true

echo "Load test completed"
