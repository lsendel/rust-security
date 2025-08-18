#!/bin/bash

# Test script to verify auth-service endpoints

echo "Starting auth-service..."
cargo build --release 2>&1 | tail -3

# Start the service in background
(cargo run --release 2>&1 | tee auth-service-test.log) &
SERVICE_PID=$!

# Wait for service to start
echo "Waiting for service to start..."
sleep 5

# Test health endpoint
echo "Testing /health endpoint..."
curl -s http://localhost:8080/health | head -100

# Test OpenID metadata
echo -e "\nTesting /.well-known/openid-configuration..."
curl -s http://localhost:8080/.well-known/openid-configuration | head -100

# Test JWKS endpoint
echo -e "\nTesting /jwks.json..."
curl -s http://localhost:8080/jwks.json | head -100

# Clean up
echo -e "\nStopping auth-service..."
kill $SERVICE_PID 2>/dev/null
wait $SERVICE_PID 2>/dev/null

echo "Test completed!"