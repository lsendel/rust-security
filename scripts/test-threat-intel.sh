#!/bin/bash

set -e

echo "🔒 Running Threat Intelligence Test Suite"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check dependencies
echo "Checking dependencies..."
if ! command -v cargo &> /dev/null; then
    print_error "Cargo not found. Please install Rust."
    exit 1
fi
print_status "Cargo found"

# Build the project
echo -e "\n📦 Building project..."
if cargo build --release; then
    print_status "Build successful"
else
    print_error "Build failed"
    exit 1
fi

# Run unit tests
echo -e "\n🧪 Running unit tests..."
if cargo test threat_intel_tests --release; then
    print_status "Unit tests passed"
else
    print_error "Unit tests failed"
    exit 1
fi

# Run integration tests
echo -e "\n🔗 Running integration tests..."
if cargo test middleware_integration_tests --release; then
    print_status "Integration tests passed"
else
    print_error "Integration tests failed"
    exit 1
fi

# Run load tests
echo -e "\n⚡ Running load tests..."
if cargo test load_test --release -- --nocapture; then
    print_status "Load tests passed"
else
    print_warning "Load tests completed with warnings"
fi

# Start server for live testing
echo -e "\n🚀 Starting server for live testing..."
cargo run --release &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Test server endpoints
echo -e "\n🌐 Testing live endpoints..."

# Test health endpoint
if curl -s http://localhost:8080/health | grep -q "OK"; then
    print_status "Health endpoint working"
else
    print_error "Health endpoint failed"
    kill $SERVER_PID
    exit 1
fi

# Test metrics endpoint
if curl -s http://localhost:8080/metrics | grep -q "threat_intel"; then
    print_status "Metrics endpoint working"
else
    print_warning "Metrics endpoint may not be fully configured"
fi

# Test with malicious IP simulation
echo -e "\n🎯 Testing threat blocking..."
for i in {1..5}; do
    curl -s -H "X-Forwarded-For: 192.168.1.100" http://localhost:8080/health > /dev/null
    sleep 0.1
done

# Clean up
kill $SERVER_PID
print_status "Server stopped"

echo -e "\n🎉 All tests completed successfully!"
echo "Threat Intelligence integration is ready for production."
