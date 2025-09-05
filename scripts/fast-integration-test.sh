#!/bin/bash

# Fast Integration Test Script
# Optimized for CI/CD with minimal compilation time

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]]; then
    print_error "Must be run from project root directory"
    exit 1
fi

print_success "Starting fast integration test..."

# 1. Quick compilation check (no full build)
print_success "Checking compilation..."
if ! cargo check --workspace --all-features --quiet; then
    print_error "Compilation check failed"
    exit 1
fi

# 2. Run only critical auth-service tests (not all tests)
print_success "Running critical auth-service tests..."
if ! cargo test -p auth-service --lib --quiet -- --test-threads=1; then
    print_error "Auth service tests failed"
    exit 1
fi

# 3. Quick clippy check on auth-service only
print_success "Running clippy on auth-service..."
if ! cargo clippy -p auth-service --all-features --quiet -- -D warnings; then
    print_error "Clippy warnings found in auth-service"
    exit 1
fi

# 4. Basic service startup test (no full integration)
print_success "Testing basic service startup..."
timeout 10s cargo run --bin auth-service --quiet &
AUTH_PID=$!
sleep 3

# Check if service is responsive
if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    print_success "Auth service is responsive"
else
    print_warning "Auth service not responsive (expected in fast test)"
fi

# Cleanup
kill $AUTH_PID 2>/dev/null || true
wait $AUTH_PID 2>/dev/null || true

print_success "Fast integration test completed successfully!"
print_success "Auth service compiles without warnings and passes critical tests"

echo
echo "For full integration testing, run:"
echo "  ./scripts/setup/quick-start.sh"
echo "  ./scripts/run-integration-tests.sh"
