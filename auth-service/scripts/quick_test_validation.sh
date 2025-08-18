#!/bin/bash

# Quick test validation script for Rust auth service
# This script runs a subset of tests to quickly validate the system

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${BLUE}🚀 Quick Test Validation for Auth Service${NC}"

# Set test environment
export TEST_MODE=1
export RUST_BACKTRACE=1
export REQUEST_SIGNING_SECRET=test_secret
export DISABLE_RATE_LIMIT=1

# Function to run a quick test
run_quick_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "${YELLOW}Running $test_name...${NC}"
    
    if timeout 60s $test_command; then
        echo -e "${GREEN}✅ $test_name passed${NC}"
        return 0
    else
        echo -e "${RED}❌ $test_name failed${NC}"
        return 1
    fi
}

# Quick validation tests
echo -e "${BLUE}Running quick validation tests...${NC}"

# 1. Check if project compiles
echo -e "\n${BLUE}1. Compilation Check${NC}"
if cargo check --all-features; then
    echo -e "${GREEN}✅ Project compiles successfully${NC}"
else
    echo -e "${RED}❌ Compilation failed${NC}"
    exit 1
fi

# 2. Run a subset of unit tests
echo -e "\n${BLUE}2. Quick Unit Tests${NC}"
run_quick_test "Unit Tests" "cargo test --lib test_pkce_code_generation_and_validation test_token_binding_generation_and_validation test_input_validation --all-features -- --nocapture"

# 3. Test basic security functions
echo -e "\n${BLUE}3. Security Function Tests${NC}"
run_quick_test "Security Tests" "cargo test --lib test_request_signature_generation_and_verification test_validate_token_input test_validate_client_credentials --all-features -- --nocapture"

# 4. Test basic store operations
echo -e "\n${BLUE}4. Store Operations Tests${NC}"
run_quick_test "Store Tests" "cargo test --lib test_token_store_operations --all-features -- --nocapture"

# 5. Quick integration test
echo -e "\n${BLUE}5. Quick Integration Test${NC}"
run_quick_test "Integration Test" "cargo test test_client_credentials_flow_complete --all-features -- --nocapture --test-threads=1"

echo -e "\n${GREEN}🎉 Quick validation completed successfully!${NC}"
echo -e "${BLUE}💡 To run the full test suite, use: ./scripts/run_comprehensive_tests.sh${NC}"