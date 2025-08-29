#!/bin/bash
# Run comprehensive integration test suite
# This script validates end-to-end functionality of the Rust Security Platform

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
AUTH_SERVICE_URL="${AUTH_SERVICE_URL:-http://localhost:8080}"
POLICY_SERVICE_URL="${POLICY_SERVICE_URL:-http://localhost:8081}"
TEST_TIMEOUT="${TEST_TIMEOUT:-300}"  # 5 minutes timeout

echo -e "${BLUE}🧪 Starting Rust Security Platform Integration Tests${NC}"
echo "Auth Service: ${AUTH_SERVICE_URL}"
echo "Policy Service: ${POLICY_SERVICE_URL}"
echo "Timeout: ${TEST_TIMEOUT}s"
echo

# Function to check if a service is healthy
check_service_health() {
    local service_name="$1"
    local service_url="$2"
    local max_attempts=30
    local attempt=1

    echo -e "${YELLOW}Checking ${service_name} health...${NC}"

    while [ $attempt -le $max_attempts ]; do
        if curl -s -f "${service_url}/health" >/dev/null 2>&1; then
            echo -e "${GREEN}✅ ${service_name} is healthy${NC}"
            return 0
        fi

        echo -e "${YELLOW}Waiting for ${service_name} (attempt ${attempt}/${max_attempts})...${NC}"
        sleep 2
        ((attempt++))
    done

    echo -e "${RED}❌ ${service_name} failed to become healthy${NC}"
    return 1
}

# Function to run a test file
run_test_file() {
    local test_file="$1"
    local test_name="$2"

    echo -e "${BLUE}Running ${test_name}...${NC}"

    if timeout "${TEST_TIMEOUT}s" cargo test \
        --test "$(basename "${test_file}" .rs)" \
        -- --nocapture; then
        echo -e "${GREEN}✅ ${test_name} passed${NC}"
        return 0
    else
        local exit_code=$?
        echo -e "${RED}❌ ${test_name} failed (exit code: ${exit_code})${NC}"
        return 1
    fi
}

# Pre-flight checks
echo -e "${BLUE}🔍 Running pre-flight checks...${NC}"

# Check if services are running
if ! check_service_health "Auth Service" "${AUTH_SERVICE_URL}"; then
    echo -e "${RED}❌ Auth Service is not available. Please start the services first.${NC}"
    echo -e "${YELLOW}💡 Run: docker-compose up -d${NC}"
    exit 1
fi

if ! check_service_health "Policy Service" "${POLICY_SERVICE_URL}"; then
    echo -e "${RED}❌ Policy Service is not available. Please start the services first.${NC}"
    echo -e "${YELLOW}💡 Run: docker-compose up -d${NC}"
    exit 1
fi

# Check if monitoring is available (optional)
if curl -s -f "http://localhost:9090/-/healthy" >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Prometheus monitoring is available${NC}"
    MONITORING_AVAILABLE=true
else
    echo -e "${YELLOW}⚠️  Prometheus monitoring not available${NC}"
    MONITORING_AVAILABLE=false
fi

echo -e "${GREEN}✅ Pre-flight checks completed${NC}"
echo

# Test execution
TEST_RESULTS=()
FAILED_TESTS=0
TOTAL_TESTS=0

# 1. Authentication Flow Tests
((TOTAL_TESTS++))
if run_test_file "tests/integration/auth_flow_integration_test.rs" "Authentication Flow Tests"; then
    TEST_RESULTS+=("✅ Authentication Flow Tests: PASSED")
else
    TEST_RESULTS+=("❌ Authentication Flow Tests: FAILED")
    ((FAILED_TESTS++))
fi

# 2. Policy Engine Tests
((TOTAL_TESTS++))
if run_test_file "tests/integration/policy_engine_integration_test.rs" "Policy Engine Tests"; then
    TEST_RESULTS+=("✅ Policy Engine Tests: PASSED")
else
    TEST_RESULTS+=("❌ Policy Engine Tests: FAILED")
    ((FAILED_TESTS++))
fi

# 3. End-to-End Workflow Tests
((TOTAL_TESTS++))
if run_test_file "tests/integration/end_to_end_workflow_test.rs" "End-to-End Workflow Tests"; then
    TEST_RESULTS+=("✅ End-to-End Workflow Tests: PASSED")
else
    TEST_RESULTS+=("❌ End-to-End Workflow Tests: FAILED")
    ((FAILED_TESTS++))
fi

# 4. Unit Tests
echo -e "${BLUE}Running unit tests...${NC}"
((TOTAL_TESTS++))
if timeout "${TEST_TIMEOUT}s" cargo test --lib --bins -- --nocapture; then
    TEST_RESULTS+=("✅ Unit Tests: PASSED")
else
    TEST_RESULTS+=("❌ Unit Tests: FAILED")
    ((FAILED_TESTS++))
fi

# 5. Performance Benchmarks
echo -e "${BLUE}Running performance benchmarks...${NC}"
if timeout "${TEST_TIMEOUT}s" cargo bench --bench performance_benchmarks -- --nocapture >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Performance benchmarks completed${NC}"
    TEST_RESULTS+=("✅ Performance Benchmarks: PASSED")
else
    echo -e "${RED}❌ Performance benchmarks failed${NC}"
    TEST_RESULTS+=("❌ Performance Benchmarks: FAILED")
    ((FAILED_TESTS++))
fi

# 6. Security Tests
echo -e "${BLUE}Running security validation...${NC}"
if [ -f "scripts/security/scan-security.sh" ]; then
    if timeout "120s" bash scripts/security/scan-security.sh >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Security scan completed${NC}"
        TEST_RESULTS+=("✅ Security Validation: PASSED")
    else
        echo -e "${RED}❌ Security scan failed${NC}"
        TEST_RESULTS+=("❌ Security Validation: FAILED")
        ((FAILED_TESTS++))
    fi
else
    echo -e "${YELLOW}⚠️  Security scan script not found${NC}"
    TEST_RESULTS+=("⚠️  Security Validation: SKIPPED")
fi

# Generate test report
echo
echo -e "${BLUE}📊 Integration Test Results${NC}"
echo "========================================"

for result in "${TEST_RESULTS[@]}"; do
    echo -e "$result"
done

echo
echo "========================================"
echo -e "${BLUE}Summary:${NC}"
echo "  Total Tests: ${TOTAL_TESTS}"
echo "  Passed: $((TOTAL_TESTS - FAILED_TESTS))"
echo "  Failed: ${FAILED_TESTS}"

# Check monitoring metrics if available
if [ "$MONITORING_AVAILABLE" = true ]; then
    echo
    echo -e "${BLUE}📈 Monitoring Metrics:${NC}"

    # Get some key metrics
    AUTH_REQUESTS=$(curl -s "http://localhost:9090/api/v1/query?query=auth_requests_total" | jq -r '.data.result[0].value[1]' 2>/dev/null || echo "N/A")
    AUTHZ_REQUESTS=$(curl -s "http://localhost:9090/api/v1/query?query=authz_requests_total" | jq -r '.data.result[0].value[1]' 2>/dev/null || echo "N/A")

    echo "  Auth Requests: ${AUTH_REQUESTS}"
    echo "  Authz Requests: ${AUTHZ_REQUESTS}"

    # Check SLO status
    SLO_ERROR_BUDGET=$(curl -s "http://localhost:9090/api/v1/query?query=slo_error_budget_remaining" | jq -r '.data.result[0].value[1]' 2>/dev/null || echo "N/A")
    if [ "$SLO_ERROR_BUDGET" != "N/A" ]; then
        SLO_PERCENTAGE=$(echo "scale=2; $SLO_ERROR_BUDGET * 100" | bc 2>/dev/null || echo "$SLO_ERROR_BUDGET")
        echo "  SLO Error Budget: ${SLO_PERCENTAGE}%"
    fi
fi

# Final status
echo
if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}🎉 All integration tests passed!${NC}"
    echo -e "${GREEN}✅ Rust Security Platform is ready for production${NC}"
    exit 0
else
    echo -e "${RED}❌ ${FAILED_TESTS} integration test(s) failed${NC}"
    echo -e "${YELLOW}🔧 Please review the test output and fix any issues${NC}"
    exit 1
fi
