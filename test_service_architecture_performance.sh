#!/bin/bash

# Service Architecture Performance Testing Script
# Tests the optimized service architecture for performance improvements

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AUTH_SERVICE_URL="${AUTH_SERVICE_URL:-http://localhost:8080}"
POLICY_SERVICE_URL="${POLICY_SERVICE_URL:-http://localhost:8081}"
CONCURRENT_USERS="${CONCURRENT_USERS:-100}"
TEST_DURATION="${TEST_DURATION:-60}"
WARMUP_DURATION="${WARMUP_DURATION:-10}"

echo -e "${BLUE}🏗️ Service Architecture Performance Testing${NC}"
echo "=============================================="
echo "Auth Service URL: $AUTH_SERVICE_URL"
echo "Policy Service URL: $POLICY_SERVICE_URL"
echo "Concurrent Users: $CONCURRENT_USERS"
echo "Test Duration: ${TEST_DURATION}s"
echo "Warmup Duration: ${WARMUP_DURATION}s"
echo ""

# Function to check if service is running
check_service() {
    local url=$1
    local service_name=$2
    
    echo -n "Checking $service_name... "
    if curl -s -f "$url/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Running${NC}"
        return 0
    else
        echo -e "${RED}✗ Not available${NC}"
        return 1
    fi
}

# Function to run performance test
run_performance_test() {
    local test_name=$1
    local url=$2
    local payload=$3
    local expected_p95_ms=$4
    
    echo -e "${YELLOW}Running $test_name...${NC}"
    
    # Create temporary files for results
    local results_file=$(mktemp)
    local stats_file=$(mktemp)
    
    # Run Apache Bench test
    ab -n $((CONCURRENT_USERS * 10)) \
       -c $CONCURRENT_USERS \
       -t $TEST_DURATION \
       -T "application/json" \
       -p <(echo "$payload") \
       -g "$stats_file" \
       "$url" > "$results_file" 2>&1
    
    # Parse results
    local requests_per_sec=$(grep "Requests per second" "$results_file" | awk '{print $4}')
    local time_per_request=$(grep "Time per request.*mean" "$results_file" | head -1 | awk '{print $4}')
    local p95_latency=$(grep "95%" "$results_file" | awk '{print $2}')
    local failed_requests=$(grep "Failed requests" "$results_file" | awk '{print $3}')
    
    # Display results
    echo "  Requests/sec: ${requests_per_sec:-N/A}"
    echo "  Mean latency: ${time_per_request:-N/A}ms"
    echo "  P95 latency: ${p95_latency:-N/A}ms"
    echo "  Failed requests: ${failed_requests:-N/A}"
    
    # Check if P95 meets target
    if [[ -n "$p95_latency" && -n "$expected_p95_ms" ]]; then
        if (( $(echo "$p95_latency < $expected_p95_ms" | bc -l) )); then
            echo -e "  ${GREEN}✓ P95 latency target met (< ${expected_p95_ms}ms)${NC}"
        else
            echo -e "  ${RED}✗ P95 latency target missed (>= ${expected_p95_ms}ms)${NC}"
        fi
    fi
    
    # Cleanup
    rm -f "$results_file" "$stats_file"
    echo ""
}

# Function to test service mesh latency
test_service_mesh_latency() {
    echo -e "${YELLOW}Testing Service Mesh Latency...${NC}"
    
    local total_time=0
    local iterations=100
    
    for i in $(seq 1 $iterations); do
        local start_time=$(date +%s%N)
        curl -s -f "$AUTH_SERVICE_URL/health" > /dev/null
        local end_time=$(date +%s%N)
        local request_time=$(( (end_time - start_time) / 1000000 )) # Convert to milliseconds
        total_time=$((total_time + request_time))
    done
    
    local avg_latency=$((total_time / iterations))
    echo "  Average mesh latency: ${avg_latency}ms"
    
    if (( avg_latency < 5 )); then
        echo -e "  ${GREEN}✓ Service mesh latency target met (< 5ms)${NC}"
    else
        echo -e "  ${RED}✗ Service mesh latency target missed (>= 5ms)${NC}"
    fi
    echo ""
}

# Function to test circuit breaker
test_circuit_breaker() {
    echo -e "${YELLOW}Testing Circuit Breaker...${NC}"
    
    # Create a payload that should trigger failures
    local bad_payload='{"invalid": "request"}'
    
    echo "  Sending requests to trigger circuit breaker..."
    local failed_count=0
    
    for i in $(seq 1 10); do
        if ! curl -s -f -X POST \
             -H "Content-Type: application/json" \
             -d "$bad_payload" \
             "$AUTH_SERVICE_URL/auth/login" > /dev/null 2>&1; then
            failed_count=$((failed_count + 1))
        fi
        sleep 0.1
    done
    
    echo "  Failed requests: $failed_count/10"
    
    if (( failed_count >= 5 )); then
        echo -e "  ${GREEN}✓ Circuit breaker appears to be working${NC}"
    else
        echo -e "  ${YELLOW}? Circuit breaker behavior unclear${NC}"
    fi
    echo ""
}

# Function to test caching performance
test_caching_performance() {
    echo -e "${YELLOW}Testing Caching Performance...${NC}"
    
    local auth_payload='{
        "email": "demo@example.com",
        "password": "demo123"
    }'
    
    # First request (cache miss)
    local start_time=$(date +%s%N)
    local response=$(curl -s -X POST \
                         -H "Content-Type: application/json" \
                         -d "$auth_payload" \
                         "$AUTH_SERVICE_URL/auth/login")
    local end_time=$(date +%s%N)
    local first_request_time=$(( (end_time - start_time) / 1000000 ))
    
    # Extract token for subsequent requests
    local token=$(echo "$response" | jq -r '.access_token // empty')
    
    if [[ -n "$token" && "$token" != "null" ]]; then
        # Second request (potential cache hit)
        start_time=$(date +%s%N)
        curl -s -H "Authorization: Bearer $token" \
             "$AUTH_SERVICE_URL/auth/user" > /dev/null
        end_time=$(date +%s%N)
        local second_request_time=$(( (end_time - start_time) / 1000000 ))
        
        echo "  First request (cache miss): ${first_request_time}ms"
        echo "  Second request (cache hit): ${second_request_time}ms"
        
        if (( second_request_time < first_request_time )); then
            echo -e "  ${GREEN}✓ Caching appears to be working${NC}"
        else
            echo -e "  ${YELLOW}? Caching benefit unclear${NC}"
        fi
    else
        echo -e "  ${RED}✗ Could not obtain auth token for cache testing${NC}"
    fi
    echo ""
}

# Function to run comprehensive load test
run_comprehensive_load_test() {
    echo -e "${YELLOW}Running Comprehensive Load Test...${NC}"
    
    # Create test data
    local auth_payload='{
        "email": "demo@example.com",
        "password": "demo123"
    }'
    
    local register_payload='{
        "email": "test@example.com",
        "password": "test123",
        "name": "Test User"
    }'
    
    # Test different endpoints
    echo "Testing authentication endpoint..."
    run_performance_test "Authentication" "$AUTH_SERVICE_URL/auth/login" "$auth_payload" "10"
    
    echo "Testing registration endpoint..."
    run_performance_test "Registration" "$AUTH_SERVICE_URL/auth/register" "$register_payload" "15"
    
    echo "Testing health endpoint..."
    run_performance_test "Health Check" "$AUTH_SERVICE_URL/health" "" "2"
}

# Function to generate performance report
generate_performance_report() {
    local report_file="service_architecture_performance_report_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" << EOF
# Service Architecture Performance Report

**Generated:** $(date)
**Test Configuration:**
- Concurrent Users: $CONCURRENT_USERS
- Test Duration: ${TEST_DURATION}s
- Auth Service: $AUTH_SERVICE_URL
- Policy Service: $POLICY_SERVICE_URL

## Performance Targets vs Results

| Metric | Target | Result | Status |
|--------|--------|--------|--------|
| Auth Latency P95 | < 10ms | TBD | TBD |
| Policy Eval P95 | < 8ms | TBD | TBD |
| Throughput | > 1000 RPS | TBD | TBD |
| Service Mesh Latency | < 5ms | TBD | TBD |

## Test Results Summary

### Authentication Performance
- **Requests/sec:** TBD
- **Mean Latency:** TBD
- **P95 Latency:** TBD
- **Failed Requests:** TBD

### Service Mesh Performance
- **Average Latency:** TBD
- **Circuit Breaker:** TBD
- **Caching Effectiveness:** TBD

## Recommendations

1. **If P95 > 10ms:** Consider increasing CPU resources or optimizing database queries
2. **If throughput < 1000 RPS:** Scale horizontally or optimize connection pooling
3. **If service mesh latency > 5ms:** Review Istio configuration and proxy resources
4. **If circuit breaker not working:** Check failure thresholds and timeout configurations

## Next Steps

- [ ] Implement identified optimizations
- [ ] Re-run performance tests
- [ ] Monitor production metrics
- [ ] Set up automated performance regression testing

EOF

    echo -e "${GREEN}Performance report generated: $report_file${NC}"
}

# Main execution
main() {
    echo -e "${BLUE}Starting Service Architecture Performance Tests...${NC}"
    echo ""
    
    # Check service availability
    if ! check_service "$AUTH_SERVICE_URL" "Auth Service"; then
        echo -e "${RED}Auth service not available. Please start the service first.${NC}"
        exit 1
    fi
    
    # Warmup period
    echo -e "${YELLOW}Warming up services for ${WARMUP_DURATION}s...${NC}"
    for i in $(seq 1 $WARMUP_DURATION); do
        curl -s "$AUTH_SERVICE_URL/health" > /dev/null || true
        sleep 1
    done
    echo ""
    
    # Run tests
    test_service_mesh_latency
    test_circuit_breaker
    test_caching_performance
    run_comprehensive_load_test
    
    # Generate report
    generate_performance_report
    
    echo -e "${GREEN}✅ Service Architecture Performance Testing Complete!${NC}"
    echo ""
    echo "Key Metrics to Monitor:"
    echo "- Authentication latency should be < 10ms P95"
    echo "- Policy evaluation should be < 8ms P95"
    echo "- Throughput should exceed 1000 RPS"
    echo "- Service mesh overhead should be < 5ms"
    echo ""
    echo "Next steps:"
    echo "1. Review the generated performance report"
    echo "2. Implement any recommended optimizations"
    echo "3. Set up continuous performance monitoring"
    echo "4. Configure automated alerts for performance regressions"
}

# Check dependencies
if ! command -v curl &> /dev/null; then
    echo -e "${RED}curl is required but not installed.${NC}"
    exit 1
fi

if ! command -v ab &> /dev/null; then
    echo -e "${RED}Apache Bench (ab) is required but not installed.${NC}"
    echo "Install with: apt-get install apache2-utils (Ubuntu) or brew install apache2 (macOS)"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${RED}jq is required but not installed.${NC}"
    echo "Install with: apt-get install jq (Ubuntu) or brew install jq (macOS)"
    exit 1
fi

if ! command -v bc &> /dev/null; then
    echo -e "${RED}bc is required but not installed.${NC}"
    echo "Install with: apt-get install bc (Ubuntu) or brew install bc (macOS)"
    exit 1
fi

# Run main function
main "$@"
