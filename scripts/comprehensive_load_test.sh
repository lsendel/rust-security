#!/bin/bash

# Comprehensive load testing script for Rust Security Workspace
# Tests auth-service, policy-service, and security features under load

set -e

# Configuration
BASE_URL_AUTH="${1:-http://localhost:8080}"
BASE_URL_POLICY="${2:-http://localhost:8081}"
CONCURRENT_USERS="${3:-20}"
REQUESTS_PER_USER="${4:-50}"
TEST_DURATION="${5:-300}" # 5 minutes
CLIENT_ID="${6:-test_client}"
CLIENT_SECRET="${7:-test_secret}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Starting Comprehensive Load Test${NC}"
echo "Auth Service: $BASE_URL_AUTH"
echo "Policy Service: $BASE_URL_POLICY"
echo "Concurrent users: $CONCURRENT_USERS"
echo "Requests per user: $REQUESTS_PER_USER"
echo "Test duration: ${TEST_DURATION}s"
echo "Total requests: $((CONCURRENT_USERS * REQUESTS_PER_USER))"

# Create temporary directory for results
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Test results tracking
TOTAL_REQUESTS=0
SUCCESSFUL_REQUESTS=0
FAILED_REQUESTS=0
TOTAL_RESPONSE_TIME=0

# Function to log with timestamp
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to test health endpoints
test_health_endpoints() {
    log "${YELLOW}Testing health endpoints...${NC}"
    
    # Test auth service health
    if curl -s -f "$BASE_URL_AUTH/health" > /dev/null; then
        log "${GREEN}✓ Auth service health check passed${NC}"
    else
        log "${RED}✗ Auth service health check failed${NC}"
        exit 1
    fi
    
    # Test policy service health
    if curl -s -f "$BASE_URL_POLICY/health" > /dev/null; then
        log "${GREEN}✓ Policy service health check passed${NC}"
    else
        log "${RED}✗ Policy service health check failed${NC}"
        exit 1
    fi
}

# Function to perform OAuth token operations
perform_oauth_operations() {
    local user_id=$1
    local results_file="$TEMP_DIR/oauth_user_${user_id}_results.txt"
    
    for i in $(seq 1 $REQUESTS_PER_USER); do
        local start_time=$(date +%s.%N)
        
        # Get access token
        local response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL_AUTH/oauth/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=read write" \
            2>/dev/null)
        
        local http_code="${response: -3}"
        local body="${response%???}"
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc -l)
        
        if [[ "$http_code" == "200" ]]; then
            local access_token=$(echo "$body" | jq -r '.access_token // empty')
            if [[ -n "$access_token" && "$access_token" != "null" ]]; then
                echo "SUCCESS,$duration,$http_code" >> "$results_file"
                
                # Test token introspection
                local introspect_start=$(date +%s.%N)
                local introspect_response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL_AUTH/oauth/introspect" \
                    -H "Content-Type: application/json" \
                    -d "{\"token\": \"$access_token\"}" \
                    2>/dev/null)
                
                local introspect_code="${introspect_response: -3}"
                local introspect_end=$(date +%s.%N)
                local introspect_duration=$(echo "$introspect_end - $introspect_start" | bc -l)
                
                if [[ "$introspect_code" == "200" ]]; then
                    echo "INTROSPECT_SUCCESS,$introspect_duration,$introspect_code" >> "$results_file"
                else
                    echo "INTROSPECT_FAILED,$introspect_duration,$introspect_code" >> "$results_file"
                fi
            else
                echo "FAILED,$duration,$http_code,no_token" >> "$results_file"
            fi
        else
            echo "FAILED,$duration,$http_code" >> "$results_file"
        fi
        
        # Small delay to prevent overwhelming the server
        sleep 0.1
    done
}

# Function to perform policy authorization operations
perform_policy_operations() {
    local user_id=$1
    local results_file="$TEMP_DIR/policy_user_${user_id}_results.txt"
    
    for i in $(seq 1 $REQUESTS_PER_USER); do
        local start_time=$(date +%s.%N)
        
        # Test authorization request
        local auth_request='{
            "request_id": "req_'$user_id'_'$i'",
            "principal": {"type": "User", "id": "user'$user_id'"},
            "action": "orders:read",
            "resource": {"type": "Order", "id": "order'$i'"},
            "context": {"ip": "192.168.1.'$((user_id % 255))'", "time": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}
        }'
        
        local response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL_POLICY/v1/authorize" \
            -H "Content-Type: application/json" \
            -d "$auth_request" \
            2>/dev/null)
        
        local http_code="${response: -3}"
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc -l)
        
        if [[ "$http_code" == "200" ]]; then
            echo "SUCCESS,$duration,$http_code" >> "$results_file"
        else
            echo "FAILED,$duration,$http_code" >> "$results_file"
        fi
        
        sleep 0.05
    done
}

# Function to test rate limiting
test_rate_limiting() {
    log "${YELLOW}Testing rate limiting...${NC}"
    
    local rate_limit_file="$TEMP_DIR/rate_limit_test.txt"
    local success_count=0
    local rate_limited_count=0
    
    # Send requests rapidly to trigger rate limiting
    for i in $(seq 1 150); do
        local response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL_AUTH/oauth/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET" \
            2>/dev/null)
        
        local http_code="${response: -3}"
        
        if [[ "$http_code" == "200" ]]; then
            ((success_count++))
        elif [[ "$http_code" == "429" ]]; then
            ((rate_limited_count++))
        fi
        
        echo "$http_code" >> "$rate_limit_file"
    done
    
    log "Rate limiting test: $success_count successful, $rate_limited_count rate-limited"
    
    if [[ $rate_limited_count -gt 0 ]]; then
        log "${GREEN}✓ Rate limiting is working${NC}"
    else
        log "${YELLOW}⚠ Rate limiting may not be configured properly${NC}"
    fi
}

# Function to analyze results
analyze_results() {
    log "${YELLOW}Analyzing results...${NC}"
    
    local total_requests=0
    local successful_requests=0
    local failed_requests=0
    local total_response_time=0
    
    # Analyze OAuth results
    for file in "$TEMP_DIR"/oauth_user_*_results.txt; do
        if [[ -f "$file" ]]; then
            while IFS=',' read -r status duration http_code extra; do
                ((total_requests++))
                total_response_time=$(echo "$total_response_time + $duration" | bc -l)
                
                if [[ "$status" == "SUCCESS" || "$status" == "INTROSPECT_SUCCESS" ]]; then
                    ((successful_requests++))
                else
                    ((failed_requests++))
                fi
            done < "$file"
        fi
    done
    
    # Analyze Policy results
    for file in "$TEMP_DIR"/policy_user_*_results.txt; do
        if [[ -f "$file" ]]; then
            while IFS=',' read -r status duration http_code; do
                ((total_requests++))
                total_response_time=$(echo "$total_response_time + $duration" | bc -l)
                
                if [[ "$status" == "SUCCESS" ]]; then
                    ((successful_requests++))
                else
                    ((failed_requests++))
                fi
            done < "$file"
        fi
    done
    
    # Calculate metrics
    local success_rate=0
    local avg_response_time=0
    
    if [[ $total_requests -gt 0 ]]; then
        success_rate=$(echo "scale=2; $successful_requests * 100 / $total_requests" | bc -l)
        avg_response_time=$(echo "scale=3; $total_response_time / $total_requests" | bc -l)
    fi
    
    # Display results
    echo
    log "${BLUE}📊 Load Test Results${NC}"
    echo "=================================="
    echo "Total Requests: $total_requests"
    echo "Successful: $successful_requests"
    echo "Failed: $failed_requests"
    echo "Success Rate: ${success_rate}%"
    echo "Average Response Time: ${avg_response_time}s"
    echo
    
    # Performance thresholds
    if (( $(echo "$success_rate >= 95" | bc -l) )); then
        log "${GREEN}✓ Success rate is acceptable (≥95%)${NC}"
    else
        log "${RED}✗ Success rate is below threshold (<95%)${NC}"
    fi
    
    if (( $(echo "$avg_response_time <= 1.0" | bc -l) )); then
        log "${GREEN}✓ Average response time is acceptable (≤1s)${NC}"
    else
        log "${YELLOW}⚠ Average response time is above threshold (>1s)${NC}"
    fi
}

# Main execution
main() {
    # Check dependencies
    command -v curl >/dev/null 2>&1 || { log "${RED}curl is required but not installed${NC}"; exit 1; }
    command -v jq >/dev/null 2>&1 || { log "${RED}jq is required but not installed${NC}"; exit 1; }
    command -v bc >/dev/null 2>&1 || { log "${RED}bc is required but not installed${NC}"; exit 1; }
    
    # Test health endpoints first
    test_health_endpoints
    
    # Test rate limiting
    test_rate_limiting
    
    log "${YELLOW}Starting concurrent load test...${NC}"
    
    # Start OAuth operations in background
    for i in $(seq 1 $CONCURRENT_USERS); do
        perform_oauth_operations $i &
    done
    
    # Start Policy operations in background
    for i in $(seq 1 $CONCURRENT_USERS); do
        perform_policy_operations $i &
    done
    
    # Wait for all background jobs to complete
    wait
    
    # Analyze and display results
    analyze_results
    
    log "${GREEN}🎉 Load test completed!${NC}"
}

# Run main function
main "$@"
