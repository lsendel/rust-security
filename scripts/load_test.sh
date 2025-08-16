#!/bin/bash

# Load testing script for auth-service
# Requires: curl, jq, parallel (GNU parallel)

set -e

BASE_URL="${1:-http://localhost:8080}"
CONCURRENT_USERS="${2:-10}"
REQUESTS_PER_USER="${3:-100}"
CLIENT_ID="${4:-test_client}"
CLIENT_SECRET="${5:-test_secret}"

echo "Starting load test..."
echo "Base URL: $BASE_URL"
echo "Concurrent users: $CONCURRENT_USERS"
echo "Requests per user: $REQUESTS_PER_USER"
echo "Total requests: $((CONCURRENT_USERS * REQUESTS_PER_USER))"

# Create temporary directory for results
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Function to perform token operations
perform_token_operations() {
    local user_id=$1
    local results_file="$TEMP_DIR/user_${user_id}_results.txt"
    
    for i in $(seq 1 $REQUESTS_PER_USER); do
        local start_time=$(date +%s.%N)
        
        # Issue token
        local token_response=$(curl -s -w "%{http_code}" \
            -X POST "$BASE_URL/oauth/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=read")
        
        local http_code="${token_response: -3}"
        local response_body="${token_response%???}"
        
        if [ "$http_code" = "200" ]; then
            local access_token=$(echo "$response_body" | jq -r '.access_token')
            
            # Introspect token
            local introspect_response=$(curl -s -w "%{http_code}" \
                -X POST "$BASE_URL/oauth/introspect" \
                -H "Content-Type: application/json" \
                -d "{\"token\":\"$access_token\"}")
            
            local introspect_code="${introspect_response: -3}"
            
            # Revoke token
            local revoke_response=$(curl -s -w "%{http_code}" \
                -X POST "$BASE_URL/oauth/revoke" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "token=$access_token")
            
            local revoke_code="${revoke_response: -3}"
            
            local end_time=$(date +%s.%N)
            local duration=$(echo "$end_time - $start_time" | bc)
            
            echo "user_${user_id},${i},${duration},${http_code},${introspect_code},${revoke_code}" >> "$results_file"
        else
            local end_time=$(date +%s.%N)
            local duration=$(echo "$end_time - $start_time" | bc)
            echo "user_${user_id},${i},${duration},${http_code},ERROR,ERROR" >> "$results_file"
        fi
        
        # Small delay to avoid overwhelming the server
        sleep 0.01
    done
}

# Export function for parallel execution
export -f perform_token_operations
export BASE_URL CLIENT_ID CLIENT_SECRET REQUESTS_PER_USER TEMP_DIR

# Run load test with parallel users
echo "Starting load test at $(date)"
seq 1 $CONCURRENT_USERS | parallel -j $CONCURRENT_USERS perform_token_operations {}

# Aggregate results
echo "Aggregating results..."
cat $TEMP_DIR/user_*_results.txt > $TEMP_DIR/all_results.txt

# Calculate statistics
total_requests=$(wc -l < $TEMP_DIR/all_results.txt)
successful_requests=$(awk -F',' '$4 == 200 && $5 == 200 && $6 == 200' $TEMP_DIR/all_results.txt | wc -l)
failed_requests=$((total_requests - successful_requests))

# Calculate response times
avg_response_time=$(awk -F',' '{sum+=$3; count++} END {print sum/count}' $TEMP_DIR/all_results.txt)
min_response_time=$(awk -F',' 'NR==1{min=$3} {if($3<min) min=$3} END {print min}' $TEMP_DIR/all_results.txt)
max_response_time=$(awk -F',' 'NR==1{max=$3} {if($3>max) max=$3} END {print max}' $TEMP_DIR/all_results.txt)

# Calculate percentiles
p95_response_time=$(awk -F',' '{print $3}' $TEMP_DIR/all_results.txt | sort -n | awk '{all[NR] = $0} END{print all[int(NR*0.95)]}')
p99_response_time=$(awk -F',' '{print $3}' $TEMP_DIR/all_results.txt | sort -n | awk '{all[NR] = $0} END{print all[int(NR*0.99)]}')

# Print results
echo ""
echo "=== LOAD TEST RESULTS ==="
echo "Total requests: $total_requests"
echo "Successful requests: $successful_requests"
echo "Failed requests: $failed_requests"
echo "Success rate: $(echo "scale=2; $successful_requests * 100 / $total_requests" | bc)%"
echo ""
echo "Response time statistics (seconds):"
echo "  Average: $(printf "%.3f" $avg_response_time)"
echo "  Minimum: $(printf "%.3f" $min_response_time)"
echo "  Maximum: $(printf "%.3f" $max_response_time)"
echo "  95th percentile: $(printf "%.3f" $p95_response_time)"
echo "  99th percentile: $(printf "%.3f" $p99_response_time)"
echo ""

# Calculate throughput
test_duration=$(awk -F',' 'NR==1{start=$3} END{print $3-start}' $TEMP_DIR/all_results.txt)
if [ $(echo "$test_duration > 0" | bc) -eq 1 ]; then
    throughput=$(echo "scale=2; $successful_requests / $test_duration" | bc)
    echo "Throughput: $throughput requests/second"
fi

# Error analysis
echo ""
echo "=== ERROR ANALYSIS ==="
echo "HTTP status code distribution:"
awk -F',' '{print $4}' $TEMP_DIR/all_results.txt | sort | uniq -c | sort -nr

# Save detailed results
results_file="load_test_results_$(date +%Y%m%d_%H%M%S).csv"
echo "user_id,request_num,duration,token_status,introspect_status,revoke_status" > "$results_file"
cat $TEMP_DIR/all_results.txt >> "$results_file"
echo ""
echo "Detailed results saved to: $results_file"

echo "Load test completed at $(date)"
