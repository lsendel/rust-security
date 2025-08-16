#!/bin/bash

# Performance Testing Script for Rust Auth Service
# Requires k6 to be installed: https://k6.io/docs/getting-started/installation/

set -e

# Configuration
SERVICE_URL=${SERVICE_URL:-"http://localhost:8080"}
CLIENT_ID=${CLIENT_ID:-"test-client"}
CLIENT_SECRET=${CLIENT_SECRET:-"test-secret"}
OUTPUT_DIR=${OUTPUT_DIR:-"./performance_results"}
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Rust Auth Service Performance Testing ===${NC}"
echo "Service URL: $SERVICE_URL"
echo "Timestamp: $TIMESTAMP"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to check if service is running
check_service() {
    echo -e "${YELLOW}Checking if auth service is running...${NC}"
    
    if curl -f -s "$SERVICE_URL/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Auth service is running${NC}"
        return 0
    else
        echo -e "${RED}✗ Auth service is not accessible at $SERVICE_URL${NC}"
        echo "Please start the auth service and try again."
        exit 1
    fi
}

# Function to run k6 test
run_k6_test() {
    local test_name="$1"
    local test_file="$2"
    local additional_options="$3"
    
    echo -e "${YELLOW}Running $test_name...${NC}"
    
    k6 run \
        --env BASE_URL="$SERVICE_URL" \
        --env CLIENT_ID="$CLIENT_ID" \
        --env CLIENT_SECRET="$CLIENT_SECRET" \
        --out json="$OUTPUT_DIR/${test_name}_${TIMESTAMP}.json" \
        --out csv="$OUTPUT_DIR/${test_name}_${TIMESTAMP}.csv" \
        $additional_options \
        "$test_file"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ $test_name completed successfully${NC}"
    else
        echo -e "${RED}✗ $test_name failed${NC}"
    fi
    echo ""
}

# Function to run basic performance test
run_basic_performance_test() {
    echo -e "${BLUE}=== Basic Performance Test ===${NC}"
    
    cat > "$OUTPUT_DIR/basic_test_${TIMESTAMP}.js" << 'EOF'
import http from 'k6/http';
import { check } from 'k6';

export let options = {
    stages: [
        { duration: '1m', target: 10 },   // Ramp up
        { duration: '3m', target: 10 },   // Stay at 10 users
        { duration: '1m', target: 50 },   // Ramp up to 50
        { duration: '3m', target: 50 },   // Stay at 50 users
        { duration: '1m', target: 0 },    // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<100'], // 95% of requests under 100ms
        http_req_failed: ['rate<0.01'],   // Error rate under 1%
    }
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID || 'test-client';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'test-secret';

export function setup() {
    // Get token for introspection tests
    const response = http.post(`${BASE_URL}/oauth/token`, {
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        scope: 'read write'
    }, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    
    if (response.status === 200) {
        return { token: JSON.parse(response.body).access_token };
    }
    return {};
}

export default function(data) {
    // Test different endpoints with weighted distribution
    const rand = Math.random();
    
    if (rand < 0.4) {
        // 40% - Token introspection (most frequent operation)
        testIntrospection(data.token);
    } else if (rand < 0.7) {
        // 30% - Token issuance
        testTokenIssuance();
    } else if (rand < 0.85) {
        // 15% - Health check
        testHealthCheck();
    } else if (rand < 0.95) {
        // 10% - JWKS endpoint
        testJwks();
    } else {
        // 5% - OAuth metadata
        testOAuthMetadata();
    }
}

function testIntrospection(token) {
    const response = http.post(`${BASE_URL}/oauth/introspect`, JSON.stringify({
        token: token || 'invalid_token'
    }), {
        headers: { 'Content-Type': 'application/json' }
    });
    
    check(response, {
        'introspection status is 200': (r) => r.status === 200,
    });
}

function testTokenIssuance() {
    const response = http.post(`${BASE_URL}/oauth/token`, {
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
    }, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    
    check(response, {
        'token issuance status is 200': (r) => r.status === 200,
    });
}

function testHealthCheck() {
    const response = http.get(`${BASE_URL}/health`);
    check(response, {
        'health status is 200': (r) => r.status === 200,
    });
}

function testJwks() {
    const response = http.get(`${BASE_URL}/jwks.json`);
    check(response, {
        'jwks status is 200': (r) => r.status === 200,
    });
}

function testOAuthMetadata() {
    const response = http.get(`${BASE_URL}/.well-known/oauth-authorization-server`);
    check(response, {
        'oauth metadata status is 200': (r) => r.status === 200,
    });
}
EOF

    run_k6_test "basic_performance" "$OUTPUT_DIR/basic_test_${TIMESTAMP}.js"
}

# Function to run stress test
run_stress_test() {
    echo -e "${BLUE}=== Stress Test ===${NC}"
    
    cat > "$OUTPUT_DIR/stress_test_${TIMESTAMP}.js" << 'EOF'
import http from 'k6/http';
import { check } from 'k6';

export let options = {
    stages: [
        { duration: '2m', target: 100 },  // Ramp up to 100 users
        { duration: '5m', target: 100 },  // Stay at 100 users
        { duration: '2m', target: 200 },  // Ramp up to 200 users
        { duration: '5m', target: 200 },  // Stay at 200 users
        { duration: '2m', target: 300 },  // Ramp up to 300 users
        { duration: '5m', target: 300 },  // Stay at 300 users
        { duration: '2m', target: 0 },    // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<200'], // More lenient threshold for stress test
        http_req_failed: ['rate<0.05'],   // Allow up to 5% error rate
    }
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

export default function() {
    const response = http.get(`${BASE_URL}/health`);
    check(response, {
        'status is 200': (r) => r.status === 200,
    });
}
EOF

    run_k6_test "stress_test" "$OUTPUT_DIR/stress_test_${TIMESTAMP}.js"
}

# Function to run spike test
run_spike_test() {
    echo -e "${BLUE}=== Spike Test ===${NC}"
    
    cat > "$OUTPUT_DIR/spike_test_${TIMESTAMP}.js" << 'EOF'
import http from 'k6/http';
import { check } from 'k6';

export let options = {
    stages: [
        { duration: '30s', target: 10 },   // Normal load
        { duration: '10s', target: 500 },  // Spike!
        { duration: '30s', target: 10 },   // Back to normal
        { duration: '10s', target: 1000 }, // Bigger spike!
        { duration: '30s', target: 10 },   // Back to normal
    ],
    thresholds: {
        http_req_failed: ['rate<0.1'], // Allow higher error rate during spikes
    }
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

export default function() {
    const response = http.get(`${BASE_URL}/health`);
    check(response, {
        'status is 200 or 429': (r) => r.status === 200 || r.status === 429,
    });
}
EOF

    run_k6_test "spike_test" "$OUTPUT_DIR/spike_test_${TIMESTAMP}.js"
}

# Function to run endurance test
run_endurance_test() {
    echo -e "${BLUE}=== Endurance Test (30 minutes) ===${NC}"
    echo -e "${YELLOW}Warning: This test will run for 30 minutes${NC}"
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Skipping endurance test"
        return
    fi
    
    cat > "$OUTPUT_DIR/endurance_test_${TIMESTAMP}.js" << 'EOF'
import http from 'k6/http';
import { check } from 'k6';

export let options = {
    stages: [
        { duration: '5m', target: 20 },   // Ramp up
        { duration: '20m', target: 20 },  // Stay at steady load
        { duration: '5m', target: 0 },    // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<150'],
        http_req_failed: ['rate<0.02'],
    }
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID || 'test-client';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'test-secret';

export function setup() {
    const response = http.post(`${BASE_URL}/oauth/token`, {
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
    }, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    
    if (response.status === 200) {
        return { token: JSON.parse(response.body).access_token };
    }
    return {};
}

export default function(data) {
    // Simulate realistic usage patterns
    const operations = [
        () => http.post(`${BASE_URL}/oauth/introspect`, JSON.stringify({
            token: data.token || 'test_token'
        }), { headers: { 'Content-Type': 'application/json' } }),
        
        () => http.post(`${BASE_URL}/oauth/token`, {
            grant_type: 'client_credentials',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
        }, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }),
        
        () => http.get(`${BASE_URL}/health`),
        () => http.get(`${BASE_URL}/jwks.json`),
        () => http.get(`${BASE_URL}/.well-known/oauth-authorization-server`),
    ];
    
    const operation = operations[Math.floor(Math.random() * operations.length)];
    const response = operation();
    
    check(response, {
        'status is success': (r) => r.status >= 200 && r.status < 400,
    });
}
EOF

    run_k6_test "endurance_test" "$OUTPUT_DIR/endurance_test_${TIMESTAMP}.js"
}

# Function to generate performance report
generate_report() {
    echo -e "${BLUE}=== Generating Performance Report ===${NC}"
    
    cat > "$OUTPUT_DIR/performance_report_${TIMESTAMP}.md" << EOF
# Performance Test Report

**Date:** $(date)
**Service URL:** $SERVICE_URL
**Test Duration:** Various
**Test Types:** Basic Performance, Stress, Spike, Endurance

## Test Results

### Files Generated
$(ls -la "$OUTPUT_DIR"/*_${TIMESTAMP}.* | grep -v ".md")

### Quick Analysis
To analyze the results:

1. **JSON Results:** Load the JSON files into tools like Grafana or custom analysis scripts
2. **CSV Results:** Import into Excel or similar tools for detailed analysis  
3. **Summary:** Check the console output from each test run

### Key Metrics to Review
- **Response Time:** p95 and p99 percentiles
- **Error Rate:** Should be < 1% under normal load
- **Throughput:** Requests per second sustained
- **Resource Usage:** Monitor CPU and memory during tests

### Recommended Actions
1. If p95 response time > 100ms: Investigate bottlenecks
2. If error rate > 1%: Check logs for specific errors
3. If throughput < expected: Consider scaling options
4. If memory usage grows: Check for memory leaks

## Performance Optimization Checklist
- [ ] Redis connection pooling optimized
- [ ] Token store operations batched
- [ ] Rate limiting tuned appropriately  
- [ ] JWT operations cached where possible
- [ ] Database queries optimized
- [ ] Async operations properly implemented

EOF

    echo -e "${GREEN}✓ Performance report generated: $OUTPUT_DIR/performance_report_${TIMESTAMP}.md${NC}"
}

# Function to cleanup test files
cleanup() {
    echo -e "${YELLOW}Cleaning up temporary test files...${NC}"
    rm -f "$OUTPUT_DIR"/*_test_${TIMESTAMP}.js
    echo -e "${GREEN}✓ Cleanup completed${NC}"
}

# Main execution
main() {
    check_service
    
    echo -e "${YELLOW}Select tests to run:${NC}"
    echo "1. Basic Performance Test (recommended)"
    echo "2. Stress Test"  
    echo "3. Spike Test"
    echo "4. Endurance Test (30 minutes)"
    echo "5. Full Test Suite (all tests)"
    echo "6. Custom K6 Test (using existing load_test.js)"
    echo ""
    
    read -p "Enter your choice (1-6): " choice
    
    case $choice in
        1)
            run_basic_performance_test
            ;;
        2)
            run_stress_test
            ;;
        3)
            run_spike_test
            ;;
        4)
            run_endurance_test
            ;;
        5)
            run_basic_performance_test
            run_stress_test
            run_spike_test
            echo -e "${YELLOW}Skipping endurance test in full suite (run separately if needed)${NC}"
            ;;
        6)
            if [ -f "load_test.js" ]; then
                run_k6_test "custom_load_test" "load_test.js" "--summary-export=$OUTPUT_DIR/custom_summary_${TIMESTAMP}.json"
            else
                echo -e "${RED}load_test.js not found in current directory${NC}"
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            exit 1
            ;;
    esac
    
    generate_report
    cleanup
    
    echo -e "${GREEN}=== Performance testing completed! ===${NC}"
    echo -e "Results saved in: ${BLUE}$OUTPUT_DIR${NC}"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo "1. Review the generated performance report"
    echo "2. Analyze JSON/CSV results for detailed metrics"
    echo "3. Compare with performance baselines"
    echo "4. Implement optimizations if needed"
    echo "5. Re-run tests to validate improvements"
}

# Handle script interruption
trap cleanup EXIT

# Run main function
main "$@"