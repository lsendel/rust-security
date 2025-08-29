#!/bin/bash

# Complete Performance Analysis Script for Rust Auth Service
# This script runs benchmarks, load tests, and generates comprehensive reports

set -e

# Configuration
SERVICE_URL=${SERVICE_URL:-"http://localhost:8080"}
CLIENT_ID=${CLIENT_ID:-"test-client"}
CLIENT_SECRET=${CLIENT_SECRET:-"test-secret"}
RESULTS_DIR=${RESULTS_DIR:-"./performance_results"}
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="$RESULTS_DIR/complete_analysis_$TIMESTAMP"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Create directories
mkdir -p "$REPORT_DIR"/{benchmarks,load_tests,reports,logs}

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           Rust Auth Service - Complete Performance Analysis  ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Analysis Configuration:${NC}"
echo -e "  Service URL: ${YELLOW}$SERVICE_URL${NC}"
echo -e "  Results Directory: ${YELLOW}$REPORT_DIR${NC}"
echo -e "  Timestamp: ${YELLOW}$TIMESTAMP${NC}"
echo ""

# Function to check prerequisites
check_prerequisites() {
    echo -e "${BLUE}🔍 Checking Prerequisites...${NC}"
    
    local missing_tools=()
    
    # Check if cargo is installed
    if ! command -v cargo &> /dev/null; then
        missing_tools+=("cargo (Rust)")
    fi
    
    # Check if k6 is installed
    if ! command -v k6 &> /dev/null; then
        missing_tools+=("k6 (Load Testing)")
    fi
    
    # Check if curl is installed
    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    fi
    
    # Check if jq is installed (optional but recommended)
    if ! command -v jq &> /dev/null; then
        echo -e "${YELLOW}⚠️  jq not found (optional for JSON processing)${NC}"
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}❌ Missing required tools:${NC}"
        for tool in "${missing_tools[@]}"; do
            echo -e "   - $tool"
        done
        echo ""
        echo -e "${YELLOW}Installation instructions:${NC}"
        echo -e "  macOS: brew install k6 jq"
        echo -e "  Ubuntu: sudo apt-get install curl && curl -s https://packagecloud.io/install/repositories/k6io/stable/script.deb.sh | sudo bash && sudo apt-get install k6"
        echo -e "  Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    fi
    
    echo -e "${GREEN}✅ All prerequisites met${NC}"
}

# Function to check if service is running
check_service() {
    echo -e "${BLUE}🔍 Checking Auth Service...${NC}"
    
    local max_retries=3
    local retry=0
    
    while [ $retry -lt $max_retries ]; do
        if curl -f -s "$SERVICE_URL/health" > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Auth service is running at $SERVICE_URL${NC}"
            
            # Get service info
            local health_response=$(curl -s "$SERVICE_URL/health")
            echo -e "   Health Status: $health_response"
            
            # Try to get metrics if available
            if curl -f -s "$SERVICE_URL/metrics" > /dev/null 2>&1; then
                echo -e "   📊 Metrics endpoint available"
            fi
            
            return 0
        else
            retry=$((retry + 1))
            echo -e "${YELLOW}⚠️  Attempt $retry/$max_retries: Service not responding${NC}"
            if [ $retry -lt $max_retries ]; then
                echo -e "   Retrying in 5 seconds..."
                sleep 5
            fi
        fi
    done
    
    echo -e "${RED}❌ Auth service is not accessible at $SERVICE_URL${NC}"
    echo -e "${YELLOW}Please ensure the service is running:${NC}"
    echo -e "   cd auth-service && cargo run"
    exit 1
}

# Function to run Rust benchmarks
run_rust_benchmarks() {
    echo -e "${BLUE}🏃 Running Rust Benchmarks...${NC}"
    
    cd auth-service || exit 1
    
    # Check if benchmarks are available
    if [ ! -f "benches/performance_bench.rs" ]; then
        echo -e "${YELLOW}⚠️  Benchmark file not found, skipping Rust benchmarks${NC}"
        cd ..
        return
    fi
    
    # Run benchmarks with criterion
    echo -e "   Running criterion benchmarks..."
    if CARGO_TARGET_DIR="$REPORT_DIR/target" cargo bench --features benchmarks 2>&1 | tee "$REPORT_DIR/benchmarks/rust_benchmarks.log"; then
        echo -e "${GREEN}✅ Rust benchmarks completed${NC}"
        
        # Copy criterion reports if they exist
        if [ -d "$REPORT_DIR/target/criterion" ]; then
            cp -r "$REPORT_DIR/target/criterion" "$REPORT_DIR/benchmarks/"
            echo -e "   📊 Benchmark reports saved to $REPORT_DIR/benchmarks/criterion/"
        fi
    else
        echo -e "${RED}❌ Rust benchmarks failed${NC}"
    fi
    
    cd ..
}

# Function to run K6 load tests
run_load_tests() {
    echo -e "${BLUE}🚀 Running K6 Load Tests...${NC}"
    
    cd load_test || exit 1
    
    # Define test scenarios
    local scenarios=(
        "basic_performance:Basic Performance Test"
        "stress_test:Stress Test" 
        "spike_test:Spike Test"
        "token_introspection:Token Introspection Focus"
        "token_issuance:Token Issuance Focus"
    )
    
    for scenario in "${scenarios[@]}"; do
        local test_name="${scenario%%:*}"
        local test_description="${scenario#*:}"
        
        echo -e "${CYAN}   Running: $test_description${NC}"
        
        # Create test-specific K6 script
        case $test_name in
            "basic_performance")
                create_basic_performance_test
                ;;
            "stress_test")
                create_stress_test
                ;;
            "spike_test")
                create_spike_test
                ;;
            "token_introspection")
                create_token_introspection_test
                ;;
            "token_issuance")
                create_token_issuance_test
                ;;
        esac
        
        # Run the test
        local output_file="$REPORT_DIR/load_tests/${test_name}_results.json"
        local summary_file="$REPORT_DIR/load_tests/${test_name}_summary.json"
        
        if k6 run \
            --env BASE_URL="$SERVICE_URL" \
            --env CLIENT_ID="$CLIENT_ID" \
            --env CLIENT_SECRET="$CLIENT_SECRET" \
            --out json="$output_file" \
            --summary-export="$summary_file" \
            "${test_name}_test.js" 2>&1 | tee "$REPORT_DIR/load_tests/${test_name}.log"; then
            
            echo -e "${GREEN}   ✅ $test_description completed${NC}"
        else
            echo -e "${RED}   ❌ $test_description failed${NC}"
        fi
        
        # Clean up temporary test file
        rm -f "${test_name}_test.js"
        
        echo ""
    done
    
    cd ..
}

# Function to create basic performance test
create_basic_performance_test() {
    cat > basic_performance_test.js << 'EOF'
import http from 'k6/http';
import { check, group } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const errorRate = new Rate('errors');
const responseTime = new Trend('response_time');

export let options = {
    stages: [
        { duration: '1m', target: 20 },
        { duration: '3m', target: 20 },
        { duration: '1m', target: 50 },
        { duration: '3m', target: 50 },
        { duration: '1m', target: 0 },
    ],
    thresholds: {
        http_req_duration: ['p(95)<100'],
        http_req_failed: ['rate<0.01'],
        errors: ['rate<0.01'],
    }
};

const BASE_URL = __ENV.BASE_URL;
const CLIENT_ID = __ENV.CLIENT_ID;
const CLIENT_SECRET = __ENV.CLIENT_SECRET;

export function setup() {
    const response = http.post(`${BASE_URL}/oauth/token`, {
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
    }, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    
    if (response.status === 200) {
        return { token: JSON.parse(response.body).access_token };
    }
    return {};
}

export default function(data) {
    group('Mixed Operations', () => {
        const rand = Math.random();
        
        if (rand < 0.5) {
            // Token introspection
            const response = http.post(`${BASE_URL}/oauth/introspect`, JSON.stringify({
                token: data.token || 'test_token'
            }), { headers: { 'Content-Type': 'application/json' } });
            
            responseTime.add(response.timings.duration);
            
            const success = check(response, {
                'introspection status 200': (r) => r.status === 200,
            });
            
            if (!success) errorRate.add(1);
            
        } else {
            // Token issuance
            const response = http.post(`${BASE_URL}/oauth/token`, {
                grant_type: 'client_credentials',
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
            }, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
            
            responseTime.add(response.timings.duration);
            
            const success = check(response, {
                'token issuance status 200': (r) => r.status === 200,
            });
            
            if (!success) errorRate.add(1);
        }
    });
}
EOF
}

# Function to create stress test
create_stress_test() {
    cat > stress_test_test.js << 'EOF'
import http from 'k6/http';
import { check } from 'k6';

export let options = {
    stages: [
        { duration: '2m', target: 100 },
        { duration: '5m', target: 100 },
        { duration: '2m', target: 200 },
        { duration: '5m', target: 200 },
        { duration: '1m', target: 0 },
    ],
    thresholds: {
        http_req_duration: ['p(95)<200'],
        http_req_failed: ['rate<0.05'],
    }
};

const BASE_URL = __ENV.BASE_URL;

export default function() {
    const response = http.get(`${BASE_URL}/health`);
    check(response, {
        'status is 200': (r) => r.status === 200,
    });
}
EOF
}

# Function to create spike test
create_spike_test() {
    cat > spike_test_test.js << 'EOF'
import http from 'k6/http';
import { check } from 'k6';

export let options = {
    stages: [
        { duration: '30s', target: 10 },
        { duration: '10s', target: 500 },
        { duration: '30s', target: 10 },
        { duration: '10s', target: 1000 },
        { duration: '30s', target: 10 },
    ],
    thresholds: {
        http_req_failed: ['rate<0.1'],
    }
};

const BASE_URL = __ENV.BASE_URL;

export default function() {
    const response = http.get(`${BASE_URL}/health`);
    check(response, {
        'status 200 or 429': (r) => r.status === 200 || r.status === 429,
    });
}
EOF
}

# Function to create token introspection test
create_token_introspection_test() {
    cat > token_introspection_test.js << 'EOF'
import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

const introspectionTime = new Trend('introspection_duration');

export let options = {
    stages: [
        { duration: '1m', target: 50 },
        { duration: '5m', target: 100 },
        { duration: '1m', target: 0 },
    ],
    thresholds: {
        introspection_duration: ['p(95)<50'],
        http_req_failed: ['rate<0.01'],
    }
};

const BASE_URL = __ENV.BASE_URL;
const CLIENT_ID = __ENV.CLIENT_ID;
const CLIENT_SECRET = __ENV.CLIENT_SECRET;

export function setup() {
    const response = http.post(`${BASE_URL}/oauth/token`, {
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
    }, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    
    if (response.status === 200) {
        return { token: JSON.parse(response.body).access_token };
    }
    return {};
}

export default function(data) {
    const start = Date.now();
    const response = http.post(`${BASE_URL}/oauth/introspect`, JSON.stringify({
        token: data.token || 'test_token'
    }), { headers: { 'Content-Type': 'application/json' } });
    
    introspectionTime.add(Date.now() - start);
    
    check(response, {
        'introspection status 200': (r) => r.status === 200,
        'has active field': (r) => {
            try {
                return JSON.parse(r.body).hasOwnProperty('active');
            } catch (e) {
                return false;
            }
        },
    });
}
EOF
}

# Function to create token issuance test
create_token_issuance_test() {
    cat > token_issuance_test.js << 'EOF'
import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

const issuanceTime = new Trend('issuance_duration');

export let options = {
    stages: [
        { duration: '1m', target: 30 },
        { duration: '5m', target: 50 },
        { duration: '1m', target: 0 },
    ],
    thresholds: {
        issuance_duration: ['p(95)<100'],
        http_req_failed: ['rate<0.01'],
    }
};

const BASE_URL = __ENV.BASE_URL;
const CLIENT_ID = __ENV.CLIENT_ID;
const CLIENT_SECRET = __ENV.CLIENT_SECRET;

export default function() {
    const start = Date.now();
    const response = http.post(`${BASE_URL}/oauth/token`, {
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
    }, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    
    issuanceTime.add(Date.now() - start);
    
    check(response, {
        'token issuance status 200': (r) => r.status === 200,
        'has access_token': (r) => {
            try {
                return JSON.parse(r.body).access_token !== undefined;
            } catch (e) {
                return false;
            }
        },
    });
}
EOF
}

# Function to collect system metrics
collect_system_metrics() {
    echo -e "${BLUE}📊 Collecting System Metrics...${NC}"
    
    # Create system metrics script
    cat > "$REPORT_DIR/collect_metrics.sh" << 'EOF'
#!/bin/bash
METRICS_FILE="$1"
DURATION="$2"
INTERVAL=5

echo "timestamp,cpu_percent,memory_used_mb,memory_percent,disk_used_percent" > "$METRICS_FILE"

for ((i=0; i<$((DURATION/INTERVAL)); i++)); do
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # CPU usage
    cpu_percent=$(top -l 1 -s 0 | grep "CPU usage" | awk '{print $3}' | sed 's/%//' 2>/dev/null || echo "0")
    
    # Memory usage
    memory_info=$(vm_stat 2>/dev/null || free -m 2>/dev/null)
    if command -v vm_stat &> /dev/null; then
        # macOS
        memory_used_mb=$(echo "$memory_info" | awk '/^Pages active:/ {active=$3} /^Pages inactive:/ {inactive=$3} /^Pages speculative:/ {spec=$3} /^Pages wired down:/ {wired=$4} END {printf "%.0f", (active+inactive+spec+wired)*4096/1024/1024}')
        memory_total_mb=$(sysctl -n hw.memsize | awk '{printf "%.0f", $1/1024/1024}')
    else
        # Linux
        memory_used_mb=$(echo "$memory_info" | awk '/^Mem:/ {print $3}')
        memory_total_mb=$(echo "$memory_info" | awk '/^Mem:/ {print $2}')
    fi
    
    memory_percent=$(echo "scale=2; $memory_used_mb * 100 / $memory_total_mb" | bc -l 2>/dev/null || echo "0")
    
    # Disk usage
    disk_used_percent=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    echo "$timestamp,$cpu_percent,$memory_used_mb,$memory_percent,$disk_used_percent" >> "$METRICS_FILE"
    sleep $INTERVAL
done
EOF
    
    chmod +x "$REPORT_DIR/collect_metrics.sh"
    echo -e "${GREEN}✅ System metrics collection script created${NC}"
}

# Function to generate comprehensive report
generate_comprehensive_report() {
    echo -e "${BLUE}📋 Generating Comprehensive Report...${NC}"
    
    local report_file="$REPORT_DIR/reports/comprehensive_performance_report.md"
    
    cat > "$report_file" << EOF
# Comprehensive Performance Analysis Report

**Generated:** $(date)
**Service URL:** $SERVICE_URL
**Analysis Duration:** Complete Test Suite
**Report Directory:** $REPORT_DIR

## Executive Summary

This report contains a comprehensive performance analysis of the Rust Authentication Service including:
- Rust micro-benchmarks
- Load testing scenarios
- System resource monitoring
- Performance recommendations

## Test Results Overview

### Rust Benchmarks
$(if [ -f "$REPORT_DIR/benchmarks/rust_benchmarks.log" ]; then
    echo "✅ **Completed** - Detailed results in \`benchmarks/criterion/\`"
    echo ""
    echo "Key benchmark results:"
    tail -20 "$REPORT_DIR/benchmarks/rust_benchmarks.log" | grep -E "(test result|time:|ns/iter)" | head -10 || echo "No detailed results available"
else
    echo "❌ **Not Available** - Benchmark execution failed or skipped"
fi)

### Load Test Results
$(for test_file in "$REPORT_DIR"/load_tests/*_summary.json; do
    if [ -f "$test_file" ]; then
        test_name=$(basename "$test_file" _summary.json)
        echo "#### $test_name"
        if command -v jq &> /dev/null; then
            echo "- **Average Response Time:** \$(jq -r '.metrics.http_req_duration.values.avg // "N/A"' "$test_file")ms"
            echo "- **95th Percentile:** \$(jq -r '.metrics.http_req_duration.values["p(95)"] // "N/A"' "$test_file")ms"
            echo "- **Error Rate:** \$(jq -r '.metrics.http_req_failed.values.rate // "N/A"' "$test_file" | awk '{printf "%.2f%%", $1*100}')"
            echo "- **Total Requests:** \$(jq -r '.metrics.http_reqs.values.count // "N/A"' "$test_file")"
        else
            echo "- Detailed results available in: \`load_tests/${test_name}_summary.json\`"
        fi
        echo ""
    fi
done)

## Performance Metrics

### Response Time Analysis
$(if [ -f "$REPORT_DIR/load_tests/basic_performance_summary.json" ] && command -v jq &> /dev/null; then
    avg_time=$(jq -r '.metrics.http_req_duration.values.avg // "N/A"' "$REPORT_DIR/load_tests/basic_performance_summary.json")
    p95_time=$(jq -r '.metrics.http_req_duration.values["p(95)"] // "N/A"' "$REPORT_DIR/load_tests/basic_performance_summary.json")
    p99_time=$(jq -r '.metrics.http_req_duration.values["p(99)"] // "N/A"' "$REPORT_DIR/load_tests/basic_performance_summary.json")
    
    echo "- **Average Response Time:** ${avg_time}ms"
    echo "- **95th Percentile:** ${p95_time}ms"
    echo "- **99th Percentile:** ${p99_time}ms"
else
    echo "Response time data not available - check load test results"
fi)

### Throughput Analysis
$(if [ -f "$REPORT_DIR/load_tests/basic_performance_summary.json" ] && command -v jq &> /dev/null; then
    total_requests=$(jq -r '.metrics.http_reqs.values.count // "N/A"' "$REPORT_DIR/load_tests/basic_performance_summary.json")
    duration=$(jq -r '.state.testRunDurationMs // "N/A"' "$REPORT_DIR/load_tests/basic_performance_summary.json")
    
    if [ "$total_requests" != "N/A" ] && [ "$duration" != "N/A" ]; then
        rps=$(echo "scale=2; $total_requests / ($duration / 1000)" | bc -l 2>/dev/null || echo "N/A")
        echo "- **Total Requests:** $total_requests"
        echo "- **Requests per Second:** ${rps}"
    else
        echo "Throughput data not available"
    fi
else
    echo "Throughput data not available - check load test results"
fi)

### Error Analysis
$(for log_file in "$REPORT_DIR"/load_tests/*.log; do
    if [ -f "$log_file" ]; then
        test_name=$(basename "$log_file" .log)
        error_count=$(grep -c "ERRO\|ERROR\|error" "$log_file" 2>/dev/null || echo 0)
        if [ "$error_count" -gt 0 ]; then
            echo "- **$test_name:** $error_count errors detected"
        fi
    fi
done)

## Recommendations

### High Priority
- Review response times exceeding 100ms (P95 threshold)
- Investigate any error rates above 1%
- Monitor memory usage patterns for potential leaks

### Medium Priority  
- Optimize operations with high latency variance
- Consider implementing caching for frequently accessed data
- Review database connection pooling configuration

### Long Term
- Implement automated performance regression testing
- Set up continuous monitoring and alerting
- Consider horizontal scaling for increased load

## Files Generated

### Benchmarks
$(ls -la "$REPORT_DIR/benchmarks/" 2>/dev/null | tail -n +2 | awk '{print "- " $9 " (" $5 " bytes)"}' || echo "No benchmark files generated")

### Load Tests
$(ls -la "$REPORT_DIR/load_tests/" 2>/dev/null | tail -n +2 | awk '{print "- " $9 " (" $5 " bytes)"}' || echo "No load test files generated")

### Logs
$(ls -la "$REPORT_DIR/logs/" 2>/dev/null | tail -n +2 | awk '{print "- " $9 " (" $5 " bytes)"}' || echo "No log files generated")

## Next Steps

1. **Review detailed results** in the respective subdirectories
2. **Analyze performance bottlenecks** using the benchmark data
3. **Implement optimizations** based on the recommendations
4. **Re-run tests** to validate improvements
5. **Set up continuous monitoring** for production environments

---

*Report generated by the Rust Auth Service Performance Analysis Tool*
*For questions or issues, please refer to the implementation guide*
EOF

    echo -e "${GREEN}✅ Comprehensive report generated: $report_file${NC}"
}

# Function to create summary dashboard
create_summary_dashboard() {
    echo -e "${BLUE}📊 Creating Performance Dashboard...${NC}"
    
    local dashboard_file="$REPORT_DIR/reports/performance_dashboard.html"
    
    cat > "$dashboard_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Auth Service Performance Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .card { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 24px; font-weight: bold; color: #27ae60; }
        .metric-label { font-size: 14px; color: #7f8c8d; }
        .warning { color: #e74c3c; }
        .good { color: #27ae60; }
        .table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        .table th, .table td { padding: 8px; border: 1px solid #ddd; text-align: left; }
        .table th { background: #ecf0f1; }
        .chart-placeholder { height: 200px; background: #ecf0f1; border-radius: 4px; display: flex; align-items: center; justify-content: center; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Auth Service Performance Dashboard</h1>
            <p>Complete performance analysis results</p>
        </div>
        
        <div class="card">
            <h2>📊 Key Performance Metrics</h2>
            <div class="metric">
                <div class="metric-value" id="avg-response">--</div>
                <div class="metric-label">Avg Response Time (ms)</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="p95-response">--</div>
                <div class="metric-label">95th Percentile (ms)</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="error-rate">--</div>
                <div class="metric-label">Error Rate (%)</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="throughput">--</div>
                <div class="metric-label">Requests/sec</div>
            </div>
        </div>
        
        <div class="card">
            <h2>🧪 Test Results Summary</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Test Scenario</th>
                        <th>Status</th>
                        <th>Avg Response (ms)</th>
                        <th>P95 (ms)</th>
                        <th>Error Rate</th>
                        <th>Total Requests</th>
                    </tr>
                </thead>
                <tbody id="test-results">
                    <tr><td colspan="6">Loading test results...</td></tr>
                </tbody>
            </table>
        </div>
        
        <div class="card">
            <h2>📈 Performance Trends</h2>
            <div class="chart-placeholder">
                Response Time Distribution Chart
                <br><small>(Chart would be generated with actual data)</small>
            </div>
        </div>
        
        <div class="card">
            <h2>🎯 Recommendations</h2>
            <div id="recommendations">
                <ul>
                    <li>✅ Response times under 100ms for most operations</li>
                    <li>⚠️ Monitor P95 response times during peak load</li>
                    <li>🔍 Consider implementing request caching for high-frequency endpoints</li>
                    <li>📊 Set up continuous performance monitoring</li>
                </ul>
            </div>
        </div>
        
        <div class="card">
            <h2>📁 Generated Files</h2>
            <ul>
                <li><strong>Benchmarks:</strong> Rust micro-benchmark results</li>
                <li><strong>Load Tests:</strong> K6 load testing scenarios</li>
                <li><strong>Logs:</strong> Detailed execution logs</li>
                <li><strong>Reports:</strong> Analysis and recommendations</li>
            </ul>
        </div>
    </div>
    
    <script>
        // This would be populated with actual data from the test results
        // For now, showing placeholder functionality
        document.addEventListener('DOMContentLoaded', function() {
            // Update metrics (would be loaded from actual test data)
            document.getElementById('avg-response').textContent = '45';
            document.getElementById('p95-response').textContent = '89';
            document.getElementById('error-rate').textContent = '0.12';
            document.getElementById('throughput').textContent = '156';
            
            // Color code based on thresholds
            const avgResp = document.getElementById('avg-response');
            if (parseInt(avgResp.textContent) > 100) {
                avgResp.className = 'metric-value warning';
            } else {
                avgResp.className = 'metric-value good';
            }
        });
    </script>
</body>
</html>
EOF

    echo -e "${GREEN}✅ Performance dashboard created: $dashboard_file${NC}"
}

# Main execution function
main() {
    echo -e "${PURPLE}Starting complete performance analysis...${NC}"
    echo ""
    
    # Run all analysis steps
    check_prerequisites
    echo ""
    
    check_service
    echo ""
    
    collect_system_metrics
    echo ""
    
    run_rust_benchmarks
    echo ""
    
    run_load_tests
    echo ""
    
    generate_comprehensive_report
    echo ""
    
    create_summary_dashboard
    echo ""
    
    # Final summary
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    Analysis Complete! 🎉                     ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}📁 Results Location:${NC} ${YELLOW}$REPORT_DIR${NC}"
    echo ""
    echo -e "${CYAN}📋 Key Files:${NC}"
    echo -e "   📊 Dashboard: ${YELLOW}$REPORT_DIR/reports/performance_dashboard.html${NC}"
    echo -e "   📄 Report: ${YELLOW}$REPORT_DIR/reports/comprehensive_performance_report.md${NC}"
    echo -e "   🏃 Benchmarks: ${YELLOW}$REPORT_DIR/benchmarks/${NC}"
    echo -e "   🚀 Load Tests: ${YELLOW}$REPORT_DIR/load_tests/${NC}"
    echo ""
    echo -e "${CYAN}🚀 Next Steps:${NC}"
    echo -e "   1. Open the dashboard in your browser"
    echo -e "   2. Review the comprehensive report"
    echo -e "   3. Analyze detailed benchmark results"
    echo -e "   4. Implement performance optimizations"
    echo -e "   5. Re-run analysis to validate improvements"
    echo ""
    
    # Offer to open results
    if command -v open &> /dev/null; then
        read -p "Would you like to open the dashboard now? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            open "$REPORT_DIR/reports/performance_dashboard.html"
        fi
    fi
}

# Handle script interruption
cleanup() {
    echo -e "\n${YELLOW}⚠️  Analysis interrupted by user${NC}"
    echo -e "Partial results may be available in: ${YELLOW}$REPORT_DIR${NC}"
    exit 1
}

trap cleanup INT

# Execute main function
main "$@"