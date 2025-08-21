#!/bin/bash

# Performance Baseline Validation Script
# Validates that the platform meets performance requirements

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Performance baselines (configurable)
BASELINE_P50_MS=${BASELINE_P50_MS:-50}      # 50ms P50 latency
BASELINE_P95_MS=${BASELINE_P95_MS:-100}     # 100ms P95 latency
BASELINE_P99_MS=${BASELINE_P99_MS:-200}     # 200ms P99 latency
BASELINE_RPS=${BASELINE_RPS:-1000}          # 1000 requests per second
BASELINE_ERROR_RATE=${BASELINE_ERROR_RATE:-0.1}  # 0.1% error rate
BASELINE_CPU_PERCENT=${BASELINE_CPU_PERCENT:-70} # 70% CPU utilization
BASELINE_MEMORY_MB=${BASELINE_MEMORY_MB:-512}   # 512MB memory usage

# Test configuration
TEST_DURATION=${TEST_DURATION:-300}  # 5 minutes
TEST_USERS=${TEST_USERS:-100}       # 100 concurrent users
SERVICE_URL=${SERVICE_URL:-"http://localhost:8080"}
NAMESPACE=${NAMESPACE:-"rust-security-staging"}

# Results storage
RESULTS_DIR="performance-results-$(date +%Y%m%d-%H%M%S)"
mkdir -p $RESULTS_DIR

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a $RESULTS_DIR/validation.log
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a $RESULTS_DIR/validation.log
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a $RESULTS_DIR/validation.log
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a $RESULTS_DIR/validation.log
}

# Header
echo "================================================================================" | tee $RESULTS_DIR/validation.log
echo "                    RUST SECURITY PLATFORM" | tee -a $RESULTS_DIR/validation.log
echo "                 Performance Baseline Validation" | tee -a $RESULTS_DIR/validation.log
echo "================================================================================" | tee -a $RESULTS_DIR/validation.log
echo | tee -a $RESULTS_DIR/validation.log

log_info "Test Configuration:"
log_info "  Duration: ${TEST_DURATION}s"
log_info "  Users: ${TEST_USERS}"
log_info "  Target: ${SERVICE_URL}"
log_info "  Results: ${RESULTS_DIR}/"
echo

# 1. Check prerequisites
log_info "Checking prerequisites..."

command -v k6 >/dev/null 2>&1 || {
    log_error "k6 is not installed. Install from: https://k6.io/docs/getting-started/installation/"
    exit 1
}

command -v kubectl >/dev/null 2>&1 || {
    log_error "kubectl is not installed"
    exit 1
}

command -v jq >/dev/null 2>&1 || {
    log_error "jq is not installed"
    exit 1
}

log_success "Prerequisites check passed"

# 2. Verify service is running
log_info "Verifying service availability..."

if ! curl -f ${SERVICE_URL}/health >/dev/null 2>&1; then
    log_error "Service is not accessible at ${SERVICE_URL}"
    exit 1
fi

log_success "Service is accessible"

# 3. Capture baseline metrics before test
log_info "Capturing baseline metrics..."

# Get current resource usage
BASELINE_METRICS=$(kubectl top pods -n ${NAMESPACE} -l app=auth-service --no-headers 2>/dev/null || echo "")
echo "$BASELINE_METRICS" > $RESULTS_DIR/baseline-metrics.txt

# 4. Run performance tests
log_info "Running performance tests..."

# Create K6 test script
cat > $RESULTS_DIR/performance-test.js <<'EOF'
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const authLatency = new Trend('auth_latency');
const tokenLatency = new Trend('token_latency');
const introspectLatency = new Trend('introspect_latency');

export const options = {
  stages: [
    { duration: '30s', target: __ENV.TEST_USERS / 2 },  // Ramp up
    { duration: __ENV.TEST_DURATION - 60 + 's', target: __ENV.TEST_USERS },  // Stay at peak
    { duration: '30s', target: 0 },  // Ramp down
  ],
  thresholds: {
    http_req_duration: [
      'p(50)<' + __ENV.BASELINE_P50_MS,
      'p(95)<' + __ENV.BASELINE_P95_MS,
      'p(99)<' + __ENV.BASELINE_P99_MS,
    ],
    http_req_failed: ['rate<' + (__ENV.BASELINE_ERROR_RATE / 100)],
    errors: ['rate<' + (__ENV.BASELINE_ERROR_RATE / 100)],
  },
};

const BASE_URL = __ENV.SERVICE_URL;

export default function () {
  // Test 1: Health check
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, {
    'health check status is 200': (r) => r.status === 200,
  });
  
  // Test 2: Authentication
  const authPayload = JSON.stringify({
    username: `user_${__VU}_${__ITER}`,
    password: 'test_password',
    grant_type: 'password',
  });
  
  const authParams = {
    headers: { 'Content-Type': 'application/json' },
  };
  
  const authStart = Date.now();
  const authRes = http.post(`${BASE_URL}/oauth/token`, authPayload, authParams);
  authLatency.add(Date.now() - authStart);
  
  const authSuccess = check(authRes, {
    'auth status is 200': (r) => r.status === 200,
    'auth has access_token': (r) => r.json('access_token') !== undefined,
  });
  
  errorRate.add(!authSuccess);
  
  if (authSuccess && authRes.json('access_token')) {
    const token = authRes.json('access_token');
    
    // Test 3: Token validation
    const validateParams = {
      headers: { 
        'Authorization': `Bearer ${token}`,
      },
    };
    
    const validateStart = Date.now();
    const validateRes = http.get(`${BASE_URL}/oauth/userinfo`, validateParams);
    tokenLatency.add(Date.now() - validateStart);
    
    check(validateRes, {
      'userinfo status is 200': (r) => r.status === 200,
    });
    
    // Test 4: Token introspection
    const introspectPayload = `token=${token}`;
    const introspectParams = {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    };
    
    const introspectStart = Date.now();
    const introspectRes = http.post(`${BASE_URL}/oauth/introspect`, introspectPayload, introspectParams);
    introspectLatency.add(Date.now() - introspectStart);
    
    check(introspectRes, {
      'introspect status is 200': (r) => r.status === 200,
      'token is active': (r) => r.json('active') === true,
    });
  }
  
  sleep(1);
}

export function handleSummary(data) {
  return {
    'summary.json': JSON.stringify(data),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, options) {
  // Custom summary format
  let summary = '\n=== Performance Test Results ===\n\n';
  
  if (data.metrics) {
    summary += 'Response Times:\n';
    summary += `  P50: ${data.metrics.http_req_duration.p(50).toFixed(2)}ms\n`;
    summary += `  P95: ${data.metrics.http_req_duration.p(95).toFixed(2)}ms\n`;
    summary += `  P99: ${data.metrics.http_req_duration.p(99).toFixed(2)}ms\n\n`;
    
    summary += 'Throughput:\n';
    summary += `  RPS: ${data.metrics.http_reqs.rate.toFixed(2)}\n\n`;
    
    summary += 'Error Rate:\n';
    summary += `  Failed Requests: ${(data.metrics.http_req_failed.rate * 100).toFixed(2)}%\n`;
  }
  
  return summary;
}
EOF

# Export environment variables for K6
export TEST_USERS
export TEST_DURATION
export SERVICE_URL
export BASELINE_P50_MS
export BASELINE_P95_MS
export BASELINE_P99_MS
export BASELINE_ERROR_RATE

# Run K6 test
k6 run \
  --out json=$RESULTS_DIR/results.json \
  --summary-export=$RESULTS_DIR/summary.json \
  $RESULTS_DIR/performance-test.js 2>&1 | tee $RESULTS_DIR/k6-output.log

# 5. Capture metrics after test
log_info "Capturing post-test metrics..."

POST_METRICS=$(kubectl top pods -n ${NAMESPACE} -l app=auth-service --no-headers 2>/dev/null || echo "")
echo "$POST_METRICS" > $RESULTS_DIR/post-metrics.txt

# 6. Analyze results
log_info "Analyzing results..."

# Parse K6 summary
if [ -f $RESULTS_DIR/summary.json ]; then
    ACTUAL_P50=$(jq '.metrics.http_req_duration.p50' $RESULTS_DIR/summary.json)
    ACTUAL_P95=$(jq '.metrics.http_req_duration.p95' $RESULTS_DIR/summary.json)
    ACTUAL_P99=$(jq '.metrics.http_req_duration.p99' $RESULTS_DIR/summary.json)
    ACTUAL_RPS=$(jq '.metrics.http_reqs.rate' $RESULTS_DIR/summary.json)
    ACTUAL_ERROR_RATE=$(jq '.metrics.http_req_failed.rate * 100' $RESULTS_DIR/summary.json)
    
    # Parse resource metrics
    if [ ! -z "$POST_METRICS" ]; then
        ACTUAL_CPU=$(echo "$POST_METRICS" | awk '{sum+=$2} END {print sum}' | sed 's/m//')
        ACTUAL_MEMORY=$(echo "$POST_METRICS" | awk '{sum+=$3} END {print sum}' | sed 's/Mi//')
    else
        ACTUAL_CPU=0
        ACTUAL_MEMORY=0
    fi
else
    log_error "Failed to parse test results"
    exit 1
fi

# 7. Validate against baselines
echo
echo "================================================================================" | tee -a $RESULTS_DIR/validation.log
echo "                         VALIDATION RESULTS" | tee -a $RESULTS_DIR/validation.log
echo "================================================================================" | tee -a $RESULTS_DIR/validation.log
echo | tee -a $RESULTS_DIR/validation.log

VALIDATION_PASSED=true

# Check latency
echo "📊 Latency Validation:" | tee -a $RESULTS_DIR/validation.log
if (( $(echo "$ACTUAL_P50 <= $BASELINE_P50_MS" | bc -l) )); then
    log_success "P50: ${ACTUAL_P50}ms ≤ ${BASELINE_P50_MS}ms"
else
    log_error "P50: ${ACTUAL_P50}ms > ${BASELINE_P50_MS}ms"
    VALIDATION_PASSED=false
fi

if (( $(echo "$ACTUAL_P95 <= $BASELINE_P95_MS" | bc -l) )); then
    log_success "P95: ${ACTUAL_P95}ms ≤ ${BASELINE_P95_MS}ms"
else
    log_error "P95: ${ACTUAL_P95}ms > ${BASELINE_P95_MS}ms"
    VALIDATION_PASSED=false
fi

if (( $(echo "$ACTUAL_P99 <= $BASELINE_P99_MS" | bc -l) )); then
    log_success "P99: ${ACTUAL_P99}ms ≤ ${BASELINE_P99_MS}ms"
else
    log_error "P99: ${ACTUAL_P99}ms > ${BASELINE_P99_MS}ms"
    VALIDATION_PASSED=false
fi

# Check throughput
echo | tee -a $RESULTS_DIR/validation.log
echo "🚀 Throughput Validation:" | tee -a $RESULTS_DIR/validation.log
if (( $(echo "$ACTUAL_RPS >= $BASELINE_RPS" | bc -l) )); then
    log_success "RPS: ${ACTUAL_RPS} ≥ ${BASELINE_RPS}"
else
    log_error "RPS: ${ACTUAL_RPS} < ${BASELINE_RPS}"
    VALIDATION_PASSED=false
fi

# Check error rate
echo | tee -a $RESULTS_DIR/validation.log
echo "❌ Error Rate Validation:" | tee -a $RESULTS_DIR/validation.log
if (( $(echo "$ACTUAL_ERROR_RATE <= $BASELINE_ERROR_RATE" | bc -l) )); then
    log_success "Error Rate: ${ACTUAL_ERROR_RATE}% ≤ ${BASELINE_ERROR_RATE}%"
else
    log_error "Error Rate: ${ACTUAL_ERROR_RATE}% > ${BASELINE_ERROR_RATE}%"
    VALIDATION_PASSED=false
fi

# Check resource usage
echo | tee -a $RESULTS_DIR/validation.log
echo "💾 Resource Usage Validation:" | tee -a $RESULTS_DIR/validation.log
if [ "$ACTUAL_CPU" -gt 0 ]; then
    CPU_PERCENT=$((ACTUAL_CPU / 10))  # Convert millicores to percentage
    if [ "$CPU_PERCENT" -le "$BASELINE_CPU_PERCENT" ]; then
        log_success "CPU: ${CPU_PERCENT}% ≤ ${BASELINE_CPU_PERCENT}%"
    else
        log_warning "CPU: ${CPU_PERCENT}% > ${BASELINE_CPU_PERCENT}%"
    fi
fi

if [ "$ACTUAL_MEMORY" -gt 0 ]; then
    if [ "$ACTUAL_MEMORY" -le "$BASELINE_MEMORY_MB" ]; then
        log_success "Memory: ${ACTUAL_MEMORY}MB ≤ ${BASELINE_MEMORY_MB}MB"
    else
        log_warning "Memory: ${ACTUAL_MEMORY}MB > ${BASELINE_MEMORY_MB}MB"
    fi
fi

# 8. Generate report
log_info "Generating performance report..."

cat > $RESULTS_DIR/performance-report.md <<EOF
# Performance Validation Report

**Date:** $(date)
**Test Duration:** ${TEST_DURATION} seconds
**Concurrent Users:** ${TEST_USERS}
**Target:** ${SERVICE_URL}

## Results Summary

### Latency Metrics
| Metric | Baseline | Actual | Status |
|--------|----------|--------|--------|
| P50 | ${BASELINE_P50_MS}ms | ${ACTUAL_P50}ms | $([ $(echo "$ACTUAL_P50 <= $BASELINE_P50_MS" | bc -l) -eq 1 ] && echo "✅ PASS" || echo "❌ FAIL") |
| P95 | ${BASELINE_P95_MS}ms | ${ACTUAL_P95}ms | $([ $(echo "$ACTUAL_P95 <= $BASELINE_P95_MS" | bc -l) -eq 1 ] && echo "✅ PASS" || echo "❌ FAIL") |
| P99 | ${BASELINE_P99_MS}ms | ${ACTUAL_P99}ms | $([ $(echo "$ACTUAL_P99 <= $BASELINE_P99_MS" | bc -l) -eq 1 ] && echo "✅ PASS" || echo "❌ FAIL") |

### Throughput
| Metric | Baseline | Actual | Status |
|--------|----------|--------|--------|
| RPS | ${BASELINE_RPS} | ${ACTUAL_RPS} | $([ $(echo "$ACTUAL_RPS >= $BASELINE_RPS" | bc -l) -eq 1 ] && echo "✅ PASS" || echo "❌ FAIL") |

### Error Rate
| Metric | Baseline | Actual | Status |
|--------|----------|--------|--------|
| Error Rate | ${BASELINE_ERROR_RATE}% | ${ACTUAL_ERROR_RATE}% | $([ $(echo "$ACTUAL_ERROR_RATE <= $BASELINE_ERROR_RATE" | bc -l) -eq 1 ] && echo "✅ PASS" || echo "❌ FAIL") |

### Resource Usage
| Metric | Baseline | Actual | Status |
|--------|----------|--------|--------|
| CPU | ${BASELINE_CPU_PERCENT}% | ${CPU_PERCENT:-N/A}% | $([ "${CPU_PERCENT:-0}" -le "$BASELINE_CPU_PERCENT" ] && echo "✅ PASS" || echo "⚠️ WARN") |
| Memory | ${BASELINE_MEMORY_MB}MB | ${ACTUAL_MEMORY:-N/A}MB | $([ "${ACTUAL_MEMORY:-0}" -le "$BASELINE_MEMORY_MB" ] && echo "✅ PASS" || echo "⚠️ WARN") |

## Recommendations

$(if [ "$VALIDATION_PASSED" = true ]; then
    echo "✅ **All performance baselines met.** The platform is ready for production deployment."
else
    echo "❌ **Some performance baselines not met.** Consider the following optimizations:"
    echo "- Review database query performance and add appropriate indexes"
    echo "- Optimize connection pooling settings"
    echo "- Consider implementing caching for frequently accessed data"
    echo "- Review and optimize critical code paths"
    echo "- Scale horizontally if throughput requirements not met"
fi)
EOF

log_success "Report generated: $RESULTS_DIR/performance-report.md"

# 9. Final summary
echo
echo "================================================================================" | tee -a $RESULTS_DIR/validation.log
echo "                           FINAL SUMMARY" | tee -a $RESULTS_DIR/validation.log
echo "================================================================================" | tee -a $RESULTS_DIR/validation.log
echo | tee -a $RESULTS_DIR/validation.log

if [ "$VALIDATION_PASSED" = true ]; then
    log_success "✅ Performance validation PASSED - All baselines met!"
    exit 0
else
    log_error "❌ Performance validation FAILED - Some baselines not met"
    log_info "Review the detailed report at: $RESULTS_DIR/performance-report.md"
    exit 1
fi