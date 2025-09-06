#!/bin/bash
# Enhanced Regression Test Orchestrator
# Provides parallel execution, smart scheduling, and comprehensive reporting

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BASELINE_DIR="$PROJECT_ROOT/tests/baseline"
REPORT_DIR="$PROJECT_ROOT/regression_reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
MAX_PARALLEL_JOBS=${MAX_PARALLEL_JOBS:-4}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test suites configuration
declare -A TEST_SUITES=(
    ["auth"]="cargo test --workspace --test auth_regression --release"
    ["security"]="cargo test --workspace --test security_regression --release"
    ["performance"]="cargo test --workspace --test performance_regression --release"
    ["database"]="cargo test --workspace --test database_regression --release"
    ["api"]="cargo test --workspace --test api_regression --release"
)

declare -A TEST_PRIORITIES=(
    ["security"]=1
    ["auth"]=2
    ["performance"]=3
    ["database"]=4
    ["api"]=5
)

# Initialize directories
mkdir -p "$REPORT_DIR" "$BASELINE_DIR"

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Smart test scheduling based on historical data
schedule_tests() {
    local mode="$1"
    local scheduled_tests=()
    
    case "$mode" in
        "quick")
            scheduled_tests=("security" "auth")
            ;;
        "full")
            # Sort by priority
            for test in $(printf '%s\n' "${!TEST_PRIORITIES[@]}" | sort -n -k2 -t' '); do
                scheduled_tests+=("$test")
            done
            ;;
        "performance")
            scheduled_tests=("performance" "database")
            ;;
        "security")
            scheduled_tests=("security" "auth")
            ;;
        *)
            scheduled_tests=("${!TEST_SUITES[@]}")
            ;;
    esac
    
    printf '%s\n' "${scheduled_tests[@]}"
}

# Execute test with timeout and resource monitoring
execute_test() {
    local test_name="$1"
    local test_command="$2"
    local timeout_duration="300" # 5 minutes default
    local log_file="$REPORT_DIR/${test_name}_${TIMESTAMP}.log"
    local metrics_file="$REPORT_DIR/${test_name}_metrics_${TIMESTAMP}.json"
    
    log "🚀 Starting $test_name regression test"
    
    # Start resource monitoring
    local monitor_pid
    {
        while true; do
            {
                echo "{"
                echo "  \"timestamp\": \"$(date -Iseconds)\","
                echo "  \"memory_mb\": $(ps -o rss= -p $$ | awk '{print $1/1024}')"
                echo "  \"cpu_percent\": $(ps -o %cpu= -p $$)"
                echo "},"
            } >> "$metrics_file"
            sleep 1
        done
    } &
    monitor_pid=$!
    
    # Execute test with timeout
    local start_time=$(date +%s)
    local exit_code=0
    
    if timeout "$timeout_duration" bash -c "$test_command" > "$log_file" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        success "✅ $test_name completed in ${duration}s"
        
        # Generate test result
        cat > "$REPORT_DIR/${test_name}_result_${TIMESTAMP}.json" << EOF
{
  "test_name": "$test_name",
  "status": "passed",
  "duration_seconds": $duration,
  "timestamp": "$(date -Iseconds)",
  "log_file": "$log_file",
  "metrics_file": "$metrics_file"
}
EOF
    else
        exit_code=$?
        error "❌ $test_name failed (exit code: $exit_code)"
        
        cat > "$REPORT_DIR/${test_name}_result_${TIMESTAMP}.json" << EOF
{
  "test_name": "$test_name",
  "status": "failed",
  "exit_code": $exit_code,
  "timestamp": "$(date -Iseconds)",
  "log_file": "$log_file",
  "metrics_file": "$metrics_file"
}
EOF
    fi
    
    # Stop monitoring
    kill $monitor_pid 2>/dev/null || true
    
    return $exit_code
}

# Parallel test execution with job control
run_parallel_tests() {
    local tests=("$@")
    local pids=()
    local results=()
    local active_jobs=0
    
    log "🔄 Running ${#tests[@]} tests with max $MAX_PARALLEL_JOBS parallel jobs"
    
    for test in "${tests[@]}"; do
        # Wait if we've reached max parallel jobs
        while [ $active_jobs -ge $MAX_PARALLEL_JOBS ]; do
            wait -n # Wait for any job to complete
            active_jobs=$((active_jobs - 1))
        done
        
        # Start test in background
        {
            execute_test "$test" "${TEST_SUITES[$test]}"
            echo "$test:$?" > "$REPORT_DIR/job_${test}_${TIMESTAMP}.result"
        } &
        
        pids+=($!)
        active_jobs=$((active_jobs + 1))
        
        log "📋 Started $test (PID: ${pids[-1]})"
    done
    
    # Wait for all jobs to complete
    log "⏳ Waiting for all tests to complete..."
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    # Collect results
    local passed=0
    local failed=0
    
    for test in "${tests[@]}"; do
        if [ -f "$REPORT_DIR/job_${test}_${TIMESTAMP}.result" ]; then
            local result=$(cat "$REPORT_DIR/job_${test}_${TIMESTAMP}.result")
            local exit_code="${result#*:}"
            
            if [ "$exit_code" -eq 0 ]; then
                passed=$((passed + 1))
            else
                failed=$((failed + 1))
            fi
        fi
    done
    
    log "📊 Test Results: $passed passed, $failed failed"
    return $failed
}

# Generate comprehensive report
generate_report() {
    local report_file="$REPORT_DIR/regression_summary_${TIMESTAMP}.json"
    
    log "📋 Generating comprehensive regression report"
    
    # Use Python analyzer if available
    if command -v python3 >/dev/null && [ -f "$SCRIPT_DIR/regression_analyzer.py" ]; then
        python3 "$SCRIPT_DIR/regression_analyzer.py" report "$report_file"
    else
        # Fallback to basic report
        cat > "$report_file" << EOF
{
  "timestamp": "$(date -Iseconds)",
  "session_id": "$TIMESTAMP",
  "test_results": [],
  "summary": {
    "total_tests": 0,
    "passed": 0,
    "failed": 0,
    "success_rate": 0.0
  }
}
EOF
    fi
    
    success "📊 Report generated: $report_file"
}

# Main execution
main() {
    local mode="${1:-full}"
    local tests_to_run
    
    log "🔄 Starting Enhanced Regression Test Suite - Mode: $mode"
    
    # Pre-flight checks
    if ! command -v cargo >/dev/null; then
        error "Cargo not found. Please install Rust."
        exit 1
    fi
    
    # Schedule tests
    readarray -t tests_to_run < <(schedule_tests "$mode")
    
    if [ ${#tests_to_run[@]} -eq 0 ]; then
        warning "No tests scheduled for mode: $mode"
        exit 0
    fi
    
    log "📋 Scheduled tests: ${tests_to_run[*]}"
    
    # Run tests
    if run_parallel_tests "${tests_to_run[@]}"; then
        success "🎉 All regression tests passed!"
        generate_report
        exit 0
    else
        error "❌ Some regression tests failed"
        generate_report
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    "quick"|"full"|"performance"|"security")
        main "$1"
        ;;
    "help"|"--help"|"-h")
        echo "Usage: $0 [quick|full|performance|security]"
        echo ""
        echo "Modes:"
        echo "  quick       - Run essential tests (security, auth)"
        echo "  full        - Run all regression tests"
        echo "  performance - Run performance-focused tests"
        echo "  security    - Run security-focused tests"
        exit 0
        ;;
    *)
        main "full"
        ;;
esac
