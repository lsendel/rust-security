#!/bin/bash

# Comprehensive test runner for Rust authentication service
# This script runs all types of tests: unit, integration, security, performance, property-based

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_TARGET_DIR="${PROJECT_ROOT}/target"
TEST_RESULTS_DIR="${PROJECT_ROOT}/test-results"
COVERAGE_DIR="${PROJECT_ROOT}/coverage"

# Test configuration
RUN_UNIT_TESTS="${RUN_UNIT_TESTS:-true}"
RUN_INTEGRATION_TESTS="${RUN_INTEGRATION_TESTS:-true}"
RUN_SECURITY_TESTS="${RUN_SECURITY_TESTS:-true}"
RUN_PERFORMANCE_TESTS="${RUN_PERFORMANCE_TESTS:-true}"
RUN_PROPERTY_TESTS="${RUN_PROPERTY_TESTS:-true}"
RUN_COVERAGE="${RUN_COVERAGE:-true}"
RUN_BENCHMARKS="${RUN_BENCHMARKS:-false}"
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"

# Test timeouts (in seconds)
UNIT_TEST_TIMEOUT=300
INTEGRATION_TEST_TIMEOUT=600
SECURITY_TEST_TIMEOUT=900
PERFORMANCE_TEST_TIMEOUT=1800

echo -e "${BLUE}🧪 Starting Comprehensive Test Suite for Rust Auth Service${NC}"
echo "Project Root: $PROJECT_ROOT"
echo "Target Dir: $CARGO_TARGET_DIR"
echo "Results Dir: $TEST_RESULTS_DIR"

# Create directories
mkdir -p "$TEST_RESULTS_DIR"
mkdir -p "$COVERAGE_DIR"

# Change to project directory
cd "$PROJECT_ROOT"

# Function to print test section headers
print_section() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Function to run tests with timeout and error handling
run_test_suite() {
    local test_name="$1"
    local test_command="$2"
    local timeout_seconds="$3"
    local output_file="$TEST_RESULTS_DIR/${test_name}.log"
    
    echo -e "${YELLOW}Running $test_name tests...${NC}"
    echo "Command: $test_command"
    echo "Timeout: ${timeout_seconds}s"
    echo "Output: $output_file"
    
    # Set test environment variables
    export TEST_MODE=1
    export RUST_BACKTRACE=1
    export RUST_LOG=debug
    export REQUEST_SIGNING_SECRET=test_secret_for_comprehensive_testing
    export DISABLE_RATE_LIMIT=1
    
    # Run the test with timeout
    if timeout "${timeout_seconds}s" bash -c "$test_command" > "$output_file" 2>&1; then
        echo -e "${GREEN}✅ $test_name tests passed${NC}"
        echo "Results saved to: $output_file"
        return 0
    else
        local exit_code=$?
        echo -e "${RED}❌ $test_name tests failed (exit code: $exit_code)${NC}"
        echo "Error output:"
        tail -20 "$output_file"
        return $exit_code
    fi
}

# Function to check prerequisites
check_prerequisites() {
    print_section "Checking Prerequisites"
    
    # Check Rust toolchain
    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}❌ Cargo not found. Please install Rust toolchain.${NC}"
        exit 1
    fi
    
    # Check required tools
    local tools=("timeout" "tail" "head")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}❌ Required tool '$tool' not found${NC}"
            exit 1
        fi
    done
    
    echo -e "${GREEN}✅ All prerequisites satisfied${NC}"
    
    # Print Rust version info
    echo "Rust version information:"
    rustc --version
    cargo --version
}

# Function to build the project
build_project() {
    print_section "Building Project"
    
    echo -e "${YELLOW}Building auth-service...${NC}"
    
    if cargo build --release --all-features; then
        echo -e "${GREEN}✅ Build successful${NC}"
    else
        echo -e "${RED}❌ Build failed${NC}"
        exit 1
    fi
    
    # Build test binaries
    echo -e "${YELLOW}Building test binaries...${NC}"
    if cargo test --no-run --all-features; then
        echo -e "${GREEN}✅ Test build successful${NC}"
    else
        echo -e "${RED}❌ Test build failed${NC}"
        exit 1
    fi
}

# Function to run unit tests
run_unit_tests() {
    print_section "Unit Tests"
    
    if [[ "$RUN_UNIT_TESTS" != "true" ]]; then
        echo -e "${YELLOW}⏭️  Unit tests skipped${NC}"
        return 0
    fi
    
    local test_command="cargo test --lib --bins unit --all-features -- --test-threads=$PARALLEL_JOBS --nocapture"
    run_test_suite "unit" "$test_command" "$UNIT_TEST_TIMEOUT"
}

# Function to run integration tests
run_integration_tests() {
    print_section "Integration Tests"
    
    if [[ "$RUN_INTEGRATION_TESTS" != "true" ]]; then
        echo -e "${YELLOW}⏭️  Integration tests skipped${NC}"
        return 0
    fi
    
    local test_command="cargo test --test '*' integration --all-features -- --test-threads=$PARALLEL_JOBS --nocapture"
    run_test_suite "integration" "$test_command" "$INTEGRATION_TEST_TIMEOUT"
}

# Function to run security tests
run_security_tests() {
    print_section "Security Tests"
    
    if [[ "$RUN_SECURITY_TESTS" != "true" ]]; then
        echo -e "${YELLOW}⏭️  Security tests skipped${NC}"
        return 0
    fi
    
    # Run attack simulation tests
    local test_command="cargo test --test '*' security --all-features -- --test-threads=1 --nocapture"
    run_test_suite "security" "$test_command" "$SECURITY_TEST_TIMEOUT"
}

# Function to run performance tests
run_performance_tests() {
    print_section "Performance Tests"
    
    if [[ "$RUN_PERFORMANCE_TESTS" != "true" ]]; then
        echo -e "${YELLOW}⏭️  Performance tests skipped${NC}"
        return 0
    fi
    
    # Run load tests
    local test_command="cargo test --test '*' performance --all-features --release -- --test-threads=1 --nocapture"
    run_test_suite "performance" "$test_command" "$PERFORMANCE_TEST_TIMEOUT"
}

# Function to run property-based tests
run_property_tests() {
    print_section "Property-Based Tests"
    
    if [[ "$RUN_PROPERTY_TESTS" != "true" ]]; then
        echo -e "${YELLOW}⏭️  Property-based tests skipped${NC}"
        return 0
    fi
    
    # Set property test environment
    export PROPTEST_CASES=1000
    export QUICKCHECK_TESTS=1000
    
    local test_command="cargo test --test '*' property --all-features -- --test-threads=$PARALLEL_JOBS --nocapture"
    run_test_suite "property" "$test_command" "$PERFORMANCE_TEST_TIMEOUT"
}

# Function to run MFA tests
run_mfa_tests() {
    print_section "MFA Tests"
    
    local test_command="cargo test --test '*' mfa --all-features -- --test-threads=2 --nocapture"
    run_test_suite "mfa" "$test_command" "$INTEGRATION_TEST_TIMEOUT"
}

# Function to run coverage analysis
run_coverage() {
    print_section "Code Coverage Analysis"
    
    if [[ "$RUN_COVERAGE" != "true" ]]; then
        echo -e "${YELLOW}⏭️  Coverage analysis skipped${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}Installing/updating tarpaulin...${NC}"
    cargo install cargo-tarpaulin --force || {
        echo -e "${YELLOW}⚠️  Failed to install tarpaulin, trying alternative method${NC}"
        
        # Alternative: use cargo-llvm-cov
        if command -v cargo-llvm-cov &> /dev/null; then
            echo -e "${YELLOW}Using cargo-llvm-cov for coverage...${NC}"
            cargo llvm-cov --all-features --html --output-dir "$COVERAGE_DIR" \
                --ignore-filename-regex "tests/.*" 2>&1 | tee "$TEST_RESULTS_DIR/coverage.log"
        else
            echo -e "${YELLOW}⚠️  No coverage tool available, skipping coverage analysis${NC}"
            return 0
        fi
        return 0
    }
    
    echo -e "${YELLOW}Running coverage analysis...${NC}"
    
    # Run tarpaulin with comprehensive options
    cargo tarpaulin \
        --all-features \
        --out Html \
        --output-dir "$COVERAGE_DIR" \
        --exclude-files "tests/*" \
        --exclude-files "benches/*" \
        --exclude-files "examples/*" \
        --timeout 1800 \
        --run-types Tests \
        --verbose 2>&1 | tee "$TEST_RESULTS_DIR/coverage.log"
    
    # Check if coverage report was generated
    if [[ -f "$COVERAGE_DIR/tarpaulin-report.html" ]]; then
        echo -e "${GREEN}✅ Coverage report generated: $COVERAGE_DIR/tarpaulin-report.html${NC}"
    else
        echo -e "${YELLOW}⚠️  Coverage report not found, check logs${NC}"
    fi
}

# Function to run benchmarks
run_benchmarks() {
    print_section "Benchmarks"
    
    if [[ "$RUN_BENCHMARKS" != "true" ]]; then
        echo -e "${YELLOW}⏭️  Benchmarks skipped${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}Running benchmarks...${NC}"
    
    # Run criterion benchmarks
    local bench_command="cargo bench --features benchmarks -- --output-format html"
    run_test_suite "benchmarks" "$bench_command" "$PERFORMANCE_TEST_TIMEOUT"
    
    # Check if benchmark report was generated
    if [[ -d "$CARGO_TARGET_DIR/criterion" ]]; then
        echo -e "${GREEN}✅ Benchmark reports generated in: $CARGO_TARGET_DIR/criterion${NC}"
    fi
}

# Function to generate test summary
generate_summary() {
    print_section "Test Summary"
    
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    echo -e "${BLUE}Test Results Summary:${NC}"
    echo "====================="
    
    for result_file in "$TEST_RESULTS_DIR"/*.log; do
        if [[ -f "$result_file" ]]; then
            local test_name=$(basename "$result_file" .log)
            total_tests=$((total_tests + 1))
            
            # Check if test passed (very basic check)
            if grep -q "test result: ok" "$result_file" || \
               grep -q "✅" "$result_file" || \
               grep -q "All tests passed" "$result_file"; then
                echo -e "${GREEN}✅ $test_name${NC}"
                passed_tests=$((passed_tests + 1))
            else
                echo -e "${RED}❌ $test_name${NC}"
                failed_tests=$((failed_tests + 1))
            fi
        fi
    done
    
    echo "====================="
    echo "Total test suites: $total_tests"
    echo "Passed: $passed_tests"
    echo "Failed: $failed_tests"
    
    if [[ $failed_tests -eq 0 ]]; then
        echo -e "${GREEN}🎉 All test suites passed!${NC}"
        return 0
    else
        echo -e "${RED}💥 $failed_tests test suite(s) failed${NC}"
        return 1
    fi
}

# Function to cleanup
cleanup() {
    print_section "Cleanup"
    
    echo -e "${YELLOW}Cleaning up temporary files...${NC}"
    
    # Kill any background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Clean up test artifacts if requested
    if [[ "${CLEAN_ARTIFACTS:-false}" == "true" ]]; then
        echo -e "${YELLOW}Removing test artifacts...${NC}"
        cargo clean
    fi
    
    echo -e "${GREEN}✅ Cleanup completed${NC}"
}

# Function to handle interrupts
handle_interrupt() {
    echo -e "\n${YELLOW}⚠️  Test run interrupted by user${NC}"
    cleanup
    exit 130
}

# Set up signal handlers
trap handle_interrupt SIGINT SIGTERM

# Main execution flow
main() {
    local start_time=$(date +%s)
    local exit_code=0
    
    echo -e "${BLUE}🚀 Starting comprehensive test execution at $(date)${NC}"
    
    # Execute test phases
    check_prerequisites || exit 1
    build_project || exit 1
    
    # Run different test suites
    run_unit_tests || exit_code=1
    run_integration_tests || exit_code=1
    run_security_tests || exit_code=1
    run_performance_tests || exit_code=1
    run_property_tests || exit_code=1
    run_mfa_tests || exit_code=1
    
    # Additional analysis
    run_coverage || true  # Don't fail on coverage errors
    run_benchmarks || true  # Don't fail on benchmark errors
    
    # Generate summary
    generate_summary || exit_code=1
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo -e "\n${BLUE}📊 Test Execution Summary:${NC}"
    echo "Start time: $(date -d @$start_time)"
    echo "End time: $(date -d @$end_time)"
    echo "Duration: ${duration}s ($(($duration / 60))m $(($duration % 60))s)"
    echo "Results directory: $TEST_RESULTS_DIR"
    echo "Coverage directory: $COVERAGE_DIR"
    
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}🎉 All tests completed successfully!${NC}"
    else
        echo -e "${RED}💥 Some tests failed. Check logs for details.${NC}"
    fi
    
    cleanup
    exit $exit_code
}

# Show help
show_help() {
    cat << EOF
Comprehensive Test Runner for Rust Auth Service

Usage: $0 [OPTIONS]

Environment Variables:
  RUN_UNIT_TESTS=true|false        Run unit tests (default: true)
  RUN_INTEGRATION_TESTS=true|false Run integration tests (default: true)  
  RUN_SECURITY_TESTS=true|false    Run security tests (default: true)
  RUN_PERFORMANCE_TESTS=true|false Run performance tests (default: true)
  RUN_PROPERTY_TESTS=true|false    Run property-based tests (default: true)
  RUN_COVERAGE=true|false          Run coverage analysis (default: true)
  RUN_BENCHMARKS=true|false        Run benchmarks (default: false)
  PARALLEL_JOBS=N                  Number of parallel test jobs (default: 4)
  CLEAN_ARTIFACTS=true|false       Clean artifacts after run (default: false)

Examples:
  # Run all tests
  $0

  # Run only security tests
  RUN_UNIT_TESTS=false RUN_INTEGRATION_TESTS=false RUN_PERFORMANCE_TESTS=false RUN_PROPERTY_TESTS=false $0

  # Run with coverage and benchmarks
  RUN_COVERAGE=true RUN_BENCHMARKS=true $0

  # Quick run (no performance tests)
  RUN_PERFORMANCE_TESTS=false RUN_BENCHMARKS=false $0
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Execute main function
main "$@"