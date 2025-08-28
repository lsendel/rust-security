#!/bin/bash

# Test Runner Script
# Provides a unified interface to run different types of tests with proper configuration

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_DIR="$PROJECT_ROOT/config"

# Default values
ENVIRONMENT="development"
TEST_SUITE="smoke"
VERBOSE=false
REPORT_DIR="$PROJECT_ROOT/test-reports"
CONFIG_FILE="$CONFIG_DIR/test-environments.yaml"

# Usage function
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Test Runner for Rust Security Platform"
    echo ""
    echo "OPTIONS:"
    echo "  -e, --environment ENV    Test environment (development|staging|production)"
    echo "  -s, --suite SUITE        Test suite (smoke|security|ml_security|performance|integration)"
    echo "  -c, --config FILE        Configuration file path"
    echo "  -r, --report-dir DIR     Report output directory"
    echo "  -v, --verbose            Verbose output"
    echo "  -l, --list-environments  List available environments"
    echo "  -t, --list-suites        List available test suites"
    echo "  -V, --validate ENV       Validate environment connectivity"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 -e development -s smoke    # Run smoke tests in development"
    echo "  $0 -e staging -s security     # Run security tests in staging"  
    echo "  $0 -V production              # Validate production connectivity"
    echo ""
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_deps=()
    
    # Check Python
    if ! command -v python3 >/dev/null 2>&1; then
        missing_deps+=("python3")
    fi
    
    # Check required Python packages
    if ! python3 -c "import yaml, requests, dataclasses" >/dev/null 2>&1; then
        missing_deps+=("python3 packages: pyyaml, requests")
    fi
    
    # Check Docker (for integration tests)
    if [[ "$TEST_SUITE" == "integration" ]] && ! command -v docker >/dev/null 2>&1; then
        missing_deps+=("docker")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        echo "Install missing dependencies and try again."
        exit 1
    fi
    
    log_success "All dependencies available"
}

# Setup test environment
setup_environment() {
    log_info "Setting up test environment..."
    
    # Create report directory
    mkdir -p "$REPORT_DIR"
    
    # Check if configuration file exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Validate configuration
    if ! python3 "$CONFIG_DIR/test-config-manager.py" --list-environments >/dev/null 2>&1; then
        log_error "Invalid configuration file: $CONFIG_FILE"
        exit 1
    fi
    
    log_success "Test environment setup complete"
}

# List environments
list_environments() {
    log_info "Available environments:"
    python3 "$CONFIG_DIR/test-config-manager.py" --config "$CONFIG_FILE" --list-environments
}

# List test suites
list_suites() {
    log_info "Available test suites:"
    python3 "$CONFIG_DIR/test-config-manager.py" --config "$CONFIG_FILE" --list-suites
}

# Validate environment connectivity
validate_environment() {
    local env="$1"
    log_info "Validating connectivity to environment: $env"
    
    if python3 "$CONFIG_DIR/test-config-manager.py" --config "$CONFIG_FILE" --validate "$env"; then
        log_success "Environment '$env' is reachable"
        return 0
    else
        log_error "Environment '$env' is not reachable"
        return 1
    fi
}

# Run smoke tests
run_smoke_tests() {
    log_info "Running smoke tests..."
    
    cd "$PROJECT_ROOT"
    python3 enhanced-test-client.py \
        --environment "$ENVIRONMENT" \
        --config "$CONFIG_FILE" \
        --suite smoke \
        --output "$REPORT_DIR/smoke-test-report.json" \
        ${VERBOSE:+--verbose}
}

# Run security tests  
run_security_tests() {
    log_info "Running security tests..."
    
    cd "$PROJECT_ROOT"
    python3 enhanced-test-client.py \
        --environment "$ENVIRONMENT" \
        --config "$CONFIG_FILE" \
        --suite security \
        --output "$REPORT_DIR/security-test-report.json" \
        ${VERBOSE:+--verbose}
}

# Run ML security tests
run_ml_security_tests() {
    log_info "Running ML security tests..."
    
    cd "$PROJECT_ROOT"
    python3 scripts/testing/ml-security-tests.py \
        --config "$CONFIG_FILE" \
        --output "$REPORT_DIR/ml-security-test-report.json" \
        ${VERBOSE:+--verbose}
}

# Run performance tests
run_performance_tests() {
    log_info "Running performance tests..."
    
    cd "$PROJECT_ROOT"
    python3 enhanced-test-client.py \
        --environment "$ENVIRONMENT" \
        --config "$CONFIG_FILE" \
        --suite performance \
        --output "$REPORT_DIR/performance-test-report.json" \
        ${VERBOSE:+--verbose}
}

# Run integration tests
run_integration_tests() {
    log_info "Running integration tests..."
    
    # Use the automated integration test script
    "$SCRIPT_DIR/automated-integration-tests.sh" \
        --environment "$ENVIRONMENT" \
        --config "$CONFIG_FILE" \
        --report-dir "$REPORT_DIR" \
        ${VERBOSE:+--verbose}
}

# Run tests based on suite
run_tests() {
    local start_time=$(date +%s)
    
    log_info "Starting test suite: $TEST_SUITE"
    log_info "Environment: $ENVIRONMENT"
    log_info "Report directory: $REPORT_DIR"
    
    case "$TEST_SUITE" in
        smoke)
            run_smoke_tests
            ;;
        security)
            run_security_tests
            ;;
        ml_security)
            run_ml_security_tests
            ;;
        performance)
            run_performance_tests
            ;;
        integration)
            run_integration_tests
            ;;
        *)
            log_error "Unknown test suite: $TEST_SUITE"
            exit 1
            ;;
    esac
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_success "Test suite '$TEST_SUITE' completed in ${duration}s"
    log_info "Reports available in: $REPORT_DIR"
}

# Generate consolidated report
generate_report() {
    log_info "Generating consolidated test report..."
    
    local report_file="$REPORT_DIR/consolidated-report.json"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Generate environment status report
    python3 "$CONFIG_DIR/test-config-manager.py" \
        --config "$CONFIG_FILE" \
        --report > "$REPORT_DIR/environment-status.json"
    
    # Create consolidated report
    cat > "$report_file" <<EOF
{
    "test_run": {
        "timestamp": "$timestamp",
        "environment": "$ENVIRONMENT",
        "test_suite": "$TEST_SUITE",
        "report_directory": "$REPORT_DIR"
    },
    "reports_generated": [
EOF
    
    # List all generated reports
    local first=true
    for report in "$REPORT_DIR"/*.json; do
        if [[ -f "$report" && "$(basename "$report")" != "consolidated-report.json" ]]; then
            if [[ "$first" == true ]]; then
                first=false
            else
                echo "," >> "$report_file"
            fi
            echo "        \"$(basename "$report")\"" >> "$report_file"
        fi
    done
    
    cat >> "$report_file" <<EOF
    ]
}
EOF
    
    log_success "Consolidated report generated: $report_file"
}

# Main function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -s|--suite)
                TEST_SUITE="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -r|--report-dir)
                REPORT_DIR="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -l|--list-environments)
                list_environments
                exit 0
                ;;
            -t|--list-suites)
                list_suites
                exit 0
                ;;
            -V|--validate)
                validate_environment "$2"
                exit $?
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Setup and run tests
    check_dependencies
    setup_environment
    run_tests
    generate_report
    
    log_success "Test run completed successfully!"
}

# Run main function
main "$@"