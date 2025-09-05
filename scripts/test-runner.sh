#!/bin/bash
# Enhanced test runner script with categorization and parallel execution
# This script dramatically improves test performance by categorizing and running tests efficiently

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
RUST_TEST_THREADS=${RUST_TEST_THREADS:-4}
RUST_LOG=${RUST_LOG:-warn}
export RUST_TEST_THREADS RUST_LOG

echo -e "${BLUE}🚀 Enhanced Rust Security Platform Test Runner${NC}"
echo -e "${BLUE}================================================${NC}"

# Function to print section headers
print_section() {
    echo -e "\n${BLUE}📋 $1${NC}"
    echo "----------------------------------------"
}

# Function to run tests with timing
run_test_category() {
    local category="$1"
    local command="$2"
    local description="$3"
    
    echo -e "${YELLOW}⚡ Running $category tests: $description${NC}"
    local start_time=$(date +%s)
    
    if eval "$command"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo -e "${GREEN}✅ $category tests completed in ${duration}s${NC}"
        return 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo -e "${RED}❌ $category tests failed after ${duration}s${NC}"
        return 1
    fi
}

# Function to clean build artifacts
clean_build_artifacts() {
    print_section "Cleaning Build Artifacts"
    
    echo "Current target directory size:"
    if [ -d "target" ]; then
        du -sh target/ || echo "Could not measure target directory size"
        
        echo -e "${YELLOW}🧹 Cleaning build artifacts...${NC}"
        cargo clean
        echo -e "${GREEN}✅ Build artifacts cleaned${NC}"
    else
        echo "No target directory found - nothing to clean"
    fi
}

# Function to run unit tests (fast)
run_unit_tests() {
    run_test_category "Unit" \
        "cargo test --workspace --lib --bins -- --test-threads=$RUST_TEST_THREADS" \
        "Library and binary unit tests"
}

# Function to run integration tests with shared infrastructure
run_integration_tests() {
    run_test_category "Integration (Shared)" \
        "cargo test --workspace --test '*shared*' -- --test-threads=1" \
        "Integration tests using shared test infrastructure"
}

# Function to run individual integration tests (slower)
run_integration_tests_individual() {
    run_test_category "Integration (Individual)" \
        "cargo test --workspace --test comprehensive_integration_test -- --test-threads=1" \
        "Integration tests with individual app spawning"
}

# Function to run security tests
run_security_tests() {
    run_test_category "Security" \
        "cargo test --workspace security -- --test-threads=$RUST_TEST_THREADS" \
        "Security-focused tests"
}

# Function to run performance tests
run_performance_tests() {
    run_test_category "Performance" \
        "cargo test --workspace --test '*performance*' -- --test-threads=1" \
        "Performance benchmarks and load tests"
}

# Function to run property-based tests
run_property_tests() {
    run_test_category "Property" \
        "cargo test --workspace property -- --test-threads=$RUST_TEST_THREADS" \
        "Property-based testing with random inputs"
}

# Function to build without running (for compilation check)
check_compilation() {
    run_test_category "Compilation" \
        "cargo test --workspace --no-run --all-features" \
        "Test compilation without execution"
}

# Function to run clippy
run_clippy() {
    run_test_category "Clippy" \
        "cargo clippy --workspace --all-features -- -D warnings" \
        "Code quality and style checks"
}

# Main execution
main() {
    local start_total=$(date +%s)
    local failed_categories=()
    
    # Parse command line arguments
    local run_all=true
    local categories=()
    local clean_first=false
    local fast_mode=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --clean)
                clean_first=true
                shift
                ;;
            --fast)
                fast_mode=true
                shift
                ;;
            --unit)
                categories+=("unit")
                run_all=false
                shift
                ;;
            --integration)
                categories+=("integration")
                run_all=false
                shift
                ;;
            --security)
                categories+=("security")
                run_all=false
                shift
                ;;
            --performance)
                categories+=("performance")
                run_all=false
                shift
                ;;
            --clippy)
                categories+=("clippy")
                run_all=false
                shift
                ;;
            --compile-only)
                categories+=("compile")
                run_all=false
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --clean          Clean build artifacts before testing"
                echo "  --fast           Fast mode - skip slow tests"
                echo "  --unit           Run only unit tests"
                echo "  --integration    Run only integration tests"
                echo "  --security       Run only security tests"
                echo "  --performance    Run only performance tests"
                echo "  --clippy         Run only clippy checks"
                echo "  --compile-only   Check compilation only"
                echo "  --help, -h       Show this help message"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Clean build artifacts if requested
    if [ "$clean_first" = true ]; then
        clean_build_artifacts
    fi
    
    # Determine which tests to run
    if [ "$run_all" = true ]; then
        if [ "$fast_mode" = true ]; then
            categories=("compile" "clippy" "unit" "integration" "security")
        else
            categories=("compile" "clippy" "unit" "integration" "security" "performance" "property")
        fi
    fi
    
    # Run selected test categories
    for category in "${categories[@]}"; do
        case $category in
            unit)
                if ! run_unit_tests; then
                    failed_categories+=("unit")
                fi
                ;;
            integration)
                if ! run_integration_tests; then
                    failed_categories+=("integration-shared")
                fi
                # Only run individual integration tests in full mode
                if [ "$fast_mode" = false ] && ! run_integration_tests_individual; then
                    failed_categories+=("integration-individual")
                fi
                ;;
            security)
                if ! run_security_tests; then
                    failed_categories+=("security")
                fi
                ;;
            performance)
                if ! run_performance_tests; then
                    failed_categories+=("performance")
                fi
                ;;
            property)
                if ! run_property_tests; then
                    failed_categories+=("property")
                fi
                ;;
            clippy)
                if ! run_clippy; then
                    failed_categories+=("clippy")
                fi
                ;;
            compile)
                if ! check_compilation; then
                    failed_categories+=("compilation")
                fi
                ;;
        esac
    done
    
    # Summary
    local end_total=$(date +%s)
    local total_duration=$((end_total - start_total))
    
    print_section "Test Results Summary"
    
    if [ ${#failed_categories[@]} -eq 0 ]; then
        echo -e "${GREEN}🎉 All tests passed! Total time: ${total_duration}s${NC}"
        echo -e "${GREEN}✅ Test suite completed successfully${NC}"
        exit 0
    else
        echo -e "${RED}❌ Some test categories failed:${NC}"
        for category in "${failed_categories[@]}"; do
            echo -e "${RED}  - $category${NC}"
        done
        echo -e "${RED}Total time: ${total_duration}s${NC}"
        exit 1
    fi
}

# Performance tips
print_section "Performance Tips"
echo "• Use --fast mode for quick development testing"
echo "• Run --unit tests frequently during development"
echo "• Use --compile-only to check build issues quickly"
echo "• Clean build artifacts if experiencing issues (--clean)"
echo "• Integration tests use shared infrastructure for speed"

# Run main function with all arguments
main "$@"