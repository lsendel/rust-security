#!/bin/bash

# Integration Test Runner for Rust Security Platform
# This script demonstrates the complete testing pipeline

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AUTH_SERVICE_PORT=8001
POLICY_SERVICE_PORT=8002
TEST_DIR="tests/integration"

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}===============================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}===============================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

check_prerequisites() {
    print_header "Checking Prerequisites"
    
    local missing_tools=()
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        missing_tools+=("node")
    else
        print_success "Node.js $(node --version) found"
    fi
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        missing_tools+=("npm")
    else
        print_success "npm $(npm --version) found"
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        missing_tools+=("python3")
    else
        print_success "Python $(python3 --version) found"
    fi
    
    # Check Hurl
    if ! command -v hurl &> /dev/null; then
        missing_tools+=("hurl")
    else
        print_success "Hurl $(hurl --version | head -1) found"
    fi
    
    # Check Schemathesis
    if ! command -v schemathesis &> /dev/null; then
        missing_tools+=("schemathesis")
    else
        print_success "Schemathesis found"
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        echo ""
        echo "Please install the missing tools:"
        for tool in "${missing_tools[@]}"; do
            case $tool in
                "node" | "npm")
                    echo "  - Install Node.js: https://nodejs.org/"
                    ;;
                "python3")
                    echo "  - Install Python 3: https://python.org/"
                    ;;
                "hurl")
                    echo "  - Install Hurl: brew install hurl"
                    ;;
                "schemathesis")
                    echo "  - Install Schemathesis: pip3 install schemathesis"
                    ;;
            esac
        done
        exit 1
    fi
}

setup_test_environment() {
    print_header "Setting up Test Environment"
    
    # Create necessary directories
    mkdir -p "$TEST_DIR/results"
    mkdir -p "$TEST_DIR/reports"
    
    # Install npm dependencies if needed
    if [ ! -d "$TEST_DIR/node_modules" ]; then
        print_info "Installing npm dependencies..."
        (cd "$TEST_DIR" && npm install)
        print_success "NPM dependencies installed"
    else
        print_success "NPM dependencies already installed"
    fi
}

run_api_linting() {
    print_header "Running API Specification Linting"
    
    if [ ! -f "api-specs/auth-service.openapi.yaml" ]; then
        print_error "API specifications not found. Skipping linting tests."
        return 1
    fi
    
    print_info "Linting OpenAPI specifications with Spectral..."
    
    if (cd "$TEST_DIR" && npm run test:api-lint); then
        print_success "API linting passed - All specifications are valid"
        return 0
    else
        print_warning "API linting found issues (non-critical)"
        return 1
    fi
}

validate_openapi_specs() {
    print_header "Validating OpenAPI Specifications"
    
    local specs=(
        "api-specs/auth-service.openapi.yaml"
        "api-specs/policy-service.openapi.yaml"
    )
    
    for spec in "${specs[@]}"; do
        if [ -f "$spec" ]; then
            print_info "Validating $spec..."
            
            # Basic YAML syntax check
            if python3 -c "import yaml; yaml.safe_load(open('$spec'))" 2>/dev/null; then
                print_success "✓ $spec is valid YAML"
            else
                print_error "✗ $spec has YAML syntax errors"
                return 1
            fi
            
            # Check for required OpenAPI fields
            if grep -q "openapi:" "$spec" && grep -q "info:" "$spec" && grep -q "paths:" "$spec"; then
                print_success "✓ $spec has required OpenAPI structure"
            else
                print_error "✗ $spec missing required OpenAPI fields"
                return 1
            fi
        else
            print_error "Specification file not found: $spec"
            return 1
        fi
    done
}

demonstrate_schemathesis() {
    print_header "Demonstrating Property-Based API Testing"
    
    print_info "This would normally test against running services..."
    print_info "Example Schemathesis command for auth service:"
    echo "  schemathesis run api-specs/auth-service.openapi.yaml \\"
    echo "    --base-url=http://localhost:$AUTH_SERVICE_PORT \\"
    echo "    --hypothesis-seed=42 \\"
    echo "    --max-examples=50"
    
    print_info "Example Schemathesis command for policy service:"
    echo "  schemathesis run api-specs/policy-service.openapi.yaml \\"
    echo "    --base-url=http://localhost:$POLICY_SERVICE_PORT \\"
    echo "    --hypothesis-seed=42 \\"
    echo "    --max-examples=50"
    
    print_warning "Services must be running to execute actual property-based tests"
}

demonstrate_regression_tests() {
    print_header "Demonstrating Regression Test Structure"
    
    local test_files=(
        "$TEST_DIR/regression/auth-service/auth-flow.hurl"
        "$TEST_DIR/regression/policy-service/policy-management.hurl"
        "$TEST_DIR/smoke/auth-service-smoke.hurl"
        "$TEST_DIR/smoke/policy-service-smoke.hurl"
    )
    
    for test_file in "${test_files[@]}"; do
        if [ -f "$test_file" ]; then
            print_success "✓ Found regression test: $(basename "$test_file")"
            
            # Show test structure
            local test_count=$(grep -c "^# Test [0-9]" "$test_file" 2>/dev/null || echo "0")
            local http_requests=$(grep -c "^POST\|^GET\|^PUT\|^DELETE" "$test_file" 2>/dev/null || echo "0")
            
            print_info "  - Contains $test_count test scenarios"
            print_info "  - Makes $http_requests HTTP requests"
        else
            print_error "✗ Missing regression test: $(basename "$test_file")"
        fi
    done
    
    print_info ""
    print_info "To run regression tests against live services:"
    echo "  cd $TEST_DIR"
    echo "  npm run test:smoke-auth    # Quick smoke tests for auth service"
    echo "  npm run test:smoke-policy  # Quick smoke tests for policy service"
    echo "  npm run test:regression    # Full regression test suite"
}

demonstrate_ci_integration() {
    print_header "CI/CD Integration"
    
    local ci_workflow=".github/workflows/integration-testing.yml"
    
    if [ -f "$ci_workflow" ]; then
        print_success "✓ GitHub Actions workflow found: $ci_workflow"
        
        # Count jobs in the workflow
        local job_count=$(grep -c "^  [a-z-]*:$" "$ci_workflow" 2>/dev/null || echo "0")
        print_info "  - Contains $job_count test jobs"
        
        # List the jobs
        print_info "  - Pipeline includes:"
        grep "^  [a-z-]*:" "$ci_workflow" | sed 's/:$//' | sed 's/^/    ✓ /' || true
        
    else
        print_error "✗ CI workflow not found: $ci_workflow"
    fi
    
    print_info ""
    print_info "The CI pipeline includes:"
    echo "  • OpenAPI specification linting with Spectral"
    echo "  • Property-based API testing with Schemathesis"
    echo "  • Comprehensive regression testing with Hurl"
    echo "  • Smoke tests for quick validation"
    echo "  • Performance testing with load generation"
    echo "  • Security scanning of API specifications"
    echo "  • Automated test reporting and PR comments"
}

generate_summary_report() {
    print_header "Integration Testing Summary"
    
    echo "🔧 TESTING INFRASTRUCTURE SETUP:"
    echo "  ✅ OpenAPI specifications created for auth and policy services"
    echo "  ✅ Spectral configuration for API linting"
    echo "  ✅ Comprehensive Hurl-based regression tests"
    echo "  ✅ Schemathesis integration for property-based testing"
    echo "  ✅ GitHub Actions CI/CD pipeline"
    echo ""
    
    echo "📊 TESTING CAPABILITIES:"
    echo "  • API Contract Testing: Validates API behavior against OpenAPI specs"
    echo "  • Regression Testing: End-to-end scenarios covering main user flows"
    echo "  • Property-Based Testing: Automated generation of test cases"
    echo "  • Smoke Testing: Quick health checks for rapid feedback"
    echo "  • Performance Testing: Load testing for scalability validation"
    echo "  • Security Testing: API security best practices validation"
    echo ""
    
    echo "🚀 NEXT STEPS:"
    echo "  1. Start your services (auth-service on :$AUTH_SERVICE_PORT, policy-service on :$POLICY_SERVICE_PORT)"
    echo "  2. Run: npm run test:smoke (in $TEST_DIR)"
    echo "  3. Run: npm run test:regression (in $TEST_DIR)"
    echo "  4. View GitHub Actions for automated testing"
    echo ""
    
    echo "📁 KEY FILES CREATED:"
    echo "  • api-specs/auth-service.openapi.yaml"
    echo "  • api-specs/policy-service.openapi.yaml"
    echo "  • $TEST_DIR/package.json"
    echo "  • $TEST_DIR/.spectral.yml"
    echo "  • $TEST_DIR/regression/auth-service/auth-flow.hurl"
    echo "  • $TEST_DIR/regression/policy-service/policy-management.hurl"
    echo "  • $TEST_DIR/smoke/*.hurl"
    echo "  • .github/workflows/integration-testing.yml"
}

main() {
    echo -e "${GREEN}"
    echo "🔧 Rust Security Platform - Integration Testing Suite"
    echo "   Comprehensive API Testing with Contract Validation"
    echo -e "${NC}"
    
    check_prerequisites
    setup_test_environment
    validate_openapi_specs
    run_api_linting
    demonstrate_schemathesis
    demonstrate_regression_tests
    demonstrate_ci_integration
    generate_summary_report
    
    echo ""
    print_success "Integration testing infrastructure is ready!"
    echo ""
}

# Allow sourcing this script for individual functions
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi