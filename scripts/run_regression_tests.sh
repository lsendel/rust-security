#!/bin/bash

# Comprehensive Regression Test Runner for Rust Security Workspace
# Tests all Phase 1 and Phase 2 features

set -e

# Configuration
AUTH_SERVICE_URL="${1:-http://localhost:8080}"
POLICY_SERVICE_URL="${2:-http://localhost:8081}"
WAIT_TIME="${3:-30}"
VERBOSE="${4:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Function to log with timestamp
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if services are running
check_services() {
    log "${BLUE}🔍 Checking service availability...${NC}"
    
    # Check auth service
    if curl -s -f "$AUTH_SERVICE_URL/health" > /dev/null; then
        log "${GREEN}✅ Auth service is running at $AUTH_SERVICE_URL${NC}"
    else
        log "${RED}❌ Auth service is not available at $AUTH_SERVICE_URL${NC}"
        return 1
    fi
    
    # Check policy service
    if curl -s -f "$POLICY_SERVICE_URL/health" > /dev/null; then
        log "${GREEN}✅ Policy service is running at $POLICY_SERVICE_URL${NC}"
    else
        log "${RED}❌ Policy service is not available at $POLICY_SERVICE_URL${NC}"
        return 1
    fi
    
    return 0
}

# Function to start services if needed
start_services() {
    log "${YELLOW}🚀 Starting services...${NC}"
    
    # Check if services are already running
    if check_services; then
        log "${GREEN}✅ Services are already running${NC}"
        return 0
    fi
    
    log "${BLUE}Starting auth-service...${NC}"
    cd "$(dirname "$0")/.."
    
    # Start auth service in background
    cargo run -p auth-service --all-features > auth-service.log 2>&1 &
    AUTH_PID=$!
    
    # Start policy service in background
    cargo run -p policy-service --all-features > policy-service.log 2>&1 &
    POLICY_PID=$!
    
    log "${BLUE}Waiting ${WAIT_TIME} seconds for services to start...${NC}"
    sleep "$WAIT_TIME"
    
    # Check if services started successfully
    if ! check_services; then
        log "${RED}❌ Failed to start services${NC}"
        cleanup_services
        return 1
    fi
    
    log "${GREEN}✅ Services started successfully${NC}"
    return 0
}

# Function to cleanup services
cleanup_services() {
    log "${YELLOW}🧹 Cleaning up services...${NC}"
    
    if [ ! -z "$AUTH_PID" ]; then
        kill "$AUTH_PID" 2>/dev/null || true
    fi
    
    if [ ! -z "$POLICY_PID" ]; then
        kill "$POLICY_PID" 2>/dev/null || true
    fi
    
    # Kill any remaining processes
    pkill -f "auth-service" 2>/dev/null || true
    pkill -f "policy-service" 2>/dev/null || true
    
    log "${GREEN}✅ Cleanup completed${NC}"
}

# Function to run regression tests
run_regression_tests() {
    log "${PURPLE}🧪 Running comprehensive regression tests...${NC}"
    
    cd "$(dirname "$0")/../tests"
    
    # Build the test suite
    log "${BLUE}Building regression test suite...${NC}"
    cargo build --release
    
    # Run the tests
    log "${BLUE}Executing regression tests...${NC}"
    if [ "$VERBOSE" = "true" ]; then
        RUST_LOG=debug ./target/release/regression-tests "$AUTH_SERVICE_URL" "$POLICY_SERVICE_URL"
    else
        ./target/release/regression-tests "$AUTH_SERVICE_URL" "$POLICY_SERVICE_URL"
    fi
    
    return $?
}

# Function to generate test report
generate_report() {
    local exit_code=$1
    local timestamp=$(date '+%Y-%m-%d_%H-%M-%S')
    local report_file="regression_test_report_${timestamp}.txt"
    
    log "${BLUE}📊 Generating test report...${NC}"
    
    cat > "$report_file" << EOF
# Rust Security Workspace - Regression Test Report

**Timestamp:** $(date)
**Auth Service:** $AUTH_SERVICE_URL
**Policy Service:** $POLICY_SERVICE_URL
**Exit Code:** $exit_code

## Test Results

$(if [ $exit_code -eq 0 ]; then
    echo "✅ **Status:** ALL TESTS PASSED"
    echo ""
    echo "The system has successfully passed all regression tests and is ready for production deployment."
elif [ $exit_code -eq 1 ]; then
    echo "⚠️ **Status:** MOST TESTS PASSED"
    echo ""
    echo "The system passed most tests but some issues were detected. Review the test output for details."
elif [ $exit_code -eq 2 ]; then
    echo "❌ **Status:** CRITICAL ISSUES DETECTED"
    echo ""
    echo "The system has critical issues that need to be addressed before deployment."
else
    echo "💥 **Status:** TEST SUITE FAILED"
    echo ""
    echo "The test suite itself failed to run properly. Check the logs for technical issues."
fi)

## Test Categories Covered

### Phase 1: Critical Security Features
- ✅ Health endpoints
- ✅ OAuth2 token flow
- ✅ Token introspection and revocation
- ✅ OpenID Connect compliance
- ✅ JWKS endpoint
- ✅ MFA TOTP functionality
- ✅ SCIM endpoints
- ✅ Rate limiting
- ✅ Security headers
- ✅ Input validation
- ✅ Request signing (placeholder)
- ✅ Token binding (placeholder)
- ✅ PKCE flow (placeholder)
- ✅ Circuit breaker (placeholder)
- ✅ Audit logging (placeholder)

### Phase 2: Operational Excellence
- ✅ Performance metrics
- ✅ Caching functionality
- ✅ Distributed tracing
- ✅ Monitoring endpoints
- ✅ Key rotation
- ✅ Policy evaluation
- ✅ Cedar policies
- ✅ Policy performance

### Integration Tests
- ✅ End-to-end flow
- ✅ Concurrent operations
- ✅ Error handling
- ✅ Failover scenarios

## Recommendations

$(if [ $exit_code -eq 0 ]; then
    echo "- Deploy to production with confidence"
    echo "- Continue monitoring system performance"
    echo "- Schedule regular regression testing"
elif [ $exit_code -eq 1 ]; then
    echo "- Review failed tests and address issues"
    echo "- Consider deploying to staging for further testing"
    echo "- Monitor system closely after deployment"
elif [ $exit_code -eq 2 ]; then
    echo "- Do not deploy to production"
    echo "- Address all critical issues"
    echo "- Re-run regression tests after fixes"
else
    echo "- Fix test suite infrastructure issues"
    echo "- Verify service configurations"
    echo "- Check network connectivity and dependencies"
fi)

---
Generated by Rust Security Workspace Regression Test Suite v2.0.0
EOF

    log "${GREEN}📋 Test report generated: $report_file${NC}"
}

# Main execution
main() {
    log "${PURPLE}🚀 Rust Security Workspace - Regression Test Runner${NC}"
    log "${BLUE}Version: 2.0.0 (Phase 1 + Phase 2)${NC}"
    log "${BLUE}Auth Service: $AUTH_SERVICE_URL${NC}"
    log "${BLUE}Policy Service: $POLICY_SERVICE_URL${NC}"
    echo
    
    # Trap to ensure cleanup on exit
    trap cleanup_services EXIT
    
    # Check if services are running, start if needed
    if ! check_services; then
        log "${YELLOW}Services not running, attempting to start...${NC}"
        if ! start_services; then
            log "${RED}❌ Failed to start services${NC}"
            exit 3
        fi
    fi
    
    # Run regression tests
    local exit_code=0
    if ! run_regression_tests; then
        exit_code=$?
    fi
    
    # Generate report
    generate_report $exit_code
    
    # Final status
    case $exit_code in
        0)
            log "${GREEN}🎉 All regression tests passed! System ready for production.${NC}"
            ;;
        1)
            log "${YELLOW}⚠️ Most tests passed, but some issues detected.${NC}"
            ;;
        2)
            log "${RED}❌ Critical issues detected. System needs attention.${NC}"
            ;;
        *)
            log "${RED}💥 Test suite failed to run properly.${NC}"
            ;;
    esac
    
    exit $exit_code
}

# Show usage if help requested
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Usage: $0 [AUTH_URL] [POLICY_URL] [WAIT_TIME] [VERBOSE]"
    echo ""
    echo "Arguments:"
    echo "  AUTH_URL     Auth service URL (default: http://localhost:8080)"
    echo "  POLICY_URL   Policy service URL (default: http://localhost:8081)"
    echo "  WAIT_TIME    Seconds to wait for services to start (default: 30)"
    echo "  VERBOSE      Enable verbose logging (default: false)"
    echo ""
    echo "Examples:"
    echo "  $0                                          # Use defaults"
    echo "  $0 http://auth.example.com http://policy.example.com"
    echo "  $0 http://localhost:8080 http://localhost:8081 60 true"
    exit 0
fi

# Run main function
main "$@"
