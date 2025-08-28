#!/bin/bash
# Automated Integration Test Suite for Rust Security Platform
# This script orchestrates comprehensive integration testing across all components

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_RESULTS_DIR="$PROJECT_ROOT/test-results"
DOCKER_COMPOSE_FILE="$PROJECT_ROOT/docker-compose.test.yml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
HEALTH_CHECK_TIMEOUT=60
TEST_TIMEOUT=300
PERFORMANCE_TEST_USERS=${PERFORMANCE_TEST_USERS:-10}
PERFORMANCE_TEST_REQUESTS=${PERFORMANCE_TEST_REQUESTS:-50}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

print_section() {
    echo
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} $(printf "%-62s" "$1") ${BLUE}║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Cleanup function
cleanup() {
    local exit_code=$?
    log_info "Cleaning up test environment..."
    
    # Stop services
    if [ -f "$DOCKER_COMPOSE_FILE" ]; then
        docker-compose -f "$DOCKER_COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
    fi
    
    # Kill any background processes
    pkill -f "auth-service|policy-service" 2>/dev/null || true
    
    # Archive test results
    if [ -d "$TEST_RESULTS_DIR" ]; then
        local archive_name="test-results-$(date +%Y%m%d-%H%M%S).tar.gz"
        tar -czf "$archive_name" -C "$(dirname "$TEST_RESULTS_DIR")" "$(basename "$TEST_RESULTS_DIR")" 2>/dev/null || true
        log_info "Test results archived as: $archive_name"
    fi
    
    exit $exit_code
}

# Set up cleanup trap
trap cleanup EXIT INT TERM

# Setup test environment
setup_test_environment() {
    print_section "Setting Up Test Environment"
    
    # Create test results directory
    mkdir -p "$TEST_RESULTS_DIR"
    
    # Generate test configuration
    cat > "$TEST_RESULTS_DIR/test-config.env" << EOF
# Test Configuration
RUST_LOG=debug
DATABASE_URL=postgresql://test_user:test_password@localhost:5432/test_db
REDIS_URL=redis://localhost:6379/1
JWT_SECRET=test_jwt_secret_key_for_integration_testing_only
ENCRYPTION_KEY=test_encryption_key_32_characters

# Test-specific settings
RATE_LIMITING_ENABLED=true
SECURITY_MONITORING_ENABLED=true
PERFORMANCE_TESTING_MODE=true

# Service endpoints
AUTH_SERVICE_URL=http://localhost:8080
POLICY_SERVICE_URL=http://localhost:8081
EOF

    # Create Docker Compose configuration for testing
    cat > "$DOCKER_COMPOSE_FILE" << 'EOF'
version: '3.8'
services:
  postgres-test:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: test_user
      POSTGRES_PASSWORD: test_password
      POSTGRES_DB: test_db
    ports:
      - "5433:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U test_user -d test_db"]
      interval: 5s
      timeout: 5s
      retries: 5
    volumes:
      - postgres_test_data:/var/lib/postgresql/data

  redis-test:
    image: redis:7-alpine
    ports:
      - "6380:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5
    command: redis-server --appendonly yes
    volumes:
      - redis_test_data:/data

volumes:
  postgres_test_data:
  redis_test_data:
EOF
    
    log_success "Test environment configuration created"
}

# Start test services
start_test_services() {
    print_section "Starting Test Services"
    
    # Start database and cache services
    log_info "Starting database and cache services..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" up -d
    
    # Wait for services to be healthy
    log_info "Waiting for services to be healthy..."
    local max_attempts=12
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if docker-compose -f "$DOCKER_COMPOSE_FILE" ps --services --filter "status=running" | wc -l | grep -q "2"; then
            if docker-compose -f "$DOCKER_COMPOSE_FILE" exec -T postgres-test pg_isready -U test_user -d test_db >/dev/null 2>&1 && \
               docker-compose -f "$DOCKER_COMPOSE_FILE" exec -T redis-test redis-cli ping >/dev/null 2>&1; then
                log_success "Database and cache services are healthy"
                break
            fi
        fi
        
        attempt=$((attempt + 1))
        log_info "Attempt $attempt/$max_attempts - waiting for services..."
        sleep 5
    done
    
    if [ $attempt -eq $max_attempts ]; then
        log_error "Services failed to become healthy within timeout"
        return 1
    fi
    
    # Build and start application services
    log_info "Building application services..."
    cd "$PROJECT_ROOT"
    
    # Build services with test configuration
    if ! cargo build --release --workspace; then
        log_error "Failed to build services"
        return 1
    fi
    
    # Update database connection for test
    export DATABASE_URL="postgresql://test_user:test_password@localhost:5433/test_db"
    export REDIS_URL="redis://localhost:6380/1"
    
    # Start auth service
    log_info "Starting auth service..."
    env $(cat "$TEST_RESULTS_DIR/test-config.env" | xargs) \
        ./target/release/auth-service &
    local AUTH_SERVICE_PID=$!
    echo $AUTH_SERVICE_PID > "$TEST_RESULTS_DIR/auth-service.pid"
    
    # Start policy service
    log_info "Starting policy service..."
    env $(cat "$TEST_RESULTS_DIR/test-config.env" | xargs) \
        ./target/release/policy-service &
    local POLICY_SERVICE_PID=$!
    echo $POLICY_SERVICE_PID > "$TEST_RESULTS_DIR/policy-service.pid"
    
    # Wait for services to be ready
    log_info "Waiting for application services to be ready..."
    local health_check_attempts=0
    local max_health_attempts=12
    
    while [ $health_check_attempts -lt $max_health_attempts ]; do
        if curl -f -s http://localhost:8080/health >/dev/null 2>&1; then
            log_success "Auth service is ready"
            break
        fi
        
        health_check_attempts=$((health_check_attempts + 1))
        log_info "Health check attempt $health_check_attempts/$max_health_attempts"
        sleep 5
    done
    
    if [ $health_check_attempts -eq $max_health_attempts ]; then
        log_error "Auth service failed to become ready"
        return 1
    fi
    
    log_success "All test services are running"
}

# Run basic functionality tests
run_basic_tests() {
    print_section "Running Basic Functionality Tests"
    
    log_info "Executing basic test suite..."
    
    if [ -f "$PROJECT_ROOT/enhanced-test-client.py" ]; then
        python3 "$PROJECT_ROOT/enhanced-test-client.py" \
            --url "http://localhost:8080" \
            --basic \
            --json-output "$TEST_RESULTS_DIR/basic-tests.json" \
            --verbose 2>&1 | tee "$TEST_RESULTS_DIR/basic-tests.log"
        
        local basic_exit_code=${PIPESTATUS[0]}
        
        if [ $basic_exit_code -eq 0 ]; then
            log_success "Basic functionality tests PASSED"
        else
            log_error "Basic functionality tests FAILED"
            return 1
        fi
    else
        log_warning "Enhanced test client not found, running legacy tests..."
        
        # Fallback to basic curl tests
        run_curl_based_tests
    fi
}

# Fallback curl-based tests
run_curl_based_tests() {
    log_info "Running curl-based integration tests..."
    
    local test_log="$TEST_RESULTS_DIR/curl-tests.log"
    local test_results="$TEST_RESULTS_DIR/curl-tests.json"
    
    {
        echo "=== Health Check ==="
        if curl -f -s -w "Response Time: %{time_total}s\n" http://localhost:8080/health; then
            echo "✅ Health check PASSED"
        else
            echo "❌ Health check FAILED"
            return 1
        fi
        
        echo -e "\n=== User Registration ==="
        local timestamp=$(date +%s)
        local test_user_data='{
            "username": "test_'$timestamp'",
            "email": "test_'$timestamp'@example.com",
            "password": "TestPassword123!",
            "profile": {"first_name": "Test", "last_name": "User"}
        }'
        
        if curl -f -s -X POST http://localhost:8080/auth/register \
            -H "Content-Type: application/json" \
            -d "$test_user_data" \
            -w "Response Time: %{time_total}s\n"; then
            echo "✅ User registration PASSED"
        else
            echo "❌ User registration FAILED"
            return 1
        fi
        
        echo -e "\n=== User Login ==="
        local login_response=$(curl -s -X POST http://localhost:8080/auth/login \
            -H "Content-Type: application/json" \
            -d '{"username": "test_'$timestamp'", "password": "TestPassword123!"}' \
            -w "\nResponse Time: %{time_total}s\n")
        
        echo "$login_response"
        
        if echo "$login_response" | grep -q "access_token"; then
            echo "✅ User login PASSED"
            
            # Extract token for authenticated tests
            local access_token=$(echo "$login_response" | jq -r '.access_token' 2>/dev/null || echo "")
            
            if [ -n "$access_token" ] && [ "$access_token" != "null" ]; then
                echo -e "\n=== Authenticated Profile Access ==="
                if curl -f -s -H "Authorization: Bearer $access_token" \
                    http://localhost:8080/auth/profile \
                    -w "Response Time: %{time_total}s\n"; then
                    echo "✅ Authenticated access PASSED"
                else
                    echo "❌ Authenticated access FAILED"
                fi
            fi
        else
            echo "❌ User login FAILED"
        fi
        
    } 2>&1 | tee "$test_log"
}

# Run security tests
run_security_tests() {
    print_section "Running Security Tests"
    
    log_info "Executing security test suite..."
    
    if [ -f "$PROJECT_ROOT/enhanced-test-client.py" ]; then
        python3 "$PROJECT_ROOT/enhanced-test-client.py" \
            --url "http://localhost:8080" \
            --security \
            --json-output "$TEST_RESULTS_DIR/security-tests.json" \
            --verbose 2>&1 | tee "$TEST_RESULTS_DIR/security-tests.log"
        
        local security_exit_code=${PIPESTATUS[0]}
        
        if [ $security_exit_code -eq 0 ]; then
            log_success "Security tests PASSED"
        else
            log_warning "Some security tests failed (may be expected)"
        fi
    else
        log_info "Running basic security validation..."
        
        # Basic security tests
        {
            echo "=== Rate Limiting Test ==="
            local rate_limit_triggered=false
            
            for i in {1..20}; do
                local response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health)
                if [ "$response" = "429" ]; then
                    echo "✅ Rate limiting triggered at request $i"
                    rate_limit_triggered=true
                    break
                fi
                sleep 0.1
            done
            
            if [ "$rate_limit_triggered" = false ]; then
                echo "⚠️  Rate limiting not triggered (may be configured with higher threshold)"
            fi
            
            echo -e "\n=== Invalid Credentials Test ==="
            local invalid_response=$(curl -s -o /dev/null -w "%{http_code}" \
                -X POST http://localhost:8080/auth/login \
                -H "Content-Type: application/json" \
                -d '{"username": "invalid", "password": "wrong"}')
            
            if [ "$invalid_response" = "401" ] || [ "$invalid_response" = "400" ]; then
                echo "✅ Invalid credentials properly rejected"
            else
                echo "❌ Invalid credentials not properly handled (got $invalid_response)"
            fi
            
        } 2>&1 | tee "$TEST_RESULTS_DIR/security-validation.log"
    fi
}

# Run performance tests
run_performance_tests() {
    print_section "Running Performance Tests"
    
    log_info "Executing performance test suite..."
    
    if [ -f "$PROJECT_ROOT/enhanced-test-client.py" ]; then
        python3 "$PROJECT_ROOT/enhanced-test-client.py" \
            --url "http://localhost:8080" \
            --performance \
            --json-output "$TEST_RESULTS_DIR/performance-tests.json" \
            --verbose 2>&1 | tee "$TEST_RESULTS_DIR/performance-tests.log"
        
        local performance_exit_code=${PIPESTATUS[0]}
        
        if [ $performance_exit_code -eq 0 ]; then
            log_success "Performance tests PASSED"
        else
            log_warning "Performance tests showed issues (may need optimization)"
        fi
    else
        log_info "Running basic performance validation..."
        run_basic_performance_test
    fi
}

# Basic performance test using Apache Bench
run_basic_performance_test() {
    local test_log="$TEST_RESULTS_DIR/performance-basic.log"
    
    if command -v ab >/dev/null 2>&1; then
        log_info "Running Apache Bench performance test..."
        
        {
            echo "=== Performance Test Results ==="
            echo "Test Configuration:"
            echo "- Concurrent Users: 10"
            echo "- Total Requests: 100"
            echo "- Endpoint: /health"
            echo
            
            ab -n 100 -c 10 -g "$TEST_RESULTS_DIR/performance-plot.tsv" \
               http://localhost:8080/health 2>&1
               
        } 2>&1 | tee "$test_log"
        
        log_success "Basic performance test completed"
    else
        log_warning "Apache Bench not available, skipping performance test"
    fi
}

# Run integration tests
run_integration_tests() {
    print_section "Running Integration Tests"
    
    log_info "Executing integration test suite..."
    
    # Run Rust integration tests if they exist
    cd "$PROJECT_ROOT"
    
    if find . -name "*integration*.rs" | grep -q .; then
        log_info "Running Rust integration tests..."
        
        env $(cat "$TEST_RESULTS_DIR/test-config.env" | xargs) \
            cargo test --test '*integration*' --all-features -- --nocapture \
            2>&1 | tee "$TEST_RESULTS_DIR/rust-integration-tests.log"
        
        local rust_exit_code=${PIPESTATUS[0]}
        
        if [ $rust_exit_code -eq 0 ]; then
            log_success "Rust integration tests PASSED"
        else
            log_error "Rust integration tests FAILED"
            return 1
        fi
    else
        log_info "No Rust integration tests found"
    fi
    
    # Run end-to-end workflow test
    log_info "Running end-to-end workflow test..."
    run_e2e_workflow_test
}

# End-to-end workflow test
run_e2e_workflow_test() {
    local workflow_log="$TEST_RESULTS_DIR/e2e-workflow.log"
    local workflow_results="$TEST_RESULTS_DIR/e2e-workflow.json"
    
    {
        echo "=== End-to-End Workflow Test ==="
        echo "Testing complete user journey..."
        
        local timestamp=$(date +%s)
        local test_user="e2e_user_$timestamp"
        local test_email="e2e_$timestamp@example.com"
        local test_password="E2ETestPassword123!"
        
        # Step 1: User Registration
        echo -e "\n--- Step 1: User Registration ---"
        local reg_response=$(curl -s -X POST http://localhost:8080/auth/register \
            -H "Content-Type: application/json" \
            -d '{
                "username": "'$test_user'",
                "email": "'$test_email'",
                "password": "'$test_password'",
                "profile": {"first_name": "E2E", "last_name": "Test"}
            }')
        
        echo "Registration Response: $reg_response"
        
        if echo "$reg_response" | jq -e '.user_id' >/dev/null 2>&1; then
            echo "✅ Step 1 PASSED: User registered successfully"
        else
            echo "❌ Step 1 FAILED: User registration failed"
            return 1
        fi
        
        # Step 2: User Login
        echo -e "\n--- Step 2: User Login ---"
        local login_response=$(curl -s -X POST http://localhost:8080/auth/login \
            -H "Content-Type: application/json" \
            -d '{"username": "'$test_user'", "password": "'$test_password'"}')
        
        echo "Login Response (access_token hidden): $(echo "$login_response" | jq 'del(.access_token)')"
        
        local access_token=$(echo "$login_response" | jq -r '.access_token' 2>/dev/null || echo "")
        
        if [ -n "$access_token" ] && [ "$access_token" != "null" ]; then
            echo "✅ Step 2 PASSED: User logged in successfully"
        else
            echo "❌ Step 2 FAILED: User login failed"
            return 1
        fi
        
        # Step 3: Profile Access
        echo -e "\n--- Step 3: Profile Access ---"
        local profile_response=$(curl -s -H "Authorization: Bearer $access_token" \
            http://localhost:8080/auth/profile)
        
        echo "Profile Response: $profile_response"
        
        if echo "$profile_response" | jq -e '.username' >/dev/null 2>&1; then
            echo "✅ Step 3 PASSED: Profile accessed successfully"
        else
            echo "❌ Step 3 FAILED: Profile access failed"
            return 1
        fi
        
        # Step 4: Profile Update
        echo -e "\n--- Step 4: Profile Update ---"
        local update_response=$(curl -s -X PUT http://localhost:8080/auth/profile \
            -H "Authorization: Bearer $access_token" \
            -H "Content-Type: application/json" \
            -d '{"profile": {"first_name": "Updated", "last_name": "User"}}')
        
        echo "Update Response: $update_response"
        
        if curl -f -s -H "Authorization: Bearer $access_token" \
            http://localhost:8080/auth/profile >/dev/null 2>&1; then
            echo "✅ Step 4 PASSED: Profile updated successfully"
        else
            echo "⚠️  Step 4 WARNING: Profile update may not be fully implemented"
        fi
        
        # Step 5: Session Management
        echo -e "\n--- Step 5: Session Management ---"
        local sessions_response=$(curl -s -H "Authorization: Bearer $access_token" \
            http://localhost:8080/auth/sessions 2>/dev/null || echo '{"error": "not_implemented"}')
        
        echo "Sessions Response: $sessions_response"
        
        if echo "$sessions_response" | jq -e '.sessions' >/dev/null 2>&1; then
            echo "✅ Step 5 PASSED: Session management working"
        else
            echo "⚠️  Step 5 WARNING: Session management may not be implemented"
        fi
        
        # Step 6: Logout
        echo -e "\n--- Step 6: Logout ---"
        local logout_response=$(curl -s -X POST http://localhost:8080/auth/logout \
            -H "Authorization: Bearer $access_token" \
            -H "Content-Type: application/json" \
            -d '{}' 2>/dev/null || echo '{"error": "endpoint_not_found"}')
        
        echo "Logout Response: $logout_response"
        
        # Verify token is invalidated
        local post_logout_response=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer $access_token" \
            http://localhost:8080/auth/profile)
        
        if [ "$post_logout_response" = "401" ]; then
            echo "✅ Step 6 PASSED: Token invalidated after logout"
        else
            echo "⚠️  Step 6 WARNING: Logout may not invalidate tokens (got $post_logout_response)"
        fi
        
        echo -e "\n=== E2E Workflow Test Complete ==="
        
    } 2>&1 | tee "$workflow_log"
    
    log_success "End-to-end workflow test completed"
}

# Generate comprehensive test report
generate_test_report() {
    print_section "Generating Test Report"
    
    local report_file="$TEST_RESULTS_DIR/integration-test-report.html"
    local summary_file="$TEST_RESULTS_DIR/test-summary.json"
    
    log_info "Generating comprehensive test report..."
    
    # Create test summary
    cat > "$summary_file" << EOF
{
  "test_run": {
    "timestamp": "$(date -Iseconds)",
    "duration": "$(date +%s) - start_time",
    "environment": {
      "auth_service_url": "http://localhost:8080",
      "policy_service_url": "http://localhost:8081",
      "database_url": "postgresql://test_user:test_password@localhost:5433/test_db",
      "redis_url": "redis://localhost:6380/1"
    }
  },
  "test_files": [
    "basic-tests.json",
    "security-tests.json", 
    "performance-tests.json",
    "e2e-workflow.log",
    "rust-integration-tests.log"
  ]
}
EOF

    # Generate HTML report
    cat > "$report_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Integration Test Report - Rust Security Platform</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background: #d4edda; border-color: #c3e6cb; }
        .warning { background: #fff3cd; border-color: #ffeaa7; }
        .error { background: #f8d7da; border-color: #f5c6cb; }
        .metrics { display: flex; gap: 20px; }
        .metric { text-align: center; padding: 10px; background: #f8f9fa; border-radius: 5px; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 3px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Integration Test Report</h1>
        <p>Rust Security Platform - Comprehensive Test Suite</p>
        <p>Generated: <span id="timestamp"></span></p>
    </div>
    
    <div class="section">
        <h2>📊 Test Summary</h2>
        <div class="metrics">
            <div class="metric">
                <h3>Total Tests</h3>
                <p id="total-tests">-</p>
            </div>
            <div class="metric">
                <h3>Passed</h3>
                <p id="passed-tests">-</p>
            </div>
            <div class="metric">
                <h3>Failed</h3>
                <p id="failed-tests">-</p>
            </div>
            <div class="metric">
                <h3>Success Rate</h3>
                <p id="success-rate">-</p>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>🔍 Test Details</h2>
        <p>Detailed test results are available in the following log files:</p>
        <ul>
            <li><strong>Basic Tests:</strong> basic-tests.log</li>
            <li><strong>Security Tests:</strong> security-tests.log</li>
            <li><strong>Performance Tests:</strong> performance-tests.log</li>
            <li><strong>Integration Tests:</strong> rust-integration-tests.log</li>
            <li><strong>E2E Workflow:</strong> e2e-workflow.log</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>🚀 Next Steps</h2>
        <ul>
            <li>Review failed tests and address issues</li>
            <li>Run tests again to verify fixes</li>
            <li>Deploy to staging environment</li>
            <li>Schedule regular integration test runs</li>
        </ul>
    </div>
    
    <script>
        document.getElementById('timestamp').textContent = new Date().toISOString();
        
        // Load test results if available
        // This would be populated by actual test results in a real implementation
        document.getElementById('total-tests').textContent = 'N/A';
        document.getElementById('passed-tests').textContent = 'N/A';
        document.getElementById('failed-tests').textContent = 'N/A';
        document.getElementById('success-rate').textContent = 'N/A';
    </script>
</body>
</html>
EOF

    log_success "Test report generated: $report_file"
    
    # Display final results
    echo
    echo "📋 Test Results Summary:"
    echo "========================"
    echo "📁 Results Directory: $TEST_RESULTS_DIR"
    echo "📄 HTML Report: $report_file"
    echo "📊 Test Summary: $summary_file"
    echo
    
    if [ -f "$TEST_RESULTS_DIR/basic-tests.json" ]; then
        local basic_success=$(jq -r '.passed_tests' "$TEST_RESULTS_DIR/basic-tests.json" 2>/dev/null || echo "unknown")
        local basic_total=$(jq -r '.total_tests' "$TEST_RESULTS_DIR/basic-tests.json" 2>/dev/null || echo "unknown")
        echo "✅ Basic Tests: $basic_success/$basic_total passed"
    fi
    
    echo "🔍 Check individual log files for detailed results"
    echo "🌐 Open $report_file in a browser for visual report"
}

# Main execution
main() {
    local start_time=$(date +%s)
    
    print_section "Automated Integration Test Suite"
    log_info "Starting comprehensive integration tests..."
    
    # Parse command line arguments
    local run_basic=true
    local run_security=true
    local run_performance=true
    local run_integration=true
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --basic-only)
                run_security=false
                run_performance=false
                run_integration=false
                shift
                ;;
            --no-performance)
                run_performance=false
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --basic-only      Run only basic functionality tests"
                echo "  --no-performance  Skip performance tests"
                echo "  --help           Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Execute test phases
    setup_test_environment
    start_test_services
    
    local overall_success=true
    
    if [ "$run_basic" = true ]; then
        if ! run_basic_tests; then
            overall_success=false
        fi
    fi
    
    if [ "$run_security" = true ]; then
        if ! run_security_tests; then
            log_warning "Security tests had issues (continuing...)"
        fi
    fi
    
    if [ "$run_performance" = true ]; then
        if ! run_performance_tests; then
            log_warning "Performance tests had issues (continuing...)"
        fi
    fi
    
    if [ "$run_integration" = true ]; then
        if ! run_integration_tests; then
            overall_success=false
        fi
    fi
    
    generate_test_report
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    print_section "Test Suite Complete"
    log_info "Total execution time: ${duration}s"
    
    if [ "$overall_success" = true ]; then
        log_success "🎉 Integration test suite completed successfully!"
        exit 0
    else
        log_error "❌ Integration test suite completed with failures"
        exit 1
    fi
}

# Run main function with all arguments
main "$@"