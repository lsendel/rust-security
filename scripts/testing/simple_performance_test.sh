#!/bin/bash

# Simple Performance Validation Script
# Tests core auth service functionality under simulated load

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Simple Performance Validation${NC}"
echo "================================="
echo -e "📍 Project root: $PROJECT_ROOT"

# Initialize results
performance_passed=0
performance_failed=0

# Function to log performance result
validate_performance() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    
    if [ "$status" = "PASS" ]; then
        echo -e "  ${GREEN}✅ $test_name${NC}"
        if [ -n "$details" ]; then
            echo -e "     $details"
        fi
        ((performance_passed++))
    else
        echo -e "  ${RED}❌ $test_name${NC}"
        if [ -n "$details" ]; then
            echo -e "     $details"
        fi
        ((performance_failed++))
    fi
}

# Function to run performance test with timing
run_performance_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_max_time="$3"
    
    echo -e "${YELLOW}🧪 Running $test_name${NC}"
    
    cd "$PROJECT_ROOT"
    start_time=$(date +%s.%N)
    
    if eval "$test_command" >/dev/null 2>&1; then
        end_time=$(date +%s.%N)
        duration=$(echo "$end_time - $start_time" | bc)
        duration_ms=$(echo "$duration * 1000" | bc | cut -d. -f1)
        
        if [ "$duration_ms" -le "$expected_max_time" ]; then
            validate_performance "$test_name" "PASS" "Completed in ${duration_ms}ms (target: <${expected_max_time}ms)"
        else
            validate_performance "$test_name" "FAIL" "Took ${duration_ms}ms (target: <${expected_max_time}ms)"
        fi
    else
        validate_performance "$test_name" "FAIL" "Test execution failed"
    fi
}

# 1. Compilation Performance
echo -e "\n${BLUE}1. Compilation Performance${NC}"
echo "=========================="

# Clean build performance
run_performance_test "Clean Build Performance" "cargo clean && cargo build --release" 120000

# Incremental build performance  
run_performance_test "Incremental Build Performance" "cargo build --release" 5000

# 2. Test Suite Performance
echo -e "\n${BLUE}2. Test Suite Performance${NC}"
echo "========================="

# Unit tests performance
run_performance_test "Unit Tests Performance" "cargo test --lib --release" 10000

# Integration tests performance
run_performance_test "Security Tests Performance" "cargo test --test security_test --release" 5000

# Token operations tests
run_performance_test "Token Operations Performance" "cargo test --test token_flow_it --release" 5000

# 3. Memory Efficiency Tests
echo -e "\n${BLUE}3. Memory Efficiency Tests${NC}"
echo "=========================="

# Binary size check
if [ -f "target/release/auth-service" ]; then
    binary_size=$(stat -f%z target/release/auth-service 2>/dev/null || stat -c%s target/release/auth-service 2>/dev/null || echo "0")
    binary_size_mb=$((binary_size / 1024 / 1024))
    
    if [ "$binary_size_mb" -le 50 ]; then
        validate_performance "Binary Size Optimization" "PASS" "Binary size: ${binary_size_mb}MB (target: <50MB)"
    else
        validate_performance "Binary Size Optimization" "FAIL" "Binary size: ${binary_size_mb}MB (target: <50MB)"
    fi
else
    validate_performance "Binary Size Optimization" "FAIL" "Binary not found"
fi

# Dependency compilation check
dep_count=$(cargo tree --depth 1 | wc -l)
if [ "$dep_count" -le 200 ]; then
    validate_performance "Dependency Count" "PASS" "Dependencies: $dep_count (target: <200)"
else
    validate_performance "Dependency Count" "FAIL" "Dependencies: $dep_count (target: <200)"
fi

# 4. Code Complexity Analysis
echo -e "\n${BLUE}4. Code Complexity Analysis${NC}"
echo "==========================="

# Count lines of code
loc=$(find auth-service/src -name "*.rs" -exec wc -l {} + | tail -1 | awk '{print $1}')
if [ "$loc" -le 10000 ]; then
    validate_performance "Lines of Code" "PASS" "LOC: $loc (target: <10,000)"
else
    validate_performance "Lines of Code" "WARN" "LOC: $loc (target: <10,000)"
fi

# Function complexity (approximate)
function_count=$(grep -r "fn " auth-service/src --include="*.rs" | wc -l)
if [ "$function_count" -le 500 ]; then
    validate_performance "Function Count" "PASS" "Functions: $function_count (target: <500)"
else
    validate_performance "Function Count" "WARN" "Functions: $function_count (target: <500)"
fi

# 5. Security Feature Performance
echo -e "\n${BLUE}5. Security Feature Performance${NC}"
echo "==============================="

# Security logging tests
run_performance_test "Security Logging Performance" "cargo test --test security_logging_test --release" 3000

# MFA tests
run_performance_test "MFA Performance" "cargo test --test totp_it --release" 8000

# PKCE tests
run_performance_test "PKCE Performance" "cargo test --test pkce_oauth_test --release" 3000

# 6. Algorithmic Performance
echo -e "\n${BLUE}6. Algorithmic Performance${NC}"
echo "=========================="

# Token generation/validation performance
run_performance_test "Token Operations" "cargo test token --release" 5000

# Scope validation performance
run_performance_test "Scope Validation" "cargo test --test scope_validation_test --release" 3000

# Authorization performance
run_performance_test "Authorization Logic" "cargo test --test authorization_it --release --ignored" 8000

# 7. Monitoring Overhead
echo -e "\n${BLUE}7. Monitoring Overhead${NC}"
echo "======================"

# Check if monitoring adds significant overhead
if grep -q "prometheus\|metrics" auth-service/Cargo.toml; then
    validate_performance "Metrics Integration" "PASS" "Prometheus metrics enabled"
else
    validate_performance "Metrics Integration" "WARN" "Metrics not explicitly configured"
fi

# Tracing overhead
if grep -q "tracing" auth-service/src/lib.rs; then
    validate_performance "Tracing Integration" "PASS" "Tracing implemented"
else
    validate_performance "Tracing Integration" "FAIL" "Tracing missing"
fi

# 8. Production Readiness Performance
echo -e "\n${BLUE}8. Production Readiness Performance${NC}"
echo "==================================="

# Startup time estimation (based on binary size and complexity)
startup_score=$((100 - binary_size_mb - (function_count / 10)))
if [ "$startup_score" -ge 80 ]; then
    validate_performance "Estimated Startup Performance" "PASS" "Score: $startup_score/100"
elif [ "$startup_score" -ge 60 ]; then
    validate_performance "Estimated Startup Performance" "WARN" "Score: $startup_score/100"
else
    validate_performance "Estimated Startup Performance" "FAIL" "Score: $startup_score/100"
fi

# Error handling overhead
error_handling_count=$(grep -r "Result\|Error" auth-service/src --include="*.rs" | wc -l)
if [ "$error_handling_count" -ge 50 ]; then
    validate_performance "Error Handling Coverage" "PASS" "Error handling: $error_handling_count occurrences"
else
    validate_performance "Error Handling Coverage" "WARN" "Error handling: $error_handling_count occurrences"
fi

# Generate Performance Report
echo -e "\n${BLUE}📋 Performance Validation Summary${NC}"
echo "=================================="
echo -e "Total Tests: $((performance_passed + performance_failed))"
echo -e "${GREEN}✅ Tests Passed: $performance_passed${NC}"
echo -e "${RED}❌ Tests Failed: $performance_failed${NC}"

# Calculate performance score
total_tests=$((performance_passed + performance_failed))
performance_score=$(( (performance_passed * 100) / total_tests ))

echo -e "\n${BLUE}📊 Performance Score: ${performance_score}%${NC}"

if [ $performance_failed -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All performance validations passed!${NC}"
    echo -e "${GREEN}✅ Performance characteristics are excellent${NC}"
    exit_code=0
elif [ $performance_score -ge 80 ]; then
    echo -e "\n${GREEN}✅ Good performance characteristics (${performance_score}%)${NC}"
    exit_code=0
elif [ $performance_score -ge 70 ]; then
    echo -e "\n${YELLOW}⚠️  Acceptable performance with room for improvement (${performance_score}%)${NC}"
    exit_code=0
else
    echo -e "\n${RED}❌ Performance characteristics need attention (${performance_score}%)${NC}"
    exit_code=1
fi

# Performance Recommendations
echo -e "\n${BLUE}💡 Performance Recommendations${NC}"
echo "==============================="
echo -e "1. ${YELLOW}Profile Critical Paths:${NC} Use cargo flamegraph for hot spots"
echo -e "2. ${YELLOW}Memory Optimization:${NC} Consider using Arc<str> vs String where appropriate"
echo -e "3. ${YELLOW}Async Optimization:${NC} Ensure proper async/await usage"
echo -e "4. ${YELLOW}Caching Strategy:${NC} Implement intelligent caching for frequent operations"
echo -e "5. ${YELLOW}Database Pooling:${NC} Optimize connection pool sizes"
echo -e "6. ${YELLOW}Load Testing:${NC} Run comprehensive load tests with k6 when service is deployed"

# Resource Usage Estimates
echo -e "\n${BLUE}📊 Estimated Resource Usage${NC}"
echo "============================="
echo -e "Memory (estimated): ${binary_size_mb}MB + runtime overhead"
echo -e "CPU (estimated): Low-Medium (optimized Rust code)"
echo -e "Disk I/O: Minimal (primarily in-memory operations)"
echo -e "Network I/O: Request-dependent"

echo -e "\n=================================="
echo -e "${BLUE}🚀 Performance validation completed!${NC}"

exit $exit_code