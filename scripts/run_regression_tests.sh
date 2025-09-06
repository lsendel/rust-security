#!/bin/bash
# Regression Test Runner for Rust Security Platform

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BASELINE_DIR="tests/baseline"
REPORT_DIR="regression_reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo "🔄 Starting Regression Test Suite - $TIMESTAMP"

# Create report directory
mkdir -p "$REPORT_DIR"

# Function to run test and capture results
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo "📋 Running $test_name..."
    
    if eval "$test_command" > "$REPORT_DIR/${test_name}_${TIMESTAMP}.log" 2>&1; then
        echo -e "${GREEN}✅ $test_name PASSED${NC}"
        return 0
    else
        echo -e "${RED}❌ $test_name FAILED${NC}"
        return 1
    fi
}

# Initialize counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# 1. Core Functionality Regression
echo "🧪 Core Functionality Tests"
((TOTAL_TESTS++))
if run_test "core_functionality" "cargo test --workspace --lib --release"; then
    ((PASSED_TESTS++))
else
    ((FAILED_TESTS++))
fi

# 2. Security Regression
echo "🔒 Security Tests"
((TOTAL_TESTS++))
if run_test "security_scan" "./scripts/security-vulnerability-scan.sh"; then
    ((PASSED_TESTS++))
else
    ((FAILED_TESTS++))
fi

# 3. Performance Regression
echo "⚡ Performance Tests"
((TOTAL_TESTS++))
if run_test "performance_bench" "cargo bench --workspace"; then
    ((PASSED_TESTS++))
else
    ((FAILED_TESTS++))
fi

# 4. E2E Regression
echo "🌐 E2E Tests"
((TOTAL_TESTS++))
if run_test "e2e_tests" "cd e2e-testing && npm test"; then
    ((PASSED_TESTS++))
else
    ((FAILED_TESTS++))
fi

# 5. API Regression
echo "🔌 API Tests"
((TOTAL_TESTS++))
if run_test "api_validation" "cargo test --workspace --test '*integration*'"; then
    ((PASSED_TESTS++))
else
    ((FAILED_TESTS++))
fi

# Generate summary report
cat > "$REPORT_DIR/regression_summary_${TIMESTAMP}.md" << EOF
# Regression Test Summary - $TIMESTAMP

## Results Overview
- **Total Tests**: $TOTAL_TESTS
- **Passed**: $PASSED_TESTS
- **Failed**: $FAILED_TESTS
- **Success Rate**: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%

## Test Details
$(for log in "$REPORT_DIR"/*_${TIMESTAMP}.log; do
    test_name=$(basename "$log" "_${TIMESTAMP}.log")
    if grep -q "test result: ok" "$log" 2>/dev/null || grep -q "PASSED" "$log" 2>/dev/null; then
        echo "- ✅ $test_name: PASSED"
    else
        echo "- ❌ $test_name: FAILED"
    fi
done)

## Recommendations
$(if [ $FAILED_TESTS -gt 0 ]; then
    echo "⚠️  **REGRESSION DETECTED** - $FAILED_TESTS test(s) failed"
    echo "- Review failed test logs in $REPORT_DIR/"
    echo "- Do not deploy until all tests pass"
    echo "- Consider rollback if in production"
else
    echo "✅ **ALL TESTS PASSED** - Safe to proceed with deployment"
fi)

Generated: $(date)
EOF

# Final summary
echo ""
echo "📊 Regression Test Summary"
echo "=========================="
echo "Total Tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
echo "Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
echo ""
echo "📁 Reports saved to: $REPORT_DIR/"

# Exit with appropriate code
if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "${RED}🚨 REGRESSION DETECTED - DO NOT DEPLOY${NC}"
    exit 1
else
    echo -e "${GREEN}✅ ALL REGRESSION TESTS PASSED${NC}"
    exit 0
fi
