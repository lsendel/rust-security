#!/bin/bash

# Comprehensive test coverage analysis script for auth-service
# Generates detailed coverage reports with security-focused metrics

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "📊 Starting comprehensive coverage analysis"
echo "Project root: $PROJECT_ROOT"

cd "$PROJECT_ROOT"

# Configuration
BASELINE_COVERAGE=${BASELINE_COVERAGE:-70}
OUTPUT_DIR="$PROJECT_ROOT/target/coverage-reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="$OUTPUT_DIR/$TIMESTAMP"

# Security-critical modules that should have high coverage
SECURITY_MODULES=(
    "auth-service/src/security.rs"
    "auth-service/src/keys.rs"
    "auth-service/src/config.rs"
    "auth-service/src/pii_protection.rs"
    "auth-service/src/admin_middleware.rs"
    "auth-service/src/rate_limit_optimized.rs"
    "auth-service/src/validation.rs"
)

# Function to check if required tools are installed
check_dependencies() {
    echo "🔧 Checking dependencies..."
    
    # Check for cargo-llvm-cov
    if ! cargo llvm-cov --version &>/dev/null; then
        echo "📦 Installing cargo-llvm-cov..."
        cargo install cargo-llvm-cov
    fi
    
    # Check for jq for JSON processing
    if ! command -v jq &>/dev/null; then
        echo "⚠️  jq not found. JSON analysis will be limited."
    fi
    
    echo "✅ Dependencies checked"
}

# Function to run comprehensive test coverage
run_coverage() {
    echo "🧪 Running comprehensive test coverage..."
    
    export TEST_MODE=1
    export RUST_LOG=error  # Reduce noise in coverage runs
    
    mkdir -p "$REPORT_DIR"
    
    echo "  📁 Output directory: $REPORT_DIR"
    
    # Generate HTML report
    echo "  📊 Generating HTML coverage report..."
    cargo llvm-cov --workspace --all-features \
        --html \
        --output-dir "$REPORT_DIR/html" \
        2>&1 | tee "$REPORT_DIR/coverage.log"
    
    # Generate LCOV report for CI integration
    echo "  📄 Generating LCOV report..."
    cargo llvm-cov --workspace --all-features \
        --lcov \
        --output-path "$REPORT_DIR/lcov.info"
    
    # Generate JSON report for analysis
    echo "  🔢 Generating JSON report..."
    cargo llvm-cov --workspace --all-features \
        --json \
        --output-path "$REPORT_DIR/coverage.json"
    
    # Generate summary report
    echo "  📋 Generating summary report..."
    cargo llvm-cov --workspace --all-features \
        --summary-only > "$REPORT_DIR/summary.txt"
    
    echo "✅ Coverage reports generated"
}

# Function to analyze security-critical module coverage
analyze_security_coverage() {
    echo "🔒 Analyzing security-critical module coverage..."
    
    local security_report="$REPORT_DIR/security_coverage_analysis.txt"
    
    {
        echo "Security-Critical Module Coverage Analysis"
        echo "Generated: $(date)"
        echo "=========================================="
        echo ""
    } > "$security_report"
    
    if [ -f "$REPORT_DIR/coverage.json" ] && command -v jq &>/dev/null; then
        echo "📊 Analyzing security modules with JSON data..."
        
        for module in "${SECURITY_MODULES[@]}"; do
            echo "  🔍 Analyzing: $module"
            
            # Extract coverage data for this module
            local coverage_percent=$(jq -r "
                .data[] | 
                select(.files[]?.filename? | contains(\"$module\")) | 
                .totals.lines.percent // \"N/A\"
            " "$REPORT_DIR/coverage.json" 2>/dev/null || echo "N/A")
            
            {
                echo "Module: $module"
                echo "Coverage: $coverage_percent%"
                echo "Status: $([ "$coverage_percent" != "N/A" ] && [ "${coverage_percent%.*}" -ge 80 ] && echo "✅ GOOD" || echo "⚠️  NEEDS ATTENTION")"
                echo ""
            } >> "$security_report"
        done
    else
        echo "  ⚠️  JSON analysis not available, generating basic report..."
        {
            echo "Note: Advanced analysis requires jq and JSON coverage report"
            echo ""
            for module in "${SECURITY_MODULES[@]}"; do
                echo "Module: $module"
                echo "Status: Manual review required"
                echo ""
            done
        } >> "$security_report"
    fi
    
    echo "✅ Security coverage analysis saved to: $security_report"
}

# Function to check coverage against baseline
check_baseline() {
    echo "🎯 Checking coverage against baseline..."
    
    local summary_file="$REPORT_DIR/summary.txt"
    local baseline_report="$REPORT_DIR/baseline_check.txt"
    
    if [ -f "$summary_file" ]; then
        # Extract overall coverage percentage
        local total_coverage=$(grep -E "^TOTAL" "$summary_file" | awk '{print $10}' | sed 's/%//' || echo "0")
        
        {
            echo "Coverage Baseline Check"
            echo "======================"
            echo "Baseline requirement: ${BASELINE_COVERAGE}%"
            echo "Current coverage: ${total_coverage}%"
            echo ""
        } > "$baseline_report"
        
        if (( $(echo "$total_coverage >= $BASELINE_COVERAGE" | bc -l 2>/dev/null || echo "0") )); then
            echo "✅ Coverage meets baseline: ${total_coverage}% >= ${BASELINE_COVERAGE}%"
            echo "Status: PASS ✅" >> "$baseline_report"
            echo 0 > "$REPORT_DIR/baseline_status"
        else
            echo "❌ Coverage below baseline: ${total_coverage}% < ${BASELINE_COVERAGE}%"
            echo "Status: FAIL ❌" >> "$baseline_report"
            echo "Recommendation: Add more tests to critical paths" >> "$baseline_report"
            echo 1 > "$REPORT_DIR/baseline_status"
        fi
    else
        echo "⚠️  Cannot find summary file for baseline check"
        echo 1 > "$REPORT_DIR/baseline_status"
    fi
}

# Function to generate coverage badges
generate_badges() {
    echo "🏅 Generating coverage badges..."
    
    local summary_file="$REPORT_DIR/summary.txt"
    local badges_dir="$REPORT_DIR/badges"
    
    mkdir -p "$badges_dir"
    
    if [ -f "$summary_file" ]; then
        local total_coverage=$(grep -E "^TOTAL" "$summary_file" | awk '{print $10}' | sed 's/%//' || echo "0")
        
        # Simple SVG badge generation
        local color="red"
        if (( $(echo "$total_coverage >= 80" | bc -l 2>/dev/null || echo "0") )); then
            color="brightgreen"
        elif (( $(echo "$total_coverage >= 60" | bc -l 2>/dev/null || echo "0") )); then
            color="yellow"
        fi
        
        # Generate a simple coverage badge URL
        local badge_url="https://img.shields.io/badge/coverage-${total_coverage}%25-${color}.svg"
        echo "$badge_url" > "$badges_dir/coverage_badge_url.txt"
        
        echo "  📌 Coverage badge URL: $badge_url"
    fi
    
    echo "✅ Badge information generated"
}

# Function to create detailed report
create_detailed_report() {
    echo "📝 Creating detailed coverage report..."
    
    local detailed_report="$REPORT_DIR/detailed_report.md"
    
    {
        echo "# Test Coverage Report"
        echo ""
        echo "Generated: $(date)"
        echo "Project: auth-service"
        echo ""
        echo "## Summary"
        echo ""
        if [ -f "$REPORT_DIR/summary.txt" ]; then
            echo '```'
            cat "$REPORT_DIR/summary.txt"
            echo '```'
        fi
        echo ""
        echo "## Security-Critical Modules"
        echo ""
        if [ -f "$REPORT_DIR/security_coverage_analysis.txt" ]; then
            echo '```'
            cat "$REPORT_DIR/security_coverage_analysis.txt"
            echo '```'
        fi
        echo ""
        echo "## Baseline Check"
        echo ""
        if [ -f "$REPORT_DIR/baseline_check.txt" ]; then
            echo '```'
            cat "$REPORT_DIR/baseline_check.txt"
            echo '```'
        fi
        echo ""
        echo "## Files"
        echo ""
        echo "- [HTML Report](./html/index.html)"
        echo "- [LCOV Report](./lcov.info)"
        echo "- [JSON Data](./coverage.json)"
        echo "- [Raw Log](./coverage.log)"
        echo ""
        echo "## Recommendations"
        echo ""
        echo "1. Focus on increasing coverage for security-critical modules"
        echo "2. Add property-based tests for edge cases"
        echo "3. Include integration tests for complete workflows"
        echo "4. Consider fuzzing for input validation functions"
        echo ""
    } > "$detailed_report"
    
    echo "✅ Detailed report created: $detailed_report"
}

# Function to clean old coverage reports
cleanup_old_reports() {
    echo "🧹 Cleaning up old coverage reports..."
    
    # Keep only the last 5 coverage reports
    if [ -d "$OUTPUT_DIR" ]; then
        local old_reports=$(find "$OUTPUT_DIR" -maxdepth 1 -type d -name "20*" | sort -r | tail -n +6)
        if [ -n "$old_reports" ]; then
            echo "  🗑️  Removing old reports..."
            echo "$old_reports" | xargs rm -rf
            echo "  ✅ Old reports cleaned"
        else
            echo "  ✅ No old reports to clean"
        fi
    fi
}

# Function to show help
show_help() {
    cat << EOF
Test Coverage Analysis Script

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    run                 Run complete coverage analysis (default)
    baseline-only       Check only against baseline
    security-only       Analyze only security-critical modules
    clean              Clean old coverage reports
    help               Show this help

Environment Variables:
    BASELINE_COVERAGE   Minimum coverage percentage (default: 70)

Examples:
    $0                              # Run complete analysis
    BASELINE_COVERAGE=80 $0         # Set higher baseline
    $0 baseline-only                # Quick baseline check
    $0 clean                        # Clean old reports

Output Location:
    $OUTPUT_DIR/[timestamp]/

Security-Critical Modules Analyzed:
$(printf '    %s\n' "${SECURITY_MODULES[@]}")
EOF
}

# Main execution function
main() {
    case "${1:-run}" in
        "run")
            check_dependencies
            cleanup_old_reports
            run_coverage
            analyze_security_coverage
            check_baseline
            generate_badges
            create_detailed_report
            
            echo ""
            echo "🎉 Coverage analysis complete!"
            echo "📊 Results available at: $REPORT_DIR"
            echo "🌐 Open HTML report: $REPORT_DIR/html/index.html"
            
            # Exit with baseline status
            if [ -f "$REPORT_DIR/baseline_status" ]; then
                exit "$(cat "$REPORT_DIR/baseline_status")"
            fi
            ;;
        "baseline-only")
            check_dependencies
            run_coverage
            check_baseline
            ;;
        "security-only")
            check_dependencies
            run_coverage
            analyze_security_coverage
            ;;
        "clean")
            cleanup_old_reports
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            echo "❌ Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Ensure we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "❌ Error: Not in project root (no Cargo.toml found)"
    exit 1
fi

# Run main function
main "$@"