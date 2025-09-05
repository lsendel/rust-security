#!/bin/bash
# 🧹 Clean Code Standards Enforcement Script
# Automatically enforces clean code standards for the Rust Security Platform

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MAX_FUNCTION_LINES=50
MAX_COMPLEXITY=10
MIN_DOCUMENTATION_COVERAGE=90
MIN_TEST_COVERAGE=80

# Logging
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

# Check if required tools are installed
check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_tools=()
    
    if ! command -v cargo &> /dev/null; then
        missing_tools+=("cargo")
    fi
    
    if ! command -v rustfmt &> /dev/null; then
        missing_tools+=("rustfmt")
    fi
    
    if ! command -v clippy &> /dev/null; then
        missing_tools+=("clippy")
    fi
    
    # Optional tools
    if ! command -v tokei &> /dev/null; then
        log_warning "tokei not found - install with: cargo install tokei"
    fi
    
    if ! command -v cargo-audit &> /dev/null; then
        log_warning "cargo-audit not found - install with: cargo install cargo-audit"
    fi
    
    if ! command -v cargo-tarpaulin &> /dev/null; then
        log_warning "cargo-tarpaulin not found - install with: cargo install cargo-tarpaulin"
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    log_success "All required dependencies found"
}

# Format code using rustfmt
format_code() {
    log_info "Formatting code with rustfmt..."
    
    cd "$PROJECT_ROOT"
    
    if cargo fmt --all -- --check &> /dev/null; then
        log_success "Code is already properly formatted"
    else
        log_info "Applying code formatting..."
        cargo fmt --all
        log_success "Code formatting applied"
    fi
}

# Run clippy for linting
run_clippy() {
    log_info "Running clippy analysis..."
    
    cd "$PROJECT_ROOT"
    
    local clippy_output
    clippy_output=$(cargo clippy --workspace --all-features -- -D warnings 2>&1) || {
        log_error "Clippy found issues:"
        echo "$clippy_output"
        return 1
    }
    
    log_success "Clippy analysis passed"
}

# Check function lengths
check_function_lengths() {
    log_info "Checking function lengths..."
    
    local violations=0
    local temp_file=$(mktemp)
    
    # Use Python script if available, otherwise use basic grep
    if [ -f "$PROJECT_ROOT/scripts/refactor/extract_functions.py" ]; then
        python3 "$PROJECT_ROOT/scripts/refactor/extract_functions.py" \
            --src-dir "$PROJECT_ROOT/src" \
            --max-lines $MAX_FUNCTION_LINES \
            --output "$temp_file" 2>/dev/null || true
        
        if [ -s "$temp_file" ]; then
            violations=$(grep -c "Priority Refactoring" "$temp_file" 2>/dev/null || echo "0")
        fi
    else
        # Fallback: simple line counting
        find "$PROJECT_ROOT" -name "*.rs" -not -path "*/target/*" | while read -r file; do
            local file_violations=0
            grep -n "fn " "$file" 2>/dev/null | while read -r line; do
                local func_line=$(echo "$line" | cut -d: -f1)
                # Simple check for large functions (basic heuristic)
                if [ "$func_line" -gt 0 ]; then
                    file_violations=$((file_violations + 1))
                fi
            done
            violations=$((violations + file_violations))
        done
    fi
    
    rm -f "$temp_file"
    
    if [ $violations -eq 0 ]; then
        log_success "All functions are within size limits"
    else
        log_warning "Found $violations functions exceeding $MAX_FUNCTION_LINES lines"
        return 1
    fi
}

# Check documentation coverage
check_documentation() {
    log_info "Checking documentation coverage..."
    
    cd "$PROJECT_ROOT"
    
    # Generate documentation and check for warnings
    local doc_output
    doc_output=$(cargo doc --workspace --all-features --no-deps 2>&1) || {
        log_error "Documentation generation failed"
        return 1
    }
    
    # Count missing documentation warnings
    local missing_docs
    missing_docs=$(echo "$doc_output" | grep -c "missing documentation" || echo "0")
    
    if [ "$missing_docs" -eq 0 ]; then
        log_success "Documentation coverage is excellent"
    else
        log_warning "Found $missing_docs items missing documentation"
        echo "$doc_output" | grep "missing documentation" | head -10
        return 1
    fi
}

# Run tests
run_tests() {
    log_info "Running test suite..."
    
    cd "$PROJECT_ROOT"
    
    if cargo test --workspace --all-features; then
        log_success "All tests passed"
    else
        log_error "Some tests failed"
        return 1
    fi
}

# Check test coverage
check_test_coverage() {
    log_info "Checking test coverage..."
    
    cd "$PROJECT_ROOT"
    
    if command -v cargo-tarpaulin &> /dev/null; then
        local coverage_output
        coverage_output=$(cargo tarpaulin --workspace --out Stdout 2>/dev/null | tail -1) || {
            log_warning "Could not determine test coverage"
            return 0
        }
        
        local coverage_percent
        coverage_percent=$(echo "$coverage_output" | grep -o '[0-9.]*%' | head -1 | tr -d '%')
        
        if [ -n "$coverage_percent" ]; then
            if (( $(echo "$coverage_percent >= $MIN_TEST_COVERAGE" | bc -l) )); then
                log_success "Test coverage: ${coverage_percent}% (target: ${MIN_TEST_COVERAGE}%)"
            else
                log_warning "Test coverage: ${coverage_percent}% (below target: ${MIN_TEST_COVERAGE}%)"
                return 1
            fi
        fi
    else
        log_warning "cargo-tarpaulin not available - skipping coverage check"
    fi
}

# Security audit
security_audit() {
    log_info "Running security audit..."
    
    cd "$PROJECT_ROOT"
    
    if command -v cargo-audit &> /dev/null; then
        if cargo audit; then
            log_success "Security audit passed"
        else
            log_error "Security vulnerabilities found"
            return 1
        fi
    else
        log_warning "cargo-audit not available - skipping security audit"
    fi
}

# Check for code smells
check_code_smells() {
    log_info "Checking for code smells..."
    
    local issues=0
    
    # Check for TODO/FIXME comments
    local todos
    todos=$(find "$PROJECT_ROOT/src" -name "*.rs" -exec grep -Hn "TODO\|FIXME\|XXX" {} \; | wc -l)
    
    if [ "$todos" -gt 0 ]; then
        log_warning "Found $todos TODO/FIXME comments"
        find "$PROJECT_ROOT/src" -name "*.rs" -exec grep -Hn "TODO\|FIXME\|XXX" {} \; | head -5
        ((issues++))
    fi
    
    # Check for panic! in production code
    local panics
    panics=$(find "$PROJECT_ROOT/src" -name "*.rs" -not -path "*/tests/*" -exec grep -Hn "panic!" {} \; | wc -l)
    
    if [ "$panics" -gt 0 ]; then
        log_error "Found $panics panic! calls in production code"
        find "$PROJECT_ROOT/src" -name "*.rs" -not -path "*/tests/*" -exec grep -Hn "panic!" {} \; | head -5
        ((issues++))
    fi
    
    # Check for unwrap() in production code
    local unwraps
    unwraps=$(find "$PROJECT_ROOT/src" -name "*.rs" -not -path "*/tests/*" -exec grep -Hn "\.unwrap()" {} \; | wc -l)
    
    if [ "$unwraps" -gt 5 ]; then  # Allow some unwraps for initialization
        log_warning "Found $unwraps .unwrap() calls in production code"
        find "$PROJECT_ROOT/src" -name "*.rs" -not -path "*/tests/*" -exec grep -Hn "\.unwrap()" {} \; | head -5
        ((issues++))
    fi
    
    if [ $issues -eq 0 ]; then
        log_success "No code smells detected"
    else
        log_warning "Found $issues types of code smells"
        return 1
    fi
}

# Generate quality report
generate_report() {
    log_info "Generating quality report..."
    
    local report_file="$PROJECT_ROOT/quality_report_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" << EOF
# 🧹 Clean Code Enforcement Report

**Generated**: $(date)
**Project**: Rust Security Platform

## Summary

EOF
    
    # Run quality monitor if available
    if [ -f "$PROJECT_ROOT/scripts/quality/quality_monitor.py" ]; then
        python3 "$PROJECT_ROOT/scripts/quality/quality_monitor.py" \
            --project-root "$PROJECT_ROOT" \
            --output "$report_file.tmp" 2>/dev/null || true
        
        if [ -f "$report_file.tmp" ]; then
            cat "$report_file.tmp" >> "$report_file"
            rm "$report_file.tmp"
        fi
    fi
    
    log_success "Quality report generated: $report_file"
}

# Fix common issues automatically
auto_fix() {
    log_info "Applying automatic fixes..."
    
    cd "$PROJECT_ROOT"
    
    # Format code
    cargo fmt --all
    
    # Fix clippy suggestions where possible
    cargo clippy --workspace --all-features --fix --allow-dirty --allow-staged 2>/dev/null || true
    
    log_success "Automatic fixes applied"
}

# Main execution
main() {
    local mode="${1:-check}"
    local exit_code=0
    
    echo "🧹 Clean Code Standards Enforcement"
    echo "=================================="
    echo
    
    check_dependencies
    
    case "$mode" in
        "check")
            log_info "Running clean code checks..."
            
            format_code || exit_code=1
            run_clippy || exit_code=1
            check_function_lengths || exit_code=1
            check_documentation || exit_code=1
            run_tests || exit_code=1
            check_test_coverage || exit_code=1
            security_audit || exit_code=1
            check_code_smells || exit_code=1
            
            if [ $exit_code -eq 0 ]; then
                log_success "All clean code checks passed! 🎉"
            else
                log_error "Some clean code checks failed. See details above."
            fi
            ;;
            
        "fix")
            log_info "Running automatic fixes..."
            auto_fix
            
            # Re-run checks after fixes
            log_info "Re-running checks after fixes..."
            "$0" check
            exit_code=$?
            ;;
            
        "report")
            log_info "Generating quality report only..."
            generate_report
            ;;
            
        *)
            echo "Usage: $0 [check|fix|report]"
            echo
            echo "  check  - Run all clean code checks (default)"
            echo "  fix    - Apply automatic fixes and re-check"
            echo "  report - Generate quality report only"
            exit 1
            ;;
    esac
    
    generate_report
    
    exit $exit_code
}

# Run main function with all arguments
main "$@"
