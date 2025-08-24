#!/bin/bash

# 🦀 Rust Clean Code Enforcement Script
# Automatically enforces clean code standards across the workspace

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MAX_FUNCTION_LINES=100
MAX_FILE_LINES=500
MAX_CYCLOMATIC_COMPLEXITY=10
MIN_TEST_COVERAGE=90

echo -e "${BLUE}🦀 Rust Clean Code Enforcement${NC}"
echo "=================================="

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "OK" ]; then
        echo -e "${GREEN}✅ $message${NC}"
    elif [ "$status" = "WARN" ]; then
        echo -e "${YELLOW}⚠️  $message${NC}"
    else
        echo -e "${RED}❌ $message${NC}"
    fi
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install required tools if missing
install_tools() {
    echo -e "${BLUE}📦 Checking required tools...${NC}"
    
    if ! command_exists "cargo-clippy"; then
        echo "Installing clippy..."
        rustup component add clippy
    fi
    
    if ! command_exists "cargo-fmt"; then
        echo "Installing rustfmt..."
        rustup component add rustfmt
    fi
    
    if ! command_exists "cargo-audit"; then
        echo "Installing cargo-audit..."
        cargo install cargo-audit
    fi
    
    if ! command_exists "cargo-tarpaulin"; then
        echo "Installing cargo-tarpaulin for coverage..."
        cargo install cargo-tarpaulin
    fi
    
    if ! command_exists "tokei"; then
        echo "Installing tokei for line counting..."
        cargo install tokei
    fi
    
    print_status "OK" "All required tools are available"
}

# Check code formatting
check_formatting() {
    echo -e "\n${BLUE}🎨 Checking code formatting...${NC}"
    
    if cargo fmt --all -- --check >/dev/null 2>&1; then
        print_status "OK" "Code formatting is consistent"
        return 0
    else
        print_status "FAIL" "Code formatting issues found"
        echo "Run 'cargo fmt --all' to fix formatting"
        return 1
    fi
}

# Check for clippy warnings
check_clippy() {
    echo -e "\n${BLUE}📎 Running clippy analysis...${NC}"
    
    local clippy_output
    clippy_output=$(cargo clippy --workspace --all-features --message-format=json 2>&1 | jq -r 'select(.reason == "compiler-message") | .message.message' 2>/dev/null || echo "")
    
    if [ -z "$clippy_output" ]; then
        print_status "OK" "No clippy warnings found"
        return 0
    else
        print_status "FAIL" "Clippy warnings found:"
        echo "$clippy_output"
        return 1
    fi
}

# Check for unused dependencies
check_unused_dependencies() {
    echo -e "\n${BLUE}📦 Checking for unused dependencies...${NC}"
    
    local unused_deps
    unused_deps=$(cargo check --workspace --all-features 2>&1 | grep "unused" | wc -l)
    
    if [ "$unused_deps" -eq 0 ]; then
        print_status "OK" "No unused dependencies found"
        return 0
    else
        print_status "WARN" "$unused_deps unused dependencies found"
        cargo check --workspace --all-features 2>&1 | grep "unused"
        return 1
    fi
}

# Check file sizes
check_file_sizes() {
    echo -e "\n${BLUE}📏 Checking file sizes...${NC}"
    
    local large_files=0
    
    while IFS= read -r -d '' file; do
        local lines
        lines=$(wc -l < "$file")
        if [ "$lines" -gt $MAX_FILE_LINES ]; then
            print_status "WARN" "Large file: $file ($lines lines > $MAX_FILE_LINES)"
            ((large_files++))
        fi
    done < <(find . -name "*.rs" -not -path "./target/*" -not -path "./.git/*" -print0)
    
    if [ "$large_files" -eq 0 ]; then
        print_status "OK" "All files are within size limits"
        return 0
    else
        print_status "WARN" "$large_files files exceed size limits"
        return 1
    fi
}

# Check function complexity (simplified check for long functions)
check_function_complexity() {
    echo -e "\n${BLUE}🧠 Checking function complexity...${NC}"
    
    local complex_functions=0
    
    # Simple heuristic: count lines between 'fn ' and matching '}'
    while IFS= read -r -d '' file; do
        local in_function=false
        local function_name=""
        local function_lines=0
        local brace_count=0
        
        while IFS= read -r line; do
            if [[ $line =~ ^[[:space:]]*pub[[:space:]]+fn[[:space:]]+([a-zA-Z_][a-zA-Z0-9_]*) ]] || [[ $line =~ ^[[:space:]]*fn[[:space:]]+([a-zA-Z_][a-zA-Z0-9_]*) ]]; then
                if [ "$in_function" = true ] && [ "$function_lines" -gt $MAX_FUNCTION_LINES ]; then
                    print_status "WARN" "Large function: $function_name in $file ($function_lines lines)"
                    ((complex_functions++))
                fi
                in_function=true
                function_name="${BASH_REMATCH[1]}"
                function_lines=0
                brace_count=0
            fi
            
            if [ "$in_function" = true ]; then
                ((function_lines++))
                # Count braces to detect function end
                local open_braces
                local close_braces
                open_braces=$(echo "$line" | tr -cd '{' | wc -c)
                close_braces=$(echo "$line" | tr -cd '}' | wc -c)
                ((brace_count += open_braces - close_braces))
                
                if [ "$brace_count" -lt 0 ]; then
                    if [ "$function_lines" -gt $MAX_FUNCTION_LINES ]; then
                        print_status "WARN" "Large function: $function_name in $file ($function_lines lines)"
                        ((complex_functions++))
                    fi
                    in_function=false
                fi
            fi
        done < "$file"
    done < <(find . -name "*.rs" -not -path "./target/*" -not -path "./.git/*" -print0)
    
    if [ "$complex_functions" -eq 0 ]; then
        print_status "OK" "All functions are within complexity limits"
        return 0
    else
        print_status "WARN" "$complex_functions functions exceed complexity limits"
        return 1
    fi
}

# Check test coverage
check_test_coverage() {
    echo -e "\n${BLUE}🧪 Checking test coverage...${NC}"
    
    if ! command_exists "cargo-tarpaulin"; then
        print_status "WARN" "cargo-tarpaulin not installed, skipping coverage check"
        return 1
    fi
    
    local coverage_output
    coverage_output=$(cargo tarpaulin --workspace --all-features --skip-clean --out Stdout 2>/dev/null | tail -1)
    
    if [[ $coverage_output =~ ([0-9]+\.[0-9]+)% ]]; then
        local coverage="${BASH_REMATCH[1]}"
        local coverage_int=${coverage%.*}
        
        if [ "$coverage_int" -ge $MIN_TEST_COVERAGE ]; then
            print_status "OK" "Test coverage: $coverage% (>= $MIN_TEST_COVERAGE%)"
            return 0
        else
            print_status "WARN" "Test coverage: $coverage% (< $MIN_TEST_COVERAGE%)"
            return 1
        fi
    else
        print_status "WARN" "Could not determine test coverage"
        return 1
    fi
}

# Check security vulnerabilities
check_security() {
    echo -e "\n${BLUE}🔒 Checking security vulnerabilities...${NC}"
    
    if cargo audit >/dev/null 2>&1; then
        print_status "OK" "No security vulnerabilities found"
        return 0
    else
        print_status "FAIL" "Security vulnerabilities found"
        cargo audit
        return 1
    fi
}

# Generate code metrics report
generate_metrics_report() {
    echo -e "\n${BLUE}📊 Generating code metrics report...${NC}"
    
    local report_file="code_metrics_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" << EOF
# Code Metrics Report

Generated: $(date)

## Overview

EOF
    
    if command_exists "tokei"; then
        echo "## Lines of Code" >> "$report_file"
        echo '```' >> "$report_file"
        tokei --exclude target >> "$report_file"
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    echo "## Workspace Structure" >> "$report_file"
    echo '```' >> "$report_file"
    find . -name "Cargo.toml" -not -path "./target/*" | head -20 >> "$report_file"
    echo '```' >> "$report_file"
    
    print_status "OK" "Metrics report generated: $report_file"
}

# Main execution
main() {
    local exit_code=0
    
    install_tools
    
    # Run all checks
    check_formatting || exit_code=1
    check_clippy || exit_code=1
    check_unused_dependencies || exit_code=1
    check_file_sizes || exit_code=1
    check_function_complexity || exit_code=1
    check_test_coverage || exit_code=1
    check_security || exit_code=1
    
    generate_metrics_report
    
    echo -e "\n${BLUE}📋 Summary${NC}"
    echo "============"
    
    if [ $exit_code -eq 0 ]; then
        print_status "OK" "All clean code checks passed!"
        echo -e "\n${GREEN}🎉 Your code meets clean code standards!${NC}"
    else
        print_status "FAIL" "Some clean code checks failed"
        echo -e "\n${RED}🔧 Please address the issues above${NC}"
        echo -e "${YELLOW}💡 Run individual commands to fix specific issues:${NC}"
        echo "  - cargo fmt --all"
        echo "  - cargo clippy --workspace --all-features --fix"
        echo "  - Remove unused dependencies from Cargo.toml files"
    fi
    
    exit $exit_code
}

# Run main function
main "$@"
