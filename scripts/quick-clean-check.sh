#!/bin/bash

# 🦀 Quick Clean Code Check (without coverage tools)
# Runs essential clean code checks without problematic dependencies

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🦀 Quick Rust Clean Code Check${NC}"
echo "================================"

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
    clippy_output=$(cargo clippy --workspace --all-features 2>&1 || true)
    
    local warnings=$(echo "$clippy_output" | grep -c "warning:" || true)
    local errors=$(echo "$clippy_output" | grep -c "error:" || true)
    
    if [ "$errors" -gt 0 ]; then
        print_status "FAIL" "$errors clippy errors found"
        echo "$clippy_output" | grep "error:" | head -5
        return 1
    elif [ "$warnings" -gt 0 ]; then
        print_status "WARN" "$warnings clippy warnings found"
        echo "$clippy_output" | grep "warning:" | head -5
        return 1
    else
        print_status "OK" "No clippy issues found"
        return 0
    fi
}

# Check compilation
check_compilation() {
    echo -e "\n${BLUE}🔨 Checking compilation...${NC}"
    
    if cargo check --workspace --all-features >/dev/null 2>&1; then
        print_status "OK" "All code compiles successfully"
        return 0
    else
        print_status "FAIL" "Compilation errors found"
        cargo check --workspace --all-features
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
        cargo check --workspace --all-features 2>&1 | grep "unused" | head -5
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
        if [ "$lines" -gt 500 ]; then
            print_status "WARN" "Large file: $file ($lines lines > 500)"
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

# Generate basic metrics
generate_basic_metrics() {
    echo -e "\n${BLUE}📊 Basic code metrics...${NC}"
    
    if command -v tokei >/dev/null 2>&1; then
        echo "Lines of code:"
        tokei --exclude target | head -10
    else
        echo "Install tokei for detailed metrics: cargo install tokei"
    fi
    
    echo -e "\nWorkspace members:"
    find . -name "Cargo.toml" -not -path "./target/*" | wc -l | xargs echo "Total Cargo.toml files:"
}

# Main execution
main() {
    local exit_code=0
    
    # Run all checks
    check_compilation || exit_code=1
    check_formatting || exit_code=1
    check_clippy || exit_code=1
    check_unused_dependencies || exit_code=1
    check_file_sizes || exit_code=1
    check_security || exit_code=1
    
    generate_basic_metrics
    
    echo -e "\n${BLUE}📋 Summary${NC}"
    echo "============"
    
    if [ $exit_code -eq 0 ]; then
        print_status "OK" "All clean code checks passed!"
        echo -e "\n${GREEN}🎉 Your code meets clean code standards!${NC}"
    else
        print_status "WARN" "Some clean code checks need attention"
        echo -e "\n${YELLOW}🔧 Recommended fixes:${NC}"
        echo "  - cargo fmt --all"
        echo "  - cargo clippy --workspace --all-features --fix"
        echo "  - Review large files and consider breaking them down"
    fi
    
    exit $exit_code
}

# Run main function
main "$@"
