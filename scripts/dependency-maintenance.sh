#!/bin/bash
# Dependency Maintenance Script
# Automates dependency cleanup and validation

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if required tools are installed
check_tools() {
    print_status "Checking required tools..."
    
    local missing_tools=()
    
    if ! command -v cargo-machete &> /dev/null; then
        missing_tools+=("cargo-machete")
    fi
    
    if ! command -v cargo-audit &> /dev/null; then
        missing_tools+=("cargo-audit")
    fi
    
    if ! command -v cargo-hack &> /dev/null; then
        missing_tools+=("cargo-hack")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_warning "Missing tools: ${missing_tools[*]}"
        print_status "Installing missing tools..."
        cargo install "${missing_tools[@]}"
    fi
    
    print_success "All required tools are installed"
}

# Check for unused dependencies
check_unused_deps() {
    print_status "Checking for unused dependencies..."
    
    if cargo machete; then
        print_success "No unused dependencies found"
    else
        print_error "Unused dependencies detected - see output above"
        return 1
    fi
}

# Run security audit
security_audit() {
    print_status "Running security audit..."
    
    if cargo audit; then
        print_success "Security audit passed"
    else
        print_error "Security vulnerabilities found - see output above"
        return 1
    fi
}

# Test feature flag combinations
test_features() {
    print_status "Testing feature flag combinations..."
    
    if cargo hack check --each-feature --workspace; then
        print_success "All feature combinations build successfully"
    else
        print_error "Some feature combinations failed to build"
        return 1
    fi
}

# Clean and rebuild
clean_rebuild() {
    print_status "Performing clean rebuild..."
    
    cargo clean
    
    if cargo build --workspace --release; then
        print_success "Clean rebuild successful"
    else
        print_error "Clean rebuild failed"
        return 1
    fi
}

# Run clippy with strict warnings
strict_clippy() {
    print_status "Running clippy with strict warnings..."
    
    if cargo clippy --workspace --all-targets --all-features -- -D warnings; then
        print_success "Clippy check passed"
    else
        print_warning "Clippy found issues - review output above"
        # Don't fail on clippy warnings, just warn
    fi
}

# Generate dependency report
generate_report() {
    print_status "Generating dependency report..."
    
    local report_file="dependency-report-$(date +%Y%m%d-%H%M%S).md"
    
    {
        echo "# Dependency Report - $(date)"
        echo ""
        echo "## Cargo Tree"
        echo '```'
        cargo tree --workspace
        echo '```'
        echo ""
        echo "## Dependency Count"
        local dep_count=$(cargo tree --workspace --depth 0 | wc -l)
        echo "Total dependencies: $dep_count"
        echo ""
        echo "## Security Audit"
        echo '```'
        cargo audit || true
        echo '```'
    } > "$report_file"
    
    print_success "Report generated: $report_file"
}

# Main execution
main() {
    print_status "Starting dependency maintenance..."
    echo ""
    
    # Check tools first
    check_tools
    echo ""
    
    # Run all checks
    local failed=0
    
    check_unused_deps || ((failed++))
    echo ""
    
    security_audit || ((failed++))
    echo ""
    
    test_features || ((failed++))
    echo ""
    
    clean_rebuild || ((failed++))
    echo ""
    
    strict_clippy || true  # Don't count clippy warnings as failures
    echo ""
    
    generate_report
    echo ""
    
    if [ $failed -eq 0 ]; then
        print_success "All dependency maintenance checks passed!"
        echo ""
        print_status "Recommendations:"
        echo "  - Review any clippy warnings above"
        echo "  - Consider updating outdated dependencies"
        echo "  - Run this script monthly for best results"
    else
        print_error "$failed checks failed - review output above"
        echo ""
        print_status "Common fixes:"
        echo "  - Remove unused dependencies from Cargo.toml"
        echo "  - Update vulnerable dependencies"
        echo "  - Fix feature flag conflicts"
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Dependency Maintenance Script"
        echo ""
        echo "Usage: $0 [OPTION]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --check-only   Run checks without rebuilding"
        echo "  --report-only  Generate report only"
        echo ""
        exit 0
        ;;
    --check-only)
        check_tools
        check_unused_deps
        security_audit
        ;;
    --report-only)
        generate_report
        ;;
    *)
        main
        ;;
esac