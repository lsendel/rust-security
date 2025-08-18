#!/bin/bash

# Weekly Security Maintenance Script for Rust Security Workspace
# This script performs comprehensive security checks and maintenance tasks

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if required tools are installed
check_dependencies() {
    log "Checking required dependencies..."
    
    local missing_tools=()
    
    if ! command -v cargo &> /dev/null; then
        missing_tools+=("cargo")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        error "Missing required tools: ${missing_tools[*]}"
        error "Please install missing tools and try again"
        exit 1
    fi
    
    success "All dependencies are available"
}

# Install security tools if not present
install_security_tools() {
    log "Installing/updating security tools..."
    
    # Install cargo-audit
    if ! command -v cargo-audit &> /dev/null; then
        log "Installing cargo-audit..."
        cargo install cargo-audit
    else
        log "Updating cargo-audit..."
        cargo install --force cargo-audit
    fi
    
    # Install cargo-deny
    if ! command -v cargo-deny &> /dev/null; then
        log "Installing cargo-deny..."
        cargo install cargo-deny
    else
        log "Updating cargo-deny..."
        cargo install --force cargo-deny
    fi
    
    # Install cargo-outdated
    if ! command -v cargo-outdated &> /dev/null; then
        log "Installing cargo-outdated..."
        cargo install cargo-outdated
    fi
    
    # Install cargo-tarpaulin for coverage
    if ! command -v cargo-tarpaulin &> /dev/null; then
        log "Installing cargo-tarpaulin..."
        cargo install cargo-tarpaulin
    fi
    
    success "Security tools installed/updated"
}

# Run security audit
run_security_audit() {
    log "Running security audit..."
    
    local audit_output
    local audit_exit_code=0
    
    # Run cargo audit and capture output
    if audit_output=$(cargo audit --json 2>&1); then
        local vuln_count
        vuln_count=$(echo "$audit_output" | jq '.vulnerabilities | length' 2>/dev/null || echo "0")
        
        if [ "$vuln_count" -eq 0 ]; then
            success "No security vulnerabilities found"
        else
            warning "Found $vuln_count security vulnerabilities"
            echo "$audit_output" | jq '.vulnerabilities[] | {id: .advisory.id, package: .package.name, version: .package.version, title: .advisory.title}' 2>/dev/null || true
            audit_exit_code=1
        fi
    else
        error "Security audit failed"
        echo "$audit_output"
        audit_exit_code=1
    fi
    
    # Save audit results
    echo "$audit_output" > "security_audit_$(date +%Y%m%d_%H%M%S).json"
    
    return $audit_exit_code
}

# Run dependency policy check
run_dependency_check() {
    log "Running dependency policy check..."
    
    if cargo deny check --all-features; then
        success "Dependency policy check passed"
        return 0
    else
        warning "Dependency policy check found issues"
        return 1
    fi
}

# Check for outdated dependencies
check_outdated_dependencies() {
    log "Checking for outdated dependencies..."
    
    if command -v cargo-outdated &> /dev/null; then
        local outdated_output
        if outdated_output=$(cargo outdated --format json 2>/dev/null); then
            local outdated_count
            outdated_count=$(echo "$outdated_output" | jq '.dependencies | length' 2>/dev/null || echo "0")
            
            if [ "$outdated_count" -eq 0 ]; then
                success "All dependencies are up to date"
            else
                warning "Found $outdated_count outdated dependencies"
                cargo outdated
            fi
        else
            warning "Could not check outdated dependencies"
        fi
    else
        warning "cargo-outdated not available, skipping outdated check"
    fi
}

# Run security linting
run_security_linting() {
    log "Running security linting..."
    
    local lint_issues=0
    
    # Run clippy with security-focused lints
    if ! cargo clippy --all-targets --all-features -- \
        -W clippy::suspicious \
        -W clippy::security \
        -W clippy::panic \
        -W clippy::unwrap_used \
        -W clippy::expect_used \
        -D warnings; then
        warning "Security linting found issues"
        lint_issues=1
    fi
    
    if [ $lint_issues -eq 0 ]; then
        success "Security linting passed"
    fi
    
    return $lint_issues
}

# Check code formatting
check_formatting() {
    log "Checking code formatting..."
    
    if cargo fmt --all -- --check; then
        success "Code formatting is correct"
        return 0
    else
        warning "Code formatting issues found"
        return 1
    fi
}

# Run tests with coverage
run_test_coverage() {
    log "Running tests with coverage..."
    
    if command -v cargo-tarpaulin &> /dev/null; then
        if cargo tarpaulin --all --all-features --timeout 120 --out Json --output-dir ./coverage/; then
            success "Test coverage completed"
            
            # Extract coverage percentage if available
            if [ -f "./coverage/tarpaulin-report.json" ]; then
                local coverage
                coverage=$(jq '.files | map(.coverage) | add / length' ./coverage/tarpaulin-report.json 2>/dev/null || echo "unknown")
                log "Test coverage: ${coverage}%"
            fi
        else
            warning "Test coverage failed"
            return 1
        fi
    else
        warning "cargo-tarpaulin not available, running regular tests"
        cargo test --all --all-features
    fi
}

# Generate security report
generate_security_report() {
    log "Generating security report..."
    
    local report_file="security_report_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" << EOF
# Security Maintenance Report

**Generated:** $(date)
**Project:** Rust Security Workspace

## Summary

This report contains the results of automated security maintenance checks.

## Security Audit Results

$(if [ -f "security_audit_$(date +%Y%m%d)_"*.json ]; then
    echo "See attached JSON file for detailed vulnerability information."
else
    echo "No recent audit results found."
fi)

## Dependency Status

- **Policy Check:** $(if cargo deny check --all-features &>/dev/null; then echo "✅ PASSED"; else echo "❌ FAILED"; fi)
- **Outdated Dependencies:** $(if command -v cargo-outdated &>/dev/null; then cargo outdated --format json 2>/dev/null | jq '.dependencies | length' || echo "Unknown"; else echo "Not checked"; fi)

## Code Quality

- **Security Linting:** $(if cargo clippy --all-targets --all-features -- -W clippy::suspicious -D warnings &>/dev/null; then echo "✅ PASSED"; else echo "❌ FAILED"; fi)
- **Formatting:** $(if cargo fmt --all -- --check &>/dev/null; then echo "✅ PASSED"; else echo "❌ FAILED"; fi)

## Recommendations

1. Review any security vulnerabilities found in the audit
2. Update outdated dependencies where appropriate
3. Address any linting issues
4. Ensure code formatting is consistent

## Next Steps

- Schedule next security maintenance for $(date -d '+1 week' +%Y-%m-%d)
- Monitor security advisories for new vulnerabilities
- Review and update security policies as needed

EOF

    success "Security report generated: $report_file"
}

# Main execution
main() {
    log "Starting weekly security maintenance for Rust Security Workspace"
    log "=================================================="
    
    local exit_code=0
    
    # Check dependencies
    check_dependencies
    
    # Install/update security tools
    install_security_tools
    
    # Run security checks
    if ! run_security_audit; then
        exit_code=1
    fi
    
    if ! run_dependency_check; then
        exit_code=1
    fi
    
    check_outdated_dependencies
    
    if ! run_security_linting; then
        exit_code=1
    fi
    
    if ! check_formatting; then
        exit_code=1
    fi
    
    run_test_coverage
    
    # Generate report
    generate_security_report
    
    log "=================================================="
    if [ $exit_code -eq 0 ]; then
        success "Security maintenance completed successfully"
    else
        warning "Security maintenance completed with issues (exit code: $exit_code)"
    fi
    
    log "Next maintenance recommended: $(date -d '+1 week' +%Y-%m-%d)"
    
    exit $exit_code
}

# Run main function
main "$@"
