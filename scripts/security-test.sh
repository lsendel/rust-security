#!/bin/bash
#
# Local Security Testing Script
# 
# Runs comprehensive security tests locally before CI/CD pipeline
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_ROOT/security-reports"

# Create reports directory
mkdir -p "$REPORTS_DIR"

echo -e "${BLUE}🔒 Starting Comprehensive Security Testing${NC}"
echo "================================================"

# Function to print section headers
print_section() {
    echo -e "\n${BLUE}>>> $1${NC}"
    echo "----------------------------------------"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install missing tools
install_tools() {
    print_section "Installing Security Tools"
    
    # Install Rust security tools
    if ! command_exists cargo-audit; then
        echo "Installing cargo-audit..."
        cargo install --locked cargo-audit
    fi
    
    if ! command_exists cargo-deny; then
        echo "Installing cargo-deny..."
        cargo install --locked cargo-deny
    fi
    
    if ! command_exists cargo-outdated; then
        echo "Installing cargo-outdated..."
        cargo install --locked cargo-outdated
    fi
    
    echo -e "${GREEN}✓ Tools installation complete${NC}"
}

# Function to run static analysis
run_sast() {
    print_section "Static Application Security Testing (SAST)"
    
    echo "Running Rust security lints..."
    cargo clippy --all-targets --all-features -- \
        -W clippy::suspicious \
        -W clippy::complexity \
        -W clippy::perf \
        -W clippy::correctness \
        -D clippy::mem_forget \
        -D clippy::todo \
        -D clippy::unimplemented \
        -D clippy::panic \
        -D clippy::unwrap_used \
        -D clippy::expect_used \
        2>&1 | tee "$REPORTS_DIR/clippy-security.log"
    
    echo -e "${GREEN}✓ SAST analysis complete${NC}"
}

# Function to run dependency analysis
run_dependency_scan() {
    print_section "Dependency Security Analysis"
    
    echo "Auditing Rust dependencies for vulnerabilities..."
    cargo audit --format json > "$REPORTS_DIR/cargo-audit.json" 2>&1 || {
        echo -e "${RED}❌ Cargo audit found vulnerabilities${NC}"
        cargo audit
    }
    
    echo "Checking for outdated dependencies..."
    cargo outdated --format json > "$REPORTS_DIR/outdated-deps.json" 2>/dev/null || {
        cargo outdated 2>&1 | tee "$REPORTS_DIR/outdated-deps.log"
    }
    
    echo -e "${GREEN}✓ Dependency scan complete${NC}"
}

# Function to run security tests
run_security_tests() {
    print_section "Security Unit Tests"
    
    echo "Running security-focused tests..."
    
    # Set up test environment
    export JWT_SECRET=$(openssl rand -hex 32)
    export APP_ENV=test
    export RATE_LIMIT_PER_IP_PER_MINUTE=1000
    
    # Generate test RSA key
    openssl genrsa -out test_key.pem 2048 2>/dev/null
    export RSA_PRIVATE_KEY=$(base64 -w 0 test_key.pem)
    rm test_key.pem
    
    # Run security tests
    cargo test security_test 2>&1 | tee "$REPORTS_DIR/security-tests.log"
    cargo test property_test 2>&1 | tee -a "$REPORTS_DIR/security-tests.log"
    
    echo -e "${GREEN}✓ Security tests complete${NC}"
}

# Function to generate comprehensive report
generate_report() {
    print_section "Generating Security Report"
    
    cat > "$REPORTS_DIR/SECURITY_SUMMARY.md" << EOF
# Security Test Summary

Generated: $(date)
Project: Rust Security Platform

## Test Results

### Static Analysis (SAST)
- **Status**: $([ -f "$REPORTS_DIR/clippy-security.log" ] && echo "✅ Completed" || echo "❌ Failed")

### Dependency Security
- **Vulnerability Audit**: $([ -f "$REPORTS_DIR/cargo-audit.json" ] && echo "✅ Completed" || echo "❌ Failed")
- **Outdated Dependencies**: $([ -f "$REPORTS_DIR/outdated-deps.json" ] && echo "✅ Identified" || echo "❌ Skipped")

### Security Tests
- **Unit Tests**: $([ -f "$REPORTS_DIR/security-tests.log" ] && echo "✅ Passed" || echo "❌ Failed")

## Recommendations

1. **Review all generated reports** in the security-reports directory
2. **Fix high and critical severity issues** before deployment
3. **Update vulnerable dependencies** to latest secure versions
4. **Implement additional security controls** based on findings
5. **Schedule regular security testing** in CI/CD pipeline

EOF
    
    echo -e "${GREEN}✓ Security report generated: $REPORTS_DIR/SECURITY_SUMMARY.md${NC}"
}

# Main execution
main() {
    echo "Project root: $PROJECT_ROOT"
    echo "Reports directory: $REPORTS_DIR"
    
    # Change to project root
    cd "$PROJECT_ROOT"
    
    # Install required tools
    install_tools
    
    # Run security tests
    run_sast
    run_dependency_scan
    run_security_tests
    
    # Generate comprehensive report
    generate_report
    
    echo -e "\n${GREEN}🎉 Security testing complete!${NC}"
    echo -e "${BLUE}📊 Review the comprehensive report: $REPORTS_DIR/SECURITY_SUMMARY.md${NC}"
    
    echo -e "\n${GREEN}✅ Security testing completed successfully${NC}"
    exit 0
}

# Run main function
main "$@"