#!/bin/bash

# Comprehensive Security Testing Suite
# Automates security testing across multiple dimensions

set -euo pipefail

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_OUTPUT_DIR="$PROJECT_ROOT/security-test-results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_FILE="$TEST_OUTPUT_DIR/security_test_results_$TIMESTAMP.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Initialize test results
TEST_RESULTS='{
  "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
  "project": "rust-security",
  "tests": [],
  "summary": {
    "total": 0,
    "passed": 0,
    "failed": 0,
    "warnings": 0
  }
}'

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

# Add test result
add_test_result() {
    local test_name="$1"
    local status="$2"
    local message="$3"
    local severity="${4:-medium}"
    
    TEST_RESULTS=$(echo "$TEST_RESULTS" | jq --arg name "$test_name" --arg status "$status" --arg msg "$message" --arg sev "$severity" '
        .tests += [{
            "name": $name,
            "status": $status,
            "message": $msg,
            "severity": $sev,
            "timestamp": (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
        }] |
        .summary.total += 1 |
        if $status == "passed" then .summary.passed += 1
        elif $status == "failed" then .summary.failed += 1
        else .summary.warnings += 1
        end
    ')
}

# Initialize test environment
initialize_tests() {
    log_info "Initializing security test environment"
    
    mkdir -p "$TEST_OUTPUT_DIR"
    cd "$PROJECT_ROOT"
    
    # Install required tools if not present
    command -v cargo-audit >/dev/null 2>&1 || {
        log_info "Installing cargo-audit..."
        cargo install cargo-audit
    }
    
    command -v cargo-deny >/dev/null 2>&1 || {
        log_info "Installing cargo-deny..."
        cargo install cargo-deny
    }
    
    # Check for additional tools
    if ! command -v semgrep >/dev/null 2>&1; then
        log_warning "semgrep not found - SAST analysis will be skipped"
    fi
    
    if ! command -v trivy >/dev/null 2>&1; then
        log_warning "trivy not found - container scanning will be skipped"
    fi
}

# Test 1: Dependency Vulnerability Scanning
test_dependency_vulnerabilities() {
    log_info "Running dependency vulnerability scan..."
    
    local test_name="dependency_vulnerabilities"
    
    if cargo audit --json > "$TEST_OUTPUT_DIR/cargo_audit.json" 2>&1; then
        local vuln_count=$(jq '.vulnerabilities.count' "$TEST_OUTPUT_DIR/cargo_audit.json" 2>/dev/null || echo "0")
        
        if [ "$vuln_count" -eq 0 ]; then
            log_success "No dependency vulnerabilities found"
            add_test_result "$test_name" "passed" "No vulnerabilities detected" "low"
        else
            log_error "$vuln_count dependency vulnerabilities found"
            add_test_result "$test_name" "failed" "$vuln_count vulnerabilities detected" "high"
        fi
    else
        log_error "Failed to run cargo audit"
        add_test_result "$test_name" "failed" "cargo audit execution failed" "high"
    fi
}

# Test 2: Supply Chain Policy Compliance
test_supply_chain_policy() {
    log_info "Checking supply chain policy compliance..."
    
    local test_name="supply_chain_policy"
    
    if cargo deny check > "$TEST_OUTPUT_DIR/cargo_deny.txt" 2>&1; then
        log_success "Supply chain policy compliance verified"
        add_test_result "$test_name" "passed" "All policies compliant" "low"
    else
        local violations=$(grep -c "error" "$TEST_OUTPUT_DIR/cargo_deny.txt" || echo "0")
        log_error "$violations supply chain policy violations"
        add_test_result "$test_name" "failed" "$violations policy violations" "medium"
    fi
}

# Test 3: Static Application Security Testing (SAST)
test_sast_analysis() {
    log_info "Running static application security testing..."
    
    local test_name="sast_analysis"
    
    if command -v semgrep >/dev/null 2>&1; then
        if semgrep --config=auto --json --output="$TEST_OUTPUT_DIR/semgrep.json" . 2>/dev/null; then
            local findings=$(jq '.results | length' "$TEST_OUTPUT_DIR/semgrep.json" 2>/dev/null || echo "0")
            
            if [ "$findings" -eq 0 ]; then
                log_success "No SAST findings detected"
                add_test_result "$test_name" "passed" "No security issues found" "low"
            else
                log_warning "$findings SAST findings detected"
                add_test_result "$test_name" "warning" "$findings security findings" "medium"
            fi
        else
            log_error "SAST analysis failed"
            add_test_result "$test_name" "failed" "semgrep execution failed" "medium"
        fi
    else
        log_warning "Semgrep not available - skipping SAST analysis"
        add_test_result "$test_name" "skipped" "semgrep not installed" "low"
    fi
}

# Test 4: Secret Detection
test_secret_detection() {
    log_info "Scanning for exposed secrets..."
    
    local test_name="secret_detection"
    
    # Use multiple patterns to detect secrets
    local secret_patterns=(
        "password\s*[:=]\s*[\"'][^\"']*[\"']"
        "api_key\s*[:=]\s*[\"'][^\"']*[\"']"
        "secret\s*[:=]\s*[\"'][^\"']*[\"']"
        "token\s*[:=]\s*[\"'][^\"']*[\"']"
        "-----BEGIN (RSA )?PRIVATE KEY-----"
        "AKIA[0-9A-Z]{16}"  # AWS Access Key
    )
    
    local secrets_found=0
    
    for pattern in "${secret_patterns[@]}"; do
        if grep -rE "$pattern" --include="*.rs" --include="*.toml" --include="*.yml" --include="*.yaml" . > "$TEST_OUTPUT_DIR/secrets_temp.txt" 2>/dev/null; then
            secrets_found=$((secrets_found + $(wc -l < "$TEST_OUTPUT_DIR/secrets_temp.txt")))
        fi
    done
    
    if [ "$secrets_found" -eq 0 ]; then
        log_success "No exposed secrets detected"
        add_test_result "$test_name" "passed" "No secrets found" "low"
    else
        log_error "$secrets_found potential secrets detected"
        add_test_result "$test_name" "failed" "$secrets_found potential secrets" "high"
    fi
    
    rm -f "$TEST_OUTPUT_DIR/secrets_temp.txt"
}

# Test 5: Container Security Scanning
test_container_security() {
    log_info "Scanning container configurations..."
    
    local test_name="container_security"
    
    if command -v trivy >/dev/null 2>&1; then
        # Scan Dockerfiles if present
        local dockerfile_issues=0
        
        find . -name "Dockerfile*" -type f | while read -r dockerfile; do
            if trivy config "$dockerfile" --format json > "$TEST_OUTPUT_DIR/trivy_$(basename "$dockerfile").json" 2>/dev/null; then
                local issues=$(jq '.Results[0].Misconfigurations | length' "$TEST_OUTPUT_DIR/trivy_$(basename "$dockerfile").json" 2>/dev/null || echo "0")
                dockerfile_issues=$((dockerfile_issues + issues))
            fi
        done
        
        if [ "$dockerfile_issues" -eq 0 ]; then
            log_success "No container security issues found"
            add_test_result "$test_name" "passed" "Container configs secure" "low"
        else
            log_warning "$dockerfile_issues container security issues found"
            add_test_result "$test_name" "warning" "$dockerfile_issues configuration issues" "medium"
        fi
    else
        log_warning "Trivy not available - skipping container security scan"
        add_test_result "$test_name" "skipped" "trivy not installed" "low"
    fi
}

# Test 6: Kubernetes Security Policy Validation
test_kubernetes_security() {
    log_info "Validating Kubernetes security policies..."
    
    local test_name="kubernetes_security"
    local k8s_issues=0
    
    # Check for security context violations
    if find k8s/ -name "*.yaml" -type f 2>/dev/null | head -1 >/dev/null; then
        while IFS= read -r -d '' manifest; do
            # Check for runAsRoot: true
            if grep -q "runAsRoot: true" "$manifest"; then
                log_warning "Found runAsRoot: true in $manifest"
                k8s_issues=$((k8s_issues + 1))
            fi
            
            # Check for privileged: true
            if grep -q "privileged: true" "$manifest"; then
                log_error "Found privileged: true in $manifest"
                k8s_issues=$((k8s_issues + 1))
            fi
            
            # Check for allowPrivilegeEscalation: true
            if grep -q "allowPrivilegeEscalation: true" "$manifest"; then
                log_error "Found allowPrivilegeEscalation: true in $manifest"
                k8s_issues=$((k8s_issues + 1))
            fi
            
        done < <(find k8s/ -name "*.yaml" -type f -print0 2>/dev/null)
        
        if [ "$k8s_issues" -eq 0 ]; then
            log_success "Kubernetes security policies validated"
            add_test_result "$test_name" "passed" "All K8s configs secure" "low"
        else
            log_error "$k8s_issues Kubernetes security issues found"
            add_test_result "$test_name" "failed" "$k8s_issues K8s security violations" "high"
        fi
    else
        log_info "No Kubernetes manifests found - skipping K8s security check"
        add_test_result "$test_name" "skipped" "No K8s manifests present" "low"
    fi
}

# Test 7: License Compliance
test_license_compliance() {
    log_info "Checking license compliance..."
    
    local test_name="license_compliance"
    
    # Check if project has license
    if [ ! -f "LICENSE" ] && [ ! -f "LICENSE.txt" ] && [ ! -f "LICENSE.md" ]; then
        log_warning "No LICENSE file found"
        add_test_result "$test_name" "warning" "Missing LICENSE file" "medium"
        return
    fi
    
    # Check Cargo.toml for license field
    if ! grep -q "license.*=" Cargo.toml 2>/dev/null; then
        log_warning "No license field in Cargo.toml"
        add_test_result "$test_name" "warning" "Missing license in Cargo.toml" "medium"
        return
    fi
    
    log_success "License compliance verified"
    add_test_result "$test_name" "passed" "License compliance OK" "low"
}

# Test 8: Code Quality Security Checks
test_code_quality_security() {
    log_info "Running security-focused code quality checks..."
    
    local test_name="code_quality_security"
    local issues=0
    
    # Check for unsafe blocks
    local unsafe_count=$(find . -name "*.rs" -type f -exec grep -c "unsafe" {} + 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
    
    if [ "$unsafe_count" -gt 0 ]; then
        log_warning "$unsafe_count unsafe blocks found - review for security implications"
        issues=$((issues + 1))
    fi
    
    # Check for unwrap() calls (potential panics)
    local unwrap_count=$(find . -name "*.rs" -type f -exec grep -c "\.unwrap()" {} + 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
    
    if [ "$unwrap_count" -gt 50 ]; then  # Allow some unwraps but warn on excessive use
        log_warning "$unwrap_count unwrap() calls found - consider proper error handling"
        issues=$((issues + 1))
    fi
    
    # Check for TODO/FIXME comments related to security
    local security_todos=$(grep -rn -i "TODO.*security\|FIXME.*security" --include="*.rs" . | wc -l)
    
    if [ "$security_todos" -gt 0 ]; then
        log_warning "$security_todos security-related TODO/FIXME comments found"
        issues=$((issues + 1))
    fi
    
    if [ "$issues" -eq 0 ]; then
        log_success "Code quality security checks passed"
        add_test_result "$test_name" "passed" "No security code quality issues" "low"
    else
        log_warning "$issues code quality security concerns found"
        add_test_result "$test_name" "warning" "$issues security code quality issues" "medium"
    fi
}

# Generate security test report
generate_report() {
    log_info "Generating security test report..."
    
    # Save JSON results
    echo "$TEST_RESULTS" > "$RESULTS_FILE"
    
    # Generate human-readable report
    local report_file="$TEST_OUTPUT_DIR/security_test_report_$TIMESTAMP.md"
    
    {
        echo "# Security Test Report"
        echo ""
        echo "**Generated:** $(date)"
        echo "**Project:** rust-security"
        echo ""
        
        # Summary
        local total=$(echo "$TEST_RESULTS" | jq '.summary.total')
        local passed=$(echo "$TEST_RESULTS" | jq '.summary.passed')
        local failed=$(echo "$TEST_RESULTS" | jq '.summary.failed')
        local warnings=$(echo "$TEST_RESULTS" | jq '.summary.warnings')
        
        echo "## Summary"
        echo ""
        echo "- **Total Tests:** $total"
        echo "- **Passed:** $passed"
        echo "- **Failed:** $failed"
        echo "- **Warnings:** $warnings"
        echo ""
        
        # Calculate security score
        local score=$(echo "scale=1; ($passed * 100) / $total" | bc -l)
        echo "**Security Score:** $score%"
        echo ""
        
        # Detailed results
        echo "## Test Results"
        echo ""
        
        echo "$TEST_RESULTS" | jq -r '.tests[] | "### \(.name)\n- **Status:** \(.status)\n- **Message:** \(.message)\n- **Severity:** \(.severity)\n"'
        
    } > "$report_file"
    
    log_success "Report generated: $report_file"
    
    # Display summary
    echo ""
    echo "========================================"
    echo "        SECURITY TEST SUMMARY"
    echo "========================================"
    echo "Total Tests: $total"
    echo "Passed:      $passed"
    echo "Failed:      $failed"
    echo "Warnings:    $warnings"
    echo "Security Score: $score%"
    echo "========================================"
}

# Main execution
main() {
    echo "========================================="
    echo "     Security Testing Suite"
    echo "========================================="
    echo ""
    
    initialize_tests
    
    # Run all security tests
    test_dependency_vulnerabilities
    test_supply_chain_policy
    test_sast_analysis
    test_secret_detection
    test_container_security
    test_kubernetes_security
    test_license_compliance
    test_code_quality_security
    
    # Generate final report
    generate_report
    
    # Exit with appropriate code
    local failed=$(echo "$TEST_RESULTS" | jq '.summary.failed')
    if [ "$failed" -gt 0 ]; then
        exit 1
    fi
}

# Execute main function
main "$@"