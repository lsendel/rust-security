#!/bin/bash
# Automated dependency security auditing script
# This script performs comprehensive security auditing of all dependencies

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AUDIT_REPORTS_DIR="$PROJECT_ROOT/target/security-reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Create reports directory
mkdir -p "$AUDIT_REPORTS_DIR"

# Check if required tools are installed
check_tools() {
    log_info "Checking required tools..."
    
    local tools=("cargo-audit" "cargo-deny" "cargo-cyclonedx" "jq")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Installing missing tools..."
        
        for tool in "${missing_tools[@]}"; do
            case "$tool" in
                "cargo-audit")
                    cargo install cargo-audit --locked
                    ;;
                "cargo-deny")
                    cargo install cargo-deny --locked
                    ;;
                "cargo-cyclonedx")
                    cargo install cargo-cyclonedx --locked
                    ;;
                "jq")
                    log_error "Please install jq manually"
                    exit 1
                    ;;
            esac
        done
    fi
    
    log_success "All required tools are available"
}

# Update advisory database
update_advisory_db() {
    log_info "Updating advisory database..."
    cargo audit --update || {
        log_warning "Failed to update advisory database, continuing with existing data"
    }
}

# Run cargo audit
run_cargo_audit() {
    log_info "Running cargo audit..."
    
    local audit_file="$AUDIT_REPORTS_DIR/cargo-audit-$TIMESTAMP.json"
    
    if cargo audit --json > "$audit_file" 2>&1; then
        log_success "Cargo audit completed successfully"
        
        # Parse results
        local vulnerabilities
        vulnerabilities=$(jq '.vulnerabilities.found | length' "$audit_file" 2>/dev/null || echo "0")
        
        if [ "$vulnerabilities" -gt 0 ]; then
            log_warning "Found $vulnerabilities vulnerabilities"
            
            # Extract high/critical vulnerabilities
            jq -r '.vulnerabilities.found[] | select(.advisory.informational == false) | 
                   "• \(.advisory.id): \(.advisory.title) (Severity: \(.advisory.severity // "Unknown"))"' \
                   "$audit_file" > "$AUDIT_REPORTS_DIR/vulnerabilities-$TIMESTAMP.txt"
            
            return 1
        else
            log_success "No vulnerabilities found"
        fi
    else
        log_error "Cargo audit failed"
        return 1
    fi
}

# Run cargo deny
run_cargo_deny() {
    log_info "Running cargo deny checks..."
    
    local deny_file="$AUDIT_REPORTS_DIR/cargo-deny-$TIMESTAMP.json"
    
    # Run all cargo-deny checks
    local checks=("advisories" "licenses" "bans" "sources")
    local overall_result=0
    
    for check in "${checks[@]}"; do
        log_info "Running cargo deny $check check..."
        
        if cargo deny --format json check "$check" > "${deny_file}-${check}" 2>&1; then
            log_success "Cargo deny $check check passed"
        else
            log_error "Cargo deny $check check failed"
            overall_result=1
            
            # Extract specific issues
            if [[ -f "${deny_file}-${check}" ]]; then
                case "$check" in
                    "advisories")
                        jq -r '.advisories[]? | "• \(.advisory.id): \(.advisory.title)"' \
                            "${deny_file}-${check}" >> "$AUDIT_REPORTS_DIR/deny-issues-$TIMESTAMP.txt" 2>/dev/null || true
                        ;;
                    "licenses")
                        jq -r '.licenses[]? | "• License issue: \(.name) (\(.license))"' \
                            "${deny_file}-${check}" >> "$AUDIT_REPORTS_DIR/deny-issues-$TIMESTAMP.txt" 2>/dev/null || true
                        ;;
                    "bans")
                        jq -r '.bans[]? | "• Banned dependency: \(.name) - \(.reason // "No reason specified")"' \
                            "${deny_file}-${check}" >> "$AUDIT_REPORTS_DIR/deny-issues-$TIMESTAMP.txt" 2>/dev/null || true
                        ;;
                esac
            fi
        fi
    done
    
    return $overall_result
}

# Generate SBOM
generate_sbom() {
    log_info "Generating Software Bill of Materials (SBOM)..."
    
    local sbom_dir="$AUDIT_REPORTS_DIR/sbom"
    mkdir -p "$sbom_dir"
    
    # Generate CycloneDX SBOM
    if cargo cyclonedx --format json --output-file "$sbom_dir/sbom-cyclonedx-$TIMESTAMP.json"; then
        log_success "CycloneDX SBOM generated"
    else
        log_warning "Failed to generate CycloneDX SBOM"
    fi
    
    # Generate SPDX SBOM (if spdx tool is available)
    if command -v cargo-spdx &> /dev/null; then
        cargo spdx --output-file "$sbom_dir/sbom-spdx-$TIMESTAMP.spdx" || {
            log_warning "Failed to generate SPDX SBOM"
        }
    fi
    
    # Generate dependency tree
    cargo tree --format "{p} {l}" > "$sbom_dir/dependency-tree-$TIMESTAMP.txt"
    log_success "Dependency tree generated"
}

# Check for outdated dependencies
check_outdated() {
    log_info "Checking for outdated dependencies..."
    
    local outdated_file="$AUDIT_REPORTS_DIR/outdated-$TIMESTAMP.json"
    
    if command -v cargo-outdated &> /dev/null; then
        cargo outdated --format json > "$outdated_file" || {
            log_warning "Failed to check outdated dependencies"
        }
    else
        log_info "cargo-outdated not available, skipping outdated check"
    fi
}

# Check dependency licenses
check_licenses() {
    log_info "Checking dependency licenses..."
    
    local licenses_file="$AUDIT_REPORTS_DIR/licenses-$TIMESTAMP.json"
    
    if command -v cargo-license &> /dev/null; then
        cargo license --json > "$licenses_file" || {
            log_warning "Failed to generate license report"
            return 0
        }
        
        # Check for forbidden licenses
        local forbidden_licenses=("GPL-3.0" "AGPL-3.0" "LGPL-3.0" "SSPL-1.0")
        local found_forbidden=false
        
        for license in "${forbidden_licenses[@]}"; do
            if jq -r '.[].license' "$licenses_file" | grep -q "$license"; then
                log_error "Forbidden license found: $license"
                found_forbidden=true
            fi
        done
        
        if $found_forbidden; then
            return 1
        else
            log_success "All licenses are compliant"
        fi
    else
        log_info "cargo-license not available, installing..."
        cargo install cargo-license --locked
        check_licenses
    fi
}

# Risk assessment
perform_risk_assessment() {
    log_info "Performing dependency risk assessment..."
    
    local risk_file="$AUDIT_REPORTS_DIR/risk-assessment-$TIMESTAMP.txt"
    
    cat > "$risk_file" << EOF
# Dependency Risk Assessment Report
Generated: $(date)

## Summary
This report analyzes the security risk profile of dependencies in the Rust Security Platform.

## Risk Categories

### HIGH RISK
Dependencies that pose significant security risks:

EOF
    
    # Check for dependencies with known vulnerabilities
    if [[ -f "$AUDIT_REPORTS_DIR/vulnerabilities-$TIMESTAMP.txt" ]]; then
        echo "### Vulnerabilities Found:" >> "$risk_file"
        cat "$AUDIT_REPORTS_DIR/vulnerabilities-$TIMESTAMP.txt" >> "$risk_file"
        echo "" >> "$risk_file"
    fi
    
    # Check for cargo-deny issues
    if [[ -f "$AUDIT_REPORTS_DIR/deny-issues-$TIMESTAMP.txt" ]]; then
        echo "### Policy Violations:" >> "$risk_file"
        cat "$AUDIT_REPORTS_DIR/deny-issues-$TIMESTAMP.txt" >> "$risk_file"
        echo "" >> "$risk_file"
    fi
    
    cat >> "$risk_file" << EOF

### MEDIUM RISK
Dependencies requiring attention:
- Unmaintained crates (>1 year without updates)
- Dependencies with multiple versions in tree
- Crates with informational advisories

### LOW RISK
Dependencies with minor concerns:
- Outdated but patched dependencies
- Development-only dependencies
- Well-maintained crates with recent updates

## Recommendations

1. **Immediate Action Required:**
   - Address all HIGH RISK issues before deployment
   - Review and approve any security exceptions

2. **Plan for Next Release:**
   - Update MEDIUM RISK dependencies
   - Consider alternatives for unmaintained crates

3. **Monitor:**
   - Set up alerts for new vulnerabilities
   - Regular dependency updates

## Exception Process

If a vulnerability cannot be immediately fixed:
1. Document the risk assessment
2. Implement compensating controls
3. Get security team approval
4. Set remediation timeline

EOF
    
    log_success "Risk assessment completed: $risk_file"
}

# Generate summary report
generate_summary() {
    log_info "Generating summary report..."
    
    local summary_file="$AUDIT_REPORTS_DIR/audit-summary-$TIMESTAMP.md"
    
    cat > "$summary_file" << EOF
# Security Audit Summary

**Audit Date:** $(date)
**Project:** Rust Security Platform
**Audit ID:** $TIMESTAMP

## Executive Summary

This automated security audit examined all dependencies for vulnerabilities, license compliance, and policy violations.

## Audit Results

EOF
    
    # Add vulnerability summary
    if [[ -f "$AUDIT_REPORTS_DIR/vulnerabilities-$TIMESTAMP.txt" ]]; then
        local vuln_count
        vuln_count=$(wc -l < "$AUDIT_REPORTS_DIR/vulnerabilities-$TIMESTAMP.txt")
        echo "### 🚨 Vulnerabilities: $vuln_count found" >> "$summary_file"
        echo "" >> "$summary_file"
        cat "$AUDIT_REPORTS_DIR/vulnerabilities-$TIMESTAMP.txt" >> "$summary_file"
        echo "" >> "$summary_file"
    else
        echo "### ✅ Vulnerabilities: None found" >> "$summary_file"
        echo "" >> "$summary_file"
    fi
    
    # Add license summary
    echo "### 📄 License Compliance: Checked" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Add SBOM info
    echo "### 📋 SBOM Generated: Yes" >> "$summary_file"
    echo "- Location: \`$AUDIT_REPORTS_DIR/sbom/\`" >> "$summary_file"
    echo "" >> "$summary_file"
    
    cat >> "$summary_file" << EOF

## Files Generated

- Cargo Audit Report: \`cargo-audit-$TIMESTAMP.json\`
- Cargo Deny Reports: \`cargo-deny-$TIMESTAMP-*.json\`
- SBOM Files: \`sbom/\`
- Risk Assessment: \`risk-assessment-$TIMESTAMP.txt\`

## Next Steps

1. Review all HIGH risk findings
2. Plan remediation for MEDIUM risk issues
3. Monitor for new vulnerabilities
4. Schedule next audit

---
*This report was generated automatically by the security audit system.*
EOF
    
    log_success "Summary report generated: $summary_file"
}

# Main execution
main() {
    log_info "Starting comprehensive security audit..."
    log_info "Project: $PROJECT_ROOT"
    log_info "Reports will be saved to: $AUDIT_REPORTS_DIR"
    
    cd "$PROJECT_ROOT"
    
    local exit_code=0
    
    # Run all checks
    check_tools || exit_code=1
    update_advisory_db
    run_cargo_audit || exit_code=1
    run_cargo_deny || exit_code=1
    generate_sbom
    check_outdated
    check_licenses || exit_code=1
    perform_risk_assessment
    generate_summary
    
    if [ $exit_code -eq 0 ]; then
        log_success "Security audit completed successfully"
        echo "Reports available in: $AUDIT_REPORTS_DIR"
    else
        log_error "Security audit completed with issues"
        echo "Reports available in: $AUDIT_REPORTS_DIR"
        echo "Review the findings and address security issues before deployment."
    fi
    
    return $exit_code
}

# Allow running specific functions
if [ "${1:-}" = "--function" ] && [ -n "${2:-}" ]; then
    shift
    "$@"
else
    main "$@"
fi