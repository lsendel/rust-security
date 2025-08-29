#!/bin/bash
# Automated dependency vulnerability scanning and compliance checking
# This script performs comprehensive dependency analysis for security and compliance

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
REPORTS_DIR="${PROJECT_ROOT}/security-reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create reports directory
mkdir -p "${REPORTS_DIR}"

echo -e "${BLUE}🔍 Starting Automated Dependency Audit${NC}"
echo "Reports will be saved to: ${REPORTS_DIR}"

# Function to run audit tool and capture results
run_audit_tool() {
    local tool_name="$1"
    local command="$2"
    local output_file="${REPORTS_DIR}/${TIMESTAMP}_${tool_name}.txt"
    local exit_code=0

    echo -e "${YELLOW}Running ${tool_name}...${NC}"

    if eval "${command}" > "${output_file}" 2>&1; then
        echo -e "${GREEN}✅ ${tool_name} completed successfully${NC}"
    else
        exit_code=$?
        echo -e "${RED}❌ ${tool_name} failed with exit code ${exit_code}${NC}"
        echo "Check ${output_file} for details"
    fi

    return $exit_code
}

# 1. Cargo Audit - Check for known security vulnerabilities
echo -e "${BLUE}🔒 Checking for security vulnerabilities...${NC}"
AUDIT_EXIT_CODE=0
run_audit_tool "cargo_audit" "cargo audit --format json --deny warnings" || AUDIT_EXIT_CODE=$?

# Parse audit results
if [ -f "${REPORTS_DIR}/${TIMESTAMP}_cargo_audit.txt" ]; then
    VULN_COUNT=$(grep -c '"vulnerability"' "${REPORTS_DIR}/${TIMESTAMP}_cargo_audit.txt" 2>/dev/null || echo "0")
    if [ "$VULN_COUNT" -gt 0 ]; then
        echo -e "${RED}🚨 Found ${VULN_COUNT} security vulnerabilities!${NC}"
    else
        echo -e "${GREEN}✅ No security vulnerabilities found${NC}"
    fi
fi

# 2. Cargo Deny - Check licenses and bans
echo -e "${BLUE}⚖️  Checking license compliance...${NC}"
DENY_EXIT_CODE=0
run_audit_tool "cargo_deny_licenses" "cargo deny check licenses" || DENY_EXIT_CODE=$?

run_audit_tool "cargo_deny_bans" "cargo deny check bans" || DENY_EXIT_CODE=$?

run_audit_tool "cargo_deny_sources" "cargo deny check sources" || DENY_EXIT_CODE=$?

# 3. Cargo Outdated - Check for outdated dependencies
echo -e "${BLUE}📦 Checking for outdated dependencies...${NC}"
run_audit_tool "cargo_outdated" "cargo outdated --exit-code 1" || true

# 4. Cargo Tree - Analyze dependency tree
echo -e "${BLUE}🌳 Analyzing dependency tree...${NC}"
run_audit_tool "cargo_tree" "cargo tree --all-features"

# 5. Cargo Geiger - Check for unsafe code in dependencies
echo -e "${BLUE}⚠️  Analyzing unsafe code in dependencies...${NC}"
if command -v "cargo-geiger" >/dev/null 2>&1; then
    run_audit_tool "cargo_geiger" "cargo geiger --all-features"
else
    echo -e "${YELLOW}⚠️  cargo-geiger not installed, skipping unsafe analysis${NC}"
    echo "Install with: cargo install cargo-geiger" > "${REPORTS_DIR}/${TIMESTAMP}_cargo_geiger.txt"
fi

# 6. SBOM Generation
echo -e "${BLUE}📋 Generating Software Bill of Materials...${NC}"
if command -v "cargo-sbom" >/dev/null 2>&1; then
    run_audit_tool "cargo_sbom" "cargo sbom --output-format json"
else
    echo -e "${YELLOW}⚠️  cargo-sbom not installed, skipping SBOM generation${NC}"
    echo "Install with: cargo install cargo-sbom" > "${REPORTS_DIR}/${TIMESTAMP}_cargo_sbom.txt"
fi

# 7. Dependency size analysis
echo -e "${BLUE}📊 Analyzing dependency sizes...${NC}"
run_audit_tool "cargo_bloat" "cargo bloat --release --all-features"

# 8. Check for unmaintained dependencies
echo -e "${BLUE}🕰️  Checking for unmaintained dependencies...${NC}"
run_audit_tool "cargo_unmaintained" "cargo +nightly udeps --all-targets --all-features" || true

# Generate comprehensive audit report
echo -e "${BLUE}📊 Generating comprehensive audit report...${NC}"
AUDIT_REPORT="${REPORTS_DIR}/${TIMESTAMP}_dependency_audit_report.md"

cat > "${AUDIT_REPORT}" << EOF
# Dependency Audit Report
**Date:** $(date)
**Project:** Rust Security Platform
**Audit ID:** ${TIMESTAMP}

## Executive Summary

This report provides a comprehensive analysis of the project's dependencies for security, compliance, and maintenance purposes.

## Audit Results

### Security Vulnerabilities
EOF

if [ -f "${REPORTS_DIR}/${TIMESTAMP}_cargo_audit.txt" ]; then
    if [ "$VULN_COUNT" -gt 0 ]; then
        cat >> "${AUDIT_REPORT}" << EOF
🚨 **CRITICAL**: Found ${VULN_COUNT} security vulnerabilities that must be addressed immediately.

**Details:**
\`\`\`json
$(cat "${REPORTS_DIR}/${TIMESTAMP}_cargo_audit.txt")
\`\`\`

**Recommended Actions:**
1. Update vulnerable dependencies to secure versions
2. If updates are not available, implement mitigations
3. Consider alternative dependencies if necessary
4. Update risk assessment and security documentation
EOF
    else
        cat >> "${AUDIT_REPORT}" << EOF
✅ **PASS**: No security vulnerabilities found in dependencies.
EOF
    fi
fi

cat >> "${AUDIT_REPORT}" << EOF

### License Compliance
EOF

if [ -f "${REPORTS_DIR}/${TIMESTAMP}_cargo_deny_licenses.txt" ]; then
    if [ $DENY_EXIT_CODE -eq 0 ]; then
        cat >> "${AUDIT_REPORT}" << EOF
✅ **PASS**: All dependencies have acceptable licenses.
EOF
    else
        cat >> "${AUDIT_REPORT}" << EOF
❌ **FAIL**: License compliance issues found.

**Details:**
\`\`\`
$(cat "${REPORTS_DIR}/${TIMESTAMP}_cargo_deny_licenses.txt")
\`\`\`
EOF
    fi
fi

cat >> "${AUDIT_REPORT}" << EOF

### Outdated Dependencies
EOF

if [ -f "${REPORTS_DIR}/${TIMESTAMP}_cargo_outdated.txt" ]; then
    OUTDATED_COUNT=$(wc -l < "${REPORTS_DIR}/${TIMESTAMP}_cargo_outdated.txt")
    if [ "$OUTDATED_COUNT" -gt 1 ]; then  # More than just header
        cat >> "${AUDIT_REPORT}" << EOF
⚠️  **WARNING**: ${OUTDATED_COUNT} dependencies have available updates.

**Details:**
\`\`\`
$(cat "${REPORTS_DIR}/${TIMESTAMP}_cargo_outdated.txt")
\`\`\`

**Recommended Actions:**
1. Review and update dependencies regularly
2. Test thoroughly after updates
3. Update CHANGELOG.md with dependency changes
EOF
    else
        cat >> "${AUDIT_REPORT}" << EOF
✅ **PASS**: All dependencies are up to date.
EOF
    fi
fi

cat >> "${AUDIT_REPORT}" << EOF

## Detailed Findings

### Dependency Tree Analysis
Located at: ${REPORTS_DIR}/${TIMESTAMP}_cargo_tree.txt

### Dependency Size Analysis
Located at: ${REPORTS_DIR}/${TIMESTAMP}_cargo_bloat.txt

### Security Analysis
EOF

if [ -f "${REPORTS_DIR}/${TIMESTAMP}_cargo_geiger.txt" ]; then
    cat >> "${AUDIT_REPORT}" << EOF
Located at: ${REPORTS_DIR}/${TIMESTAMP}_cargo_geiger.txt
EOF
fi

cat >> "${AUDIT_REPORT}" << EOF

## Compliance Status

### SOC 2 Type II Requirements
- [ ] Dependency vulnerability scanning: $([ $AUDIT_EXIT_CODE -eq 0 ] && echo "✅ PASS" || echo "❌ FAIL")
- [ ] License compliance checking: $([ $DENY_EXIT_CODE -eq 0 ] && echo "✅ PASS" || echo "❌ FAIL")
- [ ] Regular dependency updates: $([ -f "${REPORTS_DIR}/${TIMESTAMP}_cargo_outdated.txt" ] && echo "⚠️  REVIEW" || echo "✅ PASS")
- [ ] SBOM generation: $([ -f "${REPORTS_DIR}/${TIMESTAMP}_cargo_sbom.txt" ] && echo "✅ PASS" || echo "⚠️  MANUAL")

### Security Best Practices
- [x] Automated vulnerability scanning
- [x] License compliance verification
- [x] Dependency size monitoring
- [ ] Regular security audits (quarterly)
- [ ] Third-party risk assessments

## Recommendations

### Immediate Actions Required
EOF

if [ $AUDIT_EXIT_CODE -ne 0 ]; then
    cat >> "${AUDIT_REPORT}" << EOF
1. **URGENT**: Address security vulnerabilities in dependencies
2. Update risk register with new vulnerabilities
3. Implement compensating controls if updates not available
EOF
fi

if [ $DENY_EXIT_CODE -ne 0 ]; then
    cat >> "${AUDIT_REPORT}" << EOF
4. Review and resolve license compliance issues
5. Update legal documentation if necessary
EOF
fi

cat >> "${AUDIT_REPORT}" << EOF

### Maintenance Recommendations
1. **Weekly**: Run automated dependency scans
2. **Monthly**: Review outdated dependencies and update where safe
3. **Quarterly**: Perform comprehensive security audits
4. **Annually**: Review and update dependency management policies

### Security Improvements
1. Consider using cargo-deny for additional security checks
2. Implement automated PR checks for dependency changes
3. Set up alerts for new vulnerabilities in monitored dependencies
4. Regular review of dependency usage and necessity

## Files Generated
EOF

for file in "${REPORTS_DIR}/${TIMESTAMP}_"*.txt; do
    if [ -f "$file" ]; then
        echo "- $(basename "$file")" >> "${AUDIT_REPORT}"
    fi
done

cat >> "${AUDIT_REPORT}" << EOF

## Next Steps
1. Review this report with security and development teams
2. Create action items for any issues found
3. Schedule regular dependency audits
4. Update security documentation and procedures

---
*Generated by automated dependency audit script*
*Report ID: ${TIMESTAMP}*
EOF

# Set exit code based on audit results
OVERALL_EXIT_CODE=0

if [ $AUDIT_EXIT_CODE -ne 0 ]; then
    OVERALL_EXIT_CODE=1
    echo -e "${RED}❌ CRITICAL: Security vulnerabilities found${NC}"
elif [ $DENY_EXIT_CODE -ne 0 ]; then
    OVERALL_EXIT_CODE=1
    echo -e "${RED}❌ CRITICAL: License compliance issues found${NC}"
fi

echo -e "${GREEN}🎉 Dependency audit completed!${NC}"
echo -e "${BLUE}📁 Comprehensive report: ${AUDIT_REPORT}${NC}"

# List all generated files
echo -e "${YELLOW}📋 Generated files:${NC}"
for file in "${REPORTS_DIR}/${TIMESTAMP}_"*.txt; do
    if [ -f "$file" ]; then
        echo -e "  • $(basename "$file")"
    fi
done

echo -e "${BLUE}📊 Summary:${NC}"
echo -e "  • Vulnerabilities: $([ $AUDIT_EXIT_CODE -eq 0 ] && echo '✅ None' || echo '❌ Found')"
echo -e "  • License Compliance: $([ $DENY_EXIT_CODE -eq 0 ] && echo '✅ Pass' || echo '❌ Issues')"
echo -e "  • Outdated Dependencies: $([ -f "${REPORTS_DIR}/${TIMESTAMP}_cargo_outdated.txt" ] && echo '⚠️  Check report' || echo '✅ Up to date')"

exit $OVERALL_EXIT_CODE
