#!/bin/bash
# Dependency Risk Management and Exception Handling Script
# Manages security exceptions and risk assessments for dependencies

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EXCEPTIONS_DIR="$PROJECT_ROOT/.security"
EXCEPTIONS_FILE="$EXCEPTIONS_DIR/dependency-exceptions.toml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Initialize exceptions directory and file
init_exceptions() {
    mkdir -p "$EXCEPTIONS_DIR"
    
    if [[ ! -f "$EXCEPTIONS_FILE" ]]; then
        cat > "$EXCEPTIONS_FILE" << 'EOF'
# Dependency Security Exceptions Configuration
# This file tracks approved security exceptions for dependencies
# Each exception requires justification and approval

[metadata]
version = "1.0"
last_updated = ""
reviewed_by = []

# Vulnerability exceptions
[[vulnerability_exceptions]]
# Example:
# advisory_id = "RUSTSEC-2023-0001"
# crate_name = "example-crate"
# affected_versions = "< 1.2.3"
# justification = "Not exploitable in our use case - we don't use the vulnerable function"
# mitigation = "Input validation prevents exploitation"
# approved_by = "security-team"
# approval_date = "2024-01-15"
# review_date = "2024-04-15"
# status = "approved" # approved, expired, revoked

# License exceptions
[[license_exceptions]]
# Example:
# crate_name = "example-crate"
# license = "GPL-3.0"
# justification = "Used only in test environment, not distributed"
# approved_by = "legal-team"
# approval_date = "2024-01-15"
# review_date = "2024-07-15"
# status = "approved"

# Maintenance exceptions (for unmaintained crates)
[[maintenance_exceptions]]
# Example:
# crate_name = "legacy-crate"
# last_update = "2022-01-01"
# justification = "No suitable alternative exists, minimal attack surface"
# risk_assessment = "low"
# approved_by = "architecture-team"
# approval_date = "2024-01-15"
# review_date = "2024-06-15"
# status = "approved"
EOF
        log_info "Created exceptions file: $EXCEPTIONS_FILE"
    fi
}

# Add a vulnerability exception
add_vulnerability_exception() {
    local advisory_id="$1"
    local crate_name="$2"
    local justification="$3"
    local mitigation="$4"
    local approved_by="$5"
    
    log_info "Adding vulnerability exception for $advisory_id ($crate_name)"
    
    # Get current date
    local current_date
    current_date=$(date +"%Y-%m-%d")
    
    # Calculate review date (3 months from now)
    local review_date
    if command -v date &> /dev/null && date -v +3m &> /dev/null 2>&1; then
        # macOS
        review_date=$(date -v +3m +"%Y-%m-%d")
    elif command -v date &> /dev/null && date -d "+3 months" &> /dev/null 2>&1; then
        # Linux
        review_date=$(date -d "+3 months" +"%Y-%m-%d")
    else
        # Fallback
        review_date="2024-12-31"
    fi
    
    # Add to exceptions file
    cat >> "$EXCEPTIONS_FILE" << EOF

[[vulnerability_exceptions]]
advisory_id = "$advisory_id"
crate_name = "$crate_name"
justification = "$justification"
mitigation = "$mitigation"
approved_by = "$approved_by"
approval_date = "$current_date"
review_date = "$review_date"
status = "approved"
EOF
    
    log_success "Vulnerability exception added for $advisory_id"
}

# Add a license exception
add_license_exception() {
    local crate_name="$1"
    local license="$2"
    local justification="$3"
    local approved_by="$4"
    
    log_info "Adding license exception for $crate_name ($license)"
    
    local current_date
    current_date=$(date +"%Y-%m-%d")
    
    local review_date
    if command -v date &> /dev/null && date -v +6m &> /dev/null 2>&1; then
        review_date=$(date -v +6m +"%Y-%m-%d")
    elif command -v date &> /dev/null && date -d "+6 months" &> /dev/null 2>&1; then
        review_date=$(date -d "+6 months" +"%Y-%m-%d")
    else
        review_date="2024-12-31"
    fi
    
    cat >> "$EXCEPTIONS_FILE" << EOF

[[license_exceptions]]
crate_name = "$crate_name"
license = "$license"
justification = "$justification"
approved_by = "$approved_by"
approval_date = "$current_date"
review_date = "$review_date"
status = "approved"
EOF
    
    log_success "License exception added for $crate_name"
}

# Check for expired exceptions
check_expired_exceptions() {
    log_info "Checking for expired exceptions..."
    
    if ! command -v python3 &> /dev/null; then
        log_warning "Python3 not available, skipping expiration check"
        return 0
    fi
    
    python3 << EOF
import toml
import datetime
import sys

try:
    with open('$EXCEPTIONS_FILE', 'r') as f:
        data = toml.load(f)
    
    current_date = datetime.date.today()
    expired_count = 0
    
    for category in ['vulnerability_exceptions', 'license_exceptions', 'maintenance_exceptions']:
        if category in data:
            for exception in data[category]:
                if 'review_date' in exception and exception.get('status') == 'approved':
                    review_date = datetime.datetime.strptime(exception['review_date'], '%Y-%m-%d').date()
                    if review_date <= current_date:
                        print(f"EXPIRED: {exception.get('crate_name', 'unknown')} - {exception.get('advisory_id', exception.get('license', 'maintenance'))}")
                        expired_count += 1
    
    if expired_count > 0:
        print(f"\n{expired_count} exceptions require review!")
        sys.exit(1)
    else:
        print("All exceptions are current")
        sys.exit(0)

except Exception as e:
    print(f"Error checking exceptions: {e}")
    sys.exit(1)
EOF
    
    local exit_code=$?
    if [ $exit_code -eq 1 ]; then
        log_warning "Some exceptions have expired and need review"
        return 1
    else
        log_success "All exceptions are current"
        return 0
    fi
}

# Generate cargo-deny configuration with exceptions
update_cargo_deny_config() {
    log_info "Updating cargo-deny configuration with current exceptions..."
    
    if ! command -v python3 &> /dev/null; then
        log_warning "Python3 not available, cannot update cargo-deny config"
        return 0
    fi
    
    # Backup current deny.toml
    cp "$PROJECT_ROOT/deny.toml" "$PROJECT_ROOT/deny.toml.bak"
    
    python3 << EOF
import toml
import re

# Load exceptions
try:
    with open('$EXCEPTIONS_FILE', 'r') as f:
        exceptions = toml.load(f)
except:
    print("No exceptions file found")
    exit(0)

# Load current deny.toml
with open('$PROJECT_ROOT/deny.toml', 'r') as f:
    deny_content = f.read()

# Extract advisories section
advisories_match = re.search(r'\[advisories\](.*?)(?=\n\[|\nEOF|\Z)', deny_content, re.DOTALL)
if not advisories_match:
    print("Could not find advisories section")
    exit(1)

advisories_section = advisories_match.group(1)

# Check if ignore array exists
if 'ignore = [' in advisories_section:
    # Find existing ignore array
    ignore_match = re.search(r'ignore = \[(.*?)\]', advisories_section, re.DOTALL)
    if ignore_match:
        current_ignores = ignore_match.group(1)
    else:
        current_ignores = ""
else:
    current_ignores = ""

# Build new ignore list
ignores = []

# Add static ignores (keep existing comments)
for line in current_ignores.split('\n'):
    line = line.strip()
    if line and not line.startswith('#'):
        ignores.append(line)

# Add exceptions
vuln_exceptions = exceptions.get('vulnerability_exceptions', [])
for exc in vuln_exceptions:
    if exc.get('status') == 'approved':
        advisory_id = exc.get('advisory_id', '')
        comment = exc.get('justification', 'Security team approved')
        ignores.append(f'    "{advisory_id}", # {comment}')

# Write updated content
if ignores:
    ignore_content = '[\n' + '\n'.join(ignores) + '\n]'
else:
    ignore_content = '[]'

new_advisories = re.sub(r'ignore = \[.*?\]', f'ignore = {ignore_content}', advisories_section, flags=re.DOTALL)
if 'ignore = [' not in advisories_section:
    # Add ignore section
    new_advisories = advisories_section + f'\nignore = {ignore_content}\n'

# Replace in full content
new_content = deny_content.replace(advisories_section, new_advisories)

with open('$PROJECT_ROOT/deny.toml', 'w') as f:
    f.write(new_content)

print("Updated cargo-deny configuration with exceptions")
EOF
    
    log_success "Cargo-deny configuration updated"
}

# Risk assessment for a specific crate
assess_crate_risk() {
    local crate_name="$1"
    
    log_info "Assessing risk for crate: $crate_name"
    
    # Create risk assessment directory
    local risk_dir="$PROJECT_ROOT/target/risk-assessments"
    mkdir -p "$risk_dir"
    
    local risk_file="$risk_dir/${crate_name}-risk-assessment.md"
    
    cat > "$risk_file" << EOF
# Risk Assessment: $crate_name

**Assessment Date:** $(date)
**Assessor:** $(whoami)

## Crate Information

- **Name:** $crate_name
- **Current Version:** $(cargo tree --package "$crate_name" --depth 0 2>/dev/null | head -1 || echo "Not found")
- **Usage:** $(cargo tree --package "$crate_name" --invert 2>/dev/null | head -5 || echo "Unknown")

## Security Assessment

### Vulnerability History
EOF
    
    # Check for historical vulnerabilities
    if command -v cargo &> /dev/null; then
        echo "$(cargo audit --json 2>/dev/null | jq -r ".vulnerabilities.found[] | select(.package.name == \"$crate_name\") | \"- \(.advisory.id): \(.advisory.title)\"" 2>/dev/null || echo "No vulnerabilities found")" >> "$risk_file"
    fi
    
    cat >> "$risk_file" << EOF

### Maintenance Status
- **Last Update:** Check crates.io
- **Maintainer Activity:** Check GitHub repository
- **Community Support:** Check download statistics

### License Compliance
- **License:** Check Cargo.toml
- **Compatibility:** Verify with business requirements

### Dependencies
- **Dependency Count:** $(cargo tree --package "$crate_name" 2>/dev/null | wc -l || echo "Unknown")
- **Transitive Dependencies:** Review for supply chain risks

## Risk Rating

| Category | Risk Level | Justification |
|----------|------------|---------------|
| Security | [ ] Low [ ] Medium [ ] High | |
| Maintenance | [ ] Low [ ] Medium [ ] High | |
| License | [ ] Low [ ] Medium [ ] High | |
| Dependencies | [ ] Low [ ] Medium [ ] High | |

**Overall Risk:** [ ] Low [ ] Medium [ ] High

## Recommendations

1. **Immediate Actions:**
   - [ ] Update to latest version
   - [ ] Review security advisories
   - [ ] Validate license compatibility

2. **Monitoring:**
   - [ ] Set up vulnerability alerts
   - [ ] Monitor maintenance status
   - [ ] Track dependency updates

3. **Alternatives:**
   - [ ] Research alternative crates
   - [ ] Evaluate in-house implementation
   - [ ] Consider vendor solutions

## Approval

- **Risk Accepted By:** 
- **Date:** 
- **Review Date:** 

---
*This assessment should be reviewed quarterly or when new information becomes available.*
EOF
    
    log_success "Risk assessment created: $risk_file"
    echo "Please complete the assessment in: $risk_file"
}

# List all current exceptions
list_exceptions() {
    log_info "Current security exceptions:"
    
    if [[ ! -f "$EXCEPTIONS_FILE" ]]; then
        log_warning "No exceptions file found"
        return 0
    fi
    
    if command -v python3 &> /dev/null; then
        python3 << EOF
import toml
from datetime import datetime

try:
    with open('$EXCEPTIONS_FILE', 'r') as f:
        data = toml.load(f)
    
    print("\n=== VULNERABILITY EXCEPTIONS ===")
    vuln_exceptions = data.get('vulnerability_exceptions', [])
    if not vuln_exceptions:
        print("None")
    else:
        for exc in vuln_exceptions:
            status = exc.get('status', 'unknown')
            advisory = exc.get('advisory_id', 'unknown')
            crate = exc.get('crate_name', 'unknown')
            approved_by = exc.get('approved_by', 'unknown')
            approval_date = exc.get('approval_date', 'unknown')
            review_date = exc.get('review_date', 'unknown')
            print(f"• {advisory} ({crate}) - Status: {status}")
            print(f"  Approved by: {approved_by} on {approval_date}")
            print(f"  Review due: {review_date}")
            print()
    
    print("=== LICENSE EXCEPTIONS ===")
    license_exceptions = data.get('license_exceptions', [])
    if not license_exceptions:
        print("None")
    else:
        for exc in license_exceptions:
            status = exc.get('status', 'unknown')
            crate = exc.get('crate_name', 'unknown')
            license = exc.get('license', 'unknown')
            approved_by = exc.get('approved_by', 'unknown')
            approval_date = exc.get('approval_date', 'unknown')
            print(f"• {crate} ({license}) - Status: {status}")
            print(f"  Approved by: {approved_by} on {approval_date}")
            print()
    
    print("=== MAINTENANCE EXCEPTIONS ===")
    maint_exceptions = data.get('maintenance_exceptions', [])
    if not maint_exceptions:
        print("None")
    else:
        for exc in maint_exceptions:
            status = exc.get('status', 'unknown')
            crate = exc.get('crate_name', 'unknown')
            risk = exc.get('risk_assessment', 'unknown')
            approved_by = exc.get('approved_by', 'unknown')
            print(f"• {crate} - Risk: {risk}, Status: {status}")
            print(f"  Approved by: {approved_by}")
            print()

except Exception as e:
    print(f"Error reading exceptions: {e}")
EOF
    else
        log_warning "Python3 not available, showing raw file:"
        cat "$EXCEPTIONS_FILE"
    fi
}

# Usage information
usage() {
    cat << EOF
Dependency Risk Manager

Usage: $0 <command> [arguments]

Commands:
    init                           Initialize exceptions tracking
    add-vuln <advisory> <crate> <justification> <mitigation> <approver>
                                  Add vulnerability exception
    add-license <crate> <license> <justification> <approver>
                                  Add license exception
    assess <crate>                Create risk assessment for crate
    check-expired                 Check for expired exceptions
    list                          List all current exceptions
    update-config                 Update cargo-deny with exceptions

Examples:
    $0 init
    $0 add-vuln RUSTSEC-2023-0001 example-crate "Not exploitable" "Input validation" security-team
    $0 add-license problematic-crate GPL-3.0 "Test only usage" legal-team
    $0 assess tokio
    $0 check-expired
    $0 list

EOF
}

# Main execution
main() {
    cd "$PROJECT_ROOT"
    
    case "${1:-}" in
        "init")
            init_exceptions
            ;;
        "add-vuln")
            if [ $# -ne 6 ]; then
                echo "Usage: $0 add-vuln <advisory> <crate> <justification> <mitigation> <approver>"
                exit 1
            fi
            init_exceptions
            add_vulnerability_exception "$2" "$3" "$4" "$5" "$6"
            ;;
        "add-license")
            if [ $# -ne 5 ]; then
                echo "Usage: $0 add-license <crate> <license> <justification> <approver>"
                exit 1
            fi
            init_exceptions
            add_license_exception "$2" "$3" "$4" "$5"
            ;;
        "assess")
            if [ $# -ne 2 ]; then
                echo "Usage: $0 assess <crate>"
                exit 1
            fi
            assess_crate_risk "$2"
            ;;
        "check-expired")
            check_expired_exceptions
            ;;
        "list")
            list_exceptions
            ;;
        "update-config")
            update_cargo_deny_config
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"