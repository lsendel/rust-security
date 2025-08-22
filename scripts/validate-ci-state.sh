#!/bin/bash

# GitHub Actions Validation Script
# Tests the current state of CI/CD workflows

set -euo pipefail

echo "🔍 Validating Current GitHub Actions State..."
echo "=============================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]] || [[ ! -d ".github/workflows" ]]; then
    print_error "Please run this script from the project root directory"
    exit 1
fi

ISSUES_FOUND=0

print_status "1. Analyzing workflow files..."

# Count workflows
TOTAL_WORKFLOWS=$(find .github/workflows -name "*.yml" -type f | wc -l)
DISABLED_WORKFLOWS=$(find .github/workflows -name "*.disabled" -type f 2>/dev/null | wc -l || echo 0)

echo "  • Total active workflows: $TOTAL_WORKFLOWS"
echo "  • Disabled workflows: $DISABLED_WORKFLOWS"

if [[ $TOTAL_WORKFLOWS -gt 15 ]]; then
    print_warning "High number of workflows ($TOTAL_WORKFLOWS) may cause conflicts"
    ((ISSUES_FOUND++))
fi

print_status "2. Checking for problematic patterns..."

# Check for continue-on-error usage
CONTINUE_ON_ERROR_COUNT=$(grep -r "continue-on-error: true" .github/workflows/ 2>/dev/null | wc -l || echo 0)
if [[ $CONTINUE_ON_ERROR_COUNT -gt 5 ]]; then
    print_warning "Excessive use of continue-on-error ($CONTINUE_ON_ERROR_COUNT instances)"
    print_warning "This may mask real issues"
    ((ISSUES_FOUND++))
fi

# Check for inconsistent action versions
print_status "3. Checking action version consistency..."

CHECKOUT_VERSIONS=$(grep -r "actions/checkout@" .github/workflows/ | sed 's/.*@//' | sort | uniq | wc -l)
RUST_TOOLCHAIN_VERSIONS=$(grep -r "dtolnay/rust-toolchain@" .github/workflows/ | sed 's/.*@//' | sort | uniq | wc -l)

if [[ $CHECKOUT_VERSIONS -gt 2 ]]; then
    print_warning "Inconsistent checkout action versions ($CHECKOUT_VERSIONS different versions)"
    ((ISSUES_FOUND++))
fi

if [[ $RUST_TOOLCHAIN_VERSIONS -gt 2 ]]; then
    print_warning "Inconsistent rust-toolchain versions ($RUST_TOOLCHAIN_VERSIONS different versions)"
    ((ISSUES_FOUND++))
fi

print_status "4. Testing workspace compilation..."

if cargo check --workspace --quiet; then
    print_success "Workspace compiles successfully"
else
    print_error "Workspace compilation failed"
    ((ISSUES_FOUND++))
fi

print_status "5. Testing individual packages..."

PACKAGES=("auth-core" "common" "api-contracts" "auth-service" "policy-service" "compliance-tools")
FAILED_PACKAGES=()

for package in "${PACKAGES[@]}"; do
    if cargo check -p "$package" --quiet 2>/dev/null; then
        echo "  ✅ $package"
    else
        echo "  ❌ $package"
        FAILED_PACKAGES+=("$package")
        ((ISSUES_FOUND++))
    fi
done

print_status "6. Checking for workflow conflicts..."

# Check for workflows that might run simultaneously
PUSH_WORKFLOWS=$(grep -l "push:" .github/workflows/*.yml | wc -l)
PR_WORKFLOWS=$(grep -l "pull_request:" .github/workflows/*.yml | wc -l)

if [[ $PUSH_WORKFLOWS -gt 8 ]]; then
    print_warning "Many workflows trigger on push ($PUSH_WORKFLOWS), may cause resource conflicts"
    ((ISSUES_FOUND++))
fi

print_status "7. Analyzing workflow complexity..."

# Check for complex matrices
COMPLEX_MATRICES=$(grep -A 10 "strategy:" .github/workflows/*.yml | grep -c "matrix:" || echo 0)
if [[ $COMPLEX_MATRICES -gt 5 ]]; then
    print_warning "Multiple complex build matrices detected ($COMPLEX_MATRICES)"
    print_warning "This may cause long build times and resource conflicts"
    ((ISSUES_FOUND++))
fi

print_status "8. Security check..."

# Check for hardcoded secrets or tokens
POTENTIAL_SECRETS=$(grep -r -i "token\|secret\|key" .github/workflows/ | grep -v "secrets\." | grep -v "github.token" | wc -l || echo 0)
if [[ $POTENTIAL_SECRETS -gt 0 ]]; then
    print_warning "Potential hardcoded secrets found ($POTENTIAL_SECRETS instances)"
    print_warning "Review workflow files for security issues"
    ((ISSUES_FOUND++))
fi

echo ""
echo "=============================================="
print_status "Validation Summary"
echo "=============================================="

if [[ $ISSUES_FOUND -eq 0 ]]; then
    print_success "🎉 No major issues found!"
    print_success "Your GitHub Actions setup looks good"
else
    print_warning "⚠️  Found $ISSUES_FOUND potential issues"
    echo ""
    print_status "Recommended actions:"
    echo "  1. Run ./scripts/fix-github-actions.sh to apply fixes"
    echo "  2. Review and test the optimized-ci.yml workflow"
    echo "  3. Monitor workflow performance after changes"
    echo "  4. Consider disabling unused workflows"
fi

echo ""
print_status "Current Status:"
echo "  • Active workflows: $TOTAL_WORKFLOWS"
echo "  • Compilation status: $(if cargo check --workspace --quiet 2>/dev/null; then echo "✅ PASS"; else echo "❌ FAIL"; fi)"
echo "  • Failed packages: ${#FAILED_PACKAGES[@]}"
echo "  • Issues found: $ISSUES_FOUND"

if [[ ${#FAILED_PACKAGES[@]} -gt 0 ]]; then
    echo "  • Failed packages: ${FAILED_PACKAGES[*]}"
fi

echo ""
if [[ $ISSUES_FOUND -gt 0 ]]; then
    print_warning "Run the remediation script to fix these issues:"
    echo "  ./scripts/fix-github-actions.sh"
    exit 1
else
    print_success "GitHub Actions validation completed successfully!"
    exit 0
fi
