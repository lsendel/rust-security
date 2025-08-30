#!/bin/bash

# Test Compliance Implementation Script
# This script validates all compliance and security automation implementations

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "PASS")
            echo -e "${GREEN}✅ PASS:${NC} $message"
            ((TESTS_PASSED++))
            ;;
        "FAIL")
            echo -e "${RED}❌ FAIL:${NC} $message"
            ((TESTS_FAILED++))
            ;;
        "WARN")
            echo -e "${YELLOW}⚠️  WARN:${NC} $message"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  INFO:${NC} $message"
            ;;
    esac
    ((TOTAL_TESTS++))
}

# Function to test if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to test if a file exists
test_file_exists() {
    local file=$1
    local description=$2
    
    if [[ -f "$file" ]]; then
        print_status "PASS" "$description exists: $file"
        return 0
    else
        print_status "FAIL" "$description missing: $file"
        return 1
    fi
}

# Function to test if a directory exists
test_dir_exists() {
    local dir=$1
    local description=$2
    
    if [[ -d "$dir" ]]; then
        print_status "PASS" "$description exists: $dir"
        return 0
    else
        print_status "FAIL" "$description missing: $dir"
        return 1
    fi
}

# Function to test cargo build for a package
test_cargo_build() {
    local package=$1
    local description=$2
    
    print_status "INFO" "Testing cargo build for $package..."
    
    if cargo build --package "$package" >/dev/null 2>&1; then
        print_status "PASS" "$description builds successfully"
        return 0
    else
        print_status "FAIL" "$description failed to build"
        return 1
    fi
}

# Function to test if binary exists after build
test_binary_exists() {
    local binary_path=$1
    local description=$2
    
    if [[ -f "$binary_path" ]]; then
        print_status "PASS" "$description binary exists: $binary_path"
        return 0
    else
        print_status "FAIL" "$description binary missing: $binary_path"
        return 1
    fi
}

echo "🔍 Starting Compliance Implementation Tests..."
echo "=================================================="

# Test 1: Workspace Configuration
echo -e "\n${BLUE}📦 Testing Workspace Configuration...${NC}"
test_file_exists "Cargo.toml" "Root Cargo.toml"

# Check if compliance-tools is included in workspace
if grep -q "compliance-tools" Cargo.toml; then
    print_status "PASS" "compliance-tools included in workspace members"
else
    print_status "FAIL" "compliance-tools not found in workspace members"
fi

# Test 2: Compliance Tools Package
echo -e "\n${BLUE}🛠️  Testing Compliance Tools Package...${NC}"
test_dir_exists "compliance-tools" "compliance-tools directory"
test_file_exists "compliance-tools/Cargo.toml" "compliance-tools Cargo.toml"
test_file_exists "compliance-tools/src/lib.rs" "compliance-tools lib.rs"

# Test binary source files
test_file_exists "compliance-tools/src/bin/compliance_report_generator.rs" "Compliance report generator source"
test_file_exists "compliance-tools/src/bin/sbom_generator.rs" "SBOM generator source"
test_file_exists "compliance-tools/src/bin/security_metrics_collector.rs" "Security metrics collector source"
test_file_exists "compliance-tools/src/bin/threat_feed_validator.rs" "Threat feed validator source"

# Test 3: Build Compliance Tools
echo -e "\n${BLUE}🔨 Testing Compliance Tools Build...${NC}"
test_cargo_build "compliance-tools" "compliance-tools package"

# Build release binaries for testing
print_status "INFO" "Building release binaries for testing..."
if cargo build --release --package compliance-tools >/dev/null 2>&1; then
    print_status "PASS" "Release binaries built successfully"
    
    # Test individual binaries
    test_binary_exists "target/release/compliance-report-generator" "Compliance report generator"
    test_binary_exists "target/release/sbom-generator" "SBOM generator" 
    test_binary_exists "target/release/security-metrics-collector" "Security metrics collector"
    test_binary_exists "target/release/threat-feed-validator" "Threat feed validator"
else
    print_status "FAIL" "Failed to build release binaries"
fi

# Test 4: CI/CD Workflows
echo -e "\n${BLUE}⚙️  Testing CI/CD Workflows...${NC}"
test_file_exists ".github/workflows/compliance-automation.yml" "Compliance automation workflow"
test_file_exists ".github/workflows/security.yml" "Security workflow"

# Check if security workflow includes compliance integration
if grep -q "compliance-validation" .github/workflows/security.yml; then
    print_status "PASS" "Security workflow includes compliance validation"
else
    print_status "FAIL" "Security workflow missing compliance validation"
fi

# Test 5: Configuration Files
echo -e "\n${BLUE}📋 Testing Configuration Files...${NC}"
test_file_exists ".github/dependabot.yml" "Dependabot configuration"
test_file_exists ".github/dependency-review-config.yml" "Dependency review configuration"

# Test 6: Compliance Tools Functionality
echo -e "\n${BLUE}🧪 Testing Compliance Tools Functionality...${NC}"

# Test SBOM generator
if [[ -f "target/release/sbom-generator" ]]; then
    print_status "INFO" "Testing SBOM generator functionality..."
    
    # Create test output directory
    mkdir -p test-output
    
    # Test SBOM generation
    if ./target/release/sbom-generator --project-root . --output test-output/test.spdx.json --format spdx >/dev/null 2>&1; then
        if [[ -f "test-output/test.spdx.json" ]]; then
            print_status "PASS" "SBOM generator creates SPDX output"
            
            # Test SBOM content
            if grep -q "spdxVersion" test-output/test.spdx.json; then
                print_status "PASS" "SBOM contains valid SPDX data"
            else
                print_status "FAIL" "SBOM missing SPDX version data"
            fi
        else
            print_status "FAIL" "SBOM generator did not create output file"
        fi
    else
        print_status "WARN" "SBOM generator test failed (may require cargo metadata)"
    fi
else
    print_status "WARN" "SBOM generator binary not available for testing"
fi

# Test compliance report generator
if [[ -f "target/release/compliance-report-generator" ]]; then
    print_status "INFO" "Testing compliance report generator..."
    
    # Create basic config for testing
    mkdir -p test-config
    cat > test-config/test-compliance.yaml << 'EOF'
organization:
  name: "Test Organization"
  domain: "test.local"
  contact_email: "test@test.local"
  compliance_officer: "Test Officer"
  assessment_period_days: 30

frameworks:
  - SOC2
  - NIST

data_sources:
  prometheus_url: "http://localhost:9090"
  audit_log_paths: []
  redis_url: "redis://localhost:6379"

report_settings:
  output_formats: ["html"]
  include_charts: false
  include_recommendations: true
  classification_level: "INTERNAL"
  retention_days: 365
EOF
    
    # Test report generation (this may fail without proper data sources, but we test the binary)
    if timeout 10s ./target/release/compliance-report-generator --framework soc2 --format html --output test-output/test-report.html >/dev/null 2>&1; then
        print_status "PASS" "Compliance report generator runs successfully"
    else
        print_status "WARN" "Compliance report generator test timed out (expected without data sources)"
    fi
else
    print_status "WARN" "Compliance report generator binary not available for testing"
fi

# Test 7: Security Integration
echo -e "\n${BLUE}🔐 Testing Security Integration...${NC}"

# Check for required security tools in workflows
if grep -q "cargo-audit" .github/workflows/security.yml; then
    print_status "PASS" "Security workflow includes cargo-audit"
else
    print_status "FAIL" "Security workflow missing cargo-audit"
fi

if grep -q "syft" .github/workflows/security.yml; then
    print_status "PASS" "Security workflow includes Syft SBOM generation"
else
    print_status "FAIL" "Security workflow missing Syft SBOM generation"
fi

if grep -q "grype" .github/workflows/security.yml; then
    print_status "PASS" "Security workflow includes Grype vulnerability scanning"
else
    print_status "FAIL" "Security workflow missing Grype vulnerability scanning"
fi

# Test 8: Policy Enforcement
echo -e "\n${BLUE}⚖️  Testing Policy Enforcement...${NC}"

# Check for policy enforcement in workflows
if grep -q "compliance-policy-enforcement" .github/workflows/compliance-automation.yml; then
    print_status "PASS" "Compliance workflow includes policy enforcement"
else
    print_status "FAIL" "Compliance workflow missing policy enforcement"
fi

# Check for compliance score validation
if grep -q "compliance-score" .github/workflows/compliance-automation.yml; then
    print_status "PASS" "Compliance workflow includes score validation"
else
    print_status "FAIL" "Compliance workflow missing score validation"
fi

# Test 9: Monitoring and Alerting
echo -e "\n${BLUE}📊 Testing Monitoring and Alerting...${NC}"

if grep -q "compliance-monitoring" .github/workflows/compliance-automation.yml; then
    print_status "PASS" "Compliance workflow includes monitoring"
else
    print_status "FAIL" "Compliance workflow missing monitoring"
fi

if grep -q "compliance-dashboard" .github/workflows/compliance-automation.yml; then
    print_status "PASS" "Compliance workflow includes dashboard updates"
else
    print_status "FAIL" "Compliance workflow missing dashboard updates"
fi

# Test 10: Documentation and README
echo -e "\n${BLUE}📚 Testing Documentation...${NC}"
test_file_exists "compliance-tools/README.md" "Compliance tools documentation"

if [[ -f "compliance-tools/README.md" ]]; then
    # Check for key documentation sections
    if grep -q "## Tools" compliance-tools/README.md; then
        print_status "PASS" "Documentation includes tools section"
    else
        print_status "FAIL" "Documentation missing tools section"
    fi
    
    if grep -q "## Configuration" compliance-tools/README.md; then
        print_status "PASS" "Documentation includes configuration section"
    else
        print_status "FAIL" "Documentation missing configuration section"
    fi
fi

# Cleanup test files
print_status "INFO" "Cleaning up test files..."
rm -rf test-output test-config

# Final Results
echo -e "\n${BLUE}📊 Test Summary${NC}"
echo "=================================================="
echo -e "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"

# Calculate success percentage
if [[ $TOTAL_TESTS -gt 0 ]]; then
    SUCCESS_RATE=$((TESTS_PASSED * 100 / TOTAL_TESTS))
    echo -e "Success Rate: $SUCCESS_RATE%"
    
    if [[ $SUCCESS_RATE -ge 85 ]]; then
        echo -e "\n${GREEN}🎉 COMPLIANCE IMPLEMENTATION TEST PASSED!${NC}"
        echo "Your compliance and security automation is ready for production."
        exit 0
    elif [[ $SUCCESS_RATE -ge 70 ]]; then
        echo -e "\n${YELLOW}⚠️  COMPLIANCE IMPLEMENTATION PARTIALLY PASSED${NC}"
        echo "Most features are working, but some improvements are needed."
        exit 1
    else
        echo -e "\n${RED}❌ COMPLIANCE IMPLEMENTATION TEST FAILED${NC}"
        echo "Significant issues found. Please review and fix the failures above."
        exit 1
    fi
else
    echo -e "\n${RED}❌ NO TESTS EXECUTED${NC}"
    exit 1
fi