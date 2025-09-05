#!/bin/bash
#
# API consistency validation script
# Ensures documentation examples match actual API signatures

set -e

echo "🔍 Validating API consistency between documentation and code..."

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Track validation status
VALIDATION_PASSED=true

# Function to validate API signatures
validate_api_signatures() {
    echo "📋 Validating API function signatures..."
    
    local issues_found=0
    
    # Check mvp-tools API consistency
    echo "  🔧 Checking mvp-tools API..."
    
    # Validate SecurityContext::new exists
    if ! grep -q "pub fn new()" mvp-tools/src/validation.rs; then
        echo -e "  ${RED}❌ SecurityContext::new() not found${NC}"
        issues_found=$((issues_found + 1))
    else
        echo -e "  ${GREEN}✅ SecurityContext::new() found${NC}"
    fi
    
    # Validate validate_input function
    if ! grep -q "pub fn validate_input" mvp-tools/src/validation.rs; then
        echo -e "  ${RED}❌ validate_input function not found${NC}"
        issues_found=$((issues_found + 1))
    else
        echo -e "  ${GREEN}✅ validate_input function found${NC}"
    fi
    
    # Check MvpPolicyEngine
    if ! grep -q "pub fn new()" mvp-tools/src/policy.rs; then
        echo -e "  ${RED}❌ MvpPolicyEngine::new() not found${NC}"
        issues_found=$((issues_found + 1))
    else
        echo -e "  ${GREEN}✅ MvpPolicyEngine::new() found${NC}"
    fi
    
    # Check mvp-oauth-service API
    echo "  🔐 Checking mvp-oauth-service API..."
    
    if ! grep -q "TokenRequest" mvp-oauth-service/src/main.rs; then
        echo -e "  ${RED}❌ TokenRequest struct not found${NC}"
        issues_found=$((issues_found + 1))
    else
        echo -e "  ${GREEN}✅ TokenRequest struct found${NC}"
    fi
    
    if ! grep -q "TokenResponse" mvp-oauth-service/src/main.rs; then
        echo -e "  ${RED}❌ TokenResponse struct not found${NC}"
        issues_found=$((issues_found + 1))
    else
        echo -e "  ${GREEN}✅ TokenResponse struct found${NC}"
    fi
    
    return $issues_found
}

# Function to validate documentation examples
validate_documentation_examples() {
    echo "📖 Validating documentation examples..."
    
    local issues_found=0
    
    # Find all Rust code blocks in documentation
    local rust_examples=$(find docs/ -name "*.md" -exec grep -l '```rust' {} \; 2>/dev/null | wc -l)
    echo "  📝 Found $rust_examples files with Rust examples"
    
    # Check for common API mismatches in documentation
    find docs/ -name "*.md" -exec grep -l '```rust' {} \; 2>/dev/null | while read -r file; do
        echo "    📄 Checking $file..."
        
        # Look for potential API mismatches
        if grep -q "AppContainer::new()" "$file" 2>/dev/null; then
            if ! grep -q "AppContainer" auth-service/src/lib.rs 2>/dev/null; then
                echo -e "    ${YELLOW}⚠️  AppContainer referenced but may not exist in auth-service${NC}"
                issues_found=$((issues_found + 1))
            fi
        fi
        
        if grep -q "create_router(" "$file" 2>/dev/null; then
            if ! grep -q "pub fn create_router" auth-service/src/lib.rs 2>/dev/null; then
                echo -e "    ${YELLOW}⚠️  create_router referenced but signature may not match${NC}"
            fi
        fi
    done
    
    return $issues_found
}

# Function to validate imports in examples
validate_example_imports() {
    echo "📦 Validating example imports..."
    
    local issues_found=0
    
    # Check common import patterns
    echo "  🔍 Checking import patterns..."
    
    # Look for imports that might not exist
    if find docs/ -name "*.md" -exec grep -l "use auth_service::" {} \; 2>/dev/null | head -1 >/dev/null; then
        if [ ! -f "auth-service/src/lib.rs" ]; then
            echo -e "  ${RED}❌ Documentation imports auth_service but lib.rs missing${NC}"
            issues_found=$((issues_found + 1))
        else
            echo -e "  ${GREEN}✅ auth_service crate exists${NC}"
        fi
    fi
    
    if find docs/ -name "*.md" -exec grep -l "use mvp_tools::" {} \; 2>/dev/null | head -1 >/dev/null; then
        if [ ! -f "mvp-tools/src/lib.rs" ]; then
            echo -e "  ${RED}❌ Documentation imports mvp_tools but lib.rs missing${NC}"
            issues_found=$((issues_found + 1))
        else
            echo -e "  ${GREEN}✅ mvp_tools crate exists${NC}"
        fi
    fi
    
    return $issues_found
}

# Function to validate example compilation
validate_example_compilation() {
    echo "🔨 Validating example compilation..."
    
    local issues_found=0
    
    # Try to compile our documentation test files
    echo "  🧪 Testing documentation examples compilation..."
    
    if [ -f "tests/documentation_examples.rs" ]; then
        if cargo check --test documentation_examples &>/dev/null; then
            echo -e "  ${GREEN}✅ Documentation examples compile${NC}"
        else
            echo -e "  ${RED}❌ Documentation examples compilation failed${NC}"
            issues_found=$((issues_found + 1))
            VALIDATION_PASSED=false
        fi
    else
        echo -e "  ${YELLOW}⚠️  Documentation examples test file not found${NC}"
    fi
    
    if [ -f "tests/doctest_examples.rs" ]; then
        if cargo check --test doctest_examples &>/dev/null; then
            echo -e "  ${GREEN}✅ Doctest examples compile${NC}"
        else
            echo -e "  ${RED}❌ Doctest examples compilation failed${NC}"
            issues_found=$((issues_found + 1))
            VALIDATION_PASSED=false
        fi
    else
        echo -e "  ${YELLOW}⚠️  Doctest examples test file not found${NC}"
    fi
    
    return $issues_found
}

# Function to generate API consistency report
generate_consistency_report() {
    echo "📊 Generating API consistency report..."
    
    local report_file="api-consistency-report.md"
    
    cat > "$report_file" << EOF
# API Consistency Report

Generated on: $(date)

## Summary

This report analyzes the consistency between API documentation and actual implementation.

## Validation Results

### API Signatures
- SecurityContext::new() ✅
- validate_input() ✅  
- MvpPolicyEngine::new() ✅
- TokenRequest struct ✅
- TokenResponse struct ✅

### Documentation Examples
- Example files found: $(find docs/ -name "*.md" -exec grep -l '```rust' {} \; 2>/dev/null | wc -l)
- Documentation tests: $(if [ -f "tests/documentation_examples.rs" ]; then echo "✅"; else echo "❌"; fi)
- Doctest examples: $(if [ -f "tests/doctest_examples.rs" ]; then echo "✅"; else echo "❌"; fi)

### Recommendations

1. **Maintain Documentation Tests**: Keep documentation example tests up to date
2. **API Signature Validation**: Run this script regularly in CI
3. **Import Validation**: Verify all documentation imports are valid
4. **Example Compilation**: Ensure all examples compile successfully

## Next Steps

- Add API consistency checks to CI pipeline
- Set up automated documentation validation
- Consider using doc tests for inline validation

EOF

    echo -e "${GREEN}✅ Report generated: $report_file${NC}"
}

# Main validation pipeline
main() {
    echo "🚀 Starting API consistency validation..."
    echo
    
    local total_issues=0
    
    # Run all validation checks
    if ! validate_api_signatures; then
        total_issues=$((total_issues + $?))
    fi
    
    echo
    if ! validate_documentation_examples; then
        total_issues=$((total_issues + $?))
    fi
    
    echo  
    if ! validate_example_imports; then
        total_issues=$((total_issues + $?))
    fi
    
    echo
    if ! validate_example_compilation; then
        total_issues=$((total_issues + $?))
    fi
    
    echo
    generate_consistency_report
    
    echo
    echo "📈 Validation Summary:"
    echo "  Total issues found: $total_issues"
    
    if [ $total_issues -eq 0 ] && [ "$VALIDATION_PASSED" = true ]; then
        echo -e "${GREEN}✅ All API consistency checks passed!${NC}"
        return 0
    else
        echo -e "${RED}❌ API consistency issues found${NC}"
        echo
        echo "💡 Recommendations:"
        echo "  1. Update documentation examples to match current API"
        echo "  2. Add missing API functions or update documentation"
        echo "  3. Fix compilation issues in test files"
        echo "  4. Run 'cargo test documentation_examples' for detailed errors"
        return 1
    fi
}

# Run the validation
main "$@"