#!/bin/bash
# 🔧 Automated Warning-Free Maintenance Script
# Ensures the Rust Security Platform remains warning-free

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Components to check
CORE_COMPONENTS=(
    "common"
    "policy-service"
    "compliance-tools"
)

FEATURE_HEAVY_COMPONENTS=(
    "auth-service"
)

# Function to check component warnings
check_component_warnings() {
    local component=$1
    echo -e "${BLUE}Checking $component...${NC}"
    
    # Run cargo check and capture warnings
    local warning_count=$(cargo check -p "$component" 2>&1 | grep -c "warning:" || true)
    
    if [ "$warning_count" -eq 0 ]; then
        echo -e "${GREEN}✅ $component: 0 warnings${NC}"
        return 0
    else
        echo -e "${RED}❌ $component: $warning_count warnings detected${NC}"
        return 1
    fi
}

# Function to check feature combinations
check_feature_combinations() {
    local component=$1
    echo -e "${BLUE}Checking feature combinations for $component...${NC}"
    
    local features=(
        ""  # No features
        "default"
        "security-essential"
        "api-keys"
        "enhanced-session-store"
        "rate-limiting"
        "monitoring"
        "soar"
        "threat-hunting"
    )
    
    for feature_set in "${features[@]}"; do
        if [ -z "$feature_set" ]; then
            echo -n "  Checking with no features... "
            local result=$(cargo check -p "$component" --no-default-features 2>&1 | grep -c "warning:" || true)
        else
            echo -n "  Checking with --features $feature_set... "
            local result=$(cargo check -p "$component" --no-default-features --features "$feature_set" 2>&1 | grep -c "warning:" || true)
        fi
        
        if [ "$result" -eq 0 ]; then
            echo -e "${GREEN}✅${NC}"
        else
            echo -e "${RED}❌ ($result warnings)${NC}"
        fi
    done
}

# Function to run automated fixes
run_automated_fixes() {
    echo -e "${YELLOW}🔧 Running automated fixes...${NC}"
    
    # Remove unused imports
    echo "  Removing unused imports..."
    cargo fix --workspace --allow-dirty --allow-staged 2>/dev/null || true
    
    # Apply clippy suggestions
    echo "  Applying clippy fixes..."
    cargo clippy --workspace --fix --allow-dirty --allow-staged -- -W clippy::all 2>/dev/null || true
    
    echo -e "${GREEN}✅ Automated fixes applied${NC}"
}

# Function to check for deprecated APIs
check_deprecated_apis() {
    echo -e "${BLUE}Checking for deprecated API usage...${NC}"
    
    local deprecated_patterns=(
        "base64::encode"
        "base64::decode"
        "redis::aio::Connection"
        "redis::Client::get_async_connection"
        "ring::deprecated_constant_time"
        "opentelemetry_jaeger::new_agent_pipeline"
    )
    
    for pattern in "${deprecated_patterns[@]}"; do
        echo -n "  Checking for $pattern... "
        if grep -r "$pattern" --include="*.rs" src/ 2>/dev/null | head -1 > /dev/null; then
            echo -e "${RED}❌ Found${NC}"
        else
            echo -e "${GREEN}✅ Clear${NC}"
        fi
    done
}

# Function to generate warning report
generate_warning_report() {
    local report_file="warning_report_$(date +%Y%m%d_%H%M%S).md"
    
    echo "# 📊 Compiler Warning Report" > "$report_file"
    echo "Generated: $(date)" >> "$report_file"
    echo "" >> "$report_file"
    
    echo "## Core Components Status" >> "$report_file"
    echo "| Component | Warnings | Status |" >> "$report_file"
    echo "|-----------|----------|--------|" >> "$report_file"
    
    for component in "${CORE_COMPONENTS[@]}"; do
        local warning_count=$(cargo check -p "$component" 2>&1 | grep -c "warning:" || true)
        local status="✅ Clean"
        if [ "$warning_count" -gt 0 ]; then
            status="⚠️ Needs Fix"
        fi
        echo "| $component | $warning_count | $status |" >> "$report_file"
    done
    
    echo "" >> "$report_file"
    echo "## Feature-Heavy Components" >> "$report_file"
    
    for component in "${FEATURE_HEAVY_COMPONENTS[@]}"; do
        echo "### $component" >> "$report_file"
        local warning_count=$(cargo check -p "$component" 2>&1 | grep -c "warning:" || true)
        echo "Default features: $warning_count warnings" >> "$report_file"
    done
    
    echo -e "${GREEN}📄 Report saved to $report_file${NC}"
}

# Main execution
main() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}    🔧 Rust Security Platform Warning Maintenance      ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Check if we should run fixes
    if [[ "${1:-}" == "--fix" ]]; then
        run_automated_fixes
        echo ""
    fi
    
    # Check core components
    echo -e "${YELLOW}📦 Checking Core Components...${NC}"
    local all_clean=true
    for component in "${CORE_COMPONENTS[@]}"; do
        if ! check_component_warnings "$component"; then
            all_clean=false
        fi
    done
    
    echo ""
    
    # Check feature-heavy components with different feature sets
    echo -e "${YELLOW}🔬 Checking Feature-Heavy Components...${NC}"
    for component in "${FEATURE_HEAVY_COMPONENTS[@]}"; do
        check_feature_combinations "$component"
    done
    
    echo ""
    
    # Check for deprecated APIs
    check_deprecated_apis
    
    echo ""
    
    # Generate report
    if [[ "${2:-}" == "--report" ]]; then
        generate_warning_report
    fi
    
    # Final status
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    if [ "$all_clean" = true ]; then
        echo -e "${GREEN}    ✅ All core components are warning-free!           ${NC}"
    else
        echo -e "${RED}    ⚠️  Some components have warnings                  ${NC}"
        echo -e "${YELLOW}    Run with --fix to apply automated fixes            ${NC}"
    fi
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    
    # Exit with appropriate code
    if [ "$all_clean" = true ]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function with all arguments
main "$@"