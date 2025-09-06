#!/bin/bash
# Clean Code Validation Script
# Validates code quality improvements and tracks metrics

set -euo pipefail

echo "🧹 Clean Code Validation"
echo "======================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
MAX_FUNCTION_SIZE=50
WARNING_THRESHOLD=5
SCORE_TARGET=99

# Initialize results
TOTAL_SCORE=0
CHECKS_PASSED=0
TOTAL_CHECKS=0

# Function to update score
update_score() {
    local points=$1
    local max_points=$2
    TOTAL_SCORE=$((TOTAL_SCORE + points))
    TOTAL_CHECKS=$((TOTAL_CHECKS + max_points))
    if [[ $points -eq $max_points ]]; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    fi
}

# Check function sizes
check_function_sizes() {
    echo -e "${BLUE}📏 Checking function sizes...${NC}"
    
    local large_functions=0
    local total_functions=0
    
    # Count functions and identify large ones
    while IFS= read -r -d '' file; do
        if [[ -f "$file" ]]; then
            local file_functions
            file_functions=$(grep -c "^\s*\(pub \)\?fn " "$file" 2>/dev/null || echo "0")
            total_functions=$((total_functions + file_functions))
            
            # Check for large functions (simplified check)
            local large_in_file
            large_in_file=$(awk '/^\s*(pub )?fn .*\{/{start=NR; brace=1; next} 
                                 brace>0{
                                   gsub(/[^{]/, "", temp1); brace+=length(temp1)
                                   gsub(/[^}]/, "", temp2); brace-=length(temp2)
                                   if(brace==0 && NR-start>'$MAX_FUNCTION_SIZE') print "Large function at line " start
                                 }' "$file" 2>/dev/null | wc -l)
            large_functions=$((large_functions + large_in_file))
        fi
    done < <(find auth-service/src common/src mvp-tools/src -name "*.rs" -type f -print0 2>/dev/null)
    
    echo "   Total functions: $total_functions"
    echo "   Large functions (>$MAX_FUNCTION_SIZE lines): $large_functions"
    
    if [[ $large_functions -eq 0 ]]; then
        echo -e "   ${GREEN}✅ All functions are appropriately sized${NC}"
        update_score 25 25
    elif [[ $large_functions -le 3 ]]; then
        echo -e "   ${YELLOW}⚠️  Few large functions remaining${NC}"
        update_score 20 25
    else
        echo -e "   ${RED}❌ Too many large functions${NC}"
        update_score 10 25
    fi
    echo ""
}

# Check warning status
check_warnings() {
    echo -e "${BLUE}⚠️  Checking compiler warnings...${NC}"
    
    # Run clippy and count warnings
    local warning_count
    warning_count=$(cargo clippy --all-targets --all-features -- -D warnings 2>&1 | grep -c "warning:" || echo "0")
    
    echo "   Compiler warnings: $warning_count"
    
    if [[ $warning_count -eq 0 ]]; then
        echo -e "   ${GREEN}✅ No compiler warnings${NC}"
        update_score 25 25
    elif [[ $warning_count -le $WARNING_THRESHOLD ]]; then
        echo -e "   ${YELLOW}⚠️  Few warnings remaining${NC}"
        update_score 20 25
    else
        echo -e "   ${RED}❌ Too many warnings${NC}"
        update_score 10 25
    fi
    echo ""
}

# Check documentation coverage
check_documentation() {
    echo -e "${BLUE}📚 Checking documentation coverage...${NC}"
    
    # Count documented vs undocumented public items
    local total_pub_items=0
    local documented_items=0
    
    while IFS= read -r -d '' file; do
        if [[ -f "$file" ]]; then
            # Count public items
            local pub_count
            pub_count=$(grep -c "^pub " "$file" 2>/dev/null || echo "0")
            total_pub_items=$((total_pub_items + pub_count))
            
            # Count items with documentation (/// comments)
            local doc_count
            doc_count=$(grep -B1 "^pub " "$file" | grep -c "///" 2>/dev/null || echo "0")
            documented_items=$((documented_items + doc_count))
        fi
    done < <(find auth-service/src common/src -name "*.rs" -type f -print0 2>/dev/null)
    
    local doc_percentage=0
    if [[ $total_pub_items -gt 0 ]]; then
        doc_percentage=$((documented_items * 100 / total_pub_items))
    fi
    
    echo "   Public items: $total_pub_items"
    echo "   Documented items: $documented_items"
    echo "   Documentation coverage: $doc_percentage%"
    
    if [[ $doc_percentage -ge 90 ]]; then
        echo -e "   ${GREEN}✅ Excellent documentation coverage${NC}"
        update_score 25 25
    elif [[ $doc_percentage -ge 75 ]]; then
        echo -e "   ${YELLOW}⚠️  Good documentation coverage${NC}"
        update_score 20 25
    else
        echo -e "   ${RED}❌ Insufficient documentation${NC}"
        update_score 10 25
    fi
    echo ""
}

# Check performance optimizations
check_performance() {
    echo -e "${BLUE}⚡ Checking performance optimizations...${NC}"
    
    local perf_score=0
    
    # Check if performance utilities exist
    if [[ -f "common/src/performance_utils.rs" ]]; then
        echo "   ✅ Performance utilities implemented"
        perf_score=$((perf_score + 8))
    fi
    
    # Check for async optimizations
    if [[ -f "auth-service/src/async_optimized.rs" ]]; then
        echo "   ✅ Async optimizations implemented"
        perf_score=$((perf_score + 8))
    fi
    
    # Check for memory optimizations
    if [[ -f "common/src/memory_optimization.rs" ]]; then
        echo "   ✅ Memory optimizations implemented"
        perf_score=$((perf_score + 9))
    fi
    
    echo "   Performance optimization score: $perf_score/25"
    
    if [[ $perf_score -ge 20 ]]; then
        echo -e "   ${GREEN}✅ Excellent performance optimizations${NC}"
    elif [[ $perf_score -ge 15 ]]; then
        echo -e "   ${YELLOW}⚠️  Good performance optimizations${NC}"
    else
        echo -e "   ${RED}❌ Insufficient performance optimizations${NC}"
    fi
    
    update_score $perf_score 25
    echo ""
}

# Run tests to ensure quality
check_tests() {
    echo -e "${BLUE}🧪 Running test suite...${NC}"
    
    # Run tests and capture result
    if cargo test --workspace --all-features > /dev/null 2>&1; then
        echo -e "   ${GREEN}✅ All tests passing${NC}"
        update_score 25 25
    else
        echo -e "   ${RED}❌ Some tests failing${NC}"
        update_score 0 25
    fi
    echo ""
}

# Generate final report
generate_report() {
    echo -e "${BLUE}📊 Final Quality Report${NC}"
    echo "========================"
    
    local final_score=0
    if [[ $TOTAL_CHECKS -gt 0 ]]; then
        final_score=$((TOTAL_SCORE * 100 / TOTAL_CHECKS))
    fi
    
    echo "Checks passed: $CHECKS_PASSED/5"
    echo "Total score: $TOTAL_SCORE/$TOTAL_CHECKS"
    echo "Final quality score: $final_score/100"
    echo ""
    
    if [[ $final_score -ge $SCORE_TARGET ]]; then
        echo -e "${GREEN}🎉 EXCELLENT! Target quality score achieved!${NC}"
        echo -e "${GREEN}✅ Code quality meets enterprise standards${NC}"
    elif [[ $final_score -ge 95 ]]; then
        echo -e "${YELLOW}🎯 VERY GOOD! Close to target quality score${NC}"
        echo -e "${YELLOW}⚠️  Minor improvements needed${NC}"
    else
        echo -e "${RED}❌ NEEDS IMPROVEMENT! Quality score below target${NC}"
        echo -e "${RED}🔧 Significant improvements required${NC}"
    fi
    
    echo ""
    echo "Quality breakdown:"
    echo "• Function sizes: Appropriate sizing improves maintainability"
    echo "• Warning status: Clean compilation ensures reliability"  
    echo "• Documentation: Good docs improve developer experience"
    echo "• Performance: Optimizations ensure scalability"
    echo "• Test coverage: Tests ensure correctness"
    
    # Save results to file
    cat > clean-code-validation-results.json << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "checks_passed": $CHECKS_PASSED,
  "total_checks": 5,
  "total_score": $TOTAL_SCORE,
  "max_score": $TOTAL_CHECKS,
  "final_score": $final_score,
  "target_score": $SCORE_TARGET,
  "status": "$(if [[ $final_score -ge $SCORE_TARGET ]]; then echo "PASSED"; else echo "NEEDS_IMPROVEMENT"; fi)"
}
EOF
    
    echo ""
    echo "Results saved to: clean-code-validation-results.json"
}

# Main execution
main() {
    echo "Starting clean code validation..."
    echo ""
    
    check_function_sizes
    check_warnings  
    check_documentation
    check_performance
    check_tests
    
    generate_report
    
    echo ""
    echo "Validation complete!"
    echo ""
    echo "Next steps:"
    echo "1. Address any failing checks"
    echo "2. Run validation again to verify improvements"
    echo "3. Integrate validation into CI pipeline"
    echo "4. Monitor quality metrics over time"
}

# Run main function
main "$@"
