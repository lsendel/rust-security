#!/bin/bash
# Enhanced Clippy Warning Monitor
# Tracks warning reduction progress and categorizes warnings

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 Clippy Warning Analysis${NC}"
echo "=================================="

# Get current warnings
WARNINGS=$(cargo clippy --workspace --all-features 2>&1 | grep "warning:" | grep -v -E "multiple versions|generated.*warnings" | wc -l | tr -d " ")
ORIGINAL_WARNINGS=$(cargo clippy --workspace --all-features 2>&1 | grep "warning:" | grep -v -E "multiple versions|generated.*warnings" | wc -l | tr -d " ")
REDUCTION_PERCENT=$(( (ORIGINAL_WARNINGS - WARNINGS) * 100 / ORIGINAL_WARNINGS ))

echo -e "${GREEN}📊 Current Status:${NC}"
echo "  • Total warnings: $WARNINGS"
echo "  • Original warnings: $ORIGINAL_WARNINGS"
echo "  • Reduction: ${REDUCTION_PERCENT}% (${WARNINGS} remaining)"

# Target assessment
if [ "$WARNINGS" -le 25 ]; then
    echo -e "${GREEN}✅ TARGET ACHIEVED: 95%+ reduction!${NC}"
elif [ "$WARNINGS" -le 50 ]; then
    echo -e "${YELLOW}🎯 CLOSE TO TARGET: $(( 50 - WARNINGS )) warnings to go${NC}"
else
    echo -e "${RED}📈 PROGRESS NEEDED: $(( WARNINGS - 25 )) warnings above target${NC}"
fi

echo ""
echo -e "${BLUE}📋 Warning Categories:${NC}"

# Categorize warnings
cargo clippy --workspace --all-features 2>&1 | grep "warning:" | sort | uniq -c | sort -nr | head -10 | while read count warning; do
    echo "  • $count × ${warning#warning: }"
done

echo ""
echo -e "${BLUE}🏗️ Component Status:${NC}"

# Check each component
for component in auth-service policy-service common compliance-tools; do
    if [ -d "$component" ]; then
        cd "$component"
        comp_warnings=$(cargo clippy 2>&1 | grep "warning:" | wc -l | tr -d ' ')
        if [ "$comp_warnings" -eq 0 ]; then
            echo -e "  • ${component}: ${GREEN}✅ WARNING-FREE${NC}"
        else
            echo -e "  • ${component}: ${YELLOW}$comp_warnings warnings${NC}"
        fi
        cd ..
    fi
done

echo ""
echo -e "${BLUE}🎯 Next Steps:${NC}"
if [ "$WARNINGS" -gt 25 ]; then
    echo "  1. Focus on high-frequency warning types"
    echo "  2. Add strategic #[allow] attributes for acceptable warnings"
    echo "  3. Fix genuine code quality issues"
    echo "  4. Re-run this script to track progress"
else
    echo "  🎉 Excellent work! Consider documenting the success."
fi
