#!/bin/bash
# Clippy Zero Warnings Enforcement Script
# Ensures the codebase maintains zero clippy warnings for CI/CD

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MAX_ALLOWED_WARNINGS=0
CLIPPY_ARGS="--all-targets --all-features"
SUPPRESS_ARGS="-A clippy::multiple_crate_versions"

echo -e "${BLUE}🔍 Clippy Zero Warnings Check${NC}"
echo "======================================"

# Function to run clippy and capture output
run_clippy_check() {
    echo -e "${BLUE}Running clippy check...${NC}"

    # Capture both stdout and stderr
    CLIPPY_OUTPUT=$(cargo clippy $CLIPPY_ARGS -- -D warnings $SUPPRESS_ARGS 2>&1 || true)
    CLIPPY_EXIT_CODE=$?

    echo "$CLIPPY_OUTPUT"
    echo ""

    return $CLIPPY_EXIT_CODE
}

# Function to analyze results
analyze_results() {
    local output="$1"
    local exit_code="$2"

    # Count actual warnings (excluding suppressed ones)
    WARNING_COUNT=$(echo "$output" | grep -c "warning:" || true)
    ERROR_COUNT=$(echo "$output" | grep -c "error:" || true)

    echo -e "${BLUE}📊 Analysis Results:${NC}"
    echo "  • Exit Code: $exit_code"
    echo "  • Warnings Found: $WARNING_COUNT"
    echo "  • Errors Found: $ERROR_COUNT"
    echo "  • Max Allowed Warnings: $MAX_ALLOWED_WARNINGS"
    echo ""

    return $WARNING_COUNT
}

# Function to provide recommendations
provide_recommendations() {
    local warning_count="$1"
    local output="$2"

    if [ "$warning_count" -gt "$MAX_ALLOWED_WARNINGS" ]; then
        echo -e "${YELLOW}💡 Recommendations:${NC}"

        # Show top warning types
        echo "Top warning categories:"
        echo "$output" | grep "warning:" | sed 's/.*warning: //' | sort | uniq -c | sort -nr | head -5 | while read count warning; do
            echo "  • $count × $warning"
        done
        echo ""

        echo "Quick fix commands:"
        echo "  # Fix formatting issues:"
        echo "  cargo fmt --all"
        echo ""
        echo "  # Apply automatic fixes:"
        echo "  cargo clippy --fix $CLIPPY_ARGS"
        echo ""
        echo "  # Check specific file:"
        echo "  cargo clippy --bin <binary_name> $SUPPRESS_ARGS"
        echo ""
    fi
}

# Main execution
main() {
    run_clippy_check
    local clippy_output="$CLIPPY_OUTPUT"
    local exit_code="$CLIPPY_EXIT_CODE"

    analyze_results "$clippy_output" "$exit_code"
    local warning_count=$?

    if [ "$warning_count" -le "$MAX_ALLOWED_WARNINGS" ] && [ "$exit_code" -eq 0 ]; then
        echo -e "${GREEN}✅ SUCCESS: Zero warnings achieved!${NC}"
        echo "The codebase passes all clippy checks."
        exit 0
    else
        echo -e "${RED}❌ FAILURE: Warnings detected!${NC}"
        echo "Clippy check failed with $warning_count warnings."
        echo ""

        provide_recommendations "$warning_count" "$clippy_output"

        echo -e "${RED}To ignore this failure in CI (not recommended):${NC}"
        echo "  export CLIPPY_ZERO_CHECK=false"
        echo ""

        exit 1
    fi
}

# Check if this check should be skipped
if [ "${CLIPPY_ZERO_CHECK:-true}" = "false" ]; then
    echo -e "${YELLOW}⚠️  Clippy zero check skipped by CLIPPY_ZERO_CHECK=false${NC}"
    exit 0
fi

# Run main function
main
