#!/bin/bash
#
# Warning-Free Maintenance Script
#
# This script checks all core components for warning-free status
# and provides a summary report for maintenance purposes.

set -e

echo "🔧 Running warning-free maintenance check..."

CORE_COMPONENTS=("common" "policy-service")
FAILED_COMPONENTS=()

# Check each core component
for component in "${CORE_COMPONENTS[@]}"; do
    echo "  Checking $component..."
    
    # Use a quick check - check if warnings exist first
    if cargo check -p "$component" --message-format=short 2>&1 | grep -q "warning:"; then
        warning_count=$(cargo check -p "$component" --message-format=short 2>&1 | grep -c "warning:" || true)
        echo "    ⚠️  $component: $warning_count warnings"
        FAILED_COMPONENTS+=("$component")
    else
        echo "    ✅ $component: 0 warnings"
    fi
done

# Summary report
echo ""
echo "📊 Warning-Free Status Summary:"
echo "================================"

if [ ${#FAILED_COMPONENTS[@]} -eq 0 ]; then
    echo "✅ All core components are warning-free!"
    exit 0
else
    echo "⚠️  Components with warnings: ${FAILED_COMPONENTS[*]}"
    echo "Run 'cargo check -p <component>' for details"
    exit 1
fi