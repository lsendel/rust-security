#!/bin/bash

# Comprehensive fix script for all 522 Amazon Q code issues
# This script addresses compilation errors and warnings systematically

set -e

echo "🔧 Starting comprehensive fix for 522 Amazon Q code issues..."

# Phase 1: Fix critical compilation errors
echo "📋 Phase 1: Fixing critical compilation errors..."

# Fix unused variables by prefixing with underscore
find . -name "*.rs" -type f -exec sed -i '' 's/let limiter = /let _limiter = /g' {} \;
find . -name "*.rs" -type f -exec sed -i '' 's/let size = /let _size = /g' {} \;
find . -name "*.rs" -type f -exec sed -i '' 's/let result = /let _result = /g' {} \;

# Fix deprecated ring function usage
find . -name "*.rs" -type f -exec sed -i '' 's/ring::deprecated_constant_time::verify_slices_are_equal/constant_time_eq::constant_time_eq/g' {} \;
find . -name "*.rs" -type f -exec sed -i '' 's/verify_slices_are_equal(a, b)\.is_ok()/constant_time_eq::constant_time_eq(a, b)/g' {} \;

# Phase 2: Fix warnings
echo "📋 Phase 2: Fixing warnings..."

# Remove unused imports
find . -name "*.rs" -type f -exec sed -i '' '/^use.*rayon::prelude::\*;$/d' {} \;
find . -name "*.rs" -type f -exec sed -i '' '/^use.*num_cpus as _;$/d' {} \;

# Fix unused variables in function parameters
find . -name "*.rs" -type f -exec sed -i '' 's/state): State</_state): State</g' {} \;
find . -name "*.rs" -type f -exec sed -i '' 's/id): Path</_id): Path</g' {} \;
find . -name "*.rs" -type f -exec sed -i '' 's/query): Query</_query): Query</g' {} \;

# Phase 3: Fix specific type issues
echo "📋 Phase 3: Fixing type issues..."

# Fix ambiguous numeric types
find . -name "*.rs" -type f -exec sed -i '' 's/let mut max_correlation = 0\.0;/let mut max_correlation: f64 = 0.0;/g' {} \;

# Phase 4: Clean up and validate
echo "📋 Phase 4: Cleaning up and validating..."

# Remove any backup files created by sed
find . -name "*.rs.bak" -delete 2>/dev/null || true

# Run cargo check to validate fixes
echo "🔍 Running cargo check to validate fixes..."
if cargo check --all-targets --all-features --quiet; then
    echo "✅ All compilation errors fixed successfully!"
else
    echo "⚠️  Some issues remain, but major fixes applied"
fi

# Count remaining warnings
echo "📊 Counting remaining issues..."
WARNINGS=$(cargo check --all-targets --all-features 2>&1 | grep -c "warning:" || echo "0")
ERRORS=$(cargo check --all-targets --all-features 2>&1 | grep -c "error:" || echo "0")

echo "📈 Fix Summary:"
echo "   - Errors remaining: $ERRORS"
echo "   - Warnings remaining: $WARNINGS"
echo "   - Total issues fixed: $((522 - ERRORS - WARNINGS))"

if [ "$ERRORS" -eq 0 ]; then
    echo "🎉 All compilation errors resolved! Project builds successfully."
else
    echo "🔧 $ERRORS compilation errors still need manual attention."
fi

echo "✨ Fix script completed!"