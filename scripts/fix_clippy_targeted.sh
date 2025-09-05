#!/bin/bash
# Targeted Clippy Fix Script

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "🔧 Targeted Clippy Fixes"
echo "======================="

# Fix 1: Similar variable names in handlers.rs
echo "📝 Fixing similar variable names..."
if grep -q "let client_id =" enterprise/policy-service/src/handlers.rs; then
    sed -i '' 's/let client_id =/let client_identifier =/g' enterprise/policy-service/src/handlers.rs
    echo "✅ Fixed client_id -> client_identifier"
fi

# Fix 2: Documentation backticks
echo "📝 Fixing documentation..."
sed -i '' 's/DoS protection/`DoS` protection/g' enterprise/policy-service/src/lib.rs
sed -i '' 's/OpenAPI documentation/`OpenAPI` documentation/g' enterprise/policy-service/src/documentation.rs
echo "✅ Added backticks to technical terms"

# Fix 3: Must-use attributes (manual approach)
echo "📝 Adding must_use attributes..."
# This needs manual fixing - just report what needs to be done
echo "⚠️  Manual fix needed: Add #[must_use] to error constructors in enterprise/policy-service/src/errors.rs"

# Fix 4: Format and validate
echo "📝 Formatting and validating..."
cargo fmt --all

echo "📊 Running clippy check..."
if cargo clippy --workspace --all-features -- -D warnings; then
    echo "🎉 All critical clippy warnings fixed!"
else
    echo "⚠️  Some warnings remain - see output above"
fi

echo ""
echo "🏆 Targeted fixes completed!"
