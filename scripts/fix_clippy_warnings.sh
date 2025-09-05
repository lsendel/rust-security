#!/bin/bash
# Automated Clippy Warning Fix Script

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "🔧 Fixing Clippy Warnings"
echo "========================"

# Phase 1: Fix similar variable names
echo "📝 Phase 1: Fixing similar variable names..."
sed -i '' 's/let client_id =/let client_identifier =/g' enterprise/policy-service/src/handlers.rs
sed -i '' 's/client_id\./client_identifier\./g' enterprise/policy-service/src/handlers.rs
echo "✅ Variable names fixed"

# Phase 2: Fix raw string literals
echo "📝 Phase 2: Fixing raw string literals..."
sed -i '' 's/r#"/r"/g' enterprise/policy-service/src/lib.rs
sed -i '' 's/"#/"/g' enterprise/policy-service/src/lib.rs
echo "✅ Raw strings fixed"

# Phase 3: Fix documentation
echo "📝 Phase 3: Fixing documentation..."
sed -i '' 's/DoS protection/`DoS` protection/g' enterprise/policy-service/src/lib.rs
sed -i '' 's/OpenAPI documentation/`OpenAPI` documentation/g' enterprise/policy-service/src/documentation.rs
echo "✅ Documentation fixed"

# Phase 4: Add must_use attributes
echo "📝 Phase 4: Adding must_use attributes..."
sed -i '' 's/pub fn io(/\#[must_use]\n    pub fn io(/g' enterprise/policy-service/src/errors.rs
echo "✅ Must_use attributes added"

# Phase 5: Format code
echo "📝 Phase 5: Formatting code..."
cargo fmt --all
echo "✅ Code formatted"

# Phase 6: Validate fixes
echo "📝 Phase 6: Validating fixes..."
if cargo clippy --workspace --all-features -- -D warnings; then
    echo "🎉 All clippy warnings fixed!"
    echo "✅ Code quality: 100/100"
else
    echo "❌ Some warnings remain. Manual fixes may be needed."
    exit 1
fi

echo ""
echo "🏆 Clippy fix completed successfully!"
echo "📊 Status: Zero warnings achieved"
