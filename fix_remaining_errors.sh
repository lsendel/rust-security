#!/bin/bash

# Fix remaining compilation errors systematically
set -e

echo "🔧 Fixing remaining compilation errors..."

# Fix auth-service compilation errors by addressing missing variables
find auth-service/src -name "*.rs" -exec sed -i '' 's/State(_state)/State(state)/g' {} \;
find auth-service/src -name "*.rs" -exec sed -i '' 's/Path(_id)/Path(id)/g' {} \;
find auth-service/src -name "*.rs" -exec sed -i '' 's/result\./operation_result\./g' {} \;
find auth-service/src -name "*.rs" -exec sed -i '' 's/= result;/= operation_result;/g' {} \;

# Fix config crate usage
find auth-service/src -name "*.rs" -exec sed -i '' 's/config::/crate::config::/g' {} \;

# Remove unused imports
sed -i '' 's/, UserRole//g' examples/axum-integration-example/src/repository.rs

echo "✅ Fixes applied!"

# Test compilation
if cargo check --workspace --quiet; then
    echo "✅ Compilation successful!"
else
    echo "❌ Still have errors, checking specific issues..."
    cargo check --workspace 2>&1 | head -20
fi