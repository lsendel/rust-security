#!/bin/bash
# Quality validation for clean code implementation

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "🧹 Running Clean Code Quality Validation"
echo "======================================="

# 1. Format check
echo "📝 Checking code formatting..."
if cargo fmt --all -- --check; then
    echo "✅ Code formatting: PASS"
else
    echo "❌ Code formatting: FAIL"
    exit 1
fi

# 2. Clippy check
echo "🔍 Running clippy analysis..."
if cargo clippy --workspace --all-features -- -D warnings; then
    echo "✅ Clippy analysis: PASS"
else
    echo "❌ Clippy analysis: FAIL"
    exit 1
fi

# 3. Test execution
echo "🧪 Running tests..."
if cargo test --workspace --all-features; then
    echo "✅ Tests: PASS"
else
    echo "❌ Tests: FAIL"
    exit 1
fi

# 4. Documentation check
echo "📚 Checking documentation..."
if cargo doc --workspace --all-features --no-deps; then
    echo "✅ Documentation: PASS"
else
    echo "❌ Documentation: FAIL"
    exit 1
fi

# 5. Security audit
echo "🛡️ Running security audit..."
if cargo audit; then
    echo "✅ Security audit: PASS"
else
    echo "⚠️ Security audit: WARNINGS (check output)"
fi

echo ""
echo "🎉 All quality checks completed successfully!"
echo "📊 Clean code implementation: VALIDATED"
