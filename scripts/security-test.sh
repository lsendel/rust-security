#!/bin/bash
# Security testing script

set -euo pipefail

echo "🔒 Running security tests..."

# Test 1: Check for unsafe code
echo "1. Scanning for unsafe code..."
UNSAFE_COUNT=$(grep -r "unsafe" --include="*.rs" src/ | wc -l || echo "0")
if [ "$UNSAFE_COUNT" -gt 0 ]; then
    echo "⚠️  Found $UNSAFE_COUNT unsafe blocks - manual review required"
else
    echo "✅ No unsafe code found"
fi

# Test 2: Secret scanning
echo "2. Scanning for hardcoded secrets..."
if grep -rE "(password|secret|key|token)\s*=\s*\"[^\"]{8,}\"" --include="*.rs" src/ 2>/dev/null; then
    echo "❌ Potential hardcoded secrets found"
    exit 1
else
    echo "✅ No hardcoded secrets detected"
fi

# Test 3: Dependency audit (if available)
if command -v cargo-audit >/dev/null 2>&1; then
    echo "3. Checking for vulnerable dependencies..."
    cargo audit
fi

echo "✅ Security tests completed"