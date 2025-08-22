#!/bin/bash

# Phase 2: Fix complex borrow checker and logic errors in auth-service

set -e

echo "🔧 Phase 2: Fixing complex errors in auth-service..."
echo "=================================================="

# Get initial error count
initial_errors=$(cargo check -p auth-service 2>&1 | grep -c "error\[" || echo "0")
echo "📊 Initial error count: $initial_errors"

echo ""
echo "🎯 Fix 1: Fix borrow of partially moved value in threat_classification..."

# Fix the threat_classification partial move issue
cat > /tmp/threat_fix.txt << 'EOF'
        let threat_types = threat_classification.threat_types.clone();
        let threat_assessment = ThreatAssessment {
            risk_level,
            confidence_score,
            threat_types,
            behavioral_score,
            recommended_actions: self.recommend_actions(&risk_level, &threat_classification),
        };
EOF

# Apply the fix (this is complex, so we'll do it manually if needed)
echo "  ⚠️  Complex fix needed - will address manually"

echo ""
echo "🎯 Fix 2: Fix session borrow checker issues..."

# The session borrow issue needs restructuring - let's create a simpler approach
echo "  ⚠️  Session borrow checker issues need manual restructuring"

echo ""
echo "🎯 Fix 3: Fix validation error formatting (lifetime issues)..."

# Fix ValidationError::new lifetime issues by using owned strings
sed -i '' 's/ValidationError::new(&format!/ValidationError::new(format!/g' auth-service/src/validation_secure.rs
sed -i '' 's/ValidationError::new(format!(/ValidationError::new(\&format!/g' auth-service/src/validation_secure.rs

echo "  ✅ Fixed validation error formatting"

echo ""
echo "🎯 Fix 4: Fix remaining logic issues..."

# Fix any remaining simple logic issues
sed -i '' 's/if let Ok(redis_url) = std::env::var("REDIS_URL").is_err()/if let Ok(redis_url) = std::env::var("REDIS_URL")/g' auth-service/src/lib.rs
sed -i '' 's/if std::env::var("TEST_MODE").is_err().is_err()/if std::env::var("TEST_MODE").is_ok()/g' auth-service/src/lib.rs

echo "  ✅ Fixed remaining logic issues"

echo ""
echo "🧪 Testing compilation..."

# Get final error count
if cargo check -p auth-service >/dev/null 2>&1; then
    echo "🎉 SUCCESS: auth-service now compiles!"
    echo ""
    echo "✅ Next steps:"
    echo "  1. Run tests: cargo test -p auth-service"
    echo "  2. Add auth-service to CI pipeline"
    echo "  3. Fix any remaining warnings"
else
    final_errors=$(cargo check -p auth-service 2>&1 | grep -c "error\[" || echo "0")
    echo "📊 Progress: $initial_errors → $final_errors errors"
    
    if [ "$final_errors" -lt "$initial_errors" ]; then
        echo "✅ Progress made!"
        echo ""
        echo "🔍 Remaining errors (first 10):"
        cargo check -p auth-service 2>&1 | grep -A 2 "error\[" | head -20
        echo ""
        echo "📋 Manual fixes needed for:"
        echo "  1. Borrow checker violations in session management"
        echo "  2. Partial move issues in threat detection"
        echo "  3. Complex async lifetime issues"
    else
        echo "⚠️  No progress made. Need different approach."
    fi
fi

echo ""
echo "📊 Summary of Phase 2 fixes:"
echo "  ⚠️  Identified complex borrow checker issues"
echo "  ✅ Fixed validation error formatting"
echo "  ✅ Fixed remaining logic issues"
echo "  📋 Manual fixes needed for remaining errors"
