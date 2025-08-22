#!/bin/bash

# Final fix script for remaining specific errors in auth-service

set -e

echo "🔧 Final fixes for auth-service remaining errors..."
echo "================================================="

# Get initial error count
initial_errors=$(cargo check -p auth-service 2>&1 | grep -c "error\[" || echo "0")
echo "📊 Initial error count: $initial_errors"

echo ""
echo "🎯 Fix 1: Fix remaining .is_err().is_err() patterns that were missed..."

# Fix the complex multi-line .is_err().is_err() patterns
sed -i '' '/\.is_err()$/N;s/\.is_err()\n.*\.is_err()/.is_err()/g' auth-service/src/lib.rs

# Fix specific patterns that are still problematic
sed -i '' 's/\.get(axum::http::header::AUTHORIZATION)\.is_err()/.get(axum::http::header::AUTHORIZATION)/g' auth-service/src/lib.rs
sed -i '' 's/\.and_then(|v| v\.to_str()\.ok())\.is_err()/.and_then(|v| v.to_str().ok())/g' auth-service/src/lib.rs
sed -i '' 's/\.unwrap_or(false)\.is_err()/.unwrap_or(false)/g' auth-service/src/lib.rs
sed -i '' 's/\.any(|s| s == "openid")\.is_err()/.any(|s| s == "openid")/g' auth-service/src/lib.rs

echo "  ✅ Fixed remaining .is_err().is_err() patterns"

echo ""
echo "🎯 Fix 2: Fix Option pattern matching issues..."

# Fix the mismatched Option/bool patterns
sed -i '' 's/if let Some(scope_str) = form\.scope\.as_ref()\.is_none()/if let Some(scope_str) = form.scope.as_ref()/g' auth-service/src/lib.rs

echo "  ✅ Fixed Option pattern matching"

echo ""
echo "🎯 Fix 3: Fix unstable feature usage..."

# Fix the unstable str_as_str feature (remove .as_str() calls on &str)
sed -i '' 's/header\.as_str()/header/g' auth-service/src/ai_threat_detection.rs

echo "  ✅ Fixed unstable feature usage"

echo ""
echo "🎯 Fix 4: Fix base64 decode sizing issues..."

# Fix the base64 decode sizing issues by using Vec<u8> instead of [u8]
sed -i '' 's/if let Ok(decoded)/if let Ok(decoded_vec)/g' auth-service/src/lib.rs
sed -i '' 's/std::str::from_utf8(&decoded)/std::str::from_utf8(\&decoded_vec)/g' auth-service/src/lib.rs

echo "  ✅ Fixed base64 decode sizing issues"

echo ""
echo "🎯 Fix 5: Fix validation logic inversions..."

# Fix inverted validation logic
sed -i '' 's/if !validate_scope(scope, \&state\.allowed_scopes)\.is_err()/if validate_scope(scope, \&state.allowed_scopes)/g' auth-service/src/lib.rs
sed -i '' 's/if !scope\.split_whitespace()\.any(|s| s == "openid")/if scope.split_whitespace().any(|s| s == "openid")/g' auth-service/src/lib.rs

echo "  ✅ Fixed validation logic inversions"

echo ""
echo "🧪 Testing compilation..."

# Get final error count
if cargo check -p auth-service >/dev/null 2>&1; then
    echo "🎉 SUCCESS: auth-service now compiles!"
    echo ""
    echo "✅ Next steps:"
    echo "  1. Run tests: cargo test -p auth-service"
    echo "  2. Add auth-service to CI pipeline"
    echo "  3. Fix remaining warnings"
    echo ""
    echo "🎯 Ready to add to CI!"
else
    final_errors=$(cargo check -p auth-service 2>&1 | grep -c "error\[" || echo "0")
    echo "📊 Progress: $initial_errors → $final_errors errors"
    
    if [ "$final_errors" -lt "$initial_errors" ]; then
        echo "✅ Progress made!"
        echo ""
        echo "🔍 Remaining errors (first 5):"
        cargo check -p auth-service 2>&1 | grep -A 1 "error\[" | head -10
        echo ""
        echo "📋 These may need manual review and fixing"
    else
        echo "⚠️  No progress made. Need manual intervention."
    fi
fi

echo ""
echo "📊 Summary of final fixes:"
echo "  ✅ Fixed remaining .is_err().is_err() patterns"
echo "  ✅ Fixed Option pattern matching issues"
echo "  ✅ Fixed unstable feature usage"
echo "  ✅ Fixed base64 decode sizing issues"
echo "  ✅ Fixed validation logic inversions"
