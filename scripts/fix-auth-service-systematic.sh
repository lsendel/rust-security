#!/bin/bash

# Systematic fix script for auth-service - Phase 1 Quick Wins
# Fixes the most obvious systematic errors

set -e

echo "🔧 Phase 1: Fixing systematic errors in auth-service..."
echo "======================================================"

# Get initial error count
initial_errors=$(cargo check -p auth-service 2>&1 | grep -c "error\[" || echo "0")
echo "📊 Initial error count: $initial_errors"

echo ""
echo "🎯 Fix 1: Remove duplicate trait derives..."

# Fix duplicate derives in ThreatType
sed -i '' 's/#\[derive(Debug, Clone, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)\]/#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]/' auth-service/src/ai_threat_detection.rs

# Fix duplicate derives in ThreatAction  
sed -i '' 's/#\[derive(Debug, Clone, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)\]/#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]/' auth-service/src/ai_threat_detection.rs

echo "  ✅ Fixed duplicate trait derives"

echo ""
echo "🎯 Fix 2: Fix .is_err().is_err() patterns..."

# Fix simple boolean method chains
sed -i '' 's/\.is_empty()\.is_err()\.is_err()/.is_empty()/g' auth-service/src/lib.rs
sed -i '' 's/\.starts_with(\([^)]*\))\.is_err()\.is_err()/.starts_with(\1)/g' auth-service/src/lib.rs
sed -i '' 's/\.contains(\([^)]*\))\.is_err()\.is_err()/.contains(\1)/g' auth-service/src/lib.rs
sed -i '' 's/\.is_none()\.is_err()\.is_err()/.is_none()/g' auth-service/src/lib.rs
sed -i '' 's/\.any(\([^)]*\))\.is_err()\.is_err()/.any(\1)/g' auth-service/src/lib.rs

# Fix Result method chains (these need different logic)
sed -i '' 's/std::env::var(\([^)]*\))\.is_err()\.is_err()/std::env::var(\1).is_err()/g' auth-service/src/lib.rs
sed -i '' 's/\.decode(\([^)]*\))\.is_err()\.is_err()/.decode(\1).is_err()/g' auth-service/src/lib.rs
sed -i '' 's/\.from_utf8(\([^)]*\))\.is_err()\.is_err()/.from_utf8(\1).is_err()/g' auth-service/src/lib.rs

# Fix Option method chains
sed -i '' 's/\.as_ref()\.is_err()\.is_err()/.as_ref().is_none()/g' auth-service/src/lib.rs
sed -i '' 's/\.get(\([^)]*\))\.is_err()\.is_err()/.get(\1).is_none()/g' auth-service/src/lib.rs
sed -i '' 's/== Some(\([^)]*\))\.is_err()\.is_err()/== Some(\1)/g' auth-service/src/lib.rs
sed -i '' 's/!= Some(\([^)]*\))\.is_err()\.is_err()/!= Some(\1)/g' auth-service/src/lib.rs

echo "  ✅ Fixed .is_err().is_err() patterns"

echo ""
echo "🎯 Fix 3: Fix remaining string literal issues..."

# Fix config error messages that weren't caught before
sed -i '' 's/"REQUEST_SIGNING_SECRET must be at least 32 characters"/"REQUEST_SIGNING_SECRET must be at least 32 characters".to_string()/g' auth-service/src/config_secure.rs
sed -i '' 's/"RSA key size must be at least 2048 bits"/"RSA key size must be at least 2048 bits".to_string()/g' auth-service/src/config_secure.rs
sed -i '' 's/"Access token TTL too short (minimum 5 minutes)"/"Access token TTL too short (minimum 5 minutes)".to_string()/g' auth-service/src/config_secure.rs
sed -i '' 's/"Access token TTL too long (maximum 24 hours)"/"Access token TTL too long (maximum 24 hours)".to_string()/g' auth-service/src/config_secure.rs
sed -i '' 's/"Session TTL too short (minimum 15 minutes)"/"Session TTL too short (minimum 15 minutes)".to_string()/g' auth-service/src/config_secure.rs
sed -i '' 's/"Password minimum length must be at least 8"/"Password minimum length must be at least 8".to_string()/g' auth-service/src/config_secure.rs
sed -i '' 's/"Per-IP rate limit too high (maximum 1000)"/"Per-IP rate limit too high (maximum 1000)".to_string()/g' auth-service/src/config_secure.rs

echo "  ✅ Fixed string literal issues"

echo ""
echo "🎯 Fix 4: Fix remaining float type ambiguity..."

# Fix the remaining float type issues
sed -i '' 's/let mut score = 0\.5; \/\/ Base score/let mut score: f64 = 0.5; \/\/ Base score/g' auth-service/src/zero_trust_auth.rs

echo "  ✅ Fixed float type ambiguity"

echo ""
echo "🎯 Fix 5: Fix unstable feature usage..."

# Fix the unstable str_as_str feature
sed -i '' 's/header\.as_str()/header/g' auth-service/src/ai_threat_detection.rs

echo "  ✅ Fixed unstable feature usage"

echo ""
echo "🎯 Fix 6: Fix prometheus encoder issue..."

# Fix the prometheus encoder .is_err().is_err() issue
sed -i '' 's/encoder\.encode(\([^)]*\))\.is_err()\.is_err()/encoder.encode(\1)/g' auth-service/src/lib.rs

echo "  ✅ Fixed prometheus encoder issue"

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
        echo "✅ Significant progress made!"
        echo ""
        echo "🔍 Remaining error types:"
        cargo check -p auth-service 2>&1 | grep "error\[" | cut -d':' -f4 | sort | uniq -c | head -10
        echo ""
        echo "📋 Next actions needed:"
        echo "  1. Review remaining errors manually"
        echo "  2. Fix complex borrow checker issues"
        echo "  3. Fix validation error formatting"
    else
        echo "⚠️  No progress made. Manual review needed."
    fi
fi

echo ""
echo "📊 Summary of fixes applied:"
echo "  ✅ Removed duplicate trait derives"
echo "  ✅ Fixed .is_err().is_err() patterns"
echo "  ✅ Fixed string literal lifetime issues"
echo "  ✅ Fixed float type ambiguity"
echo "  ✅ Fixed unstable feature usage"
echo "  ✅ Fixed prometheus encoder issue"
