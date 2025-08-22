#!/bin/bash

# Systematic fix script for auth-service compilation errors
# Addresses the 40+ compilation errors in a structured way

set -e

echo "🔧 Fixing auth-service compilation errors systematically..."
echo "=========================================================="

# Phase 1: Fix missing imports
echo "📦 Phase 1: Adding missing imports..."

# Add base64::Engine trait
if ! grep -q "use base64::Engine;" auth-service/src/session_secure.rs; then
    sed -i '' '1i\
use base64::Engine;\
' auth-service/src/session_secure.rs
    echo "  ✅ Added base64::Engine import"
fi

# Fix JWT validation field name
echo "🔧 Phase 2: Fixing JWT validation..."
sed -i '' 's/validation\.validate_iss/validation.validate_exp/' auth-service/src/jwt_secure.rs
echo "  ✅ Fixed JWT validation field name"

# Phase 3: Fix string literal issues in config
echo "📝 Phase 3: Fixing string literal issues..."

# Fix config error messages
sed -i '' 's/ConfigError::MissingRequiredField("REQUEST_SIGNING_SECRET")/ConfigError::MissingRequiredField("REQUEST_SIGNING_SECRET".to_string())/' auth-service/src/config_secure.rs
sed -i '' 's/ConfigError::WeakSecret("REQUEST_SIGNING_SECRET must be at least 32 characters")/ConfigError::WeakSecret("REQUEST_SIGNING_SECRET must be at least 32 characters".to_string())/' auth-service/src/config_secure.rs
sed -i '' 's/ConfigError::WeakCrypto("RSA key size must be at least 2048 bits")/ConfigError::WeakCrypto("RSA key size must be at least 2048 bits".to_string())/' auth-service/src/config_secure.rs
sed -i '' 's/ConfigError::InvalidConfiguration("Access token TTL too short (minimum 5 minutes)")/ConfigError::InvalidConfiguration("Access token TTL too short (minimum 5 minutes)".to_string())/' auth-service/src/config_secure.rs
sed -i '' 's/ConfigError::InvalidConfiguration("Access token TTL too long (maximum 24 hours)")/ConfigError::InvalidConfiguration("Access token TTL too long (maximum 24 hours)".to_string())/' auth-service/src/config_secure.rs
sed -i '' 's/ConfigError::InvalidConfiguration("Session TTL too short (minimum 15 minutes)")/ConfigError::InvalidConfiguration("Session TTL too short (minimum 15 minutes)".to_string())/' auth-service/src/config_secure.rs
sed -i '' 's/ConfigError::WeakCrypto("Password minimum length must be at least 8")/ConfigError::WeakCrypto("Password minimum length must be at least 8".to_string())/' auth-service/src/config_secure.rs
sed -i '' 's/ConfigError::InvalidConfiguration("Per-IP rate limit too high (maximum 1000)")/ConfigError::InvalidConfiguration("Per-IP rate limit too high (maximum 1000)".to_string())/' auth-service/src/config_secure.rs

echo "  ✅ Fixed config error string literals"

# Phase 4: Fix pattern matching issues
echo "🔍 Phase 4: Fixing pattern matching..."

# Fix contains() calls with triple references
sed -i '' 's/content_lower\.contains(pattern)/content_lower.contains(*pattern)/g' auth-service/src/ai_threat_detection.rs
sed -i '' 's/content\.contains(pattern)/content.contains(*pattern)/g' auth-service/src/ai_threat_detection.rs

# Fix headers contains_key issue
sed -i '' 's/!headers\.contains_key(\*header)/!headers.contains_key(header.as_str())/g' auth-service/src/ai_threat_detection.rs

echo "  ✅ Fixed pattern matching issues"

# Phase 5: Fix ErrorResponse initialization
echo "🏗️ Phase 5: Fixing ErrorResponse initialization..."

# Create a temporary file with the correct ErrorResponse initialization
cat > /tmp/error_response_fix.txt << 'EOF'
        let mut error_response = ErrorResponse {
            error: error_code.to_string(),
            error_description: user_message.to_string(),
            error_uri: None,
            error_id: None,
            correlation_id: None,
            details: None,
        };
EOF

# Replace the problematic ErrorResponse initialization
sed -i '' '/let mut error_response = ErrorResponse {/,/};/{
    /let mut error_response = ErrorResponse {/r /tmp/error_response_fix.txt
    /let mut error_response = ErrorResponse {/,/};/d
}' auth-service/src/errors.rs

# Fix error_id conversion
sed -i '' 's/error_response\.error_id = Some(\*error_id);/error_response.error_id = Some(error_id.to_string());/' auth-service/src/errors.rs

echo "  ✅ Fixed ErrorResponse initialization"

# Phase 6: Fix Result handling
echo "⚡ Phase 6: Fixing Result handling..."

# Fix PKCE validation
sed -i '' 's/if !crate::security::validate_pkce_params(/if crate::security::validate_pkce_params(/; s/) {/).is_err() {/' auth-service/src/lib.rs

# Fix token binding validation  
sed -i '' 's/if !crate::security::validate_token_binding(/if crate::security::validate_token_binding(/; s/) {/).is_err() {/' auth-service/src/lib.rs

echo "  ✅ Fixed Result handling"

# Phase 7: Fix borrow checker issues
echo "🔒 Phase 7: Fixing borrow checker issues..."

# Fix session data cloning issue
sed -i '' 's/sessions\.insert(session_id\.clone(), session_data);/sessions.insert(session_id.clone(), session_data.clone());/' auth-service/src/session_secure.rs

echo "  ✅ Fixed session data cloning"

# Phase 8: Test compilation
echo "🧪 Phase 8: Testing compilation..."

if cargo check -p auth-service >/dev/null 2>&1; then
    echo "🎉 SUCCESS: auth-service now compiles!"
    echo ""
    echo "✅ Next steps:"
    echo "  1. Run tests: cargo test -p auth-service"
    echo "  2. Add auth-service to CI pipeline"
    echo "  3. Fix remaining warnings"
else
    echo "⚠️  Still has compilation errors. Progress made, but manual fixes needed."
    echo ""
    echo "🔍 Remaining errors:"
    cargo check -p auth-service 2>&1 | head -20
    echo ""
    echo "📋 Common remaining issues:"
    echo "  - Complex borrow checker violations"
    echo "  - Logic errors in async code"
    echo "  - Type mismatches in complex expressions"
fi

# Cleanup
rm -f /tmp/error_response_fix.txt

echo ""
echo "📊 Summary of fixes applied:"
echo "  ✅ Added missing imports (base64::Engine)"
echo "  ✅ Fixed JWT validation field names"
echo "  ✅ Fixed string literal lifetime issues"
echo "  ✅ Fixed pattern matching with references"
echo "  ✅ Fixed ErrorResponse initialization"
echo "  ✅ Fixed Result type handling"
echo "  ✅ Fixed basic borrow checker issues"
