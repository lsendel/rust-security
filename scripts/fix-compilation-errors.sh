#!/bin/bash

# Quick fix script for common compilation errors
# This addresses the most frequent issues to get packages compiling

set -e

echo "🔧 Fixing common compilation errors..."

# Fix 1: Add missing derives for enums
echo "  Adding missing derives..."

# Fix ThreatType enum
sed -i '' 's/pub enum ThreatType {/#[derive(Debug, Clone, PartialEq, Eq, Hash)]\npub enum ThreatType {/' auth-service/src/ai_threat_detection.rs

# Fix ThreatAction enum  
sed -i '' 's/pub enum ThreatAction {/#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]\npub enum ThreatAction {/' auth-service/src/ai_threat_detection.rs

# Fix ComplianceStatus enum
sed -i '' 's/pub enum ComplianceStatus {/#[derive(Debug, Clone, PartialEq, Eq)]\npub enum ComplianceStatus {/' auth-service/src/zero_trust_auth.rs

# Fix 2: Add missing imports
echo "  Adding missing imports..."

# Add chrono traits
sed -i '' '1i\
use chrono::{Datelike, Timelike};\
' auth-service/src/ai_threat_detection.rs

# Add base64 Engine trait
sed -i '' '1i\
use base64::Engine;\
' auth-service/src/session_secure.rs

# Fix 3: Fix type annotations for float ambiguity
echo "  Fixing float type ambiguity..."

sed -i '' 's/let mut score = 0\.3;/let mut score: f64 = 0.3;/' auth-service/src/zero_trust_auth.rs
sed -i '' 's/let mut score = 0\.5;/let mut score: f64 = 0.5;/' auth-service/src/zero_trust_auth.rs

# Fix 4: Fix string literal issues in config errors
echo "  Fixing string literal issues..."

sed -i '' 's/ConfigError::MissingRequiredField("REQUEST_SIGNING_SECRET")/ConfigError::MissingRequiredField("REQUEST_SIGNING_SECRET".to_string())/' auth-service/src/config_secure.rs
sed -i '' 's/ConfigError::WeakSecret("REQUEST_SIGNING_SECRET must be at least 32 characters")/ConfigError::WeakSecret("REQUEST_SIGNING_SECRET must be at least 32 characters".to_string())/' auth-service/src/config_secure.rs

# Fix 5: Fix pattern matching issues
echo "  Fixing pattern matching..."

sed -i '' 's/content_lower\.contains(pattern)/content_lower.contains(*pattern)/' auth-service/src/ai_threat_detection.rs
sed -i '' 's/content\.contains(pattern)/content.contains(*pattern)/' auth-service/src/ai_threat_detection.rs

# Fix 6: Fix ErrorResponse missing fields
echo "  Fixing ErrorResponse initialization..."

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

sed -i '' '/let mut error_response = ErrorResponse {/,/};/c\
        let mut error_response = ErrorResponse {\
            error: error_code.to_string(),\
            error_description: user_message.to_string(),\
            error_uri: None,\
            error_id: None,\
            correlation_id: None,\
            details: None,\
        };' auth-service/src/errors.rs

echo "✅ Basic fixes applied!"
echo ""
echo "🧪 Testing compilation..."

if cargo check -p auth-service >/dev/null 2>&1; then
    echo "✅ auth-service now compiles!"
else
    echo "❌ auth-service still has errors. Manual fixes needed."
    echo "Run: cargo check -p auth-service"
fi

echo ""
echo "📋 Next steps:"
echo "1. Review remaining compilation errors"
echo "2. Fix complex logic issues manually"
echo "3. Add packages back to CI as they're fixed"
