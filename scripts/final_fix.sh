#!/bin/bash

echo "🔧 Final comprehensive fix for all remaining issues..."

# Fix all test variables in auth-service - only in test functions
find auth-service/src -name "*.rs" -exec sed -i '' '/^    #\[tokio::test\]/,/^    }$/ s/let _result = /let result = /g' {} \;
find auth-service/src -name "*.rs" -exec sed -i '' '/^    #\[test\]/,/^    }$/ s/let _result = /let result = /g' {} \;
find auth-service/src -name "*.rs" -exec sed -i '' '/^    #\[tokio::test\]/,/^    }$/ s/let _limiter = /let limiter = /g' {} \;
find auth-service/src -name "*.rs" -exec sed -i '' '/^    #\[test\]/,/^    }$/ s/let _limiter = /let limiter = /g' {} \;

# Fix SecurityEventType::Login to use correct variant
find auth-service/src -name "*.rs" -exec sed -i '' 's/SecurityEventType::Login/SecurityEventType::AuthenticationSuccess/g' {} \;

# Fix unused variables by prefixing with underscore
find auth-service/src -name "*.rs" -exec sed -i '' 's/let config = self\.config\.read()\.await;/let _config = self.config.read().await;/g' {} \;
find auth-service/src -name "*.rs" -exec sed -i '' 's/features: &mut BehavioralFeatureVector,/_features: \&mut BehavioralFeatureVector,/g' {} \;
find auth-service/src -name "*.rs" -exec sed -i '' 's/parameters: &HashMap<String, f64>,/_parameters: \&HashMap<String, f64>,/g' {} \;
find auth-service/src -name "*.rs" -exec sed -i '' 's/config: &Arc<RwLock<UserProfilingConfig>>,/_config: \&Arc<RwLock<UserProfilingConfig>>,/g' {} \;
find auth-service/src -name "*.rs" -exec sed -i '' 's/let sum_y_squared: f64/let _sum_y_squared: f64/g' {} \;

# Remove unused imports
find auth-service/src -name "*.rs" -exec sed -i '' 's/use statrs::statistics::{OrderStatistics, Statistics};/use statrs::statistics::Statistics;/g' {} \;
find auth-service/src -name "*.rs" -exec sed -i '' '/use crate::service_identity::Environment;/d' {} \;

echo "✅ Applied final fixes"

# Final validation
echo "🔍 Running final validation..."
ERRORS=$(cargo check --all-targets --all-features 2>&1 | grep -c "error:" || echo "0")
WARNINGS=$(cargo check --all-targets --all-features 2>&1 | grep -c "warning:" || echo "0")

echo "📊 Final Status:"
echo "   - Compilation errors: $ERRORS"
echo "   - Warnings: $WARNINGS"
echo "   - Total issues fixed: $((522 - ERRORS - WARNINGS))"

if [ "$ERRORS" -eq 0 ]; then
    echo "🎉 SUCCESS: All compilation errors resolved!"
    echo "✨ Project builds successfully with only $WARNINGS warnings remaining"
else
    echo "⚠️  $ERRORS compilation errors still need attention"
fi