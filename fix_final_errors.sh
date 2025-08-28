#!/bin/bash

echo "🔧 Fixing final 11 compilation errors..."

# Fix test variables in policy-service tests
sed -i '' '/^    #\[tokio::test\]/,/^    }$/ s/let _result = /let result = /g' policy-service/tests/integration_tests.rs
sed -i '' '/^    #\[test\]/,/^    }$/ s/let _result = /let result = /g' policy-service/tests/integration_tests.rs

# Fix test variables in examples
sed -i '' '/^    #\[tokio::test\]/,/^    }$/ s/let _result = /let result = /g' examples/axum-integration-example/src/repository.rs
sed -i '' '/^    #\[test\]/,/^    }$/ s/let _result = /let result = /g' examples/axum-integration-example/src/repository.rs

# Fix state variables in examples
sed -i '' 's/State(_state): State</State(state): State</g' examples/axum-integration-example/src/lib.rs

echo "✅ Applied fixes to remaining error files"

# Check final status
ERRORS=$(cargo check --all-targets --all-features 2>&1 | grep "error:" | wc -l | tr -d ' ')
WARNINGS=$(cargo check --all-targets --all-features 2>&1 | grep "warning:" | wc -l | tr -d ' ')

echo "📊 After fixes:"
echo "   - Errors: $ERRORS"
echo "   - Warnings: $WARNINGS"
echo "   - Total remaining: $((ERRORS + WARNINGS))"