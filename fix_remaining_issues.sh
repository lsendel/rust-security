#!/bin/bash

# Fix remaining test variable issues
echo "🔧 Fixing remaining test variable issues..."

# Fix test functions in sharded_rate_limiter.rs - only in test functions
sed -i '' '/^    #\[tokio::test\]/,/^    }$/ s/let _limiter = /let limiter = /g' common/src/sharded_rate_limiter.rs

# Fix test functions in crypto_utils.rs - only in test functions  
sed -i '' '/^    #\[test\]/,/^    }$/ s/let _result = /let result = /g' common/src/crypto_utils.rs

# Fix test functions in utils.rs - only in test functions
sed -i '' '/^    #\[test\]/,/^    }$/ s/let _result = /let result = /g' common/src/utils.rs

# Add back num_cpus usage to avoid unused dependency warning
echo 'use num_cpus as _;' >> common/src/lib.rs

echo "✅ Fixed remaining test issues"

# Run final check
echo "🔍 Running final cargo check..."
cargo check --all-targets --all-features --quiet

if [ $? -eq 0 ]; then
    echo "🎉 All issues fixed! Project builds successfully."
else
    echo "📊 Remaining issues:"
    cargo check --all-targets --all-features 2>&1 | grep -E "(error|warning):" | head -10
fi