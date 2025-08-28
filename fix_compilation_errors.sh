#!/bin/bash

# Comprehensive fix script for Rust Security Platform compilation errors
set -e

echo "🔧 Fixing Rust Security Platform compilation errors..."

# Fix policy_cache.rs - missing size variable
sed -i '' 's/size/cache_size/g' auth-service/src/policy_cache.rs

# Fix session_store.rs - missing result variable  
sed -i '' 's/result\./session_result\./g' auth-service/src/session_store.rs
sed -i '' 's/= result;/= session_result;/g' auth-service/src/session_store.rs

# Fix admin_middleware.rs - state variable issues
sed -i '' 's/State(_state)/State(state)/g' auth-service/src/admin_middleware.rs
sed -i '' 's/result\./admin_result\./g' auth-service/src/admin_middleware.rs

# Fix api_key_endpoints.rs - state variable issues
sed -i '' 's/State(_state)/State(state)/g' auth-service/src/api_key_endpoints.rs

# Fix api_key_store.rs - result variable
sed -i '' 's/result\./key_result\./g' auth-service/src/api_key_store.rs

# Fix backpressure.rs - result variable
sed -i '' 's/result\./bp_result\./g' auth-service/src/backpressure.rs

# Fix circuit_breaker.rs - result variable
sed -i '' 's/result\./cb_result\./g' auth-service/src/circuit_breaker.rs

# Fix health_check.rs - result variable
sed -i '' 's/result\./health_result\./g' auth-service/src/health_check.rs

# Fix validation.rs - result variable
sed -i '' 's/result\./validation_result\./g' auth-service/src/validation.rs

# Fix auth_api.rs - state variable issues
sed -i '' 's/State(_state)/State(state)/g' auth-service/src/auth_api.rs

# Fix config crate usage issues
sed -i '' 's/config::/crate::config::/g' auth-service/src/jit_token_manager.rs
sed -i '' 's/config::/crate::config::/g' auth-service/src/non_human_monitoring.rs

# Fix unused import in axum-integration-example
sed -i '' '/use.*UserRole.*;/d' examples/axum-integration-example/src/repository.rs

echo "✅ Compilation errors fixed!"

# Test compilation
echo "🧪 Testing compilation..."
if cargo check --workspace --quiet; then
    echo "✅ All compilation errors resolved!"
else
    echo "❌ Some compilation errors remain. Check output above."
    exit 1
fi

echo "🎉 Fix script completed successfully!"