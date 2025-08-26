#!/bin/bash

# Fix all test files with type mismatches

FILES=(
    "auth-service/tests/health_introspect_it.rs"
    "auth-service/tests/refresh_reuse_it.rs"
    "auth-service/tests/pkce_oauth_test.rs"
    "auth-service/tests/api_key_management_it.rs"
    "auth-service/tests/scim_it.rs"
    "auth-service/tests/security_features_test.rs"
    "auth-service/tests/openid_metadata_it.rs"
    "auth-service/tests/security_test.rs"
    "auth-service/tests/token_flow_it.rs"
    "auth-service/tests/totp_it.rs"
    "auth-service/tests/token_basic_auth_it.rs"
    "auth-service/tests/scope_validation_test.rs"
    "auth-service/tests/step_up_it.rs"
    "auth-service/tests/token_refresh_it.rs"
    "auth-service/tests/authorization_it.rs"
    "auth-service/tests/request_id_it.rs"
    "auth-service/tests/admin_protection_it.rs"
    "auth-service/tests/token_binding_it.rs"
    "auth-service/tests/scim_basic_auth_it.rs"
)

for file in "${FILES[@]}"; do
    echo "Fixing $file..."
    
    # Remove the cast to Arc<dyn Store>
    sed -i '' 's/Arc::new(HybridStore::new().await) as Arc<dyn Store>/Arc::new(HybridStore::new().await)/g' "$file"
    
    # Remove the cast to Arc<dyn SessionStore>
    sed -i '' 's/Arc::new(RedisSessionStore::new(None).await)[[:space:]]*as Arc<dyn auth_service::session_store::SessionStore>/Arc::new(RedisSessionStore::new(None).await)/g' "$file"
    
    # Fix token_store type
    sed -i '' 's/token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())))/token_store: Arc::new(std::sync::RwLock::new(HashMap::new()))/g' "$file"
    
    # Fix client_credentials wrapping
    if grep -q "client_credentials: Arc::new" "$file"; then
        echo "  client_credentials already wrapped"
    else
        sed -i '' 's/client_credentials,$/client_credentials: Arc::new(std::sync::RwLock::new(client_credentials)),/g' "$file"
    fi
    
    # Fix allowed_scopes type
    sed -i '' '/allowed_scopes: vec!\[/,/\],/{
        s/allowed_scopes: vec!\[/allowed_scopes: Arc::new(std::sync::RwLock::new({\n            let mut scopes = std::collections::HashSet::new();/
        s/"read"\.to_string(),/scopes.insert("read".to_string());/
        s/"write"\.to_string(),/scopes.insert("write".to_string());/
        s/"admin"\.to_string(),/scopes.insert("admin".to_string());/
        s/"openid"\.to_string(),/scopes.insert("openid".to_string());/
        s/"profile"\.to_string(),/scopes.insert("profile".to_string());/
        s/\],$/scopes\n        })),/
    }' "$file"
    
    # Fix backpressure_state type
    sed -i '' 's/backpressure_state: std::sync::Arc::new([[:space:]]*auth_service::backpressure::BackpressureState::new([[:space:]]*auth_service::backpressure::BackpressureConfig::default(),[[:space:]]*)[[:space:]]*,[[:space:]]*),/backpressure_state: std::sync::Arc::new(std::sync::RwLock::new(false)),/g' "$file"
done

echo "Done fixing test files!"