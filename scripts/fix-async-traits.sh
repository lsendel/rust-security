#!/bin/bash

# Async Trait Remediation Script
# Fixes the most critical async trait compatibility issues

set -e

echo "🔧 Starting async trait remediation..."

# Add async-trait dependency to Cargo.toml if not present
if ! grep -q "async-trait" auth-service/Cargo.toml; then
    echo "📦 Adding async-trait dependency..."
    sed -i '' '/^async-trait = /d' auth-service/Cargo.toml
    sed -i '' '/^anyhow = /a\
async-trait = { workspace = true }' auth-service/Cargo.toml
fi

# Fix EventProcessor trait
echo "🔧 Fixing EventProcessor trait..."
cat > /tmp/event_processor_fix.rs << 'EOF'
use async_trait::async_trait;

#[async_trait]
pub trait EventProcessor: Send + Sync {
    async fn process_event(&self, event: &DispatchEvent) -> Result<(), ProcessingError>;
}
EOF

# Fix ExternalIntegration trait
echo "🔧 Fixing ExternalIntegration trait..."
cat > /tmp/external_integration_fix.rs << 'EOF'
use async_trait::async_trait;

#[async_trait]
pub trait ExternalIntegration: Send + Sync {
    async fn execute_action(
        &self,
        action_type: &str,
        parameters: &serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>>;

    async fn validate_connection(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}
EOF

# Apply fixes to threat_response_orchestrator.rs
echo "🔧 Applying fixes to threat_response_orchestrator.rs..."
if [ -f "auth-service/src/threat_response_orchestrator.rs" ]; then
    # Add async-trait import
    if ! grep -q "use async_trait::async_trait;" auth-service/src/threat_response_orchestrator.rs; then
        sed -i '' '1i\
use async_trait::async_trait;' auth-service/src/threat_response_orchestrator.rs
    fi
    
    # Add #[async_trait] to EventProcessor
    sed -i '' 's/pub trait EventProcessor {/#[async_trait]\
pub trait EventProcessor: Send + Sync {/' auth-service/src/threat_response_orchestrator.rs
    
    # Add #[async_trait] to ExternalIntegration
    sed -i '' 's/pub trait ExternalIntegration {/#[async_trait]\
pub trait ExternalIntegration: Send + Sync {/' auth-service/src/threat_response_orchestrator.rs
fi

# Apply similar fixes to other files with async traits
for file in auth-service/src/soar_*.rs auth-service/src/threat_*.rs; do
    if [ -f "$file" ] && grep -q "async fn" "$file" && grep -q "pub trait" "$file"; then
        echo "🔧 Fixing async traits in $(basename $file)..."
        
        # Add async-trait import if not present
        if ! grep -q "use async_trait::async_trait;" "$file"; then
            sed -i '' '1i\
use async_trait::async_trait;' "$file"
        fi
        
        # Add #[async_trait] before trait definitions that contain async methods
        sed -i '' '/pub trait.*{/{
            N
            /async fn/i\
#[async_trait]
        }' "$file"
    fi
done

echo "✅ Async trait remediation completed!"
echo "📊 Next steps:"
echo "   1. Run: cargo check --package auth-service --features tracing,threat-hunting"
echo "   2. Address remaining type mismatches"
echo "   3. Add missing trait implementations"

echo ""
echo "🎯 Expected impact: Should reduce compilation errors by ~100-150"
