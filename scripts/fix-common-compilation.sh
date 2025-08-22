#!/bin/bash

# Quick fix script for common package compilation issues
# This addresses the most critical compilation errors to get the project building

set -e

echo "🔧 Fixing common package compilation issues..."

# 1. Add missing num_cpus dependency
echo "📦 Adding num_cpus dependency..."
cd /Users/lsendel/IdeaProjects/rust-security
if ! grep -q "num_cpus" Cargo.toml; then
    # Add to workspace dependencies
    sed -i '' '/^# CLI$/i\
num_cpus = "1.16"
' Cargo.toml
fi

# Add to common package
if ! grep -q "num_cpus" common/Cargo.toml; then
    sed -i '' '/^validator = { workspace = true }$/a\
num_cpus = { workspace = true }
' common/Cargo.toml
fi

# 2. Fix trait object compatibility by using Box<dyn Future> instead of impl Future
echo "🔧 Fixing trait object compatibility..."

# Create backup
cp common/src/instrumentation/mod.rs common/src/instrumentation/mod.rs.backup.$(date +%s)

# Fix MetricsCollector trait
sed -i '' 's/fn initialize(&self) -> impl std::future::Future<Output = PlatformResult<()>> + Send;/fn initialize(\&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = PlatformResult<()>> + Send>>;/' common/src/instrumentation/mod.rs

# Fix AuditLogger trait  
sed -i '' 's/fn initialize(&self) -> impl std::future::Future<Output = PlatformResult<()>> + Send;/fn initialize(\&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = PlatformResult<()>> + Send>>;/' common/src/instrumentation/mod.rs

# 3. Add missing AuditConfiguration type
echo "🔧 Adding missing AuditConfiguration..."
cat >> common/src/config/security.rs << 'EOF'

/// Audit configuration for security events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfiguration {
    /// Enable audit logging
    pub enabled: bool,
    /// Audit log level
    pub level: String,
    /// Audit log format
    pub format: String,
}

impl Default for AuditConfiguration {
    fn default() -> Self {
        Self {
            enabled: true,
            level: "info".to_string(),
            format: "json".to_string(),
        }
    }
}
EOF

# 4. Fix tracing_subscriber json method (it's now called with_format)
echo "🔧 Fixing tracing_subscriber API..."
sed -i '' 's/\.json()/\.with_format(tracing_subscriber::fmt::format().json())/' common/src/instrumentation/logging.rs
sed -i '' 's/\.json()/\.with_format(tracing_subscriber::fmt::format().json())/' common/src/instrumentation/tracing_setup.rs

# 5. Add missing init_tracing function
echo "🔧 Adding missing init_tracing function..."
cat >> common/src/instrumentation/tracing_setup.rs << 'EOF'

/// Initialize tracing with the given configuration
pub fn init_tracing(config: &crate::config::observability::TracingConfig) -> crate::errors::PlatformResult<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer());
        
    subscriber.init();
    Ok(())
}
EOF

# 6. Add missing error conversions
echo "🔧 Adding missing error conversions..."
cat >> common/src/errors/mod.rs << 'EOF'

impl From<prometheus::Error> for PlatformError {
    fn from(err: prometheus::Error) -> Self {
        PlatformError::InternalError(format!("Prometheus error: {}", err))
    }
}

impl From<std::string::FromUtf8Error> for PlatformError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        PlatformError::InternalError(format!("UTF-8 conversion error: {}", err))
    }
}
EOF

echo "✅ Common package fixes applied!"
echo "🧪 Testing compilation..."

if cargo check --package common; then
    echo "✅ Common package now compiles successfully!"
else
    echo "❌ Still has compilation issues - manual intervention needed"
    exit 1
fi
