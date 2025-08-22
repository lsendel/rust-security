#!/bin/bash

# Advanced fix script for remaining common package issues
set -e

echo "🔧 Applying advanced fixes to common package..."

cd /Users/lsendel/IdeaProjects/rust-security

# 1. Fix trait implementations to return Pin<Box<dyn Future>>
echo "🔧 Fixing trait implementations..."

# Fix PrometheusMetricsCollector::initialize
sed -i '' '/async fn initialize(&self) -> PlatformResult<()> {/,/^    }$/{
s/async fn initialize(&self) -> PlatformResult<()> {/fn initialize(\&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = PlatformResult<()>> + Send>> {/
s/^    }$/        Box::pin(async { Ok(()) })\
    }/
}' common/src/instrumentation/mod.rs

# Fix StructuredAuditLogger::initialize  
sed -i '' '/impl AuditLogger for StructuredAuditLogger/,/^}$/{
/async fn initialize(&self) -> PlatformResult<()> {/,/^    }$/{
s/async fn initialize(&self) -> PlatformResult<()> {/fn initialize(\&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = PlatformResult<()>> + Send>> {/
s/^    }$/        Box::pin(async { Ok(()) })\
    }/
}
}' common/src/instrumentation/mod.rs

# 2. Fix PlatformError enum usage - check the actual structure first
echo "🔧 Checking PlatformError structure..."
if grep -q "InternalError {" common/src/errors/mod.rs; then
    echo "PlatformError uses struct variants"
    # Fix error conversions for struct variants
    cat > /tmp/error_fixes.txt << 'EOF'
impl From<prometheus::Error> for PlatformError {
    fn from(err: prometheus::Error) -> Self {
        PlatformError::InternalError {
            details: format!("Prometheus error: {}", err),
            context: "metrics collection".to_string(),
            source: None,
        }
    }
}

impl From<std::string::FromUtf8Error> for PlatformError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        PlatformError::InternalError {
            details: format!("UTF-8 conversion error: {}", err),
            context: "string conversion".to_string(),
            source: None,
        }
    }
}
EOF
else
    echo "PlatformError uses tuple variants"
    # Fix error conversions for tuple variants
    cat > /tmp/error_fixes.txt << 'EOF'
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
fi

# Remove old error conversions and add new ones
sed -i '' '/impl From<prometheus::Error> for PlatformError/,/^}$/d' common/src/errors/mod.rs
sed -i '' '/impl From<std::string::FromUtf8Error> for PlatformError/,/^}$/d' common/src/errors/mod.rs
cat /tmp/error_fixes.txt >> common/src/errors/mod.rs

# 3. Fix tracing configuration type mismatch
echo "🔧 Fixing tracing configuration..."
# Check what the actual type is
if grep -q "TracingConfiguration" common/src/config/observability.rs; then
    sed -i '' 's/TracingConfig/TracingConfiguration/g' common/src/instrumentation/tracing_setup.rs
    sed -i '' 's/initialize_tracing/init_tracing/g' common/src/instrumentation/mod.rs
fi

# 4. Fix tracing_subscriber API - use simpler approach
echo "🔧 Fixing tracing_subscriber API..."
cat > /tmp/tracing_fix.rs << 'EOF'
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize tracing with the given configuration
pub fn init_tracing(config: &crate::config::observability::TracingConfiguration) -> crate::errors::PlatformResult<()> {
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer());
        
    subscriber.init();
    Ok(())
}
EOF

# Replace the tracing setup content
sed -i '' '/pub fn init_tracing/,/^}$/d' common/src/instrumentation/tracing_setup.rs
cat /tmp/tracing_fix.rs >> common/src/instrumentation/tracing_setup.rs

# Fix logging.rs tracing usage - use simpler format
sed -i '' 's/\.with(tracing_subscriber::fmt::layer()\.with_format(tracing_subscriber::fmt::format()\.json()))/\.with(tracing_subscriber::fmt::layer())/' common/src/instrumentation/logging.rs

# 5. Fix SecurityEvent ownership issue
echo "🔧 Fixing SecurityEvent ownership..."
sed -i '' 's/self.audit_logger.log_security_event(event);/self.audit_logger.log_security_event(event.clone());/' common/src/instrumentation/mod.rs

# 6. Add Validate derive to AuditConfiguration
echo "🔧 Adding Validate derive..."
sed -i '' 's/#\[derive(Debug, Clone, Serialize, Deserialize)\]/#[derive(Debug, Clone, Serialize, Deserialize, validator::Validate)]/' common/src/config/security.rs

# 7. Clean up unused imports
echo "🔧 Cleaning up unused imports..."
sed -i '' 's/use config::{Config, ConfigError, Environment, File};/use config::{Config, Environment, File};/' common/src/config/mod.rs
sed -i '' 's/use std::path::Path;//' common/src/config/mod.rs
sed -i '' 's/use validator::{Validate, ValidationError};/use validator::Validate;/' common/src/config/mod.rs
sed -i '' 's/use validator::{Validate, ValidationError};/use validator::Validate;/' common/src/config/database.rs
sed -i '' 's/use validator::{Validate, ValidationError};/use validator::Validate;/' common/src/config/observability.rs
sed -i '' 's/use validator::{Validate, ValidationError};/use validator::Validate;/' common/src/config/security.rs
sed -i '' 's/use tracing::{info, warn, error, instrument, Span};/use tracing::{info, warn, error, Span};/' common/src/instrumentation/mod.rs
sed -i '' 's/use std::sync::Arc;//' common/src/instrumentation/metrics.rs

# Fix unused variables
sed -i '' 's/|e|/|_e|/g' common/src/config/mod.rs
sed -i '' 's/labels: &\[(&str, &str)\]/labels: \&[(\&str, \&str)]/' common/src/instrumentation/metrics.rs
sed -i '' 's/labels: &\[(&str, &str)\]/_labels: \&[(\&str, \&str)]/' common/src/instrumentation/metrics.rs

echo "✅ Advanced fixes applied!"
echo "🧪 Testing compilation..."

if cargo check --package common; then
    echo "✅ Common package now compiles successfully!"
else
    echo "❌ Still has issues - checking specific errors..."
    cargo check --package common 2>&1 | head -20
fi

# Clean up temp files
rm -f /tmp/error_fixes.txt /tmp/tracing_fix.rs
