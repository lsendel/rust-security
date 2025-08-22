#!/bin/bash
# Automated refactoring script for large files
# This script helps break down oversized files into manageable modules

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MAX_LINES=500
BACKUP_DIR="$PROJECT_ROOT/.refactor_backup"

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Create backup directory
create_backup() {
    log "Creating backup directory..."
    mkdir -p "$BACKUP_DIR"
    
    # Backup large files
    find . -name "*.rs" -not -path "./target/*" -not -path "./user-portal/*" -exec wc -l {} + | \
    awk -v max="$MAX_LINES" '$1 > max {print $2}' | \
    while read -r file; do
        if [[ -f "$file" ]]; then
            backup_path="$BACKUP_DIR/${file//\//_}.backup"
            cp "$file" "$backup_path"
            log "Backed up $file to $backup_path"
        fi
    done
}

# Analyze large files
analyze_large_files() {
    log "Analyzing files exceeding $MAX_LINES lines..."
    
    echo "Files requiring refactoring:"
    echo "=============================="
    
    find . -name "*.rs" -not -path "./target/*" -not -path "./user-portal/*" -exec wc -l {} + | \
    awk -v max="$MAX_LINES" '$1 > max {printf "%-60s %6d lines\n", $2, $1}' | \
    sort -k2 -nr
    
    echo ""
}

# Create module structure for SOAR components
create_soar_module_structure() {
    log "Creating SOAR module structure..."
    
    local soar_dir="$PROJECT_ROOT/auth-service/src/soar"
    
    # Create directory structure
    mkdir -p "$soar_dir"/{core,case_management,workflow,executors}
    
    # Create mod.rs files
    cat > "$soar_dir/mod.rs" << 'EOF'
//! SOAR (Security Orchestration, Automation and Response) Module
//!
//! This module provides comprehensive SOAR capabilities including:
//! - Case management and workflow orchestration
//! - Automated response execution
//! - Integration with external security tools
//! - Threat intelligence correlation

pub mod core;
pub mod case_management;
pub mod workflow;
pub mod executors;

// Re-export main types
pub use core::{SoarEngine, SoarConfig};
pub use case_management::{CaseManager, Case, CaseStatus};
pub use workflow::{WorkflowEngine, WorkflowDefinition};
pub use executors::{ExecutorRegistry, ResponseExecutor};

/// SOAR service version
pub const SOAR_VERSION: &str = env!("CARGO_PKG_VERSION");
EOF

    # Create core module structure
    mkdir -p "$soar_dir/core"
    cat > "$soar_dir/core/mod.rs" << 'EOF'
//! SOAR Core Engine
//!
//! Provides the main SOAR engine functionality and configuration management.

pub mod engine;
pub mod config;
pub mod types;

pub use engine::SoarEngine;
pub use config::SoarConfig;
pub use types::*;
EOF

    # Create case management module structure
    mkdir -p "$soar_dir/case_management"
    cat > "$soar_dir/case_management/mod.rs" << 'EOF'
//! Case Management System
//!
//! Handles security incident cases, their lifecycle, and associated workflows.

pub mod manager;
pub mod types;
pub mod storage;
pub mod analytics;

pub use manager::CaseManager;
pub use types::{Case, CaseStatus, CasePriority};
EOF

    # Create workflow module structure
    mkdir -p "$soar_dir/workflow"
    cat > "$soar_dir/workflow/mod.rs" << 'EOF'
//! Workflow Engine
//!
//! Orchestrates automated security response workflows and playbooks.

pub mod engine;
pub mod definition;
pub mod executor;

pub use engine::WorkflowEngine;
pub use definition::WorkflowDefinition;
EOF

    # Create executors module structure
    mkdir -p "$soar_dir/executors"
    cat > "$soar_dir/executors/mod.rs" << 'EOF'
//! Response Executors
//!
//! Implements various automated response actions and integrations.

pub mod registry;
pub mod base;
pub mod integrations;

pub use registry::ExecutorRegistry;
pub use base::ResponseExecutor;
EOF

    success "Created SOAR module structure"
}

# Extract functions from large files
extract_functions_from_lib() {
    local lib_file="$PROJECT_ROOT/auth-service/src/lib.rs"
    
    if [[ ! -f "$lib_file" ]]; then
        warn "lib.rs not found, skipping extraction"
        return
    fi
    
    log "Analyzing lib.rs for function extraction..."
    
    # Count lines in lib.rs
    local line_count=$(wc -l < "$lib_file")
    log "lib.rs has $line_count lines"
    
    if [[ $line_count -gt $MAX_LINES ]]; then
        warn "lib.rs exceeds $MAX_LINES lines and should be refactored"
        
        # Create new lib.rs structure
        cat > "${lib_file}.new" << 'EOF'
//! Auth Service Core Library
//!
//! Provides authentication and authorization services with enterprise-grade
//! security features including rate limiting, audit logging, and threat detection.

// Core modules
pub mod auth;
pub mod config;
pub mod errors;
pub mod handlers;
pub mod middleware;
pub mod metrics;
pub mod security;
pub mod storage;
pub mod types;

// SOAR modules
pub mod soar;

// Re-export main types for convenience
pub use auth::{AuthService, AuthResult};
pub use config::AuthConfig;
pub use errors::AuthError;
pub use types::{AuthRequest, AuthResponse, Token};

// Service metadata
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SERVICE_NAME: &str = "rust-security-auth-service";

// Import dependencies for compatibility
use futures as _;
use tracing_subscriber as _;
EOF
        
        log "Created new lib.rs structure (saved as lib.rs.new)"
        log "Manual review required before replacing original file"
    fi
}

# Create improved configuration structure
create_config_modules() {
    log "Creating improved configuration structure..."
    
    local config_dir="$PROJECT_ROOT/auth-service/src/config"
    mkdir -p "$config_dir"
    
    # Main config module
    cat > "$config_dir/mod.rs" << 'EOF'
//! Configuration Management
//!
//! Provides structured configuration for all auth service components.

pub mod server;
pub mod security;
pub mod storage;
pub mod integrations;
pub mod observability;

use serde::{Deserialize, Serialize};
use validator::Validate;

pub use server::ServerConfig;
pub use security::SecurityConfig;
pub use storage::StorageConfig;
pub use integrations::IntegrationConfig;
pub use observability::ObservabilityConfig;

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AuthConfig {
    pub server: ServerConfig,
    pub security: SecurityConfig,
    pub storage: StorageConfig,
    pub integrations: IntegrationConfig,
    pub observability: ObservabilityConfig,
}

impl AuthConfig {
    /// Load configuration from environment variables and files
    pub fn load() -> anyhow::Result<Self> {
        // Implementation for loading configuration
        todo!("Implement configuration loading")
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        self.validate().map_err(|e| anyhow::anyhow!("Configuration validation failed: {}", e))
    }
}
EOF

    # Server configuration
    cat > "$config_dir/server.rs" << 'EOF'
//! Server Configuration

use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerConfig {
    #[validate(regex = "BIND_ADDR_REGEX")]
    pub bind_addr: String,
    
    #[validate(range(min = 1, max = 65535))]
    pub port: u16,
    
    #[validate(range(min = 1, max = 10000))]
    pub max_connections: usize,
    
    #[validate(range(min = 1, max = 3600))]
    pub request_timeout_seconds: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0".to_string(),
            port: 8080,
            max_connections: 1000,
            request_timeout_seconds: 30,
        }
    }
}

lazy_static::lazy_static! {
    static ref BIND_ADDR_REGEX: regex::Regex = 
        regex::Regex::new(r"^(\d{1,3}\.){3}\d{1,3}$|^localhost$|^0\.0\.0\.0$").unwrap();
}
EOF

    success "Created configuration module structure"
}

# Create error handling module
create_error_module() {
    log "Creating standardized error handling module..."
    
    local errors_dir="$PROJECT_ROOT/auth-service/src/errors"
    mkdir -p "$errors_dir"
    
    cat > "$errors_dir/mod.rs" << 'EOF'
//! Comprehensive Error Handling
//!
//! Provides standardized error types and handling for the auth service.

use thiserror::Error;
use chrono::{DateTime, Utc};
use std::time::Duration;

/// Main authentication service error type
#[derive(Debug, Error)]
pub enum AuthError {
    // Authentication errors
    #[error("Invalid credentials provided")]
    InvalidCredentials,
    
    #[error("Account locked due to too many failed attempts")]
    AccountLocked { unlock_at: DateTime<Utc> },
    
    #[error("Multi-factor authentication required")]
    MfaRequired { methods: Vec<String> },
    
    // Authorization errors
    #[error("Insufficient permissions for operation: {operation}")]
    InsufficientPermissions { operation: String },
    
    #[error("Token expired at {expired_at}")]
    TokenExpired { expired_at: DateTime<Utc> },
    
    // System errors
    #[error("Database operation failed")]
    DatabaseError(#[from] sqlx::Error),
    
    #[error("Configuration error: {message}")]
    ConfigError { message: String },
    
    // Rate limiting
    #[error("Rate limit exceeded: {current}/{limit} requests")]
    RateLimitExceeded {
        current: u32,
        limit: u32,
        retry_after: Duration,
    },
    
    // Validation errors
    #[error("Input validation failed")]
    ValidationError(#[from] validator::ValidationErrors),
    
    // Security errors
    #[error("Security threat detected: {threat_type}")]
    SecurityThreat { threat_type: String },
}

/// Result type alias for consistency
pub type AuthResult<T> = Result<T, AuthError>;

/// Error context extension trait
pub trait AuthErrorExt<T> {
    fn with_auth_context(self, context: &str) -> AuthResult<T>;
}

impl<T, E> AuthErrorExt<T> for Result<T, E>
where
    E: Into<AuthError>,
{
    fn with_auth_context(self, context: &str) -> AuthResult<T> {
        self.map_err(|e| {
            let auth_error = e.into();
            // Add context (implementation depends on specific error type)
            auth_error
        })
    }
}
EOF

    success "Created error handling module"
}

# Generate refactoring report
generate_report() {
    log "Generating refactoring report..."
    
    local report_file="$PROJECT_ROOT/REFACTORING_REPORT.md"
    
    cat > "$report_file" << EOF
# 🔧 Refactoring Report

Generated on: $(date)

## Files Analyzed

### Large Files (>$MAX_LINES lines)
\`\`\`
$(find . -name "*.rs" -not -path "./target/*" -not -path "./user-portal/*" -exec wc -l {} + | \
  awk -v max="$MAX_LINES" '$1 > max {printf "%-60s %6d lines\n", $2, $1}' | \
  sort -k2 -nr)
\`\`\`

## Actions Taken

### ✅ Completed
- Created backup directory: \`$BACKUP_DIR\`
- Created SOAR module structure
- Created configuration module structure  
- Created error handling module
- Generated new lib.rs structure (review required)

### 🔄 Next Steps
1. **Review generated module structures**
2. **Move code from large files to new modules**
3. **Update imports and dependencies**
4. **Run tests to ensure functionality**
5. **Update documentation**

### 📋 Manual Tasks Required
- [ ] Review and approve new lib.rs structure
- [ ] Extract functions from large files to appropriate modules
- [ ] Update Cargo.toml if new dependencies are needed
- [ ] Run \`cargo check\` and fix compilation errors
- [ ] Run \`cargo test\` and fix failing tests
- [ ] Update documentation and examples

## Module Structure Created

### SOAR Modules
- \`src/soar/mod.rs\` - Main SOAR module
- \`src/soar/core/\` - Core engine functionality
- \`src/soar/case_management/\` - Case management system
- \`src/soar/workflow/\` - Workflow orchestration
- \`src/soar/executors/\` - Response executors

### Configuration Modules
- \`src/config/mod.rs\` - Main configuration
- \`src/config/server.rs\` - Server configuration
- Additional config modules ready for implementation

### Error Handling
- \`src/errors/mod.rs\` - Standardized error types

## Quality Metrics

### Before Refactoring
- Largest file: $(find . -name "*.rs" -not -path "./target/*" -exec wc -l {} + | sort -nr | head -1 | awk '{print $1 " lines (" $2 ")"}')
- Files >$MAX_LINES lines: $(find . -name "*.rs" -not -path "./target/*" -exec wc -l {} + | awk -v max="$MAX_LINES" '$1 > max' | wc -l)

### Target Metrics
- Maximum file size: $MAX_LINES lines
- Maximum function size: 50 lines
- Documentation coverage: >95%
- Test coverage: >90%

EOF

    success "Generated refactoring report: $report_file"
}

# Main execution
main() {
    log "Starting automated refactoring process..."
    
    # Check if we're in the right directory
    if [[ ! -f "Cargo.toml" ]]; then
        error "Not in a Rust project directory. Please run from project root."
        exit 1
    fi
    
    # Create backup
    create_backup
    
    # Analyze current state
    analyze_large_files
    
    # Create new module structures
    create_soar_module_structure
    create_config_modules
    create_error_module
    
    # Extract functions from large files
    extract_functions_from_lib
    
    # Generate report
    generate_report
    
    success "Refactoring preparation complete!"
    echo ""
    echo "Next steps:"
    echo "1. Review the generated module structures"
    echo "2. Move code from large files to appropriate modules"
    echo "3. Run 'cargo check' to verify compilation"
    echo "4. Run 'cargo test' to ensure functionality"
    echo "5. Review and update documentation"
    echo ""
    echo "See REFACTORING_REPORT.md for detailed information."
}

# Run main function
main "$@"
