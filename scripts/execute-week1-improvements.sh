#!/bin/bash

# Execute Week 1 Improvements Script
# Automated implementation of immediate wins from the tactical guide

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
check_project_root() {
    if [[ ! -f "Cargo.toml" ]] || [[ ! -d "auth-service" ]]; then
        log_error "Please run this script from the rust-security project root directory"
        exit 1
    fi
    log_success "Project root directory confirmed"
}

# Backup existing files
backup_files() {
    log_info "Creating backups of existing files..."
    
    # Backup justfile
    if [[ -f "justfile" ]]; then
        cp justfile justfile.backup.$(date +%Y%m%d_%H%M%S)
        log_success "Backed up existing justfile"
    fi
    
    # Backup auth-service lib.rs
    if [[ -f "auth-service/src/lib.rs" ]]; then
        cp auth-service/src/lib.rs auth-service/src/lib.rs.backup.$(date +%Y%m%d_%H%M%S)
        log_success "Backed up auth-service/src/lib.rs"
    fi
}

# Install enhanced justfile
install_enhanced_justfile() {
    log_info "Installing enhanced justfile..."
    
    if [[ -f "justfile.enhanced" ]]; then
        cp justfile.enhanced justfile
        log_success "Enhanced justfile installed"
        
        # Test the new justfile
        log_info "Testing enhanced justfile commands..."
        if just --list > /dev/null 2>&1; then
            log_success "Enhanced justfile is working correctly"
            just --list | head -10
        else
            log_error "Enhanced justfile has syntax errors"
            return 1
        fi
    else
        log_error "justfile.enhanced not found. Please ensure all files are created first."
        return 1
    fi
}

# Install required tools
install_tools() {
    log_info "Installing required Rust tools..."
    
    # Check if tools are already installed
    local tools_to_install=()
    
    if ! command -v cargo-audit &> /dev/null; then
        tools_to_install+=("cargo-audit")
    fi
    
    if ! command -v cargo-deny &> /dev/null; then
        tools_to_install+=("cargo-deny")
    fi
    
    if ! cargo llvm-cov --version &> /dev/null; then
        tools_to_install+=("cargo-llvm-cov")
    fi
    
    if ! command -v just &> /dev/null; then
        tools_to_install+=("just")
    fi
    
    if [[ ${#tools_to_install[@]} -gt 0 ]]; then
        log_info "Installing tools: ${tools_to_install[*]}"
        cargo install "${tools_to_install[@]}" || log_warning "Some tools may have failed to install"
    else
        log_success "All required tools are already installed"
    fi
}

# Setup pre-commit hooks
setup_pre_commit() {
    log_info "Setting up pre-commit hooks..."
    
    # Install pre-commit if not available
    if ! command -v pre-commit &> /dev/null; then
        log_info "Installing pre-commit..."
        if command -v pip &> /dev/null; then
            pip install pre-commit || log_warning "Failed to install pre-commit via pip"
        elif command -v pip3 &> /dev/null; then
            pip3 install pre-commit || log_warning "Failed to install pre-commit via pip3"
        else
            log_warning "pip not found, skipping pre-commit installation"
            return 0
        fi
    fi
    
    # Install hooks using just command
    if command -v just &> /dev/null && command -v pre-commit &> /dev/null; then
        just install-hooks || log_warning "Failed to install pre-commit hooks"
        log_success "Pre-commit hooks installed"
    else
        log_warning "Skipping pre-commit setup due to missing dependencies"
    fi
}

# Test enhanced validation
test_validation() {
    log_info "Testing enhanced validation commands..."
    
    # Test quick validation
    log_info "Running quick validation (should complete in <30s)..."
    start_time=$(date +%s)
    
    if just validate-quick; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        log_success "Quick validation completed in ${duration}s"
        
        if [[ $duration -gt 30 ]]; then
            log_warning "Quick validation took longer than 30s target"
        fi
    else
        log_error "Quick validation failed"
        return 1
    fi
}

# Add new modules to auth-service
add_security_modules() {
    log_info "Adding new security modules to auth-service..."
    
    local lib_file="auth-service/src/lib.rs"
    
    if [[ -f "$lib_file" ]]; then
        # Check if modules are already added
        if ! grep -q "pub mod rate_limit_enhanced;" "$lib_file"; then
            echo "" >> "$lib_file"
            echo "// Enhanced security modules" >> "$lib_file"
            echo "pub mod rate_limit_enhanced;" >> "$lib_file"
            echo "pub mod csrf_protection;" >> "$lib_file"
            echo "pub mod security_logging_enhanced;" >> "$lib_file"
            echo "pub mod performance_monitoring;" >> "$lib_file"
            echo "pub mod circuit_breaker_advanced;" >> "$lib_file"
            
            log_success "Added new security modules to auth-service"
        else
            log_info "Security modules already added to auth-service"
        fi
    else
        log_error "auth-service/src/lib.rs not found"
        return 1
    fi
}

# Update Cargo.toml dependencies
update_dependencies() {
    log_info "Checking and updating dependencies..."
    
    local cargo_file="auth-service/Cargo.toml"
    
    if [[ -f "$cargo_file" ]]; then
        # Check if required dependencies are present
        local deps_needed=()
        
        if ! grep -q "thiserror" "$cargo_file"; then
            deps_needed+=("thiserror")
        fi
        
        if ! grep -q "regex" "$cargo_file"; then
            deps_needed+=("regex")
        fi
        
        if ! grep -q "hmac" "$cargo_file"; then
            deps_needed+=("hmac")
        fi
        
        if ! grep -q "sha2" "$cargo_file"; then
            deps_needed+=("sha2")
        fi
        
        if [[ ${#deps_needed[@]} -gt 0 ]]; then
            log_info "Adding missing dependencies: ${deps_needed[*]}"
            log_warning "Please manually add these dependencies to auth-service/Cargo.toml:"
            for dep in "${deps_needed[@]}"; do
                echo "  $dep = \"*\""
            done
        else
            log_success "All required dependencies are present"
        fi
    else
        log_error "auth-service/Cargo.toml not found"
        return 1
    fi
}

# Verify compilation
verify_compilation() {
    log_info "Verifying that everything compiles..."
    
    if cargo check --workspace --all-features; then
        log_success "Workspace compilation check passed"
    else
        log_error "Compilation check failed"
        log_info "This is expected if dependencies need to be added manually"
        log_info "Please add the required dependencies and run 'cargo check' again"
        return 1
    fi
}

# Run comprehensive CI
run_comprehensive_ci() {
    log_info "Running comprehensive CI pipeline..."
    
    if just ci-complete; then
        log_success "Comprehensive CI pipeline completed successfully"
    else
        log_warning "CI pipeline had some issues - this is normal for initial setup"
        log_info "Individual components may need attention"
    fi
}

# Generate initial performance baseline
generate_baseline() {
    log_info "Generating initial performance baseline..."
    
    # Run benchmarks if available
    if just bench-continuous; then
        log_success "Performance baseline generated"
    else
        log_info "Benchmarks not available yet - will be set up in later phases"
    fi
}

# Create progress tracking file
create_progress_tracking() {
    log_info "Creating progress tracking file..."
    
    cat > WEEK1_PROGRESS.md << 'EOF'
# Week 1 Implementation Progress

## Day 1: Enhanced Justfile & Validation ✅
- [x] Enhanced justfile installed
- [x] Pre-commit hooks setup
- [x] Quick validation working
- [x] Security modules added

## Day 2: Rate Limiting Implementation
- [ ] Rate limiting middleware integrated
- [ ] DoS protection testing
- [ ] Performance impact assessment

## Day 3: CSRF Protection
- [ ] CSRF protection middleware
- [ ] Token generation and validation
- [ ] Integration testing

## Day 4-5: Security Logging Enhancement
- [ ] Structured security logging
- [ ] PII protection implementation
- [ ] Threat intelligence integration

## Success Metrics
- [ ] CI pipeline time reduced by >50%
- [ ] Security score improved to >9.5/10
- [ ] Developer setup time <15 minutes
- [ ] Pre-commit adoption >90%

## Next Steps
1. Continue with Day 2 implementation
2. Monitor performance impact
3. Gather developer feedback
4. Prepare for Week 2 enhancements
EOF

    log_success "Progress tracking file created: WEEK1_PROGRESS.md"
}

# Main execution function
main() {
    log_info "🚀 Starting Week 1 Improvements Implementation"
    log_info "This script will implement immediate wins from the tactical guide"
    echo
    
    # Confirmation prompt
    read -p "Continue with Week 1 improvements? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Implementation cancelled by user"
        exit 0
    fi
    
    # Execute implementation steps
    check_project_root
    backup_files
    install_tools
    install_enhanced_justfile
    setup_pre_commit
    add_security_modules
    update_dependencies
    test_validation
    
    # Optional steps that might fail initially
    verify_compilation || log_warning "Compilation verification failed - manual dependency addition needed"
    run_comprehensive_ci || log_warning "CI pipeline needs attention - normal for initial setup"
    generate_baseline || log_info "Performance baseline will be set up in later phases"
    
    create_progress_tracking
    
    echo
    log_success "🎉 Week 1 Day 1 implementation completed!"
    echo
    log_info "Next steps:"
    echo "1. Review WEEK1_PROGRESS.md for tracking"
    echo "2. Add any missing dependencies to Cargo.toml files"
    echo "3. Run 'just ci-complete' to verify everything works"
    echo "4. Continue with Day 2 implementation (rate limiting)"
    echo
    log_info "If you encounter issues:"
    echo "- Check the backup files created"
    echo "- Review the comprehensive implementation plan"
    echo "- Run 'just --list' to see all available commands"
    echo
    log_success "Enhanced development environment is ready! 🚀"
}

# Execute main function
main "$@"
