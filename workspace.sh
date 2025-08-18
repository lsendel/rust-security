#!/bin/bash

# Rust Security Workspace Helper Script
# Provides convenient commands for workspace management

set -e

WORKSPACE_ROOT=$(git rev-parse --show-toplevel)
cd "$WORKSPACE_ROOT"

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

# Help function
show_help() {
    echo "Rust Security Workspace Helper"
    echo ""
    echo "Usage: ./workspace.sh <command> [options]"
    echo ""
    echo "Commands:"
    echo "  setup           - Initial development setup"
    echo "  build           - Build all workspace crates"
    echo "  test            - Run all tests"
    echo "  security        - Run comprehensive security checks"
    echo "  clean           - Clean build artifacts"
    echo "  update          - Update dependencies"
    echo "  lint            - Run linting and formatting"
    echo "  docs            - Generate documentation"
    echo "  examples        - Run all examples"
    echo "  ci-local        - Run CI checks locally"
    echo ""
    echo "Feature Commands:"
    echo "  build-opt       - Build with optimizations"
    echo "  build-threat    - Build with threat hunting"
    echo "  build-pq        - Build with post-quantum crypto"
    echo ""
    echo "Options:"
    echo "  -h, --help      - Show this help"
    echo "  -v, --verbose   - Verbose output"
    echo "  --release       - Use release mode"
}

# Check if required tools are installed
check_tools() {
    local tools=("cargo" "rustc" "cargo-audit" "cargo-deny")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        log_info "Run './workspace.sh setup' to install missing tools"
        exit 1
    fi
}

# Development setup
setup() {
    log_info "Setting up development environment..."
    
    # Install required tools
    log_info "Installing development tools..."
    cargo install cargo-audit
    cargo install cargo-deny
    cargo install cargo-outdated
    cargo install cargo-edit
    cargo install cargo-sweep
    cargo install cargo-watch
    
    # Install optional tools
    log_info "Installing optional tools..."
    cargo install --locked cargo-geiger || log_warning "Failed to install cargo-geiger"
    cargo install --locked cargo-mutants || log_warning "Failed to install cargo-mutants"
    
    # Setup git hooks
    if [ -d ".githooks" ]; then
        log_info "Setting up git hooks..."
        git config core.hooksPath .githooks
        chmod +x .githooks/*
    fi
    
    # Verify installation
    check_tools
    log_success "Development environment setup complete"
}

# Build functions
build() {
    local mode=""
    if [ "$1" == "--release" ]; then
        mode="--release"
        log_info "Building workspace in release mode..."
    else
        log_info "Building workspace..."
    fi
    
    cargo build --workspace $mode
    log_success "Build completed"
}

# Test functions
test() {
    log_info "Running tests..."
    
    # Set test mode for auth service
    export TEST_MODE=1
    
    cargo test --workspace --verbose
    log_success "Tests completed"
}

# Security checks
security() {
    log_info "Running comprehensive security checks..."
    
    # Vulnerability audit
    log_info "Running vulnerability audit..."
    cargo audit
    
    # Dependency policy check
    log_info "Checking dependency policies..."
    cargo deny check
    
    # Security-focused lints
    log_info "Running security lints..."
    cargo clippy --workspace --all-targets --all-features -- \
        -D clippy::unwrap_used \
        -D clippy::expect_used \
        -D clippy::panic \
        -D clippy::integer_overflow \
        -D clippy::indexing_slicing
    
    # Check for unsafe code
    if command -v cargo-geiger &> /dev/null; then
        log_info "Scanning for unsafe code..."
        cargo geiger
    fi
    
    log_success "Security checks completed"
}

# Clean build artifacts
clean() {
    log_info "Cleaning build artifacts..."
    cargo clean
    
    if command -v cargo-sweep &> /dev/null; then
        log_info "Sweeping old build files..."
        cargo sweep --time 7
    fi
    
    log_success "Clean completed"
}

# Update dependencies
update() {
    log_info "Updating dependencies..."
    
    # Check for outdated dependencies
    if command -v cargo-outdated &> /dev/null; then
        log_info "Checking for outdated dependencies..."
        cargo outdated --workspace
    fi
    
    # Update Cargo.lock
    cargo update
    
    # Run security audit after update
    log_info "Running security audit after update..."
    cargo audit
    
    log_success "Dependencies updated"
}

# Linting and formatting
lint() {
    log_info "Running linting and formatting..."
    
    # Format code
    cargo fmt --all
    
    # Run clippy
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    
    log_success "Linting completed"
}

# Generate documentation
docs() {
    log_info "Generating documentation..."
    cargo doc --workspace --no-deps --open
    log_success "Documentation generated"
}

# Run examples
examples() {
    log_info "Running examples..."
    
    # Simple auth client
    log_info "Building simple auth client..."
    cd examples/simple-auth-client && cargo build && cd ../..
    
    # Axum integration example
    log_info "Building axum integration example..."
    cd examples/axum-integration-example && cargo build && cd ../..
    
    log_success "Examples completed"
}

# CI checks locally
ci_local() {
    log_info "Running CI checks locally..."
    
    # Format check
    cargo fmt --all -- --check
    
    # Clippy with warnings as errors
    cargo clippy --workspace --all-targets -- -D warnings
    
    # Tests
    export TEST_MODE=1
    cargo test --workspace
    
    # Security checks
    cargo audit
    cargo deny check
    
    log_success "CI checks completed"
}

# Feature builds
build_opt() {
    log_info "Building with optimizations..."
    cargo build -p auth-service --features optimizations
    log_success "Optimization build completed"
}

build_threat() {
    log_info "Building with threat hunting features..."
    cargo build -p auth-service --features threat-hunting
    log_success "Threat hunting build completed"
}

build_pq() {
    log_info "Building with post-quantum crypto..."
    cargo build -p auth-service --features post-quantum
    log_success "Post-quantum build completed"
}

# Main script logic
main() {
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi
    
    case "$1" in
        setup)
            setup
            ;;
        build)
            check_tools
            build "$2"
            ;;
        test)
            check_tools
            test
            ;;
        security)
            check_tools
            security
            ;;
        clean)
            clean
            ;;
        update)
            check_tools
            update
            ;;
        lint)
            check_tools
            lint
            ;;
        docs)
            check_tools
            docs
            ;;
        examples)
            check_tools
            examples
            ;;
        ci-local)
            check_tools
            ci_local
            ;;
        build-opt)
            check_tools
            build_opt
            ;;
        build-threat)
            check_tools
            build_threat
            ;;
        build-pq)
            check_tools
            build_pq
            ;;
        -h|--help)
            show_help
            ;;
        *)
            log_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"