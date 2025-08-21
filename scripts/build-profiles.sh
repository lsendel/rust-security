#!/bin/bash
# Build profiles for different use cases

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
if [ ! -f Cargo.toml ]; then
    log_error "Please run this script from the project root directory"
    exit 1
fi

# Function to build a specific profile
build_profile() {
    local profile=$1
    local description=$2
    local features=$3
    
    log_info "Building $profile profile: $description"
    log_info "Features: $features"
    
    start_time=$(date +%s)
    
    if [ "$profile" = "minimal" ]; then
        cargo build --release \
            --package auth-core \
            --no-default-features \
            --features "$features"
    else
        cargo build --release --features "$features"
    fi
    
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    # Check if binary was created
    if [ "$profile" = "minimal" ]; then
        binary_path="target/release/auth-core"
    else
        binary_path="target/release/auth-service"
    fi
    
    if [ -f "$binary_path" ]; then
        size=$(du -h "$binary_path" | cut -f1)
        log_success "$profile profile built successfully!"
        log_info "Binary size: $size"
        log_info "Build time: ${duration}s"
        echo
    else
        log_error "Failed to build $profile profile"
        exit 1
    fi
}

# Show help
show_help() {
    echo "Usage: $0 [PROFILE]"
    echo ""
    echo "Available profiles:"
    echo "  minimal    - Minimal OAuth server (auth-core only)"
    echo "  standard   - Standard production features"
    echo "  enterprise - Full enterprise feature set"
    echo "  all        - Build all profiles"
    echo "  clean      - Clean build artifacts"
    echo ""
    echo "Examples:"
    echo "  $0 minimal     # Build minimal profile"
    echo "  $0 all         # Build all profiles"
    echo "  $0 clean       # Clean artifacts"
}

# Clean artifacts
clean_artifacts() {
    log_info "Cleaning build artifacts..."
    cargo clean
    log_success "Artifacts cleaned"
}

# Main logic
case "${1:-help}" in
    minimal)
        log_info "🚀 Building Minimal Profile"
        build_profile "minimal" "Minimal OAuth server for development" "client-credentials,jwt"
        ;;
    
    standard)
        log_info "🏭 Building Standard Profile"  
        build_profile "standard" "Production-ready with monitoring" "standard"
        ;;
    
    enterprise)
        log_info "🏢 Building Enterprise Profile"
        build_profile "enterprise" "Full enterprise feature set" "enterprise"
        ;;
    
    all)
        log_info "🎯 Building All Profiles"
        build_profile "minimal" "Minimal OAuth server" "client-credentials,jwt"
        build_profile "standard" "Standard production features" "standard" 
        build_profile "enterprise" "Full enterprise feature set" "enterprise"
        log_success "All profiles built successfully!"
        ;;
    
    clean)
        clean_artifacts
        ;;
    
    help|--help|-h|*)
        show_help
        ;;
esac