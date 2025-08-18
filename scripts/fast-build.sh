#!/bin/bash
# Fast development build script
# Optimizes build performance for rapid iteration

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Starting fast development build...${NC}"

# Set environment variables for optimal performance
export CARGO_INCREMENTAL=1
export CARGO_PROFILE_DEV_DEBUG=1
export CARGO_PROFILE_DEV_CODEGEN_UNITS=512
export RUST_BACKTRACE=0  # Disable backtrace for faster panics in dev

# Calculate optimal job count (leave 1 CPU for system)
JOBS=$(( $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4) - 1 ))
if [ $JOBS -lt 1 ]; then JOBS=1; fi

echo -e "${YELLOW}Using $JOBS parallel jobs${NC}"

# Function to time commands
time_command() {
    local cmd="$1"
    local desc="$2"
    echo -e "${YELLOW}⏱️  $desc...${NC}"
    time bash -c "$cmd"
    echo -e "${GREEN}✅ $desc completed${NC}"
}

# Clean incremental compilation cache if requested
if [[ "${1:-}" == "--clean" ]]; then
    echo -e "${YELLOW}🧹 Cleaning incremental cache...${NC}"
    rm -rf target/debug/incremental
    rm -rf target/debug/.fingerprint
fi

# Fast check first (cheapest validation)
time_command "cargo check --workspace --jobs $JOBS" "Workspace check"

# Build core components with minimal features
echo -e "${YELLOW}🔧 Building core components...${NC}"

# Build in dependency order for optimal caching
time_command "cargo build --package common --jobs $JOBS" "Common library"
time_command "cargo build --package auth-service --features fast-build --jobs $JOBS" "Auth service (fast-build)"
time_command "cargo build --package policy-service --jobs $JOBS" "Policy service"

# Optional: build examples if needed
if [[ "${BUILD_EXAMPLES:-}" == "true" ]]; then
    time_command "cargo build --package axum-integration-example --jobs $JOBS" "Axum example"
    time_command "cargo build --package simple-auth-client --jobs $JOBS" "Simple client"
fi

echo -e "${GREEN}🎉 Fast build completed successfully!${NC}"

# Display build statistics
echo -e "${YELLOW}📊 Build Statistics:${NC}"
du -sh target/debug 2>/dev/null || echo "Debug target size: N/A"
echo "Incremental compilation: $([ -d target/debug/incremental ] && echo 'Enabled' || echo 'Disabled')"

# Performance tips
echo -e "${YELLOW}💡 Performance Tips:${NC}"
echo "• Use 'cargo check' for fastest syntax validation"
echo "• Use '--features fast-build' for auth-service development"
echo "• Run './fast-build.sh --clean' if builds become slow"
echo "• Use 'cargo watch -x check' for continuous development"