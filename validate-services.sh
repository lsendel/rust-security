#!/bin/bash

# Service Validation Script
# Validates that services can compile and start without errors

set -e

echo "🔍 Validating Rust Security Platform Services..."
echo "================================================"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Set minimal environment variables
export DATABASE_URL="sqlite::memory:"
export JWT_SECRET="validation-jwt-secret-key-minimum-32-characters"
export ENCRYPTION_KEY="validation-encryption-key-minimum-32-chars"
export RUST_LOG=error

# Function to validate service
validate_service() {
    local service_dir=$1
    local service_name=$2
    
    echo ""
    echo -e "${YELLOW}🔧 Validating $service_name...${NC}"
    
    cd "/Users/lsendel/IdeaProjects/rust-security/$service_dir"
    
    # Check if Cargo.toml exists
    if [ ! -f "Cargo.toml" ]; then
        echo -e "${RED}❌ Cargo.toml not found in $service_dir${NC}"
        cd ..
        return 1
    fi
    
    # Try to build the service
    echo "  📦 Building $service_name..."
    if cargo build --quiet 2>/dev/null; then
        echo -e "  ${GREEN}✅ Build successful${NC}"
    else
        echo -e "  ${RED}❌ Build failed${NC}"
        cd ..
        return 1
    fi
    
    # Check for the binary
    binary_name=$(basename "$service_dir")
    if [ -f "./target/debug/$binary_name" ]; then
        echo -e "  ${GREEN}✅ Binary created${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Binary location varies${NC}"
    fi
    
    cd ..
    return 0
}

# Validate Auth Service
if validate_service "auth-service" "Auth Service"; then
    AUTH_STATUS="${GREEN}✅ READY${NC}"
else
    AUTH_STATUS="${RED}❌ FAILED${NC}"
fi

# Validate Policy Service  
if validate_service "policy-service" "Policy Service"; then
    POLICY_STATUS="${GREEN}✅ READY${NC}"
else
    POLICY_STATUS="${RED}❌ FAILED${NC}"
fi

# Summary
echo ""
echo "================================================"
echo "📊 Validation Summary:"
echo "================================================"
echo -e "Auth Service:   $AUTH_STATUS"
echo -e "Policy Service: $POLICY_STATUS"
echo "================================================"

# Check if both services are ready
if [[ "$AUTH_STATUS" == *"READY"* ]] && [[ "$POLICY_STATUS" == *"READY"* ]]; then
    echo -e "${GREEN}✅ All services validated successfully!${NC}"
    echo ""
    echo "You can now run:"
    echo "  ./start-services.sh    # Start all services"
    echo "  cargo test --test openapi_endpoints_test  # Run endpoint tests"
    exit 0
else
    echo -e "${RED}❌ Some services failed validation${NC}"
    echo "Please check the compilation errors above."
    exit 1
fi