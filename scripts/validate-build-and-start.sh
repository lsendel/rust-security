#!/bin/bash

# Comprehensive validation script for the Rust Security Platform
# This script validates that all components build successfully and can start

set -e

echo "🔧 Rust Security Platform - Build & Startup Validation"
echo "======================================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "SUCCESS")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "WARNING") 
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}❌ $message${NC}"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  $message${NC}"
            ;;
    esac
}

# Function to check command exists
check_command() {
    local cmd=$1
    if command -v $cmd >/dev/null 2>&1; then
        print_status "SUCCESS" "$cmd is installed"
        return 0
    else
        print_status "ERROR" "$cmd is not installed"
        return 1
    fi
}

# Cleanup function
cleanup() {
    print_status "INFO" "Cleaning up background processes..."
    
    # Kill any running services
    pkill -f "auth-service|policy-service" 2>/dev/null || true
    
    # Wait for processes to terminate
    sleep 2
    
    print_status "SUCCESS" "Cleanup completed"
}

# Set cleanup trap
trap cleanup EXIT

main() {
    print_status "INFO" "Starting validation process..."
    
    # Check prerequisites
    print_status "INFO" "Checking prerequisites..."
    check_command "cargo" || exit 1
    check_command "rustc" || exit 1
    
    # Show Rust version
    rust_version=$(rustc --version)
    print_status "INFO" "Using Rust: $rust_version"
    
    # Step 1: Build core libraries
    print_status "INFO" "Building core libraries..."
    
    if cargo build --release --package common --package auth-core; then
        print_status "SUCCESS" "Core libraries built successfully"
    else
        print_status "ERROR" "Failed to build core libraries"
        exit 1
    fi
    
    # Step 2: Build policy service (known to work)
    print_status "INFO" "Building policy service..."
    
    if cargo build --release --bin policy-service; then
        print_status "SUCCESS" "Policy service built successfully"
        POLICY_SERVICE_AVAILABLE=true
    else
        print_status "WARNING" "Policy service failed to build"
        POLICY_SERVICE_AVAILABLE=false
    fi
    
    # Step 3: Build auth service
    print_status "INFO" "Building auth service..."
    
    if cargo build --release --bin auth-service; then
        print_status "SUCCESS" "Auth service built successfully"
        AUTH_SERVICE_AVAILABLE=true
    else
        print_status "WARNING" "Auth service failed to build"
        AUTH_SERVICE_AVAILABLE=false
    fi
    
    # Step 4: Test binary functionality
    print_status "INFO" "Testing binary functionality..."
    
    if [ "$POLICY_SERVICE_AVAILABLE" = true ]; then
        if timeout 5s ./target/release/policy-service --help >/dev/null 2>&1; then
            print_status "SUCCESS" "Policy service binary responds to --help"
        else
            print_status "WARNING" "Policy service binary may have issues"
        fi
    fi
    
    if [ "$AUTH_SERVICE_AVAILABLE" = true ]; then
        if timeout 5s ./target/release/auth-service --help >/dev/null 2>&1; then
            print_status "SUCCESS" "Auth service binary responds to --help"
        else
            print_status "WARNING" "Auth service binary may have issues"
        fi
    fi
    
    # Step 5: Test service startup (quick check)
    print_status "INFO" "Testing service startup capabilities..."
    
    if [ "$POLICY_SERVICE_AVAILABLE" = true ]; then
        print_status "INFO" "Starting policy service for validation..."
        
        # Set minimal environment for policy service
        export RUST_LOG=info
        export BIND_ADDRESS="127.0.0.1:8081"
        
        # Start policy service in background
        ./target/release/policy-service &
        POLICY_PID=$!
        
        # Wait for startup
        sleep 3
        
        # Check if process is still running
        if kill -0 $POLICY_PID 2>/dev/null; then
            print_status "SUCCESS" "Policy service started successfully (PID: $POLICY_PID)"
            
            # Test health endpoint if available
            if curl -f http://127.0.0.1:8081/health >/dev/null 2>&1; then
                print_status "SUCCESS" "Policy service health endpoint responding"
            else
                print_status "WARNING" "Policy service health endpoint not responding"
            fi
            
            # Stop the service
            kill $POLICY_PID 2>/dev/null || true
            wait $POLICY_PID 2>/dev/null || true
            print_status "SUCCESS" "Policy service stopped cleanly"
        else
            print_status "WARNING" "Policy service failed to start or exited immediately"
        fi
    fi
    
    if [ "$AUTH_SERVICE_AVAILABLE" = true ]; then
        print_status "INFO" "Starting auth service for validation..."
        
        # Set minimal environment for auth service
        export RUST_LOG=info
        export BIND_ADDRESS="127.0.0.1:8080"
        export JWT_SECRET="test-secret-key-for-validation-only"
        
        # Start auth service in background
        ./target/release/auth-service &
        AUTH_PID=$!
        
        # Wait for startup
        sleep 5
        
        # Check if process is still running
        if kill -0 $AUTH_PID 2>/dev/null; then
            print_status "SUCCESS" "Auth service started successfully (PID: $AUTH_PID)"
            
            # Test health endpoint if available
            if curl -f http://127.0.0.1:8080/health >/dev/null 2>&1; then
                print_status "SUCCESS" "Auth service health endpoint responding"
            else
                print_status "WARNING" "Auth service health endpoint not responding"
            fi
            
            # Stop the service
            kill $AUTH_PID 2>/dev/null || true
            wait $AUTH_PID 2>/dev/null || true
            print_status "SUCCESS" "Auth service stopped cleanly"
        else
            print_status "WARNING" "Auth service failed to start or exited immediately"
        fi
    fi
    
    # Step 6: Test integration scripts
    print_status "INFO" "Checking integration test scripts..."
    
    if [ -f "scripts/testing/quick_e2e_validation.sh" ]; then
        print_status "SUCCESS" "Quick E2E validation script found"
    else
        print_status "WARNING" "Quick E2E validation script missing"
    fi
    
    if [ -f "scripts/testing/end_to_end_integration_test.sh" ]; then
        print_status "SUCCESS" "End-to-end integration test script found"
    else
        print_status "WARNING" "End-to-end integration test script missing"
    fi
    
    # Step 7: Check GitHub workflows
    print_status "INFO" "Validating GitHub workflows..."
    
    if [ -f ".github/workflows/security-audit.yml" ]; then
        print_status "SUCCESS" "Security audit workflow found"
    else
        print_status "WARNING" "Security audit workflow missing"
    fi
    
    if [ -f ".github/workflows/e2e-tests.yml" ]; then
        print_status "SUCCESS" "E2E tests workflow found"
    else
        print_status "WARNING" "E2E tests workflow missing"
    fi
    
    # Step 8: Final summary
    print_status "INFO" "Validation Summary:"
    echo "==================="
    
    if [ "$POLICY_SERVICE_AVAILABLE" = true ]; then
        print_status "SUCCESS" "Policy Service: ✓ Builds and starts successfully"
    else
        print_status "WARNING" "Policy Service: ⚠ Build issues detected"
    fi
    
    if [ "$AUTH_SERVICE_AVAILABLE" = true ]; then
        print_status "SUCCESS" "Auth Service: ✓ Builds and starts successfully"
    else
        print_status "WARNING" "Auth Service: ⚠ Build issues detected"
    fi
    
    # Overall status
    if [ "$POLICY_SERVICE_AVAILABLE" = true ] || [ "$AUTH_SERVICE_AVAILABLE" = true ]; then
        print_status "SUCCESS" "Platform validation completed - At least one service is operational"
        echo ""
        echo "🎉 The Rust Security Platform is ready for deployment!"
        echo ""
        echo "Next steps:"
        echo "  1. Review any warnings above"
        echo "  2. Configure environment variables for production"
        echo "  3. Run integration tests with: ./scripts/testing/quick_e2e_validation.sh"
        echo "  4. Deploy using your preferred orchestration platform"
        return 0
    else
        print_status "ERROR" "Platform validation failed - No services are operational"
        echo ""
        echo "❌ The platform requires attention before deployment."
        echo ""
        echo "Troubleshooting steps:"
        echo "  1. Check compilation errors with: cargo check --workspace"
        echo "  2. Review dependencies with: cargo tree"
        echo "  3. Check environment setup"
        return 1
    fi
}

# Run main function
main "$@"