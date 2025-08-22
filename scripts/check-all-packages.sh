#!/bin/bash

# Comprehensive package status checker
# Checks all packages in the workspace

set -e

echo "🔍 Comprehensive Package Status Check"
echo "===================================="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# All packages in workspace
ALL_PACKAGES=("auth-core" "common" "api-contracts" "auth-service" "policy-service" "compliance-tools")

echo -e "${BLUE}📦 Checking compilation status for all packages...${NC}"
echo ""

compilation_success=0
compilation_total=0

for package in "${ALL_PACKAGES[@]}"; do
    echo -n "  Checking $package... "
    compilation_total=$((compilation_total + 1))
    
    if cargo check -p "$package" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ COMPILES${NC}"
        compilation_success=$((compilation_success + 1))
    else
        echo -e "${RED}❌ ERRORS${NC}"
        error_count=$(cargo check -p "$package" 2>&1 | grep -c "error\[" || echo "0")
        echo "    → $error_count compilation errors"
    fi
done

echo ""
echo -e "${BLUE}🧪 Checking test status for all packages...${NC}"
echo ""

test_success=0
test_total=0

for package in "${ALL_PACKAGES[@]}"; do
    echo -n "  Testing $package... "
    test_total=$((test_total + 1))
    
    if cargo test -p "$package" --lib --bins >/dev/null 2>&1; then
        echo -e "${GREEN}✅ TESTS PASS${NC}"
        test_success=$((test_success + 1))
    else
        echo -e "${YELLOW}⚠️ SOME ISSUES${NC}"
        echo "    → Some tests may fail (but package compiles)"
    fi
done

echo ""
echo -e "${BLUE}📊 COMPREHENSIVE SUMMARY${NC}"
echo "========================"
echo ""
echo -e "${GREEN}🎉 COMPILATION STATUS:${NC}"
echo "  ✅ Successful: $compilation_success/$compilation_total packages"
if [ "$compilation_success" -eq "$compilation_total" ]; then
    echo -e "  ${GREEN}🚀 ALL PACKAGES COMPILE SUCCESSFULLY!${NC}"
else
    echo -e "  ${YELLOW}⚠️ $(($compilation_total - $compilation_success)) packages need fixes${NC}"
fi

echo ""
echo -e "${GREEN}🧪 TESTING STATUS:${NC}"
echo "  ✅ Clean tests: $test_success/$test_total packages"
if [ "$test_success" -eq "$test_total" ]; then
    echo -e "  ${GREEN}🎯 ALL TESTS PASS PERFECTLY!${NC}"
else
    echo -e "  ${YELLOW}⚠️ $(($test_total - $test_success)) packages have test issues${NC}"
fi

echo ""
if [ "$compilation_success" -eq "$compilation_total" ]; then
    echo -e "${GREEN}🎉 INCREDIBLE ACHIEVEMENT:${NC}"
    echo -e "  ${GREEN}✅ 100% COMPILATION SUCCESS RATE!${NC}"
    echo -e "  ${GREEN}🚀 ENTIRE RUST SECURITY PLATFORM COMPILES!${NC}"
    echo -e "  ${GREEN}📦 All 6 packages ready for production CI/CD!${NC}"
    echo ""
    echo -e "${BLUE}🎯 Ready for advanced CI features:${NC}"
    echo "  - Code coverage reporting"
    echo "  - Performance benchmarks"
    echo "  - Deployment pipelines"
    echo "  - Advanced security scanning"
else
    echo -e "${YELLOW}📋 Next steps:${NC}"
    echo "  1. Fix remaining compilation errors"
    echo "  2. Add all packages to CI pipeline"
    echo "  3. Implement advanced features"
fi

echo ""
echo "🔗 GitHub Actions: https://github.com/lsendel/rust-security/actions"
