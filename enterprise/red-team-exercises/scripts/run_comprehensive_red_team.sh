#!/bin/bash

# Comprehensive Red Team Exercise Runner
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TARGET_URL="${TARGET_URL:-http://localhost:8080}"
OUTPUT_DIR="${OUTPUT_DIR:-${PROJECT_DIR}/reports}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_banner() {
    echo -e "${RED}"
    echo "🔴 COMPREHENSIVE RED TEAM EXERCISE SUITE"
    echo "========================================"
    echo -e "${NC}"
    echo "Target: ${TARGET_URL}"
    echo "Output: ${OUTPUT_DIR}"
    echo "Timestamp: ${TIMESTAMP}"
    echo ""
}

check_prerequisites() {
    echo -e "${BLUE}📋 Checking prerequisites...${NC}"
    
    if ! curl -s --connect-timeout 5 "${TARGET_URL}/health" >/dev/null 2>&1; then
        echo -e "${RED}❌ Target service not reachable at ${TARGET_URL}${NC}"
        exit 1
    fi
    
    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}❌ Cargo not found. Please install Rust.${NC}"
        exit 1
    fi
    
    if [ ! -f "${PROJECT_DIR}/target/release/red-team-exercises" ]; then
        echo -e "${YELLOW}🔨 Building red team exercises...${NC}"
        cd "${PROJECT_DIR}"
        cargo build --release
    fi
    
    mkdir -p "${OUTPUT_DIR}"
    echo -e "${GREEN}✅ Prerequisites check completed${NC}"
    echo ""
}

run_exercise() {
    local scenario="$1"
    local intensity="$2"
    local duration="$3"
    local description="$4"
    
    echo -e "${BLUE}🎯 Running: ${description}${NC}"
    echo "Scenario: ${scenario}, Intensity: ${intensity}, Duration: ${duration}s"
    
    local output_file="${OUTPUT_DIR}/red_team_${scenario}_${intensity}_${TIMESTAMP}.json"
    
    cd "${PROJECT_DIR}"
    
    if timeout $((duration + 60)) ./target/release/red-team-exercises \
        --target "${TARGET_URL}" \
        --scenario "${scenario}" \
        --intensity "${intensity}" \
        --duration "${duration}" \
        --output "${output_file}"; then
        echo -e "${GREEN}✅ Exercise completed: ${output_file}${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}❌ Exercise failed or timed out${NC}"
        return 1
    fi
}

main() {
    print_banner
    check_prerequisites
    
    local failed_exercises=0
    
    echo -e "${YELLOW}🚀 Starting comprehensive red team exercises...${NC}"
    echo ""
    
    # Run exercises
    run_exercise "auth" "medium" 300 "Authentication Bypass Scenarios" || ((failed_exercises++))
    run_exercise "mfa" "medium" 240 "MFA Bypass Scenarios" || ((failed_exercises++))
    run_exercise "idor" "medium" 300 "IDOR Attack Scenarios" || ((failed_exercises++))
    run_exercise "oauth" "medium" 240 "OAuth2/OIDC Manipulation" || ((failed_exercises++))
    run_exercise "session" "medium" 240 "Session Management Attacks" || ((failed_exercises++))
    run_exercise "token" "medium" 300 "Token Manipulation Attacks" || ((failed_exercises++))
    run_exercise "rate_limit" "medium" 240 "Rate Limiting Bypass" || ((failed_exercises++))
    run_exercise "social" "low" 180 "Social Engineering" || ((failed_exercises++))
    
    echo -e "${GREEN}🎉 Red Team Exercise Suite Completed${NC}"
    echo "Failed Exercises: ${failed_exercises}"
    echo "Output Directory: ${OUTPUT_DIR}"
    
    if [ $failed_exercises -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

trap 'echo -e "\n${RED}❌ Red team exercises interrupted${NC}"; exit 130' INT TERM
main "$@"
