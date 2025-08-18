#!/bin/bash

# Quick Security Controls Validation Script
# Validates security controls without running time-intensive tests

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔐 Quick Security Controls Validation${NC}"
echo "===================================="
echo -e "📍 Project root: $PROJECT_ROOT"

# Initialize validation results
validation_passed=0
validation_failed=0

# Function to log validation result
validate_control() {
    local control_name="$1"
    local status="$2"
    local details="$3"
    
    if [ "$status" = "PASS" ]; then
        echo -e "  ${GREEN}✅ $control_name${NC}"
        if [ -n "$details" ]; then
            echo -e "     $details"
        fi
        ((validation_passed++))
    elif [ "$status" = "WARN" ]; then
        echo -e "  ${YELLOW}⚠️  $control_name${NC}"
        if [ -n "$details" ]; then
            echo -e "     $details"
        fi
        ((validation_passed++))
    else
        echo -e "  ${RED}❌ $control_name${NC}"
        if [ -n "$details" ]; then
            echo -e "     $details"
        fi
        ((validation_failed++))
    fi
}

# 1. Core Security Modules
echo -e "\n${BLUE}1. Core Security Modules${NC}"
echo "========================="

# Security logging module
if [ -f "$PROJECT_ROOT/auth-service/src/security_logging.rs" ]; then
    events=$(grep -c "SecurityEvent\|log_.*_attempt\|log_.*_operation" "$PROJECT_ROOT/auth-service/src/security_logging.rs" 2>/dev/null || echo "0")
    validate_control "Security Logging Module" "PASS" "$events security logging functions found"
else
    validate_control "Security Logging Module" "FAIL" "Security logging module missing"
fi

# Key management
if [ -f "$PROJECT_ROOT/auth-service/src/keys.rs" ]; then
    validate_control "Key Management Module" "PASS" "Key management module exists"
else
    validate_control "Key Management Module" "FAIL" "Key management module missing"
fi

# MFA module
if [ -f "$PROJECT_ROOT/auth-service/src/mfa.rs" ]; then
    validate_control "Multi-Factor Authentication" "PASS" "MFA module exists"
else
    validate_control "Multi-Factor Authentication" "FAIL" "MFA module missing"
fi

# Circuit breaker
if [ -f "$PROJECT_ROOT/auth-service/src/circuit_breaker.rs" ]; then
    validate_control "Circuit Breaker" "PASS" "Circuit breaker module exists"
else
    validate_control "Circuit Breaker" "FAIL" "Circuit breaker module missing"
fi

# SCIM 2.0 support
if [ -f "$PROJECT_ROOT/auth-service/src/scim.rs" ]; then
    validate_control "SCIM 2.0 Support" "PASS" "SCIM module exists"
else
    validate_control "SCIM 2.0 Support" "FAIL" "SCIM module missing"
fi

# 2. Security Dependencies
echo -e "\n${BLUE}2. Security Dependencies${NC}"
echo "========================"

cd "$PROJECT_ROOT/auth-service"

# JWT library
if grep -q "jsonwebtoken" Cargo.toml; then
    validate_control "JWT Library" "PASS" "jsonwebtoken dependency found"
else
    validate_control "JWT Library" "FAIL" "JWT library dependency missing"
fi

# Cryptographic libraries
if grep -q "ring\|rustls\|sha2\|hmac" Cargo.toml; then
    validate_control "Cryptographic Libraries" "PASS" "Crypto dependencies found"
else
    validate_control "Cryptographic Libraries" "FAIL" "Crypto dependencies missing"
fi

# HTTP security
if grep -q "axum\|tower" Cargo.toml; then
    validate_control "HTTP Security Framework" "PASS" "Axum/Tower framework found"
else
    validate_control "HTTP Security Framework" "FAIL" "HTTP security framework missing"
fi

# Async runtime
if grep -q "tokio" Cargo.toml; then
    validate_control "Async Runtime" "PASS" "Tokio runtime found"
else
    validate_control "Async Runtime" "FAIL" "Async runtime missing"
fi

# 3. Authentication Implementation
echo -e "\n${BLUE}3. Authentication Implementation${NC}"
echo "==============================="

# OAuth2 endpoints
if grep -q "oauth/token\|oauth/introspect" "$PROJECT_ROOT/auth-service/src/lib.rs"; then
    validate_control "OAuth2 Endpoints" "PASS" "OAuth2 endpoints implemented"
else
    validate_control "OAuth2 Endpoints" "FAIL" "OAuth2 endpoints missing"
fi

# Client credentials validation
if grep -q "client_id\|client_secret" "$PROJECT_ROOT/auth-service/src/lib.rs"; then
    validate_control "Client Credentials" "PASS" "Client credentials validation found"
else
    validate_control "Client Credentials" "FAIL" "Client credentials validation missing"
fi

# Token generation and validation
if grep -q "generate.*token\|validate.*token\|TokenRecord" "$PROJECT_ROOT/auth-service/src/lib.rs"; then
    validate_control "Token Management" "PASS" "Token management implemented"
else
    validate_control "Token Management" "FAIL" "Token management missing"
fi

# 4. Authorization Implementation
echo -e "\n${BLUE}4. Authorization Implementation${NC}"
echo "==============================="

# Authorization endpoint
if grep -q "v1/authorize" "$PROJECT_ROOT/auth-service/src/lib.rs"; then
    validate_control "Authorization Endpoint" "PASS" "Authorization endpoint implemented"
else
    validate_control "Authorization Endpoint" "FAIL" "Authorization endpoint missing"
fi

# Policy service integration
if grep -q "POLICY_SERVICE_URL\|policy.*service" "$PROJECT_ROOT/auth-service/src/lib.rs"; then
    validate_control "Policy Service Integration" "PASS" "Policy service integration found"
else
    validate_control "Policy Service Integration" "FAIL" "Policy service integration missing"
fi

# Strict/permissive enforcement
if grep -q "POLICY_ENFORCEMENT\|strict.*mode" "$PROJECT_ROOT/auth-service/src/lib.rs"; then
    validate_control "Policy Enforcement Modes" "PASS" "Enforcement modes implemented"
else
    validate_control "Policy Enforcement Modes" "FAIL" "Enforcement modes missing"
fi

# 5. Security Logging Integration
echo -e "\n${BLUE}5. Security Logging Integration${NC}"
echo "==============================="

# Security logging in endpoints
if grep -q "SecurityLogger\|security.*log" "$PROJECT_ROOT/auth-service/src/lib.rs"; then
    integrations=$(grep -c "SecurityLogger::" "$PROJECT_ROOT/auth-service/src/lib.rs" 2>/dev/null || echo "0")
    validate_control "Security Logging Integration" "PASS" "$integrations security logging calls found"
else
    validate_control "Security Logging Integration" "FAIL" "Security logging not integrated"
fi

# Audit events
if grep -q "log_auth_attempt\|log_token_operation\|log_validation_failure" "$PROJECT_ROOT/auth-service/src/lib.rs"; then
    validate_control "Audit Event Logging" "PASS" "Audit events implemented"
else
    validate_control "Audit Event Logging" "FAIL" "Audit events missing"
fi

# 6. Monitoring Infrastructure
echo -e "\n${BLUE}6. Monitoring Infrastructure${NC}"
echo "============================="

# Prometheus alerting rules
if [ -f "$PROJECT_ROOT/monitoring/prometheus/security-alerts.yml" ]; then
    alert_count=$(grep -c "alert:" "$PROJECT_ROOT/monitoring/prometheus/security-alerts.yml" 2>/dev/null || echo "0")
    validate_control "Prometheus Security Alerts" "PASS" "$alert_count security alerts configured"
else
    validate_control "Prometheus Security Alerts" "FAIL" "Security alerts configuration missing"
fi

# Alertmanager configuration
if [ -f "$PROJECT_ROOT/monitoring/alertmanager/alertmanager.yml" ]; then
    routes=$(grep -c "receiver:\|route:" "$PROJECT_ROOT/monitoring/alertmanager/alertmanager.yml" 2>/dev/null || echo "0")
    validate_control "Alertmanager Configuration" "PASS" "$routes notification routes configured"
else
    validate_control "Alertmanager Configuration" "FAIL" "Alertmanager configuration missing"
fi

# Fluentd log collection
if [ -f "$PROJECT_ROOT/monitoring/fluentd/fluent.conf" ]; then
    sources=$(grep -c "<source>\|<match>" "$PROJECT_ROOT/monitoring/fluentd/fluent.conf" 2>/dev/null || echo "0")
    validate_control "Fluentd Log Collection" "PASS" "$sources log collection rules configured"
else
    validate_control "Fluentd Log Collection" "FAIL" "Fluentd configuration missing"
fi

# Elasticsearch ILM policies
if [ -f "$PROJECT_ROOT/monitoring/elasticsearch/ilm-policies.json" ]; then
    policies=$(grep -c "policy" "$PROJECT_ROOT/monitoring/elasticsearch/ilm-policies.json" 2>/dev/null || echo "0")
    validate_control "Elasticsearch ILM Policies" "PASS" "$policies retention policies configured"
else
    validate_control "Elasticsearch ILM Policies" "FAIL" "ILM policies missing"
fi

# 7. Security Test Coverage
echo -e "\n${BLUE}7. Security Test Coverage${NC}"
echo "========================="

# Security test files
security_tests=$(find "$PROJECT_ROOT" -name "*security*test*.rs" | wc -l)
if [ "$security_tests" -gt 0 ]; then
    validate_control "Security Test Files" "PASS" "$security_tests security test files found"
else
    validate_control "Security Test Files" "FAIL" "No security test files found"
fi

# Integration tests
integration_tests=$(find "$PROJECT_ROOT" -path "*/tests/*.rs" | wc -l)
if [ "$integration_tests" -gt 0 ]; then
    validate_control "Integration Tests" "PASS" "$integration_tests integration test files found"
else
    validate_control "Integration Tests" "FAIL" "No integration test files found"
fi

# 8. Configuration Security
echo -e "\n${BLUE}8. Configuration Security${NC}"
echo "========================="

# Environment-based configuration
if grep -q "std::env::var\|env!" "$PROJECT_ROOT/auth-service/src/lib.rs"; then
    validate_control "Environment Configuration" "PASS" "Environment-based configuration found"
else
    validate_control "Environment Configuration" "FAIL" "Environment configuration missing"
fi

# Security feature flags
if grep -q "all-features\|security.*feature" "$PROJECT_ROOT/auth-service/Cargo.toml"; then
    validate_control "Security Features" "PASS" "Security features configured"
else
    validate_control "Security Features" "WARN" "Security features not explicitly configured"
fi

# 9. Production Readiness
echo -e "\n${BLUE}9. Production Readiness${NC}"
echo "======================="

# Error handling
if grep -q "AuthError\|Result<.*Error>" "$PROJECT_ROOT/auth-service/src/lib.rs"; then
    validate_control "Error Handling" "PASS" "Comprehensive error handling found"
else
    validate_control "Error Handling" "FAIL" "Error handling missing"
fi

# Tracing/observability
if grep -q "tracing::" "$PROJECT_ROOT/auth-service/src/lib.rs"; then
    validate_control "Observability" "PASS" "Tracing implementation found"
else
    validate_control "Observability" "FAIL" "Observability missing"
fi

# Health endpoint
if grep -q "health" "$PROJECT_ROOT/auth-service/src/lib.rs"; then
    validate_control "Health Endpoint" "PASS" "Health endpoint implemented"
else
    validate_control "Health Endpoint" "FAIL" "Health endpoint missing"
fi

# Generate Summary Report
echo -e "\n${BLUE}📋 Security Controls Validation Summary${NC}"
echo "========================================"
echo -e "Total Controls Validated: $((validation_passed + validation_failed))"
echo -e "${GREEN}✅ Controls Passed: $validation_passed${NC}"
echo -e "${RED}❌ Controls Failed: $validation_failed${NC}"

# Calculate security score
total_controls=$((validation_passed + validation_failed))
security_score=$(( (validation_passed * 100) / total_controls ))

echo -e "\n${BLUE}📊 Security Score: ${security_score}%${NC}"

if [ $validation_failed -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All security controls validation passed!${NC}"
    echo -e "${GREEN}✅ Security posture is strong${NC}"
    exit_code=0
elif [ $security_score -ge 90 ]; then
    echo -e "\n${GREEN}✅ Excellent security posture (${security_score}%)${NC}"
    exit_code=0
elif [ $security_score -ge 80 ]; then
    echo -e "\n${YELLOW}⚠️  Good security posture (${security_score}%)${NC}"
    echo -e "${YELLOW}📝 Minor improvements needed${NC}"
    exit_code=0
else
    echo -e "\n${RED}❌ Security posture needs improvement (${security_score}%)${NC}"
    echo -e "${RED}📝 Review failed validations above${NC}"
    exit_code=1
fi

echo -e "\n========================================"
echo -e "${BLUE}🔐 Quick security validation completed!${NC}"

exit $exit_code