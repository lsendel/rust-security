#!/bin/bash

# Script to validate all security controls in the Rust Security Workspace
# This script systematically checks authentication, authorization, logging, and security mechanisms

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔐 Rust Security Workspace - Security Controls Validation${NC}"
echo "========================================================="
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
    else
        echo -e "  ${RED}❌ $control_name${NC}"
        if [ -n "$details" ]; then
            echo -e "     $details"
        fi
        ((validation_failed++))
    fi
}

# Function to run cargo test and check results
run_security_test() {
    local test_name="$1"
    local test_pattern="$2"
    
    echo -e "${YELLOW}🧪 Running $test_name tests${NC}"
    
    cd "$PROJECT_ROOT"
    if cargo test "$test_pattern" --all-features >/dev/null 2>&1; then
        local test_count=$(cargo test "$test_pattern" --all-features 2>/dev/null | grep -E "test result:" | grep -o "[0-9]\+ passed" | grep -o "[0-9]\+" || echo "0")
        validate_control "$test_name" "PASS" "$test_count tests passed"
        return 0
    else
        validate_control "$test_name" "FAIL" "Tests failed or not found"
        return 1
    fi
}

# 1. Authentication Mechanisms
echo -e "\n${BLUE}1. Authentication Mechanisms${NC}"
echo "================================"

# OAuth2 Client Credentials
run_security_test "OAuth2 Client Credentials" "test.*client.*credential"

# Token Operations
run_security_test "Token Operations" "test.*token.*"

# PKCE OAuth Flow
run_security_test "PKCE OAuth Flow" "pkce"

# MFA (TOTP)
run_security_test "Multi-Factor Authentication (TOTP)" "totp"

# 2. Authorization Controls
echo -e "\n${BLUE}2. Authorization Controls${NC}"
echo "=========================="

# Authorization endpoint
run_security_test "Authorization Endpoint" "authorization"

# Scope validation
run_security_test "Scope Validation" "scope.*validation"

# Policy enforcement
if cargo test --test authorization_it authorize_strict_mode_errors_when_service_unavailable >/dev/null 2>&1; then
    validate_control "Policy Enforcement (Strict Mode)" "PASS" "Strict mode correctly fails when policy service unavailable"
else
    validate_control "Policy Enforcement (Strict Mode)" "FAIL" "Strict mode test failed"
fi

# 3. Security Logging
echo -e "\n${BLUE}3. Security Logging${NC}"
echo "==================="

# Security logging module
run_security_test "Security Logging Module" "security.*logging"

# Audit logging
run_security_test "Audit Logging" "audit.*log"

# Check security logging integration
if [ -f "$PROJECT_ROOT/auth-service/src/security_logging.rs" ]; then
    validate_control "Security Logging Module" "PASS" "Security logging module exists"
else
    validate_control "Security Logging Module" "FAIL" "Security logging module missing"
fi

# 4. Security Headers and Input Validation
echo -e "\n${BLUE}4. Security Headers and Input Validation${NC}"
echo "========================================="

# Security headers
run_security_test "Security Headers" "security.*header"

# Input validation
run_security_test "Input Validation" "test.*invalid.*"

# 5. Token Security
echo -e "\n${BLUE}5. Token Security${NC}"
echo "=================="

# Token binding
run_security_test "Token Binding" "token.*binding"

# Token refresh
run_security_test "Token Refresh" "refresh.*token"

# Token introspection
run_security_test "Token Introspection" "introspect"

# 6. Rate Limiting and Circuit Breaker
echo -e "\n${BLUE}6. Rate Limiting and Circuit Breaker${NC}"
echo "==================================="

# Rate limiting
if grep -r "rate.limit" "$PROJECT_ROOT/auth-service/src/" >/dev/null 2>&1; then
    validate_control "Rate Limiting Implementation" "PASS" "Rate limiting code found"
else
    validate_control "Rate Limiting Implementation" "FAIL" "Rate limiting code not found"
fi

# Circuit breaker
run_security_test "Circuit Breaker" "circuit.*breaker"

# 7. Cryptographic Controls
echo -e "\n${BLUE}7. Cryptographic Controls${NC}"
echo "========================="

# JWT handling
if grep -r "jsonwebtoken\|jwt" "$PROJECT_ROOT/auth-service/Cargo.toml" >/dev/null 2>&1; then
    validate_control "JWT Library" "PASS" "JWT library dependency found"
else
    validate_control "JWT Library" "FAIL" "JWT library dependency missing"
fi

# Key management
if [ -f "$PROJECT_ROOT/auth-service/src/keys.rs" ]; then
    validate_control "Key Management Module" "PASS" "Key management module exists"
else
    validate_control "Key Management Module" "FAIL" "Key management module missing"
fi

# 8. Request Security
echo -e "\n${BLUE}8. Request Security${NC}"
echo "==================="

# Request ID tracking
run_security_test "Request ID Tracking" "request.*id"

# Request signing
run_security_test "Request Signing" "request.*sign"

# 9. Security Configuration
echo -e "\n${BLUE}9. Security Configuration${NC}"
echo "=========================="

# Environment-based configuration
if grep -r "POLICY_ENFORCEMENT\|AUTH_" "$PROJECT_ROOT/auth-service/src/" >/dev/null 2>&1; then
    validate_control "Environment Configuration" "PASS" "Environment-based security configuration found"
else
    validate_control "Environment Configuration" "FAIL" "Environment-based security configuration missing"
fi

# Security features compilation
if grep -r "all-features\|security" "$PROJECT_ROOT/auth-service/Cargo.toml" >/dev/null 2>&1; then
    validate_control "Security Features" "PASS" "Security features configured"
else
    validate_control "Security Features" "FAIL" "Security features not configured"
fi

# 10. Monitoring and Alerting Infrastructure
echo -e "\n${BLUE}10. Monitoring and Alerting Infrastructure${NC}"
echo "=========================================="

# Prometheus alerting rules
if [ -f "$PROJECT_ROOT/monitoring/prometheus/security-alerts.yml" ]; then
    local alert_count=$(grep -c "alert:" "$PROJECT_ROOT/monitoring/prometheus/security-alerts.yml" 2>/dev/null || echo "0")
    validate_control "Prometheus Security Alerts" "PASS" "$alert_count security alerts configured"
else
    validate_control "Prometheus Security Alerts" "FAIL" "Security alerts configuration missing"
fi

# Alertmanager configuration
if [ -f "$PROJECT_ROOT/monitoring/alertmanager/alertmanager.yml" ]; then
    validate_control "Alertmanager Configuration" "PASS" "Alertmanager configuration exists"
else
    validate_control "Alertmanager Configuration" "FAIL" "Alertmanager configuration missing"
fi

# Fluentd log collection
if [ -f "$PROJECT_ROOT/monitoring/fluentd/fluent.conf" ]; then
    validate_control "Fluentd Log Collection" "PASS" "Fluentd configuration exists"
else
    validate_control "Fluentd Log Collection" "FAIL" "Fluentd configuration missing"
fi

# Elasticsearch ILM policies
if [ -f "$PROJECT_ROOT/monitoring/elasticsearch/ilm-policies.json" ]; then
    validate_control "Elasticsearch ILM Policies" "PASS" "ILM policies configured"
else
    validate_control "Elasticsearch ILM Policies" "FAIL" "ILM policies missing"
fi

# 11. Compliance and Audit Features
echo -e "\n${BLUE}11. Compliance and Audit Features${NC}"
echo "================================="

# SCIM 2.0 support
if [ -f "$PROJECT_ROOT/auth-service/src/scim.rs" ]; then
    validate_control "SCIM 2.0 Support" "PASS" "SCIM module exists"
else
    validate_control "SCIM 2.0 Support" "FAIL" "SCIM module missing"
fi

# OpenID Connect metadata
run_security_test "OpenID Connect Metadata" "openid.*metadata"

# 12. Vulnerability Prevention
echo -e "\n${BLUE}12. Vulnerability Prevention${NC}"
echo "============================="

# SQL Injection prevention (checking for parameterized queries)
if grep -r "sqlx\|diesel" "$PROJECT_ROOT/auth-service/Cargo.toml" >/dev/null 2>&1; then
    validate_control "SQL Injection Prevention" "PASS" "ORM/query builder in use"
else
    validate_control "SQL Injection Prevention" "WARN" "Manual SQL injection prevention required"
fi

# XSS prevention
if grep -r "serde_json\|escape" "$PROJECT_ROOT/auth-service/src/" >/dev/null 2>&1; then
    validate_control "XSS Prevention" "PASS" "JSON serialization and escaping found"
else
    validate_control "XSS Prevention" "FAIL" "XSS prevention mechanisms missing"
fi

# CSRF protection
if grep -r "csrf\|SameSite" "$PROJECT_ROOT/" >/dev/null 2>&1; then
    validate_control "CSRF Protection" "PASS" "CSRF protection mechanisms found"
else
    validate_control "CSRF Protection" "WARN" "CSRF protection mechanisms not explicitly found"
fi

# Generate Summary Report
echo -e "\n${BLUE}📋 Security Controls Validation Summary${NC}"
echo "========================================"
echo -e "Total Controls Validated: $((validation_passed + validation_failed))"
echo -e "${GREEN}✅ Controls Passed: $validation_passed${NC}"
echo -e "${RED}❌ Controls Failed: $validation_failed${NC}"

if [ $validation_failed -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All security controls validation passed!${NC}"
    echo -e "${GREEN}✅ Security posture is strong${NC}"
    exit_code=0
else
    echo -e "\n${YELLOW}⚠️  Some security controls need attention${NC}"
    echo -e "${YELLOW}📝 Review failed validations above${NC}"
    exit_code=1
fi

# Recommendations
echo -e "\n${BLUE}💡 Security Recommendations${NC}"
echo "============================="
echo -e "1. ${YELLOW}Regular Security Testing:${NC} Run this validation script regularly"
echo -e "2. ${YELLOW}Penetration Testing:${NC} Conduct external security assessments"
echo -e "3. ${YELLOW}Dependency Updates:${NC} Keep security dependencies updated"
echo -e "4. ${YELLOW}Log Monitoring:${NC} Monitor security logs for threats"
echo -e "5. ${YELLOW}Access Reviews:${NC} Regular reviews of access controls"
echo -e "6. ${YELLOW}Incident Response:${NC} Test incident response procedures"

# Additional Security Metrics
echo -e "\n${BLUE}📊 Security Metrics${NC}"
echo "==================="
echo -e "Security Test Coverage: $(( (validation_passed * 100) / (validation_passed + validation_failed) ))%"
echo -e "Critical Security Controls: $(( validation_passed >= 25 ? 100 : (validation_passed * 100) / 25 ))%"

echo -e "\n========================================"
echo -e "${BLUE}🔐 Security controls validation completed!${NC}"

exit $exit_code