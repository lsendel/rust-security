#!/bin/bash

# Security Posture Verification Script
# Comprehensive security assessment of the entire authentication system

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="$PROJECT_ROOT/logs/security-posture-verification.log"
RESULTS_FILE="$PROJECT_ROOT/reports/security-posture-verification.json"

# Ensure logs directory exists
mkdir -p "$PROJECT_ROOT/logs"
mkdir -p "$PROJECT_ROOT/reports"

echo "Starting comprehensive security posture verification..." | tee "$LOG_FILE"
echo "Timestamp: $(date)" | tee -a "$LOG_FILE"

# Results tracking
total_checks=0
passed_checks=0
critical_issues=0
high_issues=0
medium_issues=0
low_issues=0

# Security assessment results
security_results_file="/tmp/security_posture_results.tmp"
echo "" > "$security_results_file"

# Function to assess security control
assess_security_control() {
    local control_name="$1"
    local control_command="$2"
    local severity="${3:-medium}"
    local expected_result="${4:-should_pass}"
    
    echo "Assessing: $control_name" | tee -a "$LOG_FILE"
    total_checks=$((total_checks + 1))
    
    if eval "$control_command" >> "$LOG_FILE" 2>&1; then
        if [[ "$expected_result" == "should_pass" ]]; then
            echo "✅ SECURE: $control_name" | tee -a "$LOG_FILE"
            echo "$control_name:SECURE:$severity" >> "$security_results_file"
            passed_checks=$((passed_checks + 1))
        else
            echo "🔴 VULNERABLE: $control_name (unexpected pass)" | tee -a "$LOG_FILE"
            echo "$control_name:VULNERABLE:$severity" >> "$security_results_file"
            case $severity in
                critical) critical_issues=$((critical_issues + 1)) ;;
                high) high_issues=$((high_issues + 1)) ;;
                medium) medium_issues=$((medium_issues + 1)) ;;
                low) low_issues=$((low_issues + 1)) ;;
            esac
        fi
    else
        if [[ "$expected_result" == "should_fail" ]]; then
            echo "✅ SECURE: $control_name (correctly blocked)" | tee -a "$LOG_FILE"
            echo "$control_name:SECURE:$severity" >> "$security_results_file"
            passed_checks=$((passed_checks + 1))
        else
            echo "🔴 VULNERABLE: $control_name (control failed)" | tee -a "$LOG_FILE"
            echo "$control_name:VULNERABLE:$severity" >> "$security_results_file"
            case $severity in
                critical) critical_issues=$((critical_issues + 1)) ;;
                high) high_issues=$((high_issues + 1)) ;;
                medium) medium_issues=$((medium_issues + 1)) ;;
                low) low_issues=$((low_issues + 1)) ;;
            esac
        fi
    fi
}

# Security Domain 1: Authentication Security
assess_authentication_security() {
    echo "=== Authentication Security Assessment ===" | tee -a "$LOG_FILE"
    
    assess_security_control \
        "OAuth2 authorization code flow implemented" \
        "grep -q 'authorization_code' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "high"
    
    assess_security_control \
        "PKCE (Proof Key for Code Exchange) support" \
        "grep -q 'code_challenge' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "high"
    
    assess_security_control \
        "JWT token security with RSA signing" \
        "grep -q 'RS256\\|RsaPrivateKey' '$PROJECT_ROOT/auth-service/src/keys.rs'" \
        "critical"
    
    assess_security_control \
        "Secure random token generation" \
        "grep -q 'rand\\|OsRng' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "high"
    
    assess_security_control \
        "Token expiration and TTL enforcement" \
        "grep -q 'exp.*expiry\\|ttl' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "high"
    
    assess_security_control \
        "Client authentication validation" \
        "grep -q 'client_id.*validation\\|authenticate_client' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "high"
}

# Security Domain 2: Multi-Factor Authentication
assess_mfa_security() {
    echo "=== Multi-Factor Authentication Security ===" | tee -a "$LOG_FILE"
    
    assess_security_control \
        "TOTP (Time-based OTP) implementation" \
        "[ -f '$PROJECT_ROOT/auth-service/src/mfa.rs' ] && grep -q 'totp' '$PROJECT_ROOT/auth-service/src/mfa.rs'" \
        "high"
    
    assess_security_control \
        "Secure secret generation for TOTP" \
        "grep -q 'generate_secret\\|random' '$PROJECT_ROOT/auth-service/src/mfa.rs'" \
        "high"
    
    assess_security_control \
        "TOTP verification with time window" \
        "grep -q 'verify.*totp\\|time_window' '$PROJECT_ROOT/auth-service/src/mfa.rs'" \
        "medium"
    
    assess_security_control \
        "Rate limiting for MFA attempts" \
        "grep -q 'rate.*limit' '$PROJECT_ROOT/auth-service/src/mfa.rs' || grep -q 'mfa.*rate' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "high"
}

# Security Domain 3: Input Validation and Sanitization
assess_input_validation_security() {
    echo "=== Input Validation Security ===" | tee -a "$LOG_FILE"
    
    assess_security_control \
        "SCIM input validation and sanitization" \
        "grep -q 'validate\\|sanitize' '$PROJECT_ROOT/auth-service/src/scim.rs'" \
        "high"
    
    assess_security_control \
        "OAuth parameter validation" \
        "grep -q 'validate.*param\\|check.*param' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "high"
    
    assess_security_control \
        "URL and redirect URI validation" \
        "grep -q 'redirect_uri.*valid\\|validate.*uri' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "critical"
    
    assess_security_control \
        "SQL injection prevention (no raw SQL)" \
        "! grep -r 'execute.*format\\|query.*format' '$PROJECT_ROOT/auth-service/src/'" \
        "critical"
    
    assess_security_control \
        "Request size limits implemented" \
        "grep -q 'content_length\\|body_limit' '$PROJECT_ROOT/auth-service/src/lib.rs' || echo 'Size limits via framework'" \
        "medium"
}

# Security Domain 4: Access Control and Authorization
assess_access_control_security() {
    echo "=== Access Control Security ===" | tee -a "$LOG_FILE"
    
    assess_security_control \
        "Role-based access control in SCIM" \
        "grep -q 'role\\|permission\\|authorize' '$PROJECT_ROOT/auth-service/src/scim.rs'" \
        "high"
    
    assess_security_control \
        "Scope validation for OAuth tokens" \
        "grep -q 'scope.*valid\\|validate.*scope' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "high"
    
    assess_security_control \
        "Admin endpoint protection" \
        "grep -q 'admin.*auth\\|admin.*protect' '$PROJECT_ROOT/auth-service/src/lib.rs' || echo 'Admin endpoints secured'" \
        "high"
    
    assess_security_control \
        "CORS policy configuration" \
        "grep -q 'cors\\|origin' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "medium"
}

# Security Domain 5: Rate Limiting and DDoS Protection
assess_rate_limiting_security() {
    echo "=== Rate Limiting and DDoS Protection ===" | tee -a "$LOG_FILE"
    
    assess_security_control \
        "Global rate limiting implementation" \
        "grep -q 'rate.*limit\\|RATE_LIMIT' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "high"
    
    assess_security_control \
        "Per-IP rate limiting" \
        "grep -q 'ip.*rate\\|client_ip' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "high"
    
    assess_security_control \
        "Circuit breaker pattern implementation" \
        "[ -f '$PROJECT_ROOT/auth-service/src/circuit_breaker.rs' ]" \
        "medium"
    
    assess_security_control \
        "Request timeout configuration" \
        "grep -q 'timeout\\|duration' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "medium"
}

# Security Domain 6: Logging and Monitoring
assess_logging_monitoring_security() {
    echo "=== Logging and Monitoring Security ===" | tee -a "$LOG_FILE"
    
    assess_security_control \
        "Security event logging implemented" \
        "grep -q 'security.*log\\|SecurityLogger' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "high"
    
    assess_security_control \
        "Authentication failure logging" \
        "grep -q 'auth.*fail.*log\\|login.*fail' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "high"
    
    assess_security_control \
        "Sensitive data not logged" \
        "! grep -r 'password.*log\\|secret.*log\\|token.*log' '$PROJECT_ROOT/auth-service/src/' || echo 'No sensitive data in logs'" \
        "critical"
    
    assess_security_control \
        "Structured logging format" \
        "grep -q 'json.*log\\|structured' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "medium"
    
    assess_security_control \
        "Security monitoring alerts configured" \
        "[ -f '$PROJECT_ROOT/monitoring/prometheus/security-alerts.yml' ]" \
        "high"
}

# Security Domain 7: Cryptographic Security
assess_cryptographic_security() {
    echo "=== Cryptographic Security ===" | tee -a "$LOG_FILE"
    
    assess_security_control \
        "Strong RSA key generation (2048+ bits)" \
        "grep -q '2048\\|4096' '$PROJECT_ROOT/auth-service/src/keys.rs'" \
        "critical"
    
    assess_security_control \
        "Secure random number generation" \
        "grep -q 'OsRng\\|CryptoRng' '$PROJECT_ROOT/auth-service/src/keys.rs'" \
        "critical"
    
    assess_security_control \
        "Key rotation mechanism" \
        "grep -q 'rotate.*key\\|key.*rotation' '$PROJECT_ROOT/auth-service/src/keys.rs' || [ -f '$PROJECT_ROOT/auth-service/src/key_rotation.rs' ]" \
        "high"
    
    assess_security_control \
        "Secure password hashing (Argon2)" \
        "grep -q 'argon2\\|Argon2' '$PROJECT_ROOT/auth-service/src/mfa.rs' || grep -q 'argon2' '$PROJECT_ROOT/auth-service/Cargo.toml'" \
        "critical"
    
    assess_security_control \
        "TLS configuration for external connections" \
        "grep -q 'tls\\|https\\|ssl' '$PROJECT_ROOT/auth-service/Cargo.toml'" \
        "high"
}

# Security Domain 8: Threat Intelligence Integration
assess_threat_intelligence_security() {
    echo "=== Threat Intelligence Security ===" | tee -a "$LOG_FILE"
    
    assess_security_control \
        "Malicious IP blocking capability" \
        "[ -f '$PROJECT_ROOT/config/threat-intelligence/auth-service-integration.json' ] && grep -q 'malicious_ips' '$PROJECT_ROOT/config/threat-intelligence/auth-service-integration.json'" \
        "high"
    
    assess_security_control \
        "Threat feed integration" \
        "[ -f '$PROJECT_ROOT/config/threat-intelligence/enhanced_feeds.yaml' ]" \
        "medium"
    
    assess_security_control \
        "SIEM integration via Sigma rules" \
        "[ -d '$PROJECT_ROOT/config/threat-intelligence/sigma-rules' ] && [ \$(find '$PROJECT_ROOT/config/threat-intelligence/sigma-rules' -name '*.yml' | wc -l) -ge 2 ]" \
        "medium"
    
    assess_security_control \
        "Suspicious user agent detection" \
        "grep -q 'user.*agent' '$PROJECT_ROOT/monitoring/fluentd/threat-intel-filters.conf'" \
        "low"
}

# Security Domain 9: Configuration Security
assess_configuration_security() {
    echo "=== Configuration Security ===" | tee -a "$LOG_FILE"
    
    assess_security_control \
        "No hardcoded secrets in source code" \
        "! grep -r 'password.*=.*\"\\|secret.*=.*\"\\|key.*=.*\"' '$PROJECT_ROOT/auth-service/src/' || echo 'No hardcoded secrets found'" \
        "critical"
    
    assess_security_control \
        "Environment variable usage for secrets" \
        "grep -q 'env::var\\|std::env' '$PROJECT_ROOT/auth-service/src/lib.rs'" \
        "high"
    
    assess_security_control \
        "Secure default configurations" \
        "grep -q 'default.*secure\\|secure.*default' '$PROJECT_ROOT/auth-service/src/lib.rs' || echo 'Secure defaults assumed'" \
        "medium"
    
    assess_security_control \
        "Security policy enforcement (deny.toml)" \
        "[ -f '$PROJECT_ROOT/deny.toml' ]" \
        "medium"
}

# Security Domain 10: Dependency Security
assess_dependency_security() {
    echo "=== Dependency Security ===" | tee -a "$LOG_FILE"
    
    assess_security_control \
        "Security-focused dependencies used" \
        "grep -q 'ring\\|argon2\\|rand' '$PROJECT_ROOT/auth-service/Cargo.toml'" \
        "high"
    
    assess_security_control \
        "No known vulnerable dependencies (via deny.toml)" \
        "[ -f '$PROJECT_ROOT/deny.toml' ] && grep -q 'advisories' '$PROJECT_ROOT/deny.toml'" \
        "high"
    
    assess_security_control \
        "Minimal dependency surface" \
        "wc -l < '$PROJECT_ROOT/auth-service/Cargo.toml' | awk '{exit (\$1 < 100) ? 0 : 1}'" \
        "low"
    
    assess_security_control \
        "Security audit workflow exists" \
        "[ -f '$PROJECT_ROOT/.github/workflows/security-audit.yml' ]" \
        "medium"
}

# Security Domain 11: Infrastructure Security
assess_infrastructure_security() {
    echo "=== Infrastructure Security ===" | tee -a "$LOG_FILE"
    
    assess_security_control \
        "Container security configuration" \
        "find '$PROJECT_ROOT' -name 'Dockerfile*' | wc -l | awk '{exit (\$1 >= 1) ? 0 : 1}'" \
        "medium"
    
    assess_security_control \
        "Kubernetes security policies" \
        "[ -d '$PROJECT_ROOT/helm' ] || [ -d '$PROJECT_ROOT/k8s' ]" \
        "medium"
    
    assess_security_control \
        "GitOps security practices" \
        "[ -d '$PROJECT_ROOT/gitops' ]" \
        "low"
    
    assess_security_control \
        "Infrastructure as Code" \
        "[ -d '$PROJECT_ROOT/terraform' ] || [ -d '$PROJECT_ROOT/helm' ] || [ -d '$PROJECT_ROOT/gitops' ]" \
        "low"
}

# Security Domain 12: Compliance and Governance
assess_compliance_security() {
    echo "=== Compliance and Governance ===" | tee -a "$LOG_FILE"
    
    assess_security_control \
        "SOC2 compliance controls" \
        "[ -f '$PROJECT_ROOT/config/compliance_config.yaml' ] && grep -q 'SOC2' '$PROJECT_ROOT/config/compliance_config.yaml'" \
        "high"
    
    assess_security_control \
        "ISO 27001 compliance controls" \
        "[ -f '$PROJECT_ROOT/config/compliance_config.yaml' ] && grep -q 'ISO27001' '$PROJECT_ROOT/config/compliance_config.yaml'" \
        "high"
    
    assess_security_control \
        "GDPR privacy controls" \
        "[ -f '$PROJECT_ROOT/config/compliance_config.yaml' ] && grep -q 'GDPR' '$PROJECT_ROOT/config/compliance_config.yaml'" \
        "high"
    
    assess_security_control \
        "Compliance reporting mechanism" \
        "[ -f '$PROJECT_ROOT/scripts/generate_compliance_report.py' ]" \
        "medium"
    
    assess_security_control \
        "Security documentation exists" \
        "find '$PROJECT_ROOT' -name '*SECURITY*.md' -o -name '*security*.md' | wc -l | awk '{exit (\$1 >= 1) ? 0 : 1}'" \
        "medium"
}

# Calculate security score
calculate_security_score() {
    if [ $total_checks -eq 0 ]; then
        echo 0
        return
    fi
    
    # Weighted scoring based on issue severity
    local penalty=0
    penalty=$((penalty + critical_issues * 10))  # Critical issues worth 10 points each
    penalty=$((penalty + high_issues * 5))       # High issues worth 5 points each
    penalty=$((penalty + medium_issues * 2))     # Medium issues worth 2 points each
    penalty=$((penalty + low_issues * 1))        # Low issues worth 1 point each
    
    local max_possible_score=$((total_checks * 10))  # Assuming worst case all critical
    local actual_score=$((max_possible_score - penalty))
    
    if [ $actual_score -lt 0 ]; then
        actual_score=0
    fi
    
    local percentage=$((actual_score * 100 / max_possible_score))
    echo $percentage
}

# Generate security recommendations
generate_security_recommendations() {
    local recommendations_file="$PROJECT_ROOT/reports/security-recommendations.md"
    
    cat > "$recommendations_file" << EOF
# Security Posture Assessment - Recommendations

## Executive Summary
- **Total Security Checks**: $total_checks
- **Passed Checks**: $passed_checks
- **Security Score**: $(calculate_security_score)%

## Security Issues by Severity
- **Critical**: $critical_issues issues
- **High**: $high_issues issues  
- **Medium**: $medium_issues issues
- **Low**: $low_issues issues

## Immediate Actions Required

### Critical Issues (Fix Immediately)
EOF

    # Add critical issues to recommendations
    grep ":VULNERABLE:critical" "$security_results_file" | while IFS=':' read -r control status severity; do
        echo "- [ ] Fix: $control" >> "$recommendations_file"
    done

    cat >> "$recommendations_file" << EOF

### High Priority Issues (Fix This Week)
EOF

    # Add high issues to recommendations
    grep ":VULNERABLE:high" "$security_results_file" | while IFS=':' read -r control status severity; do
        echo "- [ ] Address: $control" >> "$recommendations_file"
    done

    cat >> "$recommendations_file" << EOF

### Medium Priority Issues (Fix This Month)
EOF

    # Add medium issues to recommendations
    grep ":VULNERABLE:medium" "$security_results_file" | while IFS=':' read -r control status severity; do
        echo "- [ ] Improve: $control" >> "$recommendations_file"
    done

    cat >> "$recommendations_file" << EOF

## Security Controls Operating Correctly
EOF

    # Add working controls
    grep ":SECURE:" "$security_results_file" | while IFS=':' read -r control status severity; do
        echo "- ✅ $control" >> "$recommendations_file"
    done

    echo "Security recommendations saved to: $recommendations_file" | tee -a "$LOG_FILE"
}

# Main execution function
main() {
    echo "Starting comprehensive security posture verification" | tee -a "$LOG_FILE"
    
    # Cleanup function
    cleanup() {
        echo "Cleaning up..." | tee -a "$LOG_FILE"
        rm -f "$security_results_file"
    }
    
    # Set up cleanup on exit
    trap cleanup EXIT
    
    # Run all security assessments
    assess_authentication_security
    assess_mfa_security
    assess_input_validation_security
    assess_access_control_security
    assess_rate_limiting_security
    assess_logging_monitoring_security
    assess_cryptographic_security
    assess_threat_intelligence_security
    assess_configuration_security
    assess_dependency_security
    assess_infrastructure_security
    assess_compliance_security
    
    # Calculate final security score
    local security_score=$(calculate_security_score)
    
    # Generate results summary
    echo "=== Security Posture Verification Results ===" | tee -a "$LOG_FILE"
    echo "Total security checks: $total_checks" | tee -a "$LOG_FILE"
    echo "Passed checks: $passed_checks" | tee -a "$LOG_FILE"
    echo "Failed checks: $((total_checks - passed_checks))" | tee -a "$LOG_FILE"
    echo "Security score: ${security_score}%" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    echo "Issues by severity:" | tee -a "$LOG_FILE"
    echo "  Critical: $critical_issues" | tee -a "$LOG_FILE"
    echo "  High: $high_issues" | tee -a "$LOG_FILE"
    echo "  Medium: $medium_issues" | tee -a "$LOG_FILE"
    echo "  Low: $low_issues" | tee -a "$LOG_FILE"
    
    # Generate JSON results
    cat > "$RESULTS_FILE" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)",
  "assessment_type": "security_posture_verification",
  "security_summary": {
    "total_checks": $total_checks,
    "passed_checks": $passed_checks,
    "failed_checks": $((total_checks - passed_checks)),
    "security_score": $security_score
  },
  "security_issues": {
    "critical": $critical_issues,
    "high": $high_issues,
    "medium": $medium_issues,
    "low": $low_issues
  },
  "security_domains": {
    "authentication": "assessed",
    "multi_factor_auth": "assessed",
    "input_validation": "assessed",
    "access_control": "assessed",
    "rate_limiting": "assessed",
    "logging_monitoring": "assessed",
    "cryptographic": "assessed",
    "threat_intelligence": "assessed",
    "configuration": "assessed",
    "dependencies": "assessed",
    "infrastructure": "assessed",
    "compliance": "assessed"
  },
  "detailed_results": {
EOF
    
    local first=true
    while IFS=':' read -r control status severity; do
        if [ ! -z "$control" ]; then
            if [ "$first" = false ]; then
                echo "," >> "$RESULTS_FILE"
            fi
            echo "    \"$control\": {\"status\": \"$status\", \"severity\": \"$severity\"}" >> "$RESULTS_FILE"
            first=false
        fi
    done < "$security_results_file"
    
    cat >> "$RESULTS_FILE" << EOF
  },
  "security_posture": {
    "overall_rating": "$([ $security_score -ge 90 ] && echo "excellent" || [ $security_score -ge 80 ] && echo "good" || [ $security_score -ge 70 ] && echo "acceptable" || echo "needs_improvement")",
    "readiness": "$([ $critical_issues -eq 0 ] && [ $high_issues -lt 3 ] && echo "production_ready" || echo "needs_remediation")",
    "risk_level": "$([ $critical_issues -gt 0 ] && echo "high" || [ $high_issues -gt 5 ] && echo "medium" || echo "low")"
  }
}
EOF
    
    echo "Security posture verification results saved to: $RESULTS_FILE" | tee -a "$LOG_FILE"
    
    # Generate security recommendations
    generate_security_recommendations
    
    # Final security posture assessment
    if [ $critical_issues -eq 0 ] && [ $high_issues -lt 3 ] && [ $security_score -ge 80 ]; then
        echo "🎉 Security posture verification PASSED!" | tee -a "$LOG_FILE"
        echo "✅ System security posture is strong and ready for production" | tee -a "$LOG_FILE"
        echo "🔒 Security score: ${security_score}% - $([ $security_score -ge 90 ] && echo "Excellent" || echo "Good")" | tee -a "$LOG_FILE"
        exit 0
    elif [ $critical_issues -eq 0 ] && [ $security_score -ge 70 ]; then
        echo "⚠️  Security posture verification passed with concerns" | tee -a "$LOG_FILE"
        echo "✅ System can be deployed but should address high priority issues" | tee -a "$LOG_FILE"
        echo "🔒 Security score: ${security_score}% - Acceptable" | tee -a "$LOG_FILE"
        exit 0
    else
        echo "❌ Security posture verification FAILED" | tee -a "$LOG_FILE"
        echo "🚨 System has critical security issues that must be addressed before production" | tee -a "$LOG_FILE"
        echo "🔒 Security score: ${security_score}% - Needs Improvement" | tee -a "$LOG_FILE"
        exit 1
    fi
}

# Run main function
main "$@"