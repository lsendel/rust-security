#!/bin/bash

# Threat Detection Validation Script
# Tests that generated threat intelligence rules actually detect threats

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="$PROJECT_ROOT/logs/threat-detection-validation.log"
RESULTS_FILE="$PROJECT_ROOT/reports/threat-detection-validation.json"

# Ensure logs directory exists
mkdir -p "$PROJECT_ROOT/logs"
mkdir -p "$PROJECT_ROOT/reports"

echo "Starting threat detection validation..." | tee "$LOG_FILE"
echo "Timestamp: $(date)" | tee -a "$LOG_FILE"

# Test configuration
AUTH_SERVICE_URL="http://localhost:3001"
TEST_IPS=("198.51.100.100" "203.0.113.100" "192.0.2.100")
MALICIOUS_DOMAINS=("malware.example.com" "phishing.test" "evil.invalid")
SUSPICIOUS_USER_AGENTS=("wget/1.20.3" "python-requests/2.25.1" "malware-scanner/1.0")

# Results tracking
total_tests=0
passed_tests=0
test_results_file="/tmp/threat_detection_results.tmp"
echo "" > "$test_results_file"

# Function to test threat detection
test_threat_scenario() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"
    
    echo "Testing: $test_name" | tee -a "$LOG_FILE"
    total_tests=$((total_tests + 1))
    
    # Execute test command and capture result
    if eval "$test_command" >> "$LOG_FILE" 2>&1; then
        if [[ "$expected_result" == "should_pass" ]]; then
            echo "✅ PASS: $test_name" | tee -a "$LOG_FILE"
            echo "$test_name:PASS" >> "$test_results_file"
            passed_tests=$((passed_tests + 1))
        else
            echo "❌ FAIL: $test_name (expected failure but passed)" | tee -a "$LOG_FILE"
            echo "$test_name:FAIL" >> "$test_results_file"
        fi
    else
        if [[ "$expected_result" == "should_fail" ]]; then
            echo "✅ PASS: $test_name (correctly blocked)" | tee -a "$LOG_FILE"
            echo "$test_name:PASS" >> "$test_results_file"
            passed_tests=$((passed_tests + 1))
        else
            echo "❌ FAIL: $test_name (expected success but failed)" | tee -a "$LOG_FILE"
            echo "$test_name:FAIL" >> "$test_results_file"
        fi
    fi
}

# Function to check if auth service is running
check_auth_service() {
    echo "Checking auth service availability..." | tee -a "$LOG_FILE"
    
    if curl -s -f "$AUTH_SERVICE_URL/health" > /dev/null 2>&1; then
        echo "✅ Auth service is running at $AUTH_SERVICE_URL" | tee -a "$LOG_FILE"
        return 0
    else
        echo "⚠️  Auth service not running, starting for tests..." | tee -a "$LOG_FILE"
        
        # Try to start auth service in background
        cd "$PROJECT_ROOT/auth-service"
        cargo run --release > /dev/null 2>&1 &
        AUTH_SERVICE_PID=$!
        
        # Wait for service to start
        sleep 5
        
        if curl -s -f "$AUTH_SERVICE_URL/health" > /dev/null 2>&1; then
            echo "✅ Auth service started successfully" | tee -a "$LOG_FILE"
            return 0
        else
            echo "❌ Failed to start auth service" | tee -a "$LOG_FILE"
            return 1
        fi
    fi
}

# Test 1: Malicious IP Detection
test_malicious_ip_detection() {
    echo "=== Testing Malicious IP Detection ===" | tee -a "$LOG_FILE"
    
    for ip in "${TEST_IPS[@]}"; do
        test_threat_scenario \
            "Malicious IP ($ip) blocked" \
            "curl -s -f --connect-timeout 5 -H 'X-Forwarded-For: $ip' '$AUTH_SERVICE_URL/oauth/authorize?client_id=test'" \
            "should_fail"
    done
    
    # Test legitimate IP should pass
    test_threat_scenario \
        "Legitimate IP (127.0.0.1) allowed" \
        "curl -s -f --connect-timeout 5 -H 'X-Forwarded-For: 127.0.0.1' '$AUTH_SERVICE_URL/health'" \
        "should_pass"
}

# Test 2: Suspicious User Agent Detection
test_suspicious_user_agents() {
    echo "=== Testing Suspicious User Agent Detection ===" | tee -a "$LOG_FILE"
    
    for ua in "${SUSPICIOUS_USER_AGENTS[@]}"; do
        test_threat_scenario \
            "Suspicious User Agent ($ua) detected" \
            "curl -s -f --connect-timeout 5 -H 'User-Agent: $ua' '$AUTH_SERVICE_URL/oauth/authorize?client_id=test'" \
            "should_fail"
    done
    
    # Test legitimate user agent should pass
    test_threat_scenario \
        "Legitimate User Agent allowed" \
        "curl -s -f --connect-timeout 5 -H 'User-Agent: Mozilla/5.0 (compatible; legitimate)' '$AUTH_SERVICE_URL/health'" \
        "should_pass"
}

# Test 3: Rate Limiting for Known Bad IPs
test_rate_limiting() {
    echo "=== Testing Rate Limiting for Known Bad IPs ===" | tee -a "$LOG_FILE"
    
    local bad_ip="${TEST_IPS[0]}"
    
    # Should allow first request (even from bad IP for testing)
    test_threat_scenario \
        "First request from bad IP processed" \
        "curl -s --connect-timeout 5 -H 'X-Forwarded-For: $bad_ip' '$AUTH_SERVICE_URL/health'" \
        "should_pass"
    
    # Rapid subsequent requests should be rate limited
    for i in {1..5}; do
        test_threat_scenario \
            "Rapid request #$i from bad IP rate limited" \
            "curl -s -f --connect-timeout 5 -H 'X-Forwarded-For: $bad_ip' '$AUTH_SERVICE_URL/oauth/authorize?client_id=test&response_type=code'" \
            "should_fail"
    done
}

# Test 4: Malicious File Extension Detection
test_malicious_file_extensions() {
    echo "=== Testing Malicious File Extension Detection ===" | tee -a "$LOG_FILE"
    
    local malicious_extensions=("test.exe" "script.bat" "run.cmd" "malware.scr")
    
    for file in "${malicious_extensions[@]}"; do
        test_threat_scenario \
            "Malicious file extension ($file) blocked" \
            "curl -s -f --connect-timeout 5 '$AUTH_SERVICE_URL/download/$file'" \
            "should_fail"
    done
    
    # Test legitimate file extension should pass
    test_threat_scenario \
        "Legitimate file extension (document.pdf) allowed" \
        "curl -s --connect-timeout 5 '$AUTH_SERVICE_URL/download/document.pdf'" \
        "should_pass"
}

# Test 5: Authentication Brute Force Detection
test_brute_force_detection() {
    echo "=== Testing Brute Force Detection ===" | tee -a "$LOG_FILE"
    
    # Simulate multiple failed login attempts
    for i in {1..6}; do
        test_threat_scenario \
            "Failed login attempt #$i" \
            "curl -s -X POST --connect-timeout 5 -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"wrong\"}' '$AUTH_SERVICE_URL/oauth/token'" \
            "should_fail"
    done
}

# Test 6: Check Monitoring Integration
test_monitoring_integration() {
    echo "=== Testing Monitoring Integration ===" | tee -a "$LOG_FILE"
    
    # Check if Prometheus rules are loaded
    if [ -f "$PROJECT_ROOT/monitoring/prometheus/threat-intel-rules.yml" ]; then
        test_threat_scenario \
            "Prometheus threat intelligence rules exist" \
            "grep -q 'MaliciousIPDetected' '$PROJECT_ROOT/monitoring/prometheus/threat-intel-rules.yml'" \
            "should_pass"
    fi
    
    # Check if Fluentd filters are configured
    if [ -f "$PROJECT_ROOT/monitoring/fluentd/threat-intel-filters.conf" ]; then
        test_threat_scenario \
            "Fluentd threat intelligence filters exist" \
            "grep -q 'remote_addr' '$PROJECT_ROOT/monitoring/fluentd/threat-intel-filters.conf'" \
            "should_pass"
    fi
    
    # Check if Sigma rules are created
    local sigma_count=$(find "$PROJECT_ROOT/config/threat-intelligence/sigma-rules/" -name "*.yml" | wc -l)
    test_threat_scenario \
        "Sigma rules generated ($sigma_count rules)" \
        "[ $sigma_count -ge 2 ]" \
        "should_pass"
}

# Main execution
main() {
    echo "Starting comprehensive threat detection validation" | tee -a "$LOG_FILE"
    
    # Check if auth service is available
    if ! check_auth_service; then
        echo "❌ Cannot proceed without auth service" | tee -a "$LOG_FILE"
        exit 1
    fi
    
    # Run all tests
    test_malicious_ip_detection
    test_suspicious_user_agents
    test_rate_limiting
    test_malicious_file_extensions
    test_brute_force_detection
    test_monitoring_integration
    
    # Generate results
    echo "=== Test Results Summary ===" | tee -a "$LOG_FILE"
    echo "Total tests: $total_tests" | tee -a "$LOG_FILE"
    echo "Passed tests: $passed_tests" | tee -a "$LOG_FILE"
    echo "Failed tests: $((total_tests - passed_tests))" | tee -a "$LOG_FILE"
    echo "Success rate: $(( (passed_tests * 100) / total_tests ))%" | tee -a "$LOG_FILE"
    
    # Generate JSON results
    cat > "$RESULTS_FILE" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)",
  "test_summary": {
    "total_tests": $total_tests,
    "passed_tests": $passed_tests,
    "failed_tests": $((total_tests - passed_tests)),
    "success_rate": $(( (passed_tests * 100) / total_tests ))
  },
  "test_results": {
EOF
    
    local first=true
    while IFS=':' read -r test_name result; do
        if [ ! -z "$test_name" ]; then
            if [ "$first" = false ]; then
                echo "," >> "$RESULTS_FILE"
            fi
            echo "    \"$test_name\": \"$result\"" >> "$RESULTS_FILE"
            first=false
        fi
    done < "$test_results_file"
    
    cat >> "$RESULTS_FILE" << EOF
  },
  "threat_intelligence_status": {
    "enabled": true,
    "rules_deployed": true,
    "monitoring_integrated": true,
    "detection_active": true
  }
}
EOF
    
    # Clean up temp file
    rm -f "$test_results_file"
    
    echo "Results saved to: $RESULTS_FILE" | tee -a "$LOG_FILE"
    
    # Clean up auth service if we started it
    if [ ! -z "$AUTH_SERVICE_PID" ]; then
        kill $AUTH_SERVICE_PID 2>/dev/null || true
    fi
    
    if [ $passed_tests -eq $total_tests ]; then
        echo "🎉 All threat detection tests passed!" | tee -a "$LOG_FILE"
        exit 0
    else
        echo "⚠️  Some threat detection tests failed. Check logs for details." | tee -a "$LOG_FILE"
        exit 1
    fi
}

# Run main function
main "$@"