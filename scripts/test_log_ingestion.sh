#!/bin/bash

# Script to test the log ingestion pipeline for the Rust Security Workspace
# This script validates the flow: Auth Service → Fluentd → Elasticsearch

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
FLUENTD_HOST="${FLUENTD_HOST:-localhost}"
FLUENTD_PORT="${FLUENTD_PORT:-24224}"
ELASTICSEARCH_HOST="${ELASTICSEARCH_HOST:-localhost}"
ELASTICSEARCH_PORT="${ELASTICSEARCH_PORT:-9200}"
ELASTICSEARCH_SCHEME="${ELASTICSEARCH_SCHEME:-http}"
AUTH_SERVICE_HOST="${AUTH_SERVICE_HOST:-localhost}"
AUTH_SERVICE_PORT="${AUTH_SERVICE_PORT:-8080}"

echo -e "${BLUE}🔍 Testing Log Ingestion Pipeline${NC}"
echo "======================================"
echo -e "📍 Auth Service: http://${AUTH_SERVICE_HOST}:${AUTH_SERVICE_PORT}"
echo -e "📍 Fluentd: ${FLUENTD_HOST}:${FLUENTD_PORT}"
echo -e "📍 Elasticsearch: ${ELASTICSEARCH_SCHEME}://${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}"

# Function to check if a service is available
check_service() {
    local service_name="$1"
    local host="$2"
    local port="$3"
    local protocol="${4:-http}"
    
    echo -e "\n${YELLOW}🔍 Checking $service_name connectivity${NC}"
    
    if [ "$protocol" = "tcp" ]; then
        if timeout 5 bash -c "</dev/tcp/$host/$port" 2>/dev/null; then
            echo -e "${GREEN}✅ $service_name is available at $host:$port${NC}"
            return 0
        else
            echo -e "${RED}❌ $service_name is not available at $host:$port${NC}"
            return 1
        fi
    else
        if curl -s -f "${protocol}://${host}:${port}/health" >/dev/null 2>&1 || \
           curl -s -f "${protocol}://${host}:${port}/_cluster/health" >/dev/null 2>&1; then
            echo -e "${GREEN}✅ $service_name is available${NC}"
            return 0
        else
            echo -e "${RED}❌ $service_name is not available${NC}"
            return 1
        fi
    fi
}

# Function to generate test security logs
generate_test_logs() {
    echo -e "\n${YELLOW}📝 Generating test security logs${NC}"
    
    # Create test log entries that will be processed by Fluentd
    local test_log_dir="/tmp/rust-security-test-logs"
    mkdir -p "$test_log_dir"
    
    # Generate security audit log
    local security_log="$test_log_dir/security-audit.log"
    cat > "$security_log" << EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)","level":"INFO","target":"security_audit","fields":{"event_id":"test-001","event_type":"authentication_attempt","severity":"medium","source":"auth-service","client_id":"test-client-001","ip_address":"192.168.1.100","user_agent":"TestAgent/1.0","outcome":"success","description":"Test authentication attempt for log ingestion validation"}}
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)","level":"WARN","target":"security_audit","fields":{"event_id":"test-002","event_type":"suspicious_activity","severity":"high","source":"auth-service","client_id":"test-client-002","ip_address":"10.0.0.50","user_agent":"SuspiciousAgent/1.0","outcome":"blocked","description":"Test suspicious activity for log ingestion validation","risk_score":75}}
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)","level":"ERROR","target":"security_audit","fields":{"event_id":"test-003","event_type":"token_binding_violation","severity":"critical","source":"auth-service","client_id":"test-client-003","ip_address":"203.0.113.10","outcome":"violation_detected","description":"Test token binding violation for log ingestion validation","risk_score":95}}
EOF
    
    # Generate application log
    local app_log="$test_log_dir/auth-service.log"
    cat > "$app_log" << EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)","level":"INFO","target":"auth_service","fields":{"message":"Test application log message","service":"auth-service","request_id":"req-test-001"}}
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)","level":"DEBUG","target":"auth_service","fields":{"message":"Test debug message for log ingestion","service":"auth-service","module":"token_validation"}}
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)","level":"ERROR","target":"auth_service","fields":{"message":"Test error message","service":"auth-service","error_type":"validation_error"}}
EOF
    
    echo -e "${GREEN}✅ Generated test logs:${NC}"
    echo -e "  Security audit: $security_log"
    echo -e "  Application: $app_log"
    
    echo "$test_log_dir"
}

# Function to send logs to Fluentd (if directly accessible)
send_logs_to_fluentd() {
    local test_log_dir="$1"
    
    echo -e "\n${YELLOW}📤 Sending test logs to Fluentd${NC}"
    
    # Try to send logs directly to Fluentd using fluent-cat if available
    if command -v fluent-cat >/dev/null 2>&1; then
        echo "Using fluent-cat to send test logs..."
        
        # Send security audit logs
        cat "$test_log_dir/security-audit.log" | fluent-cat security.audit --host "$FLUENTD_HOST" --port "$FLUENTD_PORT" || true
        
        # Send application logs
        cat "$test_log_dir/auth-service.log" | fluent-cat auth.service --host "$FLUENTD_HOST" --port "$FLUENTD_PORT" || true
        
        echo -e "${GREEN}✅ Sent test logs to Fluentd${NC}"
    else
        echo -e "${YELLOW}⚠️  fluent-cat not available, skipping direct Fluentd test${NC}"
        echo -e "Install fluent-cat with: gem install fluentd"
    fi
}

# Function to trigger log generation via auth service
trigger_auth_service_logs() {
    echo -e "\n${YELLOW}🚀 Triggering log generation via auth service${NC}"
    
    if ! check_service "Auth Service" "$AUTH_SERVICE_HOST" "$AUTH_SERVICE_PORT" "http"; then
        echo -e "${YELLOW}⚠️  Auth service not available, skipping live log generation${NC}"
        return 1
    fi
    
    echo "Making test requests to generate logs..."
    
    # Test health endpoint (should generate application logs)
    curl -s "http://${AUTH_SERVICE_HOST}:${AUTH_SERVICE_PORT}/health" >/dev/null || true
    
    # Test introspection with invalid token (should generate security logs)
    curl -s -X POST "http://${AUTH_SERVICE_HOST}:${AUTH_SERVICE_PORT}/oauth/introspect" \
         -H "Content-Type: application/json" \
         -H "X-Forwarded-For: 192.168.1.200" \
         -H "User-Agent: TestClient/1.0" \
         -d '{"token":"invalid-test-token-for-logging"}' >/dev/null || true
    
    # Test token endpoint with invalid credentials (should generate security logs)
    curl -s -X POST "http://${AUTH_SERVICE_HOST}:${AUTH_SERVICE_PORT}/oauth/token" \
         -H "Content-Type: application/x-www-form-urlencoded" \
         -H "X-Forwarded-For: 10.0.0.100" \
         -H "User-Agent: TestClient/1.0" \
         -d "grant_type=client_credentials&client_id=test-client&client_secret=invalid-secret" >/dev/null || true
    
    echo -e "${GREEN}✅ Generated logs via auth service requests${NC}"
}

# Function to wait for log processing
wait_for_log_processing() {
    echo -e "\n${YELLOW}⏳ Waiting for log processing (30 seconds)${NC}"
    sleep 30
}

# Function to verify logs in Elasticsearch
verify_elasticsearch_logs() {
    echo -e "\n${YELLOW}🔍 Verifying logs in Elasticsearch${NC}"
    
    if ! check_service "Elasticsearch" "$ELASTICSEARCH_HOST" "$ELASTICSEARCH_PORT" "$ELASTICSEARCH_SCHEME"; then
        echo -e "${YELLOW}⚠️  Elasticsearch not available, skipping verification${NC}"
        return 1
    fi
    
    local es_url="${ELASTICSEARCH_SCHEME}://${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}"
    
    # Check for security audit logs
    echo "Checking security audit logs..."
    local security_logs=$(curl -s "${es_url}/security-audit-*/_search?q=event_id:test-*" | jq -r '.hits.total.value // .hits.total' 2>/dev/null || echo "0")
    echo -e "  Security audit logs found: $security_logs"
    
    # Check for application logs  
    echo "Checking application logs..."
    local app_logs=$(curl -s "${es_url}/application-logs-*/_search?q=service:auth-service" | jq -r '.hits.total.value // .hits.total' 2>/dev/null || echo "0")
    echo -e "  Application logs found: $app_logs"
    
    # Check recent logs (last hour)
    local now=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
    local hour_ago=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S.000Z)
    local recent_logs=$(curl -s "${es_url}/*/_search" \
        -H "Content-Type: application/json" \
        -d "{
          \"query\": {
            \"range\": {
              \"timestamp\": {
                \"gte\": \"$hour_ago\",
                \"lte\": \"$now\"
              }
            }
          }
        }" | jq -r '.hits.total.value // .hits.total' 2>/dev/null || echo "0")
    echo -e "  Recent logs (last hour): $recent_logs"
    
    # Verify index health
    echo "Checking index health..."
    local indices_health=$(curl -s "${es_url}/_cat/indices?format=json" | jq -r '.[].health' 2>/dev/null | grep -v "green\|yellow" | wc -l || echo "0")
    if [ "$indices_health" -eq 0 ]; then
        echo -e "  ${GREEN}✅ All indices are healthy${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Some indices may have health issues${NC}"
    fi
}

# Function to check Fluentd metrics
check_fluentd_metrics() {
    echo -e "\n${YELLOW}📊 Checking Fluentd metrics${NC}"
    
    # Try to access Fluentd monitor endpoint
    if curl -s "http://${FLUENTD_HOST}:24220/api/plugins.json" >/dev/null 2>&1; then
        local buffer_queue_length=$(curl -s "http://${FLUENTD_HOST}:24220/api/plugins.json" | jq -r '.plugins[] | select(.type=="buffer") | .buffer_queue_length' 2>/dev/null | head -1 || echo "unknown")
        local retry_count=$(curl -s "http://${FLUENTD_HOST}:24220/api/plugins.json" | jq -r '.plugins[] | select(.type=="buffer") | .retry_count' 2>/dev/null | head -1 || echo "unknown")
        
        echo -e "  Buffer queue length: $buffer_queue_length"
        echo -e "  Retry count: $retry_count"
        echo -e "${GREEN}✅ Fluentd metrics accessible${NC}"
    else
        echo -e "${YELLOW}⚠️  Fluentd metrics not accessible at ${FLUENTD_HOST}:24220${NC}"
    fi
    
    # Try to access Prometheus metrics
    if curl -s "http://${FLUENTD_HOST}:24231/metrics" >/dev/null 2>&1; then
        local fluentd_metrics=$(curl -s "http://${FLUENTD_HOST}:24231/metrics" | grep -c "fluentd_" || echo "0")
        echo -e "  Prometheus metrics count: $fluentd_metrics"
        echo -e "${GREEN}✅ Fluentd Prometheus metrics accessible${NC}"
    else
        echo -e "${YELLOW}⚠️  Fluentd Prometheus metrics not accessible at ${FLUENTD_HOST}:24231${NC}"
    fi
}

# Function to test log retention policies
test_retention_policies() {
    echo -e "\n${YELLOW}📅 Testing log retention policies${NC}"
    
    if ! check_service "Elasticsearch" "$ELASTICSEARCH_HOST" "$ELASTICSEARCH_PORT" "$ELASTICSEARCH_SCHEME"; then
        echo -e "${YELLOW}⚠️  Elasticsearch not available, skipping retention policy test${NC}"
        return 1
    fi
    
    local es_url="${ELASTICSEARCH_SCHEME}://${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}"
    
    # Check ILM policies
    echo "Checking ILM policies..."
    local ilm_policies=$(curl -s "${es_url}/_ilm/policy" | jq -r 'keys[]' 2>/dev/null | wc -l || echo "0")
    echo -e "  ILM policies configured: $ilm_policies"
    
    # Check specific policies
    local policies=("security-audit-policy" "application-logs-policy" "system-logs-policy")
    for policy in "${policies[@]}"; do
        if curl -s "${es_url}/_ilm/policy/${policy}" | jq -e '.policy' >/dev/null 2>&1; then
            echo -e "  ${GREEN}✅ $policy exists${NC}"
        else
            echo -e "  ${RED}❌ $policy missing${NC}"
        fi
    done
}

# Function to generate test report
generate_test_report() {
    local test_log_dir="$1"
    
    echo -e "\n${BLUE}📋 Log Ingestion Test Report${NC}"
    echo "=============================="
    
    echo -e "\n${YELLOW}Test Configuration:${NC}"
    echo -e "  Auth Service: http://${AUTH_SERVICE_HOST}:${AUTH_SERVICE_PORT}"
    echo -e "  Fluentd: ${FLUENTD_HOST}:${FLUENTD_PORT}"
    echo -e "  Elasticsearch: ${ELASTICSEARCH_SCHEME}://${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}"
    
    echo -e "\n${YELLOW}Test Results Summary:${NC}"
    echo -e "  Test logs generated: ✅"
    echo -e "  Auth service logs triggered: ✅"
    echo -e "  Fluentd connectivity: ⚠️  (check required)"
    echo -e "  Elasticsearch verification: ⚠️  (check required)"
    echo -e "  Retention policies: ⚠️  (check required)"
    
    echo -e "\n${YELLOW}Recommendations:${NC}"
    echo -e "  1. Ensure all services are running before testing"
    echo -e "  2. Install fluent-cat for direct Fluentd testing: gem install fluentd"
    echo -e "  3. Monitor logs for 5-10 minutes after generation"
    echo -e "  4. Check Elasticsearch indices for new data"
    echo -e "  5. Verify ILM policies are applied correctly"
    
    echo -e "\n${YELLOW}Test artifacts:${NC}"
    echo -e "  Test logs directory: $test_log_dir"
    echo -e "  Clean up: rm -rf $test_log_dir"
}

# Function to clean up test artifacts
cleanup_test_artifacts() {
    local test_log_dir="$1"
    
    echo -e "\n${YELLOW}🧹 Cleaning up test artifacts${NC}"
    if [ -d "$test_log_dir" ]; then
        rm -rf "$test_log_dir"
        echo -e "${GREEN}✅ Cleaned up test logs directory${NC}"
    fi
}

# Main function
main() {
    local exit_code=0
    
    echo -e "📍 Project root: $PROJECT_ROOT"
    
    # Check dependencies
    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}❌ curl is required but not installed${NC}"
        exit 1
    fi
    
    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  jq not available, some features will be limited${NC}"
    fi
    
    # Generate test logs
    local test_log_dir
    test_log_dir=$(generate_test_logs)
    
    # Test the pipeline
    send_logs_to_fluentd "$test_log_dir"
    trigger_auth_service_logs
    wait_for_log_processing
    verify_elasticsearch_logs || true
    check_fluentd_metrics || true
    test_retention_policies || true
    
    # Generate report
    generate_test_report "$test_log_dir"
    
    # Clean up (optional)
    read -p "Clean up test artifacts? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cleanup_test_artifacts "$test_log_dir"
    fi
    
    echo -e "\n======================================"
    echo -e "${GREEN}🎉 Log ingestion pipeline test completed!${NC}"
    echo -e "${BLUE}📝 Review the results above and verify logs in Elasticsearch${NC}"
    
    return $exit_code
}

# Handle command line arguments
case "${1:-test}" in
    "test")
        main
        ;;
    "generate-only")
        test_log_dir=$(generate_test_logs)
        echo "Test logs generated in: $test_log_dir"
        ;;
    "verify-only")
        verify_elasticsearch_logs
        test_retention_policies
        ;;
    "help")
        echo "Usage: $0 [test|generate-only|verify-only|help]"
        echo "  test         - Run full pipeline test (default)"
        echo "  generate-only - Only generate test logs"
        echo "  verify-only  - Only verify existing logs in Elasticsearch"
        echo "  help         - Show this help message"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac