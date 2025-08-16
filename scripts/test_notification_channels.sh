#!/bin/bash

# Script to test Alertmanager notification channel configuration
# This script validates the alertmanager configuration and can send test alerts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ALERTMANAGER_DIR="$PROJECT_ROOT/monitoring/alertmanager"
ALERTMANAGER_CONFIG="$ALERTMANAGER_DIR/alertmanager.yml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔔 Testing Alertmanager Notification Channels${NC}"
echo "=================================================="

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to validate YAML syntax
validate_alertmanager_config() {
    echo -e "\n${YELLOW}📝 Validating Alertmanager configuration syntax${NC}"
    
    if [ ! -f "$ALERTMANAGER_CONFIG" ]; then
        echo -e "${RED}❌ Alertmanager config not found: $ALERTMANAGER_CONFIG${NC}"
        return 1
    fi
    
    if command_exists python3; then
        if python3 -c "
import yaml
try:
    with open('$ALERTMANAGER_CONFIG', 'r') as f:
        yaml.safe_load(f)
    print('✅ YAML syntax is valid')
except yaml.YAMLError as e:
    print(f'❌ YAML syntax error: {e}')
    exit(1)
"; then
            echo -e "${GREEN}✅ Alertmanager configuration syntax is valid${NC}"
        else
            echo -e "${RED}❌ Configuration syntax validation failed${NC}"
            return 1
        fi
    else
        echo "⚠️  Python3 not available, skipping YAML validation"
    fi
}

# Function to check configuration structure
check_config_structure() {
    echo -e "\n${YELLOW}🏗️  Checking configuration structure${NC}"
    
    local config_checks=(
        "route:"
        "receivers:"
        "global:"
        "inhibit_rules:"
        "time_intervals:"
    )
    
    local missing_sections=()
    
    for section in "${config_checks[@]}"; do
        if ! grep -q "^$section" "$ALERTMANAGER_CONFIG"; then
            missing_sections+=("$section")
        fi
    done
    
    if [ ${#missing_sections[@]} -eq 0 ]; then
        echo -e "${GREEN}✅ All required configuration sections present${NC}"
    else
        echo -e "${YELLOW}⚠️  Missing sections: ${missing_sections[*]}${NC}"
    fi
}

# Function to validate receivers
validate_receivers() {
    echo -e "\n${YELLOW}📬 Validating notification receivers${NC}"
    
    local expected_receivers=(
        "security-critical"
        "ops-critical" 
        "compliance-team"
        "security-high"
        "ops-high"
        "sla-notifications"
        "business-hours"
        "default"
    )
    
    local missing_receivers=()
    
    for receiver in "${expected_receivers[@]}"; do
        if ! grep -q "name: '$receiver'" "$ALERTMANAGER_CONFIG"; then
            missing_receivers+=("$receiver")
        fi
    done
    
    if [ ${#missing_receivers[@]} -eq 0 ]; then
        echo -e "${GREEN}✅ All expected receivers are configured${NC}"
    else
        echo -e "${YELLOW}⚠️  Missing receivers: ${missing_receivers[*]}${NC}"
    fi
    
    # Count notification types
    local slack_count=$(grep -c "slack_configs:" "$ALERTMANAGER_CONFIG" || echo "0")
    local email_count=$(grep -c "email_configs:" "$ALERTMANAGER_CONFIG" || echo "0")
    local webhook_count=$(grep -c "webhook_configs:" "$ALERTMANAGER_CONFIG" || echo "0")
    local pagerduty_count=$(grep -c "pagerduty_configs:" "$ALERTMANAGER_CONFIG" || echo "0")
    
    echo -e "\n📊 Notification Channel Distribution:"
    echo -e "  Slack:     ${BLUE}$slack_count${NC}"
    echo -e "  Email:     ${GREEN}$email_count${NC}"
    echo -e "  Webhook:   ${YELLOW}$webhook_count${NC}"
    echo -e "  PagerDuty: ${RED}$pagerduty_count${NC}"
}

# Function to check for placeholder values
check_placeholders() {
    echo -e "\n${YELLOW}🔍 Checking for placeholder values that need configuration${NC}"
    
    local placeholders=(
        "SLACK_WEBHOOK_URL"
        "SECURITY_CRITICAL_ROUTING_KEY"
        "OPS_CRITICAL_ROUTING_KEY"
        "SIEM_API_TOKEN"
        "COMPLIANCE_API_TOKEN"
        "company.com"
        "your-"
    )
    
    local found_placeholders=()
    
    for placeholder in "${placeholders[@]}"; do
        if grep -q "$placeholder" "$ALERTMANAGER_CONFIG"; then
            found_placeholders+=("$placeholder")
        fi
    done
    
    if [ ${#found_placeholders[@]} -eq 0 ]; then
        echo -e "${GREEN}✅ No placeholder values found - configuration appears customized${NC}"
    else
        echo -e "${YELLOW}⚠️  Found placeholder values that need configuration:${NC}"
        for placeholder in "${found_placeholders[@]}"; do
            echo -e "    • $placeholder"
        done
        echo -e "${YELLOW}📝 Please update these values with actual configuration${NC}"
    fi
}

# Function to validate routing rules
validate_routing() {
    echo -e "\n${YELLOW}🛣️  Validating alert routing rules${NC}"
    
    # Check for critical security routing
    if grep -A 5 "severity: critical" "$ALERTMANAGER_CONFIG" | grep -q "category: security"; then
        echo -e "${GREEN}✅ Critical security alert routing configured${NC}"
    else
        echo -e "${YELLOW}⚠️  Critical security alert routing may need review${NC}"
    fi
    
    # Check for business hours routing
    if grep -q "active_time_intervals:" "$ALERTMANAGER_CONFIG"; then
        echo -e "${GREEN}✅ Business hours routing configured${NC}"
    else
        echo -e "${YELLOW}⚠️  Business hours routing not configured${NC}"
    fi
    
    # Check for inhibition rules
    local inhibition_count=$(grep -c "source_matchers:" "$ALERTMANAGER_CONFIG" || echo "0")
    if [ "$inhibition_count" -gt 0 ]; then
        echo -e "${GREEN}✅ Alert inhibition rules configured ($inhibition_count rules)${NC}"
    else
        echo -e "${YELLOW}⚠️  No alert inhibition rules configured${NC}"
    fi
}

# Function to test amtool if available
test_amtool() {
    echo -e "\n${YELLOW}🔧 Testing with amtool (if available)${NC}"
    
    if command_exists amtool; then
        echo "Using amtool to validate configuration..."
        
        # Test configuration parsing
        if amtool config show --config.file="$ALERTMANAGER_CONFIG" >/dev/null 2>&1; then
            echo -e "${GREEN}✅ amtool configuration validation passed${NC}"
        else
            echo -e "${RED}❌ amtool configuration validation failed${NC}"
            return 1
        fi
        
        # Test routing for critical security alert
        echo "Testing routing for critical security alert..."
        local route_test=$(amtool config routes test \
            --config.file="$ALERTMANAGER_CONFIG" \
            severity=critical category=security service=auth-service 2>/dev/null || echo "")
        
        if [ -n "$route_test" ]; then
            echo -e "${GREEN}✅ Critical security alert routing test passed${NC}"
            echo "Route: $route_test"
        else
            echo -e "${YELLOW}⚠️  Could not test routing (amtool may need running Alertmanager)${NC}"
        fi
    else
        echo "amtool not available - install Alertmanager for advanced testing"
        echo "Download from: https://github.com/prometheus/alertmanager/releases"
    fi
}

# Function to create test alert payload
create_test_alert() {
    echo -e "\n${YELLOW}🧪 Creating test alert payload${NC}"
    
    local test_alert_file="/tmp/test_security_alert.json"
    
    cat > "$test_alert_file" << 'EOF'
[
  {
    "labels": {
      "alertname": "TestSecurityAlert",
      "severity": "critical", 
      "category": "security",
      "service": "auth-service",
      "instance": "test-instance"
    },
    "annotations": {
      "summary": "Test critical security alert for notification validation",
      "description": "This is a test alert to verify notification channels are properly configured",
      "runbook_url": "https://docs.company.com/runbooks/test-alert"
    },
    "startsAt": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "generatorURL": "http://prometheus:9090/graph?g0.expr=test_metric"
  }
]
EOF
    
    echo -e "${GREEN}✅ Test alert payload created: $test_alert_file${NC}"
    echo "To send this test alert (when Alertmanager is running):"
    echo "curl -H 'Content-Type: application/json' -d @$test_alert_file http://localhost:9093/api/v1/alerts"
}

# Function to check template files
check_templates() {
    echo -e "\n${YELLOW}📄 Checking template files${NC}"
    
    local template_dir="$ALERTMANAGER_DIR/templates"
    
    if [ -d "$template_dir" ]; then
        local template_count=$(find "$template_dir" -name "*.tmpl" | wc -l)
        echo -e "${GREEN}✅ Template directory exists with $template_count template files${NC}"
        
        # List template files
        find "$template_dir" -name "*.tmpl" | while read -r template; do
            echo "  • $(basename "$template")"
        done
    else
        echo -e "${YELLOW}⚠️  Template directory not found: $template_dir${NC}"
    fi
}

# Function to provide setup recommendations
provide_setup_recommendations() {
    echo -e "\n${BLUE}💡 Setup Recommendations${NC}"
    echo "========================================"
    
    echo -e "\n${YELLOW}1. Required Actions:${NC}"
    echo "   • Update placeholder webhook URLs with actual values"
    echo "   • Configure SMTP settings for email notifications"
    echo "   • Set up PagerDuty integration keys"
    echo "   • Replace example email addresses with real team addresses"
    
    echo -e "\n${YELLOW}2. Optional Improvements:${NC}"
    echo "   • Install amtool for advanced configuration testing"
    echo "   • Set up monitoring for Alertmanager itself"
    echo "   • Configure TLS for secure webhook communication"
    echo "   • Implement notification rate limiting if needed"
    
    echo -e "\n${YELLOW}3. Testing Steps:${NC}"
    echo "   • Start Alertmanager with the configuration"
    echo "   • Send test alerts to verify notification delivery"
    echo "   • Verify all team members receive notifications"
    echo "   • Test alert resolution notifications"
    
    echo -e "\n${YELLOW}4. Security Considerations:${NC}"
    echo "   • Secure API tokens and webhook URLs"
    echo "   • Restrict network access to Alertmanager"
    echo "   • Monitor notification logs for anomalies"
    echo "   • Regularly rotate API tokens and credentials"
}

# Main function
main() {
    local exit_code=0
    
    echo -e "📍 Project root: $PROJECT_ROOT"
    echo -e "📍 Alertmanager directory: $ALERTMANAGER_DIR"
    
    # Run all validation checks
    validate_alertmanager_config || exit_code=1
    check_config_structure
    validate_receivers
    check_placeholders
    validate_routing
    check_templates
    test_amtool
    create_test_alert
    provide_setup_recommendations
    
    echo -e "\n=================================================="
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}🎉 Notification channel configuration validation completed!${NC}"
        echo -e "${GREEN}✅ Alertmanager configuration is structurally sound${NC}"
        echo -e "${YELLOW}📝 Remember to update placeholder values with actual configuration${NC}"
    else
        echo -e "${RED}❌ Some validation checks failed${NC}"
        echo -e "${YELLOW}📝 Please review and fix the issues above${NC}"
    fi
    
    return $exit_code
}

# Run main function
main "$@"