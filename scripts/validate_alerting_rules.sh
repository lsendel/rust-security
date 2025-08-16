#!/bin/bash

# Script to validate Prometheus alerting rules
# This script validates the syntax and configuration of security alerting rules

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MONITORING_DIR="$PROJECT_ROOT/monitoring"
PROMETHEUS_DIR="$MONITORING_DIR/prometheus"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 Validating Prometheus Alerting Rules${NC}"
echo "=============================================="

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to validate YAML syntax
validate_yaml_syntax() {
    local file="$1"
    echo -e "\n${YELLOW}📝 Validating YAML syntax for $file${NC}"
    
    if command_exists python3; then
        python3 -c "
import yaml
import sys
try:
    with open('$file', 'r') as f:
        yaml.safe_load(f)
    print('✅ YAML syntax is valid')
except yaml.YAMLError as e:
    print(f'❌ YAML syntax error: {e}')
    sys.exit(1)
except FileNotFoundError:
    print('❌ File not found: $file')
    sys.exit(1)
"
    else
        echo "⚠️  Python3 not available, skipping YAML syntax validation"
    fi
}

# Function to validate Prometheus rule syntax using promtool if available
validate_prometheus_rules() {
    local file="$1"
    echo -e "\n${YELLOW}🔧 Validating Prometheus rule syntax for $file${NC}"
    
    if command_exists promtool; then
        if promtool check rules "$file"; then
            echo -e "${GREEN}✅ Prometheus rules syntax is valid${NC}"
        else
            echo -e "${RED}❌ Prometheus rules syntax validation failed${NC}"
            return 1
        fi
    else
        echo "⚠️  promtool not available, performing basic validation"
        
        # Basic validation - check for required fields
        if grep -q "groups:" "$file" && \
           grep -q "name:" "$file" && \
           grep -q "rules:" "$file" && \
           grep -q "alert:" "$file" && \
           grep -q "expr:" "$file"; then
            echo -e "${GREEN}✅ Basic structure validation passed${NC}"
        else
            echo -e "${RED}❌ Missing required Prometheus rule fields${NC}"
            return 1
        fi
    fi
}

# Function to validate alert coverage
validate_alert_coverage() {
    local file="$1"
    echo -e "\n${YELLOW}📊 Validating alert coverage${NC}"
    
    # Check for critical security metrics
    local critical_metrics=(
        "token_binding_violations"
        "auth_failures"
        "request_signature_failures"
        "suspicious_activity"
        "rate_limit_hits"
        "input_validation_failures"
        "mfa_failures"
    )
    
    local missing_metrics=()
    
    for metric in "${critical_metrics[@]}"; do
        if ! grep -q "$metric" "$file"; then
            missing_metrics+=("$metric")
        fi
    done
    
    if [ ${#missing_metrics[@]} -eq 0 ]; then
        echo -e "${GREEN}✅ All critical security metrics are covered${NC}"
    else
        echo -e "${YELLOW}⚠️  Missing coverage for metrics: ${missing_metrics[*]}${NC}"
    fi
    
    # Count alert rules by severity
    local critical_count=$(grep -c 'severity: critical' "$file" || echo "0")
    local high_count=$(grep -c 'severity: high' "$file" || echo "0")
    local medium_count=$(grep -c 'severity: medium' "$file" || echo "0")
    
    echo -e "\n📈 Alert Distribution:"
    echo -e "  Critical: ${RED}$critical_count${NC}"
    echo -e "  High:     ${YELLOW}$high_count${NC}"
    echo -e "  Medium:   ${BLUE}$medium_count${NC}"
}

# Function to validate alert annotations
validate_alert_annotations() {
    local file="$1"
    echo -e "\n${YELLOW}📋 Validating alert annotations${NC}"
    
    # Check that all alerts have required annotations
    local alerts_without_summary=$(awk '/^  - alert:/{alert=1; summary=0; description=0; runbook=0; next} 
                                      /^  - alert:|^- name:/{if(alert && !summary) print prev_alert} 
                                      /summary:/{summary=1} 
                                      /description:/{description=1} 
                                      /runbook_url:/{runbook=1} 
                                      /^  - alert:/{prev_alert=$0}' "$file")
    
    if [ -z "$alerts_without_summary" ]; then
        echo -e "${GREEN}✅ All alerts have proper annotations${NC}"
    else
        echo -e "${YELLOW}⚠️  Some alerts may be missing annotations${NC}"
    fi
}

# Function to validate SLA thresholds
validate_sla_thresholds() {
    local file="$1"
    echo -e "\n${YELLOW}📏 Validating SLA thresholds${NC}"
    
    # Check for reasonable thresholds
    local unreasonable_thresholds=()
    
    # Authentication failure rate check (should be reasonable, not too low)
    if grep -q "rate.*auth_failures.*> 100" "$file"; then
        unreasonable_thresholds+=("auth_failures threshold too high")
    fi
    
    # Response time thresholds
    if grep -q "histogram_quantile.*> 10" "$file"; then
        unreasonable_thresholds+=("response time threshold too high")
    fi
    
    if [ ${#unreasonable_thresholds[@]} -eq 0 ]; then
        echo -e "${GREEN}✅ SLA thresholds appear reasonable${NC}"
    else
        echo -e "${YELLOW}⚠️  Potential threshold issues: ${unreasonable_thresholds[*]}${NC}"
    fi
}

# Function to test rule evaluation (mock test)
test_rule_evaluation() {
    echo -e "\n${YELLOW}🧪 Testing rule evaluation logic${NC}"
    
    # This would ideally connect to a Prometheus instance
    # For now, we'll do syntax validation of expressions
    
    local invalid_expressions=()
    
    # Extract expressions and check for common issues
    while IFS= read -r expr; do
        # Check for common PromQL issues
        if [[ "$expr" =~ rate.*[^[].*] && ! "$expr" =~ rate.*\[.*\] ]]; then
            invalid_expressions+=("Missing time range in rate(): $expr")
        fi
        
        if [[ "$expr" =~ histogram_quantile.*rate && ! "$expr" =~ _bucket ]]; then
            invalid_expressions+=("histogram_quantile without _bucket: $expr")
        fi
    done < <(grep -o 'expr: .*' "$PROMETHEUS_DIR/security-alerts.yml" | sed 's/expr: //')
    
    if [ ${#invalid_expressions[@]} -eq 0 ]; then
        echo -e "${GREEN}✅ PromQL expressions appear valid${NC}"
    else
        echo -e "${YELLOW}⚠️  Potential PromQL issues:${NC}"
        for issue in "${invalid_expressions[@]}"; do
            echo -e "    • $issue"
        done
    fi
}

# Main validation function
main() {
    local exit_code=0
    
    echo -e "📍 Project root: $PROJECT_ROOT"
    echo -e "📍 Monitoring directory: $MONITORING_DIR"
    
    # Check if monitoring directory exists
    if [ ! -d "$MONITORING_DIR" ]; then
        echo -e "${RED}❌ Monitoring directory not found: $MONITORING_DIR${NC}"
        exit 1
    fi
    
    # Check if Prometheus alerting rules exist
    local rules_file="$PROMETHEUS_DIR/security-alerts.yml"
    if [ ! -f "$rules_file" ]; then
        echo -e "${RED}❌ Alerting rules file not found: $rules_file${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Found alerting rules file: $rules_file${NC}"
    
    # Run all validations
    validate_yaml_syntax "$rules_file" || exit_code=1
    validate_prometheus_rules "$rules_file" || exit_code=1
    validate_alert_coverage "$rules_file"
    validate_alert_annotations "$rules_file"
    validate_sla_thresholds "$rules_file"
    test_rule_evaluation
    
    echo -e "\n=============================================="
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}🎉 All alerting rule validations passed!${NC}"
        echo -e "${GREEN}✅ Security alerting rules are properly configured${NC}"
    else
        echo -e "${RED}❌ Some validations failed${NC}"
        echo -e "${YELLOW}📝 Please review and fix the issues above${NC}"
    fi
    
    return $exit_code
}

# Run main function
main "$@"