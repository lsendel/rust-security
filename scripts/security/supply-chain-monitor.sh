#!/bin/bash
# Supply Chain Security Monitoring Script
# Comprehensive monitoring and alerting for supply chain security

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_FILE="${PROJECT_ROOT}/logs/supply-chain-security.log"
METRICS_FILE="${PROJECT_ROOT}/logs/security-metrics.json"
ALERT_THRESHOLD_CRITICAL=1
ALERT_THRESHOLD_HIGH=5

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo -e "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_success() { log "SUCCESS" "$@"; }

# Initialize directories
setup_monitoring() {
    log_info "Setting up supply chain security monitoring..."
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$METRICS_FILE")"
}

# Dependency vulnerability scanning
scan_dependencies() {
    log_info "Starting dependency vulnerability scan..."
    
    local vulnerabilities=0
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0
    
    cd "$PROJECT_ROOT"
    
    # Cargo audit scan
    log_info "Running cargo audit..."
    if cargo audit --json > /tmp/audit-results.json 2>/dev/null; then
        log_success "Cargo audit completed successfully"
    else
        log_warn "Cargo audit found vulnerabilities"
        vulnerabilities=$(jq '.vulnerabilities | length' /tmp/audit-results.json 2>/dev/null || echo "0")
        
        # Count by severity
        critical_count=$(jq '[.vulnerabilities[] | select(.advisory.severity == "critical")] | length' /tmp/audit-results.json 2>/dev/null || echo "0")
        high_count=$(jq '[.vulnerabilities[] | select(.advisory.severity == "high")] | length' /tmp/audit-results.json 2>/dev/null || echo "0")
        medium_count=$(jq '[.vulnerabilities[] | select(.advisory.severity == "medium")] | length' /tmp/audit-results.json 2>/dev/null || echo "0")
        low_count=$(jq '[.vulnerabilities[] | select(.advisory.severity == "low")] | length' /tmp/audit-results.json 2>/dev/null || echo "0")
    fi
    
    # Report results
    log_info "Vulnerability scan results:"
    log_info "  Total vulnerabilities: $vulnerabilities"
    log_info "  Critical: $critical_count"
    log_info "  High: $high_count" 
    log_info "  Medium: $medium_count"
    log_info "  Low: $low_count"
    
    # Alert on critical/high vulnerabilities
    if [ "$critical_count" -ge "$ALERT_THRESHOLD_CRITICAL" ]; then
        send_alert "CRITICAL" "Found $critical_count critical vulnerabilities"
    fi
    
    if [ "$high_count" -ge "$ALERT_THRESHOLD_HIGH" ]; then
        send_alert "HIGH" "Found $high_count high severity vulnerabilities"
    fi
    
    # Store metrics
    store_metrics "dependency_scan" "$vulnerabilities" "$critical_count" "$high_count" "$medium_count" "$low_count"
}

# Store security metrics
store_metrics() {
    local scan_type=$1
    local total_issues=$2
    local critical=$3
    local high=$4
    local medium=$5
    local low=$6
    
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    local metrics=$(cat <<METRICS_EOF
{
  "timestamp": "$timestamp",
  "scan_type": "$scan_type",
  "metrics": {
    "total_issues": $total_issues,
    "critical": $critical,
    "high": $high,
    "medium": $medium,
    "low": $low
  }
}
METRICS_EOF
)
    
    echo "$metrics" >> "$METRICS_FILE"
}

# Send security alerts
send_alert() {
    local severity=$1
    local message=$2
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    log_error "SECURITY ALERT [$severity]: $message"
    
    # Store alert
    local alert=$(cat <<ALERT_EOF
{
  "timestamp": "$timestamp",
  "severity": "$severity",
  "message": "$message",
  "repository": "$(git remote get-url origin 2>/dev/null || echo 'unknown')",
  "commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
}
ALERT_EOF
)
    
    echo "$alert" >> "${PROJECT_ROOT}/logs/security-alerts.json"
}

# Main execution function
main() {
    echo -e "${BLUE}Supply Chain Security Monitor${NC}"
    echo -e "${BLUE}=============================${NC}"
    
    setup_monitoring
    
    log_info "Starting comprehensive supply chain security scan..."
    
    # Core security scans
    scan_dependencies
    
    log_success "Supply chain security scan completed"
    
    # Summary
    echo -e "\n${GREEN}Security Scan Summary:${NC}"
    echo -e "  📊 Metrics logged to: $METRICS_FILE"
    echo -e "  📋 Detailed logs: $LOG_FILE"
    
    if [ -f "${PROJECT_ROOT}/logs/security-alerts.json" ]; then
        local alert_count=$(wc -l < "${PROJECT_ROOT}/logs/security-alerts.json" 2>/dev/null || echo "0")
        if [ "$alert_count" -gt 0 ]; then
            echo -e "  🚨 ${RED}$alert_count security alerts generated${NC}"
        fi
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
