#!/bin/bash

# Threat Intelligence Updater for Rust Security Workspace
# This script continuously updates threat intelligence feeds and security rules

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$PROJECT_ROOT/config/threat-intelligence"
FEEDS_DIR="$CONFIG_DIR/feeds"
RULES_DIR="$CONFIG_DIR/rules"
LOG_FILE="$PROJECT_ROOT/logs/threat-intelligence-updater.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging function
log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[$timestamp]${NC} $message" | tee -a "$LOG_FILE"
}

error() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[$timestamp ERROR]${NC} $message" | tee -a "$LOG_FILE" >&2
}

warning() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[$timestamp WARNING]${NC} $message" | tee -a "$LOG_FILE"
}

success() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[$timestamp SUCCESS]${NC} $message" | tee -a "$LOG_FILE"
}

# Create necessary directories
setup_directories() {
    log "Setting up threat intelligence directories..."
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$FEEDS_DIR"
    mkdir -p "$RULES_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
    
    success "Directories created successfully"
}

# Download threat intelligence feeds
update_threat_feeds() {
    log "Updating threat intelligence feeds..."
    
    # Malware domain blocklist
    log "Downloading malware domain blocklist..."
    if curl -s -o "$FEEDS_DIR/malware_domains.txt" \
        "https://mirror1.malwaredomains.com/files/justdomains"; then
        success "Malware domains updated"
    else
        error "Failed to download malware domains"
    fi
    
    # Abuse.ch URLhaus
    log "Downloading URLhaus malware URLs..."
    if curl -s -o "$FEEDS_DIR/urlhaus_urls.txt" \
        "https://urlhaus.abuse.ch/downloads/text/"; then
        success "URLhaus URLs updated"
    else
        error "Failed to download URLhaus URLs"
    fi
    
    # Emerging Threats rules (if available)
    log "Downloading Emerging Threats rules..."
    if curl -s -o "$FEEDS_DIR/emerging_threats.rules" \
        "https://rules.emergingthreats.net/open/suricata/rules/emerging-all.rules"; then
        success "Emerging Threats rules updated"
    else
        warning "Failed to download Emerging Threats rules (may require subscription)"
    fi
    
    # MISP threat intelligence (placeholder - would need API key)
    log "Checking MISP threat intelligence..."
    if [ -n "${MISP_API_KEY:-}" ] && [ -n "${MISP_URL:-}" ]; then
        log "Downloading MISP indicators..."
        if curl -s -H "Authorization: $MISP_API_KEY" \
            -H "Accept: application/json" \
            "$MISP_URL/attributes/restSearch" \
            -o "$FEEDS_DIR/misp_indicators.json"; then
            success "MISP indicators updated"
        else
            error "Failed to download MISP indicators"
        fi
    else
        warning "MISP API credentials not configured"
    fi
    
    # Generate feed statistics
    generate_feed_statistics
}

# Generate statistics about threat feeds
generate_feed_statistics() {
    log "Generating threat feed statistics..."
    
    local stats_file="$CONFIG_DIR/feed_statistics.json"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat > "$stats_file" << EOF
{
  "last_updated": "$timestamp",
  "feeds": {
    "malware_domains": {
      "file": "malware_domains.txt",
      "count": $(wc -l < "$FEEDS_DIR/malware_domains.txt" 2>/dev/null || echo 0),
      "status": "$([ -f "$FEEDS_DIR/malware_domains.txt" ] && echo "active" || echo "inactive")"
    },
    "urlhaus_urls": {
      "file": "urlhaus_urls.txt",
      "count": $(wc -l < "$FEEDS_DIR/urlhaus_urls.txt" 2>/dev/null || echo 0),
      "status": "$([ -f "$FEEDS_DIR/urlhaus_urls.txt" ] && echo "active" || echo "inactive")"
    },
    "emerging_threats": {
      "file": "emerging_threats.rules",
      "count": $(grep -c "^alert" "$FEEDS_DIR/emerging_threats.rules" 2>/dev/null || echo 0),
      "status": "$([ -f "$FEEDS_DIR/emerging_threats.rules" ] && echo "active" || echo "inactive")"
    },
    "misp_indicators": {
      "file": "misp_indicators.json",
      "count": $(jq '.response.Attribute | length' "$FEEDS_DIR/misp_indicators.json" 2>/dev/null || echo 0),
      "status": "$([ -f "$FEEDS_DIR/misp_indicators.json" ] && echo "active" || echo "inactive")"
    }
  }
}
EOF

    success "Feed statistics generated: $stats_file"
}

# Update security rules based on threat intelligence
update_security_rules() {
    log "Updating security rules based on threat intelligence..."
    
    # Generate IP blocklist from various sources
    generate_ip_blocklist
    
    # Generate domain blocklist
    generate_domain_blocklist
    
    # Update rate limiting rules
    update_rate_limiting_rules
    
    # Update WAF rules
    update_waf_rules
    
    success "Security rules updated"
}

# Generate IP blocklist
generate_ip_blocklist() {
    log "Generating IP blocklist..."
    
    local blocklist_file="$RULES_DIR/blocked_ips.txt"
    local temp_file=$(mktemp)
    
    # Start with empty file
    > "$temp_file"
    
    # Add known malicious IPs (example sources)
    if [ -f "$FEEDS_DIR/malicious_ips.txt" ]; then
        cat "$FEEDS_DIR/malicious_ips.txt" >> "$temp_file"
    fi
    
    # Add IPs from security incidents (would integrate with incident response system)
    if [ -f "$CONFIG_DIR/incident_ips.txt" ]; then
        cat "$CONFIG_DIR/incident_ips.txt" >> "$temp_file"
    fi
    
    # Remove duplicates and sort
    sort -u "$temp_file" > "$blocklist_file"
    rm "$temp_file"
    
    local count=$(wc -l < "$blocklist_file")
    success "IP blocklist updated with $count entries"
}

# Generate domain blocklist
generate_domain_blocklist() {
    log "Generating domain blocklist..."
    
    local blocklist_file="$RULES_DIR/blocked_domains.txt"
    local temp_file=$(mktemp)
    
    # Start with empty file
    > "$temp_file"
    
    # Add malware domains
    if [ -f "$FEEDS_DIR/malware_domains.txt" ]; then
        grep -v '^#' "$FEEDS_DIR/malware_domains.txt" | grep -v '^$' >> "$temp_file"
    fi
    
    # Add domains from URLhaus
    if [ -f "$FEEDS_DIR/urlhaus_urls.txt" ]; then
        grep -o 'https\?://[^/]*' "$FEEDS_DIR/urlhaus_urls.txt" | \
        sed 's|https\?://||' | \
        cut -d'/' -f1 >> "$temp_file"
    fi
    
    # Remove duplicates and sort
    sort -u "$temp_file" > "$blocklist_file"
    rm "$temp_file"
    
    local count=$(wc -l < "$blocklist_file")
    success "Domain blocklist updated with $count entries"
}

# Update rate limiting rules based on threat patterns
update_rate_limiting_rules() {
    log "Updating rate limiting rules..."
    
    local rules_file="$RULES_DIR/rate_limiting_rules.json"
    
    # Generate adaptive rate limiting rules
    cat > "$rules_file" << EOF
{
  "last_updated": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "rules": {
    "authentication": {
      "normal_rate": 60,
      "burst_rate": 10,
      "window_seconds": 60,
      "penalty_seconds": 300
    },
    "token_requests": {
      "normal_rate": 100,
      "burst_rate": 20,
      "window_seconds": 60,
      "penalty_seconds": 180
    },
    "api_calls": {
      "normal_rate": 1000,
      "burst_rate": 100,
      "window_seconds": 60,
      "penalty_seconds": 60
    },
    "suspicious_patterns": {
      "sql_injection_attempts": {
        "rate": 5,
        "window_seconds": 300,
        "penalty_seconds": 3600
      },
      "xss_attempts": {
        "rate": 5,
        "window_seconds": 300,
        "penalty_seconds": 3600
      },
      "brute_force_attempts": {
        "rate": 10,
        "window_seconds": 600,
        "penalty_seconds": 7200
      }
    }
  }
}
EOF

    success "Rate limiting rules updated"
}

# Update WAF rules
update_waf_rules() {
    log "Updating WAF rules..."
    
    local waf_rules_file="$RULES_DIR/waf_rules.conf"
    
    cat > "$waf_rules_file" << 'EOF'
# WAF Rules for Rust Security Workspace
# Generated automatically from threat intelligence

# Block known malicious user agents
SecRule REQUEST_HEADERS:User-Agent "@detectSQLi" \
    "id:1001,phase:1,block,msg:'SQL Injection in User-Agent',logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"

# Block requests with suspicious patterns
SecRule ARGS "@detectSQLi" \
    "id:1002,phase:2,block,msg:'SQL Injection Attack Detected',logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"

SecRule ARGS "@detectXSS" \
    "id:1003,phase:2,block,msg:'XSS Attack Detected',logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"

# Block requests to known malicious domains
SecRule REQUEST_HEADERS:Host "@pmFromFile blocked_domains.txt" \
    "id:1004,phase:1,block,msg:'Request to blocked domain',logdata:'Domain: %{MATCHED_VAR}'"

# Rate limiting rules
SecRule IP:REQUEST_COUNT "@gt 100" \
    "id:1005,phase:1,deny,status:429,msg:'Rate limit exceeded',setvar:ip.rate_limited=1,expirevar:ip.rate_limited=300"

# Block known attack patterns
SecRule REQUEST_URI "@rx (?i)(\.\./|\.\.\\|etc/passwd|proc/self/environ)" \
    "id:1006,phase:1,block,msg:'Directory traversal attack detected'"

SecRule REQUEST_BODY "@rx (?i)(union.*select|insert.*into|delete.*from|drop.*table)" \
    "id:1007,phase:2,block,msg:'SQL injection pattern detected'"

# Custom rules based on threat intelligence
SecRule REQUEST_HEADERS:X-Forwarded-For "@ipMatchFromFile blocked_ips.txt" \
    "id:1008,phase:1,block,msg:'Request from blocked IP',logdata:'IP: %{MATCHED_VAR}'"

EOF

    success "WAF rules updated"
}

# Update application configuration with new threat intelligence
update_application_config() {
    log "Updating application configuration..."
    
    # Update auth-service configuration
    if [ -f "$PROJECT_ROOT/auth-service/config/security.toml" ]; then
        log "Updating auth-service security configuration..."
        
        # This would typically update configuration files with new threat intelligence
        # For now, we'll create a threat intelligence configuration section
        
        cat >> "$PROJECT_ROOT/auth-service/config/security.toml" << EOF

# Threat Intelligence Configuration (Auto-generated)
[threat_intelligence]
last_updated = "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
blocked_domains_file = "$RULES_DIR/blocked_domains.txt"
blocked_ips_file = "$RULES_DIR/blocked_ips.txt"
rate_limiting_rules_file = "$RULES_DIR/rate_limiting_rules.json"

EOF
    fi
    
    success "Application configuration updated"
}

# Send notifications about threat intelligence updates
send_notifications() {
    log "Sending threat intelligence update notifications..."
    
    local stats_file="$CONFIG_DIR/feed_statistics.json"
    
    if [ -f "$stats_file" ]; then
        local total_indicators=$(jq -r '.feeds | to_entries | map(.value.count) | add' "$stats_file")
        local active_feeds=$(jq -r '.feeds | to_entries | map(select(.value.status == "active")) | length' "$stats_file")
        local total_feeds=$(jq -r '.feeds | length' "$stats_file")
        
        local message="Threat Intelligence Update Complete:
- Total Indicators: $total_indicators
- Active Feeds: $active_feeds/$total_feeds
- Last Updated: $(date)
- Log File: $LOG_FILE"
        
        # Send to webhook if configured
        if [ -n "${THREAT_INTEL_WEBHOOK_URL:-}" ]; then
            curl -s -X POST "$THREAT_INTEL_WEBHOOK_URL" \
                -H "Content-Type: application/json" \
                -d "{\"text\":\"$message\"}" || warning "Failed to send webhook notification"
        fi
        
        # Send email if configured
        if [ -n "${THREAT_INTEL_EMAIL:-}" ] && command -v mail >/dev/null 2>&1; then
            echo "$message" | mail -s "Threat Intelligence Update" "$THREAT_INTEL_EMAIL" || \
                warning "Failed to send email notification"
        fi
        
        success "Notifications sent"
    else
        warning "Statistics file not found, skipping notifications"
    fi
}

# Cleanup old files
cleanup_old_files() {
    log "Cleaning up old threat intelligence files..."
    
    # Remove files older than 30 days
    find "$FEEDS_DIR" -name "*.txt" -mtime +30 -delete 2>/dev/null || true
    find "$FEEDS_DIR" -name "*.json" -mtime +30 -delete 2>/dev/null || true
    find "$FEEDS_DIR" -name "*.rules" -mtime +30 -delete 2>/dev/null || true
    
    # Rotate log file if it's too large
    if [ -f "$LOG_FILE" ] && [ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt 10485760 ]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
        touch "$LOG_FILE"
        log "Log file rotated"
    fi
    
    success "Cleanup completed"
}

# Health check for threat intelligence system
health_check() {
    log "Performing threat intelligence system health check..."
    
    local health_status="healthy"
    local issues=()
    
    # Check if feeds directory exists and has recent files
    if [ ! -d "$FEEDS_DIR" ]; then
        health_status="unhealthy"
        issues+=("Feeds directory missing")
    else
        local recent_files=$(find "$FEEDS_DIR" -name "*.txt" -mtime -1 | wc -l)
        if [ "$recent_files" -eq 0 ]; then
            health_status="degraded"
            issues+=("No recent feed updates")
        fi
    fi
    
    # Check if rules directory exists
    if [ ! -d "$RULES_DIR" ]; then
        health_status="unhealthy"
        issues+=("Rules directory missing")
    fi
    
    # Check disk space
    local disk_usage=$(df "$CONFIG_DIR" | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 90 ]; then
        health_status="degraded"
        issues+=("High disk usage: ${disk_usage}%")
    fi
    
    # Generate health report
    local health_file="$CONFIG_DIR/health_status.json"
    cat > "$health_file" << EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "status": "$health_status",
  "issues": $(printf '%s\n' "${issues[@]}" | jq -R . | jq -s .),
  "metrics": {
    "disk_usage_percent": $disk_usage,
    "feeds_count": $(ls -1 "$FEEDS_DIR"/*.txt 2>/dev/null | wc -l),
    "rules_count": $(ls -1 "$RULES_DIR"/*.txt "$RULES_DIR"/*.json 2>/dev/null | wc -l),
    "last_update": "$(stat -f%m "$FEEDS_DIR" 2>/dev/null || stat -c%Y "$FEEDS_DIR" 2>/dev/null || echo 0)"
  }
}
EOF
    
    if [ "$health_status" = "healthy" ]; then
        success "Health check passed"
    else
        warning "Health check found issues: ${issues[*]}"
    fi
    
    return $([ "$health_status" = "healthy" ] && echo 0 || echo 1)
}

# Main execution function
main() {
    log "Starting threat intelligence update process..."
    
    # Setup
    setup_directories
    
    # Update threat feeds
    update_threat_feeds
    
    # Update security rules
    update_security_rules
    
    # Update application configuration
    update_application_config
    
    # Perform health check
    if health_check; then
        success "Threat intelligence update completed successfully"
    else
        warning "Threat intelligence update completed with issues"
    fi
    
    # Send notifications
    send_notifications
    
    # Cleanup
    cleanup_old_files
    
    log "Threat intelligence update process finished"
}

# Handle command line arguments
case "${1:-update}" in
    "update")
        main
        ;;
    "health")
        health_check
        ;;
    "cleanup")
        cleanup_old_files
        ;;
    "stats")
        if [ -f "$CONFIG_DIR/feed_statistics.json" ]; then
            jq . "$CONFIG_DIR/feed_statistics.json"
        else
            error "Statistics file not found"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 [update|health|cleanup|stats]"
        echo "  update  - Update threat intelligence feeds and rules (default)"
        echo "  health  - Perform health check"
        echo "  cleanup - Clean up old files"
        echo "  stats   - Show feed statistics"
        exit 1
        ;;
esac
