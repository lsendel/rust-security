#!/bin/bash

# Quality Alert System - Real-time notifications for quality regressions
# Integrates with monitoring systems and sends alerts when quality drops

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ALERT_CONFIG="$PROJECT_ROOT/.quality-alerts.conf"

# Default thresholds
CRITICAL_THRESHOLD=90
WARNING_THRESHOLD=95
TARGET_SCORE=97

# Alert channels (override in config file)
SLACK_WEBHOOK="${QUALITY_SLACK_WEBHOOK:-}"
DISCORD_WEBHOOK="${QUALITY_DISCORD_WEBHOOK:-}"
EMAIL_RECIPIENTS="${QUALITY_EMAIL_RECIPIENTS:-}"
TEAMS_WEBHOOK="${QUALITY_TEAMS_WEBHOOK:-}"

# Load configuration if exists
if [ -f "$ALERT_CONFIG" ]; then
    source "$ALERT_CONFIG"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Alert severity levels
declare -A SEVERITY_COLORS=(
    ["CRITICAL"]="🔴"
    ["WARNING"]="🟡" 
    ["INFO"]="🔵"
    ["SUCCESS"]="🟢"
)

echo -e "${BLUE}🚨 Quality Alert System - Monitoring Quality Regressions${NC}"
echo "==============================================================="

# Function to log alerts
log_alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
    
    echo "$timestamp [$severity] $message" >> "$PROJECT_ROOT/quality-monitoring/alerts.log"
}

# Function to send Slack notification
send_slack_alert() {
    local severity="$1"
    local title="$2"
    local message="$3"
    local score="$4"
    
    if [ -z "$SLACK_WEBHOOK" ]; then
        return 0
    fi
    
    local color="danger"
    case $severity in
        "SUCCESS") color="good" ;;
        "WARNING") color="warning" ;;
        "INFO") color="#36a64f" ;;
    esac
    
    local payload=$(cat << EOF
{
    "username": "Quality Monitor",
    "icon_emoji": ":warning:",
    "attachments": [
        {
            "color": "$color",
            "title": "${SEVERITY_COLORS[$severity]} $title",
            "fields": [
                {
                    "title": "Quality Score",
                    "value": "$score/100",
                    "short": true
                },
                {
                    "title": "Severity",
                    "value": "$severity",
                    "short": true
                },
                {
                    "title": "Details",
                    "value": "$message",
                    "short": false
                },
                {
                    "title": "Project",
                    "value": "Rust Security Platform",
                    "short": true
                },
                {
                    "title": "Timestamp",
                    "value": "$(date -u +"%Y-%m-%d %H:%M:%S UTC")",
                    "short": true
                }
            ],
            "footer": "Automated Quality Monitoring",
            "footer_icon": "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png"
        }
    ]
}
EOF
    )
    
    curl -X POST -H 'Content-type: application/json' \
         --data "$payload" \
         "$SLACK_WEBHOOK" \
         --silent --output /dev/null || true
    
    echo "📱 Slack notification sent"
}

# Function to send Discord notification
send_discord_alert() {
    local severity="$1"
    local title="$2"
    local message="$3"
    local score="$4"
    
    if [ -z "$DISCORD_WEBHOOK" ]; then
        return 0
    fi
    
    local color=16711680  # Red
    case $severity in
        "SUCCESS") color=65280 ;;    # Green
        "WARNING") color=16776960 ;; # Yellow
        "INFO") color=255 ;;         # Blue
    esac
    
    local payload=$(cat << EOF
{
    "username": "Quality Monitor",
    "avatar_url": "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
    "embeds": [
        {
            "title": "${SEVERITY_COLORS[$severity]} $title",
            "description": "$message",
            "color": $color,
            "fields": [
                {
                    "name": "Quality Score",
                    "value": "$score/100",
                    "inline": true
                },
                {
                    "name": "Severity",
                    "value": "$severity",
                    "inline": true
                },
                {
                    "name": "Project",
                    "value": "Rust Security Platform",
                    "inline": true
                }
            ],
            "footer": {
                "text": "Automated Quality Monitoring"
            },
            "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")"
        }
    ]
}
EOF
    )
    
    curl -X POST -H 'Content-type: application/json' \
         --data "$payload" \
         "$DISCORD_WEBHOOK" \
         --silent --output /dev/null || true
    
    echo "💬 Discord notification sent"
}

# Function to send email notification
send_email_alert() {
    local severity="$1"
    local title="$2"
    local message="$3"
    local score="$4"
    
    if [ -z "$EMAIL_RECIPIENTS" ] || ! command -v mail >/dev/null 2>&1; then
        return 0
    fi
    
    local email_body=$(cat << EOF
Code Quality Alert - $severity

Project: Rust Security Platform
Quality Score: $score/100
Severity: $severity
Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

Alert Details:
$title

$message

---
This is an automated alert from the Quality Monitoring System.
To configure alert settings, edit $ALERT_CONFIG
EOF
    )
    
    echo "$email_body" | mail -s "[Quality Alert] $title - $severity" "$EMAIL_RECIPIENTS" || true
    echo "📧 Email notification sent to $EMAIL_RECIPIENTS"
}

# Function to send Microsoft Teams notification
send_teams_alert() {
    local severity="$1"
    local title="$2"
    local message="$3"
    local score="$4"
    
    if [ -z "$TEAMS_WEBHOOK" ]; then
        return 0
    fi
    
    local theme_color="FF0000"  # Red
    case $severity in
        "SUCCESS") theme_color="00FF00" ;;  # Green
        "WARNING") theme_color="FFFF00" ;;  # Yellow
        "INFO") theme_color="0000FF" ;;     # Blue
    esac
    
    local payload=$(cat << EOF
{
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    "summary": "$title",
    "themeColor": "$theme_color",
    "sections": [
        {
            "activityTitle": "${SEVERITY_COLORS[$severity]} $title",
            "activitySubtitle": "Quality Score: $score/100",
            "activityImage": "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
            "facts": [
                {
                    "name": "Project",
                    "value": "Rust Security Platform"
                },
                {
                    "name": "Severity",
                    "value": "$severity"
                },
                {
                    "name": "Quality Score",
                    "value": "$score/100"
                },
                {
                    "name": "Timestamp",
                    "value": "$(date -u +"%Y-%m-%d %H:%M:%S UTC")"
                }
            ],
            "text": "$message"
        }
    ]
}
EOF
    )
    
    curl -X POST -H 'Content-type: application/json' \
         --data "$payload" \
         "$TEAMS_WEBHOOK" \
         --silent --output /dev/null || true
    
    echo "💼 Teams notification sent"
}

# Function to send alert to all configured channels
send_alert() {
    local severity="$1"
    local title="$2"
    local message="$3"
    local score="${4:-0}"
    
    echo -e "\n${SEVERITY_COLORS[$severity]} ${RED}ALERT [$severity]:${NC} $title"
    echo -e "${YELLOW}Score: $score/100${NC}"
    echo -e "${message}\n"
    
    log_alert "$severity" "$title - $message (Score: $score/100)"
    
    # Send to all configured channels
    send_slack_alert "$severity" "$title" "$message" "$score"
    send_discord_alert "$severity" "$title" "$message" "$score" 
    send_email_alert "$severity" "$title" "$message" "$score"
    send_teams_alert "$severity" "$title" "$message" "$score"
}

# Function to check quality score and trigger alerts
check_quality_and_alert() {
    local current_score="$1"
    local previous_score="${2:-$current_score}"
    
    # Critical threshold check
    if [ "$current_score" -lt "$CRITICAL_THRESHOLD" ]; then
        send_alert "CRITICAL" \
                  "Code Quality Critical - Immediate Action Required" \
                  "Quality score has dropped to $current_score/100, below critical threshold of $CRITICAL_THRESHOLD. This requires immediate attention to prevent production issues." \
                  "$current_score"
        return 1
    fi
    
    # Warning threshold check
    if [ "$current_score" -lt "$WARNING_THRESHOLD" ]; then
        send_alert "WARNING" \
                  "Code Quality Below Target" \
                  "Quality score is $current_score/100, below warning threshold of $WARNING_THRESHOLD. Consider addressing issues before they become critical." \
                  "$current_score"
        return 2
    fi
    
    # Regression check (if score dropped significantly)
    if [ "$previous_score" -gt 0 ]; then
        local drop=$((previous_score - current_score))
        if [ "$drop" -ge 5 ]; then
            send_alert "WARNING" \
                      "Quality Regression Detected" \
                      "Quality score dropped by $drop points from $previous_score to $current_score. Investigate recent changes." \
                      "$current_score"
            return 2
        fi
    fi
    
    # Success notification for excellent scores
    if [ "$current_score" -ge "$TARGET_SCORE" ]; then
        # Only send success alerts once per day to avoid spam
        local today=$(date +%Y-%m-%d)
        local success_log="$PROJECT_ROOT/quality-monitoring/last-success-alert.txt"
        local last_success_date=""
        
        if [ -f "$success_log" ]; then
            last_success_date=$(cat "$success_log" 2>/dev/null || echo "")
        fi
        
        if [ "$last_success_date" != "$today" ]; then
            send_alert "SUCCESS" \
                      "Excellent Code Quality Maintained" \
                      "Quality score is $current_score/100, exceeding target of $TARGET_SCORE. Outstanding work maintaining code quality standards!" \
                      "$current_score"
            echo "$today" > "$success_log"
        fi
    fi
    
    return 0
}

# Function to run quality analysis and check for alerts
run_quality_check() {
    echo "🔍 Running quality analysis..."
    
    # Run the quality monitor script to get current score
    if ! "$SCRIPT_DIR/quality-monitor.sh" single >/dev/null 2>&1; then
        echo "❌ Quality analysis failed"
        send_alert "CRITICAL" \
                  "Quality Analysis Failed" \
                  "Unable to run quality analysis. This may indicate serious build or configuration issues." \
                  "0"
        return 1
    fi
    
    # Extract current score from quality reports
    local score_file="$PROJECT_ROOT/quality-monitoring/score-history.txt"
    local current_score=0
    local previous_score=0
    
    if [ -f "$score_file" ]; then
        # Get current score (last line)
        current_score=$(tail -1 "$score_file" 2>/dev/null | grep -o '[0-9]\+/100' | cut -d'/' -f1 || echo "0")
        
        # Get previous score (second to last line) 
        previous_score=$(tail -2 "$score_file" 2>/dev/null | head -1 | grep -o '[0-9]\+/100' | cut -d'/' -f1 || echo "$current_score")
    fi
    
    echo "📊 Current Quality Score: $current_score/100"
    if [ "$previous_score" != "$current_score" ]; then
        echo "📈 Previous Score: $previous_score/100"
    fi
    
    # Check score and send alerts if needed
    check_quality_and_alert "$current_score" "$previous_score"
    return $?
}

# Function to setup alert configuration
setup_configuration() {
    echo "🔧 Setting up alert configuration..."
    
    cat > "$ALERT_CONFIG" << 'EOF'
# Quality Alert Configuration
# Copy this file and customize for your environment

# Thresholds
CRITICAL_THRESHOLD=90   # Score below this triggers critical alerts
WARNING_THRESHOLD=95    # Score below this triggers warning alerts  
TARGET_SCORE=97         # Score above this triggers success alerts

# Slack Integration
# Create a webhook at https://api.slack.com/messaging/webhooks
SLACK_WEBHOOK=""

# Discord Integration  
# Create a webhook in your Discord server settings
DISCORD_WEBHOOK=""

# Email Notifications
# Space-separated list of email addresses
EMAIL_RECIPIENTS=""

# Microsoft Teams Integration
# Create a webhook connector in your Teams channel
TEAMS_WEBHOOK=""

# Alert Frequency (minutes between checks)
ALERT_CHECK_INTERVAL=5

EOF
    
    echo "✅ Configuration template created at $ALERT_CONFIG"
    echo "📝 Edit this file to configure your alert channels"
}

# Function to test alert configuration
test_alerts() {
    echo "🧪 Testing alert configuration..."
    
    send_alert "INFO" \
              "Alert System Test" \
              "This is a test alert to verify your notification channels are configured correctly." \
              "97"
    
    echo "✅ Test alerts sent to all configured channels"
}

# Function to show alert history
show_alert_history() {
    local alert_log="$PROJECT_ROOT/quality-monitoring/alerts.log"
    
    if [ ! -f "$alert_log" ]; then
        echo "📝 No alert history found"
        return 0
    fi
    
    echo "📜 Recent Alert History (last 20 alerts):"
    echo "========================================="
    tail -20 "$alert_log" | while read -r line; do
        if [[ "$line" =~ CRITICAL ]]; then
            echo -e "${RED}$line${NC}"
        elif [[ "$line" =~ WARNING ]]; then
            echo -e "${YELLOW}$line${NC}"
        elif [[ "$line" =~ SUCCESS ]]; then
            echo -e "${GREEN}$line${NC}"
        else
            echo -e "${BLUE}$line${NC}"
        fi
    done
}

# Function to run continuous monitoring
continuous_monitoring() {
    echo "🔄 Starting continuous quality monitoring..."
    echo "Press Ctrl+C to stop"
    
    local check_interval="${ALERT_CHECK_INTERVAL:-5}"
    
    while true; do
        echo -e "\n⏰ $(date) - Running quality check..."
        
        if run_quality_check; then
            echo "✅ Quality check completed"
        else
            echo "⚠️  Quality issues detected"
        fi
        
        echo "💤 Waiting $check_interval minutes until next check..."
        sleep $((check_interval * 60))
    done
}

# Main execution
main() {
    case "${1:-check}" in
        "check"|"run")
            run_quality_check
            ;;
        "setup"|"config")
            setup_configuration
            ;;
        "test")
            test_alerts
            ;;
        "history"|"log")
            show_alert_history
            ;;
        "monitor"|"continuous"|"-m")
            continuous_monitoring
            ;;
        "help"|"-h"|"--help")
            cat << EOF
Quality Alert System - Usage

Commands:
  check, run          Run single quality check and send alerts if needed
  setup, config       Create configuration file template
  test                Send test alerts to verify configuration
  history, log        Show recent alert history
  monitor, continuous Start continuous monitoring mode
  help                Show this help message

Configuration:
  Edit $ALERT_CONFIG to configure alert channels and thresholds

Examples:
  $0 check                    # Run single quality check
  $0 setup                    # Create configuration file
  $0 test                     # Test alert notifications
  $0 monitor                  # Start continuous monitoring
  
Environment Variables:
  QUALITY_SLACK_WEBHOOK      Slack webhook URL
  QUALITY_DISCORD_WEBHOOK    Discord webhook URL
  QUALITY_EMAIL_RECIPIENTS   Email addresses for notifications
  QUALITY_TEAMS_WEBHOOK      Microsoft Teams webhook URL
EOF
            ;;
        *)
            echo "❌ Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Trap for clean shutdown in continuous mode
trap 'echo -e "\n${YELLOW}Quality monitoring stopped by user${NC}"; exit 0' INT TERM

# Ensure monitoring directory exists
mkdir -p "$PROJECT_ROOT/quality-monitoring"

# Run main function
main "$@"