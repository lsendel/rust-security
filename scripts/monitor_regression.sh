#!/bin/bash
# Regression Test Monitoring and Alerting

set -euo pipefail

REPORT_DIR="regression_reports"
ALERT_THRESHOLD=80  # Alert if success rate below 80%
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"

# Function to calculate success rate
calculate_success_rate() {
    local report_file="$1"
    
    if [ ! -f "$report_file" ]; then
        echo "0"
        return
    fi
    
    local passed=$(grep -c "PASSED" "$report_file" || echo "0")
    local failed=$(grep -c "FAILED" "$report_file" || echo "0")
    local total=$((passed + failed))
    
    if [ $total -eq 0 ]; then
        echo "0"
    else
        echo $((passed * 100 / total))
    fi
}

# Function to send alert
send_alert() {
    local message="$1"
    local success_rate="$2"
    
    echo "🚨 ALERT: $message (Success Rate: ${success_rate}%)"
    
    if [ -n "$SLACK_WEBHOOK_URL" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🚨 Regression Test Alert: $message (Success Rate: ${success_rate}%)\"}" \
            "$SLACK_WEBHOOK_URL" || echo "Failed to send Slack alert"
    fi
}

# Monitor latest regression test results
echo "📊 Monitoring Regression Test Results..."

# Find latest regression summary
LATEST_SUMMARY=$(find "$REPORT_DIR" -name "regression_summary_*.md" -type f -exec ls -t {} + | head -1)

if [ -z "$LATEST_SUMMARY" ]; then
    echo "⚠️  No regression test results found"
    exit 1
fi

echo "📋 Analyzing: $LATEST_SUMMARY"

# Calculate success rate
SUCCESS_RATE=$(calculate_success_rate "$LATEST_SUMMARY")

echo "📈 Current Success Rate: ${SUCCESS_RATE}%"

# Check if alert threshold is breached
if [ "$SUCCESS_RATE" -lt "$ALERT_THRESHOLD" ]; then
    send_alert "Regression test success rate below threshold" "$SUCCESS_RATE"
    exit 1
else
    echo "✅ Success rate above threshold (${ALERT_THRESHOLD}%)"
fi

# Check for specific failure patterns
if grep -q "REGRESSION DETECTED" "$LATEST_SUMMARY"; then
    send_alert "Performance regression detected in latest tests" "$SUCCESS_RATE"
    exit 1
fi

if grep -q "SECURITY" "$LATEST_SUMMARY" && grep -q "FAILED" "$LATEST_SUMMARY"; then
    send_alert "Security regression detected - immediate attention required" "$SUCCESS_RATE"
    exit 1
fi

echo "✅ All regression monitoring checks passed"
