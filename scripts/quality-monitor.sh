#!/bin/bash

# Real-time Code Quality Monitoring Script
# Provides continuous quality metrics tracking and alerting

set -euo pipefail

# Configuration
QUALITY_THRESHOLD=95
TARGET_SCORE=97
REPORT_DIR="./quality-monitoring"
ALERT_EMAIL="${QUALITY_ALERT_EMAIL:-}"
SLACK_WEBHOOK="${QUALITY_SLACK_WEBHOOK:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 Real-time Quality Monitor - Starting Continuous Analysis${NC}"
echo "=================================================================="

# Create monitoring directory
mkdir -p "$REPORT_DIR"

# Function to send alerts
send_alert() {
    local message="$1"
    local severity="$2"
    
    echo -e "${RED}🚨 QUALITY ALERT [${severity}]: ${message}${NC}"
    
    # Email alert (if configured)
    if [ -n "$ALERT_EMAIL" ]; then
        echo "$message" | mail -s "Code Quality Alert - $severity" "$ALERT_EMAIL" 2>/dev/null || true
    fi
    
    # Slack alert (if configured)  
    if [ -n "$SLACK_WEBHOOK" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🚨 Code Quality Alert - $severity: $message\"}" \
            "$SLACK_WEBHOOK" 2>/dev/null || true
    fi
    
    # Log to monitoring file
    echo "$(date -u +"%Y-%m-%d %H:%M:%S UTC") [$severity] $message" >> "$REPORT_DIR/alerts.log"
}

# Function to calculate quality score
calculate_quality_score() {
    local score=0
    local issues=""
    
    echo "Calculating quality metrics..."
    
    # Code formatting (25 points)
    if cargo fmt --all -- --check >/dev/null 2>&1; then
        score=$((score + 25))
        echo "✅ Code formatting: 25/25"
    else
        score=$((score + 15))
        issues="${issues}- Code formatting violations\n"
        echo "⚠️  Code formatting: 15/25"
    fi
    
    # Compilation warnings (25 points)
    if cargo check --all-targets --all-features >/dev/null 2>&1; then
        score=$((score + 25))
        echo "✅ Compilation: 25/25"
    else
        score=$((score + 10))
        issues="${issues}- Compilation warnings present\n"
        echo "❌ Compilation: 10/25"
    fi
    
    # Linting (25 points)
    if cargo clippy --all-targets --all-features -- -D warnings >/dev/null 2>&1; then
        score=$((score + 25))
        echo "✅ Linting: 25/25"
    else
        # Check for critical vs minor issues
        critical_lints=$(cargo clippy --all-targets --all-features 2>&1 | grep -c "error:" || echo "0")
        if [ "$critical_lints" -eq 0 ]; then
            score=$((score + 20))
            echo "🟡 Linting: 20/25 (minor warnings)"
        else
            score=$((score + 10))
            issues="${issues}- Critical linting errors: $critical_lints\n"
            echo "❌ Linting: 10/25 (critical errors)"
        fi
    fi
    
    # Security (25 points)
    cargo audit --format json > "$REPORT_DIR/security-audit.json" 2>/dev/null || echo '{"vulnerabilities": []}' > "$REPORT_DIR/security-audit.json"
    
    local critical_vulns=$(jq -r '.vulnerabilities | map(select(.advisory.severity == "critical")) | length' "$REPORT_DIR/security-audit.json" 2>/dev/null || echo "0")
    local high_vulns=$(jq -r '.vulnerabilities | map(select(.advisory.severity == "high")) | length' "$REPORT_DIR/security-audit.json" 2>/dev/null || echo "0")
    
    if [ "$critical_vulns" -eq 0 ] && [ "$high_vulns" -eq 0 ]; then
        score=$((score + 25))
        echo "✅ Security: 25/25"
    elif [ "$critical_vulns" -eq 0 ] && [ "$high_vulns" -le 2 ]; then
        score=$((score + 20))
        echo "🟡 Security: 20/25 (minor vulnerabilities)"
    else
        score=$((score + 10))
        issues="${issues}- Critical vulnerabilities: $critical_vulns, High: $high_vulns\n"
        echo "❌ Security: 10/25 (critical vulnerabilities)"
    fi
    
    echo "$score|$issues"
}

# Function to generate detailed report
generate_report() {
    local score="$1"
    local timestamp=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
    
    # Generate comprehensive metrics
    tokei --output json > "$REPORT_DIR/code-metrics.json" 2>/dev/null || echo '{}' > "$REPORT_DIR/code-metrics.json"
    scc --by-file --format json > "$REPORT_DIR/complexity-metrics.json" 2>/dev/null || echo '[]' > "$REPORT_DIR/complexity-metrics.json"
    
    # Extract key metrics
    local total_lines=$(jq -r '.Rust.code // 0' "$REPORT_DIR/code-metrics.json" 2>/dev/null || echo "0")
    local test_lines=$(jq -r '.Rust.tests // 0' "$REPORT_DIR/code-metrics.json" 2>/dev/null || echo "0")
    local test_coverage=0
    if [ "$total_lines" -gt 0 ]; then
        test_coverage=$(echo "scale=1; $test_lines * 100 / $total_lines" | bc -l 2>/dev/null || echo "0")
    fi
    
    cat > "$REPORT_DIR/quality-report-$timestamp.md" << EOF
# Real-time Quality Monitoring Report

**Generated**: $timestamp
**Quality Score**: $score/100
**Status**: $(if [ "$score" -ge "$TARGET_SCORE" ]; then echo "🟢 EXCELLENT"; elif [ "$score" -ge "$QUALITY_THRESHOLD" ]; then echo "🟡 GOOD"; else echo "🔴 NEEDS ATTENTION"; fi)

## Code Metrics
- **Total Lines of Code**: $total_lines
- **Test Coverage Estimate**: ${test_coverage}%
- **Last Analysis**: $timestamp

## Quality Breakdown
- **Code Formatting**: $(cargo fmt --all -- --check >/dev/null 2>&1 && echo "✅ Clean" || echo "❌ Issues")
- **Compilation**: $(cargo check --all-targets --all-features >/dev/null 2>&1 && echo "✅ Clean" || echo "❌ Warnings")
- **Linting**: $(cargo clippy --all-targets --all-features -- -D warnings >/dev/null 2>&1 && echo "✅ Clean" || echo "❌ Issues")
- **Security**: $([ "$(jq -r '.vulnerabilities | length' "$REPORT_DIR/security-audit.json" 2>/dev/null || echo "0")" -eq 0 ] && echo "✅ No vulnerabilities" || echo "⚠️ Vulnerabilities found")

## Historical Trend
$(if [ -f "$REPORT_DIR/score-history.txt" ]; then
    echo "Previous scores (last 5 runs):"
    tail -5 "$REPORT_DIR/score-history.txt" | while read -r line; do
        echo "- $line"
    done
else
    echo "- $timestamp: $score/100 (initial measurement)"
fi)

## Recommendations
$(if [ "$score" -lt "$QUALITY_THRESHOLD" ]; then
    echo "### 🚨 Immediate Actions Required"
    echo "1. Review and fix all compilation warnings"
    echo "2. Address critical linting errors"
    echo "3. Fix code formatting violations"
    echo "4. Review security vulnerabilities"
elif [ "$score" -lt "$TARGET_SCORE" ]; then
    echo "### 🎯 Optimization Opportunities"
    echo "1. Address remaining linting warnings"
    echo "2. Improve test coverage"
    echo "3. Review minor security issues"
else
    echo "### ✅ Excellent Code Quality"
    echo "Continue maintaining current high standards."
fi)

---
*Real-time Quality Monitoring - Updated every analysis*
EOF
    
    # Update score history
    echo "$timestamp: $score/100" >> "$REPORT_DIR/score-history.txt"
    
    # Keep only last 50 entries
    tail -50 "$REPORT_DIR/score-history.txt" > "$REPORT_DIR/score-history.tmp" && mv "$REPORT_DIR/score-history.tmp" "$REPORT_DIR/score-history.txt"
}

# Function for continuous monitoring mode
continuous_monitor() {
    echo -e "${BLUE}Starting continuous monitoring mode (Ctrl+C to stop)${NC}"
    
    while true; do
        echo -e "\n${BLUE}=== Quality Check - $(date) ===${NC}"
        
        result=$(calculate_quality_score)
        score=$(echo "$result" | cut -d'|' -f1)
        issues=$(echo "$result" | cut -d'|' -f2-)
        
        generate_report "$score"
        
        # Check for quality regression
        if [ "$score" -lt "$QUALITY_THRESHOLD" ]; then
            send_alert "Quality score dropped to $score/100 (threshold: $QUALITY_THRESHOLD)" "CRITICAL"
        elif [ "$score" -lt "$TARGET_SCORE" ]; then
            send_alert "Quality score is $score/100 (target: $TARGET_SCORE)" "WARNING"
        fi
        
        # Check for specific critical issues
        if echo "$issues" | grep -q "Critical"; then
            send_alert "Critical issues detected: $issues" "CRITICAL"
        fi
        
        echo -e "\n${GREEN}Quality Score: $score/100${NC}"
        if [ -n "$issues" ] && [ "$issues" != "-" ]; then
            echo -e "${YELLOW}Issues detected:${NC}"
            echo -e "$issues"
        fi
        
        # Sleep for monitoring interval (default: 5 minutes)
        sleep "${MONITOR_INTERVAL:-300}"
    done
}

# Function for single check mode
single_check() {
    echo -e "${BLUE}Running single quality check...${NC}"
    
    result=$(calculate_quality_score)
    score=$(echo "$result" | cut -d'|' -f1)
    issues=$(echo "$result" | cut -d'|' -f2-)
    
    generate_report "$score"
    
    echo -e "\n${GREEN}Final Quality Score: $score/100${NC}"
    
    if [ "$score" -ge "$TARGET_SCORE" ]; then
        echo -e "${GREEN}🎉 EXCELLENT: Code quality exceeds target!${NC}"
        exit 0
    elif [ "$score" -ge "$QUALITY_THRESHOLD" ]; then
        echo -e "${YELLOW}✅ GOOD: Code quality meets minimum standards${NC}"
        exit 0
    else
        echo -e "${RED}❌ ATTENTION REQUIRED: Code quality below acceptable threshold${NC}"
        if [ -n "$issues" ] && [ "$issues" != "-" ]; then
            echo -e "\nIssues to address:"
            echo -e "$issues"
        fi
        exit 1
    fi
}

# Main execution logic
main() {
    # Check if we're in a Rust project
    if [ ! -f "Cargo.toml" ]; then
        echo -e "${RED}❌ No Cargo.toml found. Please run from a Rust project root.${NC}"
        exit 1
    fi
    
    # Install required tools if missing
    echo "Checking analysis tools..."
    for tool in jq bc; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "Installing $tool..."
            if command -v apt-get >/dev/null 2>&1; then
                sudo apt-get update && sudo apt-get install -y "$tool"
            elif command -v brew >/dev/null 2>&1; then
                brew install "$tool"
            else
                echo "Please install $tool manually"
                exit 1
            fi
        fi
    done
    
    # Parse command line arguments
    case "${1:-single}" in
        "continuous"|"monitor"|"-c")
            continuous_monitor
            ;;
        "single"|"check"|"-s"|*)
            single_check
            ;;
    esac
}

# Trap for clean shutdown in continuous mode
trap 'echo -e "\n${YELLOW}Monitoring stopped by user${NC}"; exit 0' INT TERM

# Run main function
main "$@"