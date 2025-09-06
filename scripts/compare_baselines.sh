#!/bin/bash
# Baseline Comparison Script for Regression Testing

set -euo pipefail

BASELINE_DIR="tests/baseline"
CURRENT_RESULTS="regression_reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo "📊 Comparing Current Results with Baselines"

# Create baseline directory if it doesn't exist
mkdir -p "$BASELINE_DIR"

# Function to compare performance metrics
compare_performance() {
    local metric_name="$1"
    local current_value="$2"
    local baseline_file="$BASELINE_DIR/${metric_name}_baseline.txt"
    
    if [ -f "$baseline_file" ]; then
        local baseline_value=$(cat "$baseline_file")
        local threshold=10 # 10% threshold
        
        # Calculate percentage difference
        local diff=$(echo "scale=2; ($current_value - $baseline_value) / $baseline_value * 100" | bc -l)
        
        if (( $(echo "$diff > $threshold" | bc -l) )); then
            echo "⚠️  REGRESSION: $metric_name increased by ${diff}% (${current_value} vs ${baseline_value})"
            return 1
        elif (( $(echo "$diff < -$threshold" | bc -l) )); then
            echo "✅ IMPROVEMENT: $metric_name decreased by ${diff}% (${current_value} vs ${baseline_value})"
            return 0
        else
            echo "✅ STABLE: $metric_name within threshold (${current_value} vs ${baseline_value})"
            return 0
        fi
    else
        echo "📝 NEW BASELINE: Creating baseline for $metric_name = $current_value"
        echo "$current_value" > "$baseline_file"
        return 0
    fi
}

# Function to update baseline if approved
update_baseline() {
    local metric_name="$1"
    local new_value="$2"
    local baseline_file="$BASELINE_DIR/${metric_name}_baseline.txt"
    
    echo "$new_value" > "$baseline_file"
    echo "📝 Updated baseline for $metric_name to $new_value"
}

# Example performance comparisons
echo "🔍 Analyzing Performance Metrics..."

# Simulate getting current metrics (replace with actual metric collection)
AUTH_LATENCY=45  # milliseconds
DB_QUERY_TIME=12 # milliseconds
JWT_GEN_TIME=3   # milliseconds
MEMORY_USAGE=512 # MB

# Compare metrics with baselines
REGRESSION_DETECTED=0

if ! compare_performance "auth_latency_ms" "$AUTH_LATENCY"; then
    REGRESSION_DETECTED=1
fi

if ! compare_performance "db_query_time_ms" "$DB_QUERY_TIME"; then
    REGRESSION_DETECTED=1
fi

if ! compare_performance "jwt_generation_ms" "$JWT_GEN_TIME"; then
    REGRESSION_DETECTED=1
fi

if ! compare_performance "memory_usage_mb" "$MEMORY_USAGE"; then
    REGRESSION_DETECTED=1
fi

# Generate comparison report
cat > "$CURRENT_RESULTS/baseline_comparison_${TIMESTAMP}.md" << EOF
# Baseline Comparison Report - $TIMESTAMP

## Performance Metrics Comparison

| Metric | Current | Baseline | Change | Status |
|--------|---------|----------|--------|--------|
| Auth Latency (ms) | $AUTH_LATENCY | $(cat "$BASELINE_DIR/auth_latency_ms_baseline.txt" 2>/dev/null || echo "N/A") | - | - |
| DB Query Time (ms) | $DB_QUERY_TIME | $(cat "$BASELINE_DIR/db_query_time_ms_baseline.txt" 2>/dev/null || echo "N/A") | - | - |
| JWT Generation (ms) | $JWT_GEN_TIME | $(cat "$BASELINE_DIR/jwt_generation_ms_baseline.txt" 2>/dev/null || echo "N/A") | - | - |
| Memory Usage (MB) | $MEMORY_USAGE | $(cat "$BASELINE_DIR/memory_usage_mb_baseline.txt" 2>/dev/null || echo "N/A") | - | - |

## Summary
$(if [ $REGRESSION_DETECTED -eq 1 ]; then
    echo "⚠️  **PERFORMANCE REGRESSION DETECTED**"
    echo "- Review performance changes before deployment"
    echo "- Consider optimization or baseline updates"
else
    echo "✅ **NO PERFORMANCE REGRESSION**"
    echo "- All metrics within acceptable thresholds"
fi)

Generated: $(date)
EOF

# Final result
if [ $REGRESSION_DETECTED -eq 1 ]; then
    echo "🚨 Performance regression detected!"
    echo "📋 Review report: $CURRENT_RESULTS/baseline_comparison_${TIMESTAMP}.md"
    exit 1
else
    echo "✅ No performance regression detected"
    exit 0
fi
