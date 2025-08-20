#!/bin/bash
# Performance Budget Monitor for Rust Security Platform
# Automated performance budget enforcement with regression detection

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/config"
RESULTS_DIR="$SCRIPT_DIR/results"
BASELINES_DIR="$SCRIPT_DIR/baselines"
REPORTS_DIR="$SCRIPT_DIR/reports"

# Create directories
mkdir -p "$CONFIG_DIR" "$RESULTS_DIR" "$BASELINES_DIR" "$REPORTS_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$RESULTS_DIR/performance-monitor.log"
}

info() { log "${BLUE}INFO${NC}" "$@"; }
warn() { log "${YELLOW}WARN${NC}" "$@"; }
error() { log "${RED}ERROR${NC}" "$@"; }
success() { log "${GREEN}SUCCESS${NC}" "$@"; }

# Performance budget configuration
create_performance_budget() {
    local budget_file="$CONFIG_DIR/performance-budget.json"
    
    if [[ -f "$budget_file" ]]; then
        info "Performance budget already exists: $budget_file"
        return 0
    fi
    
    info "Creating performance budget configuration..."
    
    cat > "$budget_file" <<'EOF'
{
  "version": "1.0",
  "created_at": "2024-08-20T00:00:00Z",
  "description": "Performance budget for Rust Security Platform",
  
  "budgets": {
    "auth-service": {
      "response_time": {
        "p50": {
          "budget_ms": 100,
          "warning_threshold": 0.8,
          "critical_threshold": 1.0,
          "regression_threshold": 0.15
        },
        "p95": {
          "budget_ms": 200,
          "warning_threshold": 0.8,
          "critical_threshold": 1.0,
          "regression_threshold": 0.15
        },
        "p99": {
          "budget_ms": 500,
          "warning_threshold": 0.8,
          "critical_threshold": 1.0,
          "regression_threshold": 0.20
        }
      },
      "throughput": {
        "min_rps": 1000,
        "warning_threshold": 0.9,
        "critical_threshold": 0.8,
        "regression_threshold": 0.10
      },
      "error_rate": {
        "max_percentage": 1.0,
        "warning_threshold": 0.5,
        "critical_threshold": 0.8,
        "regression_threshold": 0.05
      },
      "resource_usage": {
        "cpu": {
          "max_percentage": 70,
          "warning_threshold": 0.8,
          "critical_threshold": 0.9,
          "regression_threshold": 0.10
        },
        "memory": {
          "max_percentage": 80,
          "warning_threshold": 0.8,
          "critical_threshold": 0.9,
          "regression_threshold": 0.10
        }
      }
    },
    
    "policy-service": {
      "response_time": {
        "p50": {
          "budget_ms": 25,
          "warning_threshold": 0.8,
          "critical_threshold": 1.0,
          "regression_threshold": 0.15
        },
        "p95": {
          "budget_ms": 50,
          "warning_threshold": 0.8,
          "critical_threshold": 1.0,
          "regression_threshold": 0.15
        },
        "p99": {
          "budget_ms": 100,
          "warning_threshold": 0.8,
          "critical_threshold": 1.0,
          "regression_threshold": 0.20
        }
      },
      "throughput": {
        "min_decisions_per_sec": 5000,
        "warning_threshold": 0.9,
        "critical_threshold": 0.8,
        "regression_threshold": 0.10
      },
      "error_rate": {
        "max_percentage": 0.1,
        "warning_threshold": 0.5,
        "critical_threshold": 0.8,
        "regression_threshold": 0.02
      },
      "cache_hit_rate": {
        "min_percentage": 80,
        "warning_threshold": 0.9,
        "critical_threshold": 0.8,
        "regression_threshold": 0.05
      }
    },
    
    "infrastructure": {
      "cluster_cpu": {
        "max_percentage": 80,
        "warning_threshold": 0.8,
        "critical_threshold": 0.9,
        "regression_threshold": 0.10
      },
      "cluster_memory": {
        "max_percentage": 85,
        "warning_threshold": 0.8,
        "critical_threshold": 0.9,
        "regression_threshold": 0.10
      },
      "node_availability": {
        "min_percentage": 99,
        "warning_threshold": 0.99,
        "critical_threshold": 0.95,
        "regression_threshold": 0.01
      }
    }
  },
  
  "monitoring": {
    "check_interval_minutes": 5,
    "baseline_comparison_days": 7,
    "regression_detection_enabled": true,
    "alert_on_budget_violation": true,
    "alert_on_regression": true,
    "auto_rollback_on_critical": false
  },
  
  "thresholds": {
    "regression_detection_window_hours": 24,
    "baseline_stability_threshold": 0.05,
    "minimum_samples_for_baseline": 100,
    "statistical_confidence": 0.95
  }
}
EOF

    success "Performance budget created: $budget_file"
    return 0
}

# Collect performance metrics from Prometheus
collect_metrics() {
    local service=$1
    local duration=${2:-"5m"}
    local output_file="$RESULTS_DIR/metrics-${service}-$(date +%Y%m%d-%H%M%S).json"
    
    info "Collecting metrics for $service (duration: $duration)"
    
    # Check if Prometheus is accessible
    local prometheus_url="http://prometheus.monitoring.svc.cluster.local:9090"
    if ! kubectl run prometheus-test --rm -i --tty --image=curlimages/curl --restart=Never -- \
         curl -s "$prometheus_url/api/v1/query?query=up" >/dev/null 2>&1; then
        error "Prometheus not accessible"
        return 1
    fi
    
    # Collect metrics based on service type
    case $service in
        "auth-service")
            collect_auth_service_metrics "$duration" "$output_file"
            ;;
        "policy-service")
            collect_policy_service_metrics "$duration" "$output_file"
            ;;
        "infrastructure")
            collect_infrastructure_metrics "$duration" "$output_file"
            ;;
        *)
            error "Unknown service: $service"
            return 1
            ;;
    esac
    
    echo "$output_file"
}

# Collect Auth Service metrics
collect_auth_service_metrics() {
    local duration=$1
    local output_file=$2
    local prometheus_url="http://prometheus.monitoring.svc.cluster.local:9090"
    
    # Create metrics collection script
    cat > "/tmp/collect_auth_metrics.sh" <<EOF
#!/bin/bash
PROM_URL="$prometheus_url"

# Response time metrics
P50=\$(curl -s "\$PROM_URL/api/v1/query?query=histogram_quantile(0.5,rate(http_request_duration_seconds_bucket{service=\"auth-service\"}[$duration]))" | jq -r '.data.result[0].value[1] // "0"')
P95=\$(curl -s "\$PROM_URL/api/v1/query?query=histogram_quantile(0.95,rate(http_request_duration_seconds_bucket{service=\"auth-service\"}[$duration]))" | jq -r '.data.result[0].value[1] // "0"')
P99=\$(curl -s "\$PROM_URL/api/v1/query?query=histogram_quantile(0.99,rate(http_request_duration_seconds_bucket{service=\"auth-service\"}[$duration]))" | jq -r '.data.result[0].value[1] // "0"')

# Throughput metrics
RPS=\$(curl -s "\$PROM_URL/api/v1/query?query=sum(rate(http_requests_total{service=\"auth-service\"}[$duration]))" | jq -r '.data.result[0].value[1] // "0"')

# Error rate
ERROR_RATE=\$(curl -s "\$PROM_URL/api/v1/query?query=sum(rate(http_requests_total{service=\"auth-service\",code=~\"5..\"}[$duration]))/sum(rate(http_requests_total{service=\"auth-service\"}[$duration]))*100" | jq -r '.data.result[0].value[1] // "0"')

# Resource usage
CPU_USAGE=\$(curl -s "\$PROM_URL/api/v1/query?query=avg(rate(container_cpu_usage_seconds_total{pod=~\"auth-service-.*\"}[$duration]))*100" | jq -r '.data.result[0].value[1] // "0"')
MEMORY_USAGE=\$(curl -s "\$PROM_URL/api/v1/query?query=avg(container_memory_usage_bytes{pod=~\"auth-service-.*\"}/container_spec_memory_limit_bytes)*100" | jq -r '.data.result[0].value[1] // "0"')

cat <<JSON
{
  "service": "auth-service",
  "timestamp": "\$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration": "$duration",
  "metrics": {
    "response_time": {
      "p50_ms": \$(echo "\$P50 * 1000" | bc -l),
      "p95_ms": \$(echo "\$P95 * 1000" | bc -l),
      "p99_ms": \$(echo "\$P99 * 1000" | bc -l)
    },
    "throughput": {
      "rps": \$(echo "\$RPS" | bc -l)
    },
    "error_rate": {
      "percentage": \$(echo "\$ERROR_RATE" | bc -l)
    },
    "resource_usage": {
      "cpu_percentage": \$(echo "\$CPU_USAGE" | bc -l),
      "memory_percentage": \$(echo "\$MEMORY_USAGE" | bc -l)
    }
  }
}
JSON
EOF

    # Execute metrics collection
    kubectl run metrics-collector --rm -i --tty --image=curlimages/curl --restart=Never -- \
        sh -c "$(cat /tmp/collect_auth_metrics.sh)" > "$output_file" 2>/dev/null
    
    rm -f "/tmp/collect_auth_metrics.sh"
    
    if [[ -s "$output_file" ]]; then
        success "Auth Service metrics collected: $output_file"
    else
        error "Failed to collect Auth Service metrics"
        return 1
    fi
}

# Collect Policy Service metrics
collect_policy_service_metrics() {
    local duration=$1
    local output_file=$2
    local prometheus_url="http://prometheus.monitoring.svc.cluster.local:9090"
    
    cat > "/tmp/collect_policy_metrics.sh" <<EOF
#!/bin/bash
PROM_URL="$prometheus_url"

# Response time metrics
P50=\$(curl -s "\$PROM_URL/api/v1/query?query=histogram_quantile(0.5,rate(authorization_duration_seconds_bucket{service=\"policy-service\"}[$duration]))" | jq -r '.data.result[0].value[1] // "0"')
P95=\$(curl -s "\$PROM_URL/api/v1/query?query=histogram_quantile(0.95,rate(authorization_duration_seconds_bucket{service=\"policy-service\"}[$duration]))" | jq -r '.data.result[0].value[1] // "0"')
P99=\$(curl -s "\$PROM_URL/api/v1/query?query=histogram_quantile(0.99,rate(authorization_duration_seconds_bucket{service=\"policy-service\"}[$duration]))" | jq -r '.data.result[0].value[1] // "0"')

# Throughput metrics
DECISIONS_PER_SEC=\$(curl -s "\$PROM_URL/api/v1/query?query=sum(rate(authorization_decisions_total{service=\"policy-service\"}[$duration]))" | jq -r '.data.result[0].value[1] // "0"')

# Error rate
ERROR_RATE=\$(curl -s "\$PROM_URL/api/v1/query?query=sum(rate(authorization_decisions_total{service=\"policy-service\",result=\"error\"}[$duration]))/sum(rate(authorization_decisions_total{service=\"policy-service\"}[$duration]))*100" | jq -r '.data.result[0].value[1] // "0"')

# Cache hit rate
CACHE_HIT_RATE=\$(curl -s "\$PROM_URL/api/v1/query?query=sum(rate(policy_cache_hits_total{service=\"policy-service\"}[$duration]))/sum(rate(policy_cache_requests_total{service=\"policy-service\"}[$duration]))*100" | jq -r '.data.result[0].value[1] // "0"')

cat <<JSON
{
  "service": "policy-service",
  "timestamp": "\$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration": "$duration",
  "metrics": {
    "response_time": {
      "p50_ms": \$(echo "\$P50 * 1000" | bc -l),
      "p95_ms": \$(echo "\$P95 * 1000" | bc -l),
      "p99_ms": \$(echo "\$P99 * 1000" | bc -l)
    },
    "throughput": {
      "decisions_per_sec": \$(echo "\$DECISIONS_PER_SEC" | bc -l)
    },
    "error_rate": {
      "percentage": \$(echo "\$ERROR_RATE" | bc -l)
    },
    "cache_hit_rate": {
      "percentage": \$(echo "\$CACHE_HIT_RATE" | bc -l)
    }
  }
}
JSON
EOF

    kubectl run metrics-collector --rm -i --tty --image=curlimages/curl --restart=Never -- \
        sh -c "$(cat /tmp/collect_policy_metrics.sh)" > "$output_file" 2>/dev/null
    
    rm -f "/tmp/collect_policy_metrics.sh"
    
    if [[ -s "$output_file" ]]; then
        success "Policy Service metrics collected: $output_file"
    else
        error "Failed to collect Policy Service metrics"
        return 1
    fi
}

# Collect Infrastructure metrics
collect_infrastructure_metrics() {
    local duration=$1
    local output_file=$2
    local prometheus_url="http://prometheus.monitoring.svc.cluster.local:9090"
    
    cat > "/tmp/collect_infra_metrics.sh" <<EOF
#!/bin/bash
PROM_URL="$prometheus_url"

# CPU utilization
CPU_USAGE=\$(curl -s "\$PROM_URL/api/v1/query?query=100-(avg(irate(node_cpu_seconds_total{mode=\"idle\"}[$duration]))*100)" | jq -r '.data.result[0].value[1] // "0"')

# Memory utilization
MEMORY_USAGE=\$(curl -s "\$PROM_URL/api/v1/query?query=(1-(node_memory_MemAvailable_bytes/node_memory_MemTotal_bytes))*100" | jq -r '.data.result[0].value[1] // "0"')

# Node availability
NODE_AVAILABILITY=\$(curl -s "\$PROM_URL/api/v1/query?query=count(up{job=\"kubernetes-nodes\"}==1)/count(up{job=\"kubernetes-nodes\"})*100" | jq -r '.data.result[0].value[1] // "0"')

cat <<JSON
{
  "service": "infrastructure",
  "timestamp": "\$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration": "$duration",
  "metrics": {
    "cluster_cpu": {
      "percentage": \$(echo "\$CPU_USAGE" | bc -l)
    },
    "cluster_memory": {
      "percentage": \$(echo "\$MEMORY_USAGE" | bc -l)
    },
    "node_availability": {
      "percentage": \$(echo "\$NODE_AVAILABILITY" | bc -l)
    }
  }
}
JSON
EOF

    kubectl run metrics-collector --rm -i --tty --image=curlimages/curl --restart=Never -- \
        sh -c "$(cat /tmp/collect_infra_metrics.sh)" > "$output_file" 2>/dev/null
    
    rm -f "/tmp/collect_infra_metrics.sh"
    
    if [[ -s "$output_file" ]]; then
        success "Infrastructure metrics collected: $output_file"
    else
        error "Failed to collect Infrastructure metrics"
        return 1
    fi
}

# Check performance budget compliance
check_budget_compliance() {
    local service=$1
    local metrics_file=$2
    local budget_file="$CONFIG_DIR/performance-budget.json"
    
    if [[ ! -f "$budget_file" ]]; then
        error "Performance budget not found: $budget_file"
        return 1
    fi
    
    if [[ ! -f "$metrics_file" ]]; then
        error "Metrics file not found: $metrics_file"
        return 1
    fi
    
    info "Checking budget compliance for $service"
    
    # Create compliance checker script
    local checker_script="/tmp/check_compliance.py"
    cat > "$checker_script" <<'EOF'
#!/usr/bin/env python3
import json
import sys
import math

def load_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def check_threshold(actual, budget, threshold_type, threshold_value):
    """Check if actual value violates threshold"""
    if threshold_type == "max":
        budget_limit = budget * threshold_value
        return actual > budget_limit, actual / budget
    elif threshold_type == "min":
        budget_limit = budget * threshold_value
        return actual < budget_limit, actual / budget
    return False, 1.0

def check_compliance(service, metrics_data, budget_data):
    results = {
        "service": service,
        "timestamp": metrics_data["timestamp"],
        "compliance": True,
        "violations": [],
        "warnings": [],
        "summary": {}
    }
    
    service_budget = budget_data["budgets"].get(service, {})
    if not service_budget:
        results["compliance"] = False
        results["violations"].append(f"No budget defined for service: {service}")
        return results
    
    metrics = metrics_data["metrics"]
    
    # Check response time budgets
    if "response_time" in service_budget and "response_time" in metrics:
        rt_budget = service_budget["response_time"]
        rt_metrics = metrics["response_time"]
        
        for percentile in ["p50", "p95", "p99"]:
            if percentile in rt_budget:
                budget_key = f"{percentile}_ms"
                if budget_key in rt_metrics:
                    actual = float(rt_metrics[budget_key])
                    budget = float(rt_budget[percentile]["budget_ms"])
                    warning_threshold = float(rt_budget[percentile]["warning_threshold"])
                    critical_threshold = float(rt_budget[percentile]["critical_threshold"])
                    
                    # Check critical threshold
                    is_critical, ratio = check_threshold(actual, budget, "max", critical_threshold)
                    if is_critical:
                        results["compliance"] = False
                        results["violations"].append({
                            "metric": f"response_time_{percentile}",
                            "actual": actual,
                            "budget": budget,
                            "ratio": ratio,
                            "severity": "critical"
                        })
                    else:
                        # Check warning threshold
                        is_warning, ratio = check_threshold(actual, budget, "max", warning_threshold)
                        if is_warning:
                            results["warnings"].append({
                                "metric": f"response_time_{percentile}",
                                "actual": actual,
                                "budget": budget,
                                "ratio": ratio,
                                "severity": "warning"
                            })
                    
                    results["summary"][f"response_time_{percentile}"] = {
                        "actual": actual,
                        "budget": budget,
                        "ratio": ratio,
                        "status": "critical" if is_critical else ("warning" if is_warning else "ok")
                    }
    
    # Check throughput budgets
    if "throughput" in service_budget and "throughput" in metrics:
        tp_budget = service_budget["throughput"]
        tp_metrics = metrics["throughput"]
        
        # Handle different throughput metrics
        throughput_key = "rps" if "rps" in tp_metrics else "decisions_per_sec"
        budget_key = "min_rps" if "min_rps" in tp_budget else "min_decisions_per_sec"
        
        if throughput_key in tp_metrics and budget_key in tp_budget:
            actual = float(tp_metrics[throughput_key])
            budget = float(tp_budget[budget_key])
            warning_threshold = float(tp_budget["warning_threshold"])
            critical_threshold = float(tp_budget["critical_threshold"])
            
            # Check critical threshold (minimum throughput)
            is_critical, ratio = check_threshold(actual, budget, "min", critical_threshold)
            if is_critical:
                results["compliance"] = False
                results["violations"].append({
                    "metric": "throughput",
                    "actual": actual,
                    "budget": budget,
                    "ratio": ratio,
                    "severity": "critical"
                })
            else:
                is_warning, ratio = check_threshold(actual, budget, "min", warning_threshold)
                if is_warning:
                    results["warnings"].append({
                        "metric": "throughput",
                        "actual": actual,
                        "budget": budget,
                        "ratio": ratio,
                        "severity": "warning"
                    })
            
            results["summary"]["throughput"] = {
                "actual": actual,
                "budget": budget,
                "ratio": ratio,
                "status": "critical" if is_critical else ("warning" if is_warning else "ok")
            }
    
    # Check error rate budgets
    if "error_rate" in service_budget and "error_rate" in metrics:
        er_budget = service_budget["error_rate"]
        er_metrics = metrics["error_rate"]
        
        if "percentage" in er_metrics:
            actual = float(er_metrics["percentage"])
            budget = float(er_budget["max_percentage"])
            warning_threshold = float(er_budget["warning_threshold"])
            critical_threshold = float(er_budget["critical_threshold"])
            
            is_critical, ratio = check_threshold(actual, budget, "max", critical_threshold)
            if is_critical:
                results["compliance"] = False
                results["violations"].append({
                    "metric": "error_rate",
                    "actual": actual,
                    "budget": budget,
                    "ratio": ratio,
                    "severity": "critical"
                })
            else:
                is_warning, ratio = check_threshold(actual, budget, "max", warning_threshold)
                if is_warning:
                    results["warnings"].append({
                        "metric": "error_rate",
                        "actual": actual,
                        "budget": budget,
                        "ratio": ratio,
                        "severity": "warning"
                    })
            
            results["summary"]["error_rate"] = {
                "actual": actual,
                "budget": budget,
                "ratio": ratio,
                "status": "critical" if is_critical else ("warning" if is_warning else "ok")
            }
    
    return results

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: check_compliance.py <service> <metrics_file> <budget_file>")
        sys.exit(1)
    
    service = sys.argv[1]
    metrics_file = sys.argv[2]
    budget_file = sys.argv[3]
    
    try:
        metrics_data = load_json(metrics_file)
        budget_data = load_json(budget_file)
        
        results = check_compliance(service, metrics_data, budget_data)
        print(json.dumps(results, indent=2))
        
        # Exit with error code if compliance failed
        if not results["compliance"]:
            sys.exit(1)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
EOF

    # Run compliance check
    local compliance_result="$RESULTS_DIR/compliance-${service}-$(date +%Y%m%d-%H%M%S).json"
    
    if python3 "$checker_script" "$service" "$metrics_file" "$budget_file" > "$compliance_result" 2>/dev/null; then
        success "Budget compliance check passed for $service"
        local compliance_status="PASS"
    else
        warn "Budget compliance check failed for $service"
        local compliance_status="FAIL"
    fi
    
    # Clean up
    rm -f "$checker_script"
    
    # Display results
    if [[ -f "$compliance_result" ]]; then
        echo "Compliance Results for $service:"
        echo "================================"
        jq -r '.summary | to_entries[] | "\(.key): \(.value.status) (actual: \(.value.actual), budget: \(.value.budget), ratio: \(.value.ratio))"' "$compliance_result" 2>/dev/null || echo "Results saved to: $compliance_result"
        
        # Show violations if any
        local violations=$(jq -r '.violations[]? | "VIOLATION: \(.metric) - actual: \(.actual), budget: \(.budget), severity: \(.severity)"' "$compliance_result" 2>/dev/null)
        if [[ -n "$violations" ]]; then
            echo ""
            echo "VIOLATIONS:"
            echo "$violations"
        fi
        
        # Show warnings if any
        local warnings=$(jq -r '.warnings[]? | "WARNING: \(.metric) - actual: \(.actual), budget: \(.budget), severity: \(.severity)"' "$compliance_result" 2>/dev/null)
        if [[ -n "$warnings" ]]; then
            echo ""
            echo "WARNINGS:"
            echo "$warnings"
        fi
    fi
    
    echo "$compliance_result"
}

# Detect performance regressions
detect_regressions() {
    local service=$1
    local current_metrics_file=$2
    local baseline_dir="$BASELINES_DIR/$service"
    
    info "Detecting performance regressions for $service"
    
    if [[ ! -d "$baseline_dir" ]]; then
        warn "No baseline found for $service. Creating initial baseline."
        create_baseline "$service" "$current_metrics_file"
        return 0
    fi
    
    # Find the most recent baseline
    local baseline_file=$(find "$baseline_dir" -name "baseline-*.json" | sort | tail -1)
    if [[ ! -f "$baseline_file" ]]; then
        warn "No baseline file found for $service"
        return 1
    fi
    
    info "Comparing against baseline: $(basename "$baseline_file")"
    
    # Create regression detection script
    local detector_script="/tmp/detect_regressions.py"
    cat > "$detector_script" <<'EOF'
#!/usr/bin/env python3
import json
import sys
import statistics
import math

def load_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def calculate_regression(current_value, baseline_mean, baseline_std, regression_threshold):
    """Calculate if there's a significant regression"""
    if baseline_std == 0:
        # If no variance in baseline, use simple threshold
        change_ratio = abs(current_value - baseline_mean) / baseline_mean if baseline_mean > 0 else 0
        return change_ratio > regression_threshold, change_ratio
    
    # Calculate z-score
    z_score = (current_value - baseline_mean) / baseline_std
    
    # Calculate percentage change
    change_ratio = (current_value - baseline_mean) / baseline_mean if baseline_mean > 0 else 0
    
    # Regression if z-score > 2 (95% confidence) AND change > threshold
    is_regression = abs(z_score) > 2.0 and abs(change_ratio) > regression_threshold
    
    return is_regression, change_ratio

def detect_regressions(service, current_data, baseline_data, budget_data):
    results = {
        "service": service,
        "timestamp": current_data["timestamp"],
        "baseline_timestamp": baseline_data["timestamp"],
        "regressions_detected": False,
        "regressions": [],
        "summary": {}
    }
    
    current_metrics = current_data["metrics"]
    baseline_metrics = baseline_data["baseline_metrics"]
    service_budget = budget_data["budgets"].get(service, {})
    
    # Check response time regressions
    if "response_time" in current_metrics and "response_time" in baseline_metrics:
        rt_current = current_metrics["response_time"]
        rt_baseline = baseline_metrics["response_time"]
        rt_budget = service_budget.get("response_time", {})
        
        for percentile in ["p50", "p95", "p99"]:
            current_key = f"{percentile}_ms"
            if current_key in rt_current and percentile in rt_baseline:
                current_value = float(rt_current[current_key])
                baseline_mean = float(rt_baseline[percentile]["mean"])
                baseline_std = float(rt_baseline[percentile]["std"])
                
                # Get regression threshold from budget
                regression_threshold = 0.15  # default
                if percentile in rt_budget:
                    regression_threshold = float(rt_budget[percentile].get("regression_threshold", 0.15))
                
                is_regression, change_ratio = calculate_regression(
                    current_value, baseline_mean, baseline_std, regression_threshold
                )
                
                if is_regression:
                    results["regressions_detected"] = True
                    results["regressions"].append({
                        "metric": f"response_time_{percentile}",
                        "current_value": current_value,
                        "baseline_mean": baseline_mean,
                        "baseline_std": baseline_std,
                        "change_percentage": change_ratio * 100,
                        "regression_threshold": regression_threshold * 100,
                        "severity": "high" if abs(change_ratio) > 0.25 else "medium"
                    })
                
                results["summary"][f"response_time_{percentile}"] = {
                    "current": current_value,
                    "baseline_mean": baseline_mean,
                    "change_percentage": change_ratio * 100,
                    "status": "regression" if is_regression else "ok"
                }
    
    # Check throughput regressions
    if "throughput" in current_metrics and "throughput" in baseline_metrics:
        tp_current = current_metrics["throughput"]
        tp_baseline = baseline_metrics["throughput"]
        tp_budget = service_budget.get("throughput", {})
        
        # Handle different throughput metrics
        current_key = "rps" if "rps" in tp_current else "decisions_per_sec"
        baseline_key = "rps" if "rps" in tp_baseline else "decisions_per_sec"
        
        if current_key in tp_current and baseline_key in tp_baseline:
            current_value = float(tp_current[current_key])
            baseline_mean = float(tp_baseline[baseline_key]["mean"])
            baseline_std = float(tp_baseline[baseline_key]["std"])
            
            regression_threshold = float(tp_budget.get("regression_threshold", 0.10))
            
            # For throughput, regression is a decrease
            is_regression = current_value < (baseline_mean * (1 - regression_threshold))
            change_ratio = (current_value - baseline_mean) / baseline_mean if baseline_mean > 0 else 0
            
            if is_regression:
                results["regressions_detected"] = True
                results["regressions"].append({
                    "metric": "throughput",
                    "current_value": current_value,
                    "baseline_mean": baseline_mean,
                    "baseline_std": baseline_std,
                    "change_percentage": change_ratio * 100,
                    "regression_threshold": regression_threshold * 100,
                    "severity": "high" if abs(change_ratio) > 0.20 else "medium"
                })
            
            results["summary"]["throughput"] = {
                "current": current_value,
                "baseline_mean": baseline_mean,
                "change_percentage": change_ratio * 100,
                "status": "regression" if is_regression else "ok"
            }
    
    return results

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: detect_regressions.py <service> <current_file> <baseline_file> <budget_file>")
        sys.exit(1)
    
    service = sys.argv[1]
    current_file = sys.argv[2]
    baseline_file = sys.argv[3]
    budget_file = sys.argv[4]
    
    try:
        current_data = load_json(current_file)
        baseline_data = load_json(baseline_file)
        budget_data = load_json(budget_file)
        
        results = detect_regressions(service, current_data, baseline_data, budget_data)
        print(json.dumps(results, indent=2))
        
        # Exit with error code if regressions detected
        if results["regressions_detected"]:
            sys.exit(1)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
EOF

    # Run regression detection
    local regression_result="$RESULTS_DIR/regressions-${service}-$(date +%Y%m%d-%H%M%S).json"
    
    if python3 "$detector_script" "$service" "$current_metrics_file" "$baseline_file" "$CONFIG_DIR/performance-budget.json" > "$regression_result" 2>/dev/null; then
        success "No performance regressions detected for $service"
        local regression_status="PASS"
    else
        warn "Performance regressions detected for $service"
        local regression_status="FAIL"
    fi
    
    # Clean up
    rm -f "$detector_script"
    
    # Display results
    if [[ -f "$regression_result" ]]; then
        echo ""
        echo "Regression Analysis for $service:"
        echo "================================="
        
        local regressions_detected=$(jq -r '.regressions_detected' "$regression_result" 2>/dev/null)
        if [[ "$regressions_detected" == "true" ]]; then
            echo "⚠ REGRESSIONS DETECTED:"
            jq -r '.regressions[] | "  \(.metric): \(.change_percentage | round)% change (threshold: \(.regression_threshold)%, severity: \(.severity))"' "$regression_result" 2>/dev/null
        else
            echo "✓ No regressions detected"
        fi
        
        echo ""
        echo "Summary:"
        jq -r '.summary | to_entries[] | "  \(.key): \(.value.change_percentage | round)% change (\(.value.status))"' "$regression_result" 2>/dev/null
    fi
    
    echo "$regression_result"
}

# Create baseline from historical data
create_baseline() {
    local service=$1
    local metrics_file=$2
    local baseline_dir="$BASELINES_DIR/$service"
    
    mkdir -p "$baseline_dir"
    
    info "Creating baseline for $service"
    
    # For now, create a simple baseline from the current metrics
    # In a real implementation, this would aggregate historical data
    local baseline_file="$baseline_dir/baseline-$(date +%Y%m%d-%H%M%S).json"
    
    # Create baseline generation script
    local generator_script="/tmp/create_baseline.py"
    cat > "$generator_script" <<'EOF'
#!/usr/bin/env python3
import json
import sys

def create_baseline(metrics_data):
    """Create baseline from current metrics (simplified for demonstration)"""
    baseline = {
        "service": metrics_data["service"],
        "timestamp": metrics_data["timestamp"],
        "baseline_type": "single_sample",
        "baseline_metrics": {}
    }
    
    metrics = metrics_data["metrics"]
    
    # Create baseline for response time
    if "response_time" in metrics:
        rt_metrics = metrics["response_time"]
        baseline["baseline_metrics"]["response_time"] = {}
        
        for percentile in ["p50", "p95", "p99"]:
            key = f"{percentile}_ms"
            if key in rt_metrics:
                value = float(rt_metrics[key])
                baseline["baseline_metrics"]["response_time"][percentile] = {
                    "mean": value,
                    "std": value * 0.05,  # Assume 5% std dev for initial baseline
                    "samples": 1,
                    "min": value,
                    "max": value
                }
    
    # Create baseline for throughput
    if "throughput" in metrics:
        tp_metrics = metrics["throughput"]
        baseline["baseline_metrics"]["throughput"] = {}
        
        for key in ["rps", "decisions_per_sec"]:
            if key in tp_metrics:
                value = float(tp_metrics[key])
                baseline["baseline_metrics"]["throughput"][key] = {
                    "mean": value,
                    "std": value * 0.1,  # Assume 10% std dev for throughput
                    "samples": 1,
                    "min": value,
                    "max": value
                }
    
    # Create baseline for error rate
    if "error_rate" in metrics:
        er_metrics = metrics["error_rate"]
        if "percentage" in er_metrics:
            value = float(er_metrics["percentage"])
            baseline["baseline_metrics"]["error_rate"] = {
                "percentage": {
                    "mean": value,
                    "std": max(value * 0.2, 0.01),  # Minimum 0.01% std dev
                    "samples": 1,
                    "min": value,
                    "max": value
                }
            }
    
    return baseline

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: create_baseline.py <metrics_file>")
        sys.exit(1)
    
    metrics_file = sys.argv[1]
    
    try:
        with open(metrics_file, 'r') as f:
            metrics_data = json.load(f)
        
        baseline = create_baseline(metrics_data)
        print(json.dumps(baseline, indent=2))
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
EOF

    # Generate baseline
    if python3 "$generator_script" "$metrics_file" > "$baseline_file" 2>/dev/null; then
        success "Baseline created: $baseline_file"
    else
        error "Failed to create baseline for $service"
        rm -f "$generator_script"
        return 1
    fi
    
    # Clean up
    rm -f "$generator_script"
    
    echo "$baseline_file"
}

# Generate performance report
generate_report() {
    local report_file="$REPORTS_DIR/performance-report-$(date +%Y%m%d-%H%M%S).html"
    
    info "Generating performance report: $report_file"
    
    # Create HTML report
    cat > "$report_file" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rust Security Platform - Performance Report</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px; 
        }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 30px; 
            border-radius: 10px; 
            margin-bottom: 30px; 
        }
        .metric-card { 
            background: white; 
            border: 1px solid #e1e5e9; 
            border-radius: 8px; 
            padding: 20px; 
            margin: 20px 0; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-warning { color: #ffc107; font-weight: bold; }
        .status-critical { color: #dc3545; font-weight: bold; }
        .status-regression { color: #fd7e14; font-weight: bold; }
        .metric-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 20px; 
        }
        .metric-value { 
            font-size: 2em; 
            font-weight: bold; 
            margin: 10px 0; 
        }
        .metric-label { 
            font-size: 0.9em; 
            color: #666; 
            text-transform: uppercase; 
            letter-spacing: 1px; 
        }
        .progress-bar { 
            width: 100%; 
            height: 8px; 
            background: #e9ecef; 
            border-radius: 4px; 
            overflow: hidden; 
            margin: 10px 0; 
        }
        .progress-fill { 
            height: 100%; 
            transition: width 0.3s ease; 
        }
        .progress-ok { background: #28a745; }
        .progress-warning { background: #ffc107; }
        .progress-critical { background: #dc3545; }
        .footer { 
            margin-top: 40px; 
            padding: 20px; 
            background: #f8f9fa; 
            border-radius: 8px; 
            text-align: center; 
            color: #666; 
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 Rust Security Platform</h1>
        <h2>Performance Budget Report</h2>
        <p>Generated on: TIMESTAMP_PLACEHOLDER</p>
    </div>

    <div class="metric-grid">
        <!-- Performance metrics will be inserted here -->
        METRICS_PLACEHOLDER
    </div>

    <div class="footer">
        <p>This report is automatically generated by the Performance Budget Monitor</p>
        <p>For more information, see the <a href="../docs/operations/migration-guide.md">Operations Guide</a></p>
    </div>
</body>
</html>
EOF

    # Replace placeholders
    sed -i "s/TIMESTAMP_PLACEHOLDER/$(date)/g" "$report_file"
    
    # Add metrics data (simplified for now)
    local metrics_html="<div class=\"metric-card\"><h3>📊 Performance Metrics</h3><p>Detailed metrics will be populated by future enhancements</p></div>"
    sed -i "s/METRICS_PLACEHOLDER/$metrics_html/g" "$report_file"
    
    success "Performance report generated: $report_file"
    echo "$report_file"
}

# Main monitoring function
monitor() {
    local services=("auth-service" "policy-service" "infrastructure")
    local duration=${1:-"5m"}
    local overall_status="PASS"
    
    info "Starting performance budget monitoring (duration: $duration)"
    
    # Ensure performance budget exists
    create_performance_budget
    
    for service in "${services[@]}"; do
        info "Monitoring $service..."
        
        # Collect metrics
        local metrics_file
        if metrics_file=$(collect_metrics "$service" "$duration"); then
            info "Metrics collected for $service: $metrics_file"
            
            # Check budget compliance
            local compliance_file
            if compliance_file=$(check_budget_compliance "$service" "$metrics_file"); then
                info "Budget compliance checked for $service"
            else
                warn "Budget compliance failed for $service"
                overall_status="FAIL"
            fi
            
            # Detect regressions
            local regression_file
            if regression_file=$(detect_regressions "$service" "$metrics_file"); then
                info "Regression detection completed for $service"
            else
                warn "Performance regressions detected for $service"
                overall_status="FAIL"
            fi
            
        else
            error "Failed to collect metrics for $service"
            overall_status="FAIL"
        fi
        
        echo "----------------------------------------"
    done
    
    # Generate report
    generate_report
    
    # Final status
    if [[ "$overall_status" == "PASS" ]]; then
        success "Performance budget monitoring completed successfully"
        return 0
    else
        warn "Performance budget monitoring detected issues"
        return 1
    fi
}

# Usage information
usage() {
    cat << EOF
Performance Budget Monitor for Rust Security Platform

Usage: $0 <command> [arguments]

Commands:
    monitor [duration]              - Run complete performance monitoring (default: 5m)
    collect <service> [duration]    - Collect metrics for specific service
    check <service> <metrics_file>  - Check budget compliance
    regression <service> <metrics>  - Detect performance regressions
    baseline <service> <metrics>    - Create performance baseline
    report                         - Generate performance report
    create-budget                  - Create performance budget configuration

Services:
    auth-service     - Authentication service
    policy-service   - Authorization service  
    infrastructure   - Cluster infrastructure

Examples:
    $0 monitor                      # Run full monitoring with 5m duration
    $0 monitor 10m                  # Run full monitoring with 10m duration
    $0 collect auth-service         # Collect auth service metrics
    $0 create-budget               # Create initial performance budget

EOF
}

# Main execution
main() {
    local command=${1:-""}
    
    case "$command" in
        "monitor")
            monitor "${2:-5m}"
            ;;
        "collect")
            if [[ $# -lt 2 ]]; then
                error "Service name required"
                usage
                exit 1
            fi
            collect_metrics "$2" "${3:-5m}"
            ;;
        "check")
            if [[ $# -lt 3 ]]; then
                error "Service name and metrics file required"
                usage
                exit 1
            fi
            check_budget_compliance "$2" "$3"
            ;;
        "regression")
            if [[ $# -lt 3 ]]; then
                error "Service name and metrics file required"
                usage
                exit 1
            fi
            detect_regressions "$2" "$3"
            ;;
        "baseline")
            if [[ $# -lt 3 ]]; then
                error "Service name and metrics file required"
                usage
                exit 1
            fi
            create_baseline "$2" "$3"
            ;;
        "report")
            generate_report
            ;;
        "create-budget")
            create_performance_budget
            ;;
        "help"|"-h"|"--help"|"")
            usage
            ;;
        *)
            error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi