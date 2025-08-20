#!/bin/bash
# Automated Load Testing for Rust Security Platform
# Continuous performance testing with regression detection

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_CONFIG_DIR="$SCRIPT_DIR/test-configs"
TEST_RESULTS_DIR="$SCRIPT_DIR/test-results"
LOAD_TEST_SCRIPTS_DIR="$SCRIPT_DIR/load-tests"

# Create directories
mkdir -p "$TEST_CONFIG_DIR" "$TEST_RESULTS_DIR" "$LOAD_TEST_SCRIPTS_DIR"

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
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$TEST_RESULTS_DIR/load-test.log"
}

info() { log "${BLUE}INFO${NC}" "$@"; }
warn() { log "${YELLOW}WARN${NC}" "$@"; }
error() { log "${RED}ERROR${NC}" "$@"; }
success() { log "${GREEN}SUCCESS${NC}" "$@"; }

# Create load test configurations
create_test_configs() {
    info "Creating load test configurations..."
    
    # Auth Service Load Test Configuration
    cat > "$TEST_CONFIG_DIR/auth-service-load-test.json" <<'EOF'
{
  "name": "auth-service-load-test",
  "description": "Load test for Authentication Service",
  "target": {
    "base_url": "https://auth.example.com",
    "endpoints": [
      {
        "path": "/login",
        "method": "POST",
        "weight": 40,
        "payload": {
          "email": "loadtest{{.ID}}@example.com",
          "password": "LoadTest123!"
        },
        "headers": {
          "Content-Type": "application/json"
        }
      },
      {
        "path": "/token/refresh",
        "method": "POST", 
        "weight": 30,
        "auth_required": true,
        "payload": {
          "refresh_token": "{{.RefreshToken}}"
        },
        "headers": {
          "Content-Type": "application/json"
        }
      },
      {
        "path": "/user/profile",
        "method": "GET",
        "weight": 20,
        "auth_required": true,
        "headers": {
          "Authorization": "Bearer {{.Token}}"
        }
      },
      {
        "path": "/logout",
        "method": "POST",
        "weight": 10,
        "auth_required": true,
        "headers": {
          "Authorization": "Bearer {{.Token}}"
        }
      }
    ]
  },
  "load_profiles": {
    "smoke": {
      "virtual_users": 10,
      "duration": "2m",
      "ramp_up": "30s"
    },
    "baseline": {
      "virtual_users": 100,
      "duration": "10m",
      "ramp_up": "2m"
    },
    "stress": {
      "virtual_users": 500,
      "duration": "15m",
      "ramp_up": "5m"
    },
    "spike": {
      "virtual_users": 1000,
      "duration": "5m",
      "ramp_up": "30s"
    },
    "endurance": {
      "virtual_users": 200,
      "duration": "60m",
      "ramp_up": "5m"
    }
  },
  "success_criteria": {
    "response_time": {
      "p95": 200,
      "p99": 500
    },
    "error_rate": {
      "max_percentage": 1.0
    },
    "throughput": {
      "min_rps": 800
    }
  }
}
EOF

    # Policy Service Load Test Configuration
    cat > "$TEST_CONFIG_DIR/policy-service-load-test.json" <<'EOF'
{
  "name": "policy-service-load-test",
  "description": "Load test for Policy Service",
  "target": {
    "base_url": "https://policy.example.com",
    "endpoints": [
      {
        "path": "/authorize",
        "method": "POST",
        "weight": 80,
        "payload": {
          "user": "user{{.ID}}@example.com",
          "action": "{{.RandomAction}}",
          "resource": "{{.RandomResource}}",
          "context": {
            "ip": "{{.RandomIP}}",
            "time": "{{.CurrentTime}}"
          }
        },
        "headers": {
          "Content-Type": "application/json",
          "Authorization": "Bearer {{.Token}}"
        }
      },
      {
        "path": "/policies",
        "method": "GET",
        "weight": 15,
        "headers": {
          "Authorization": "Bearer {{.AdminToken}}"
        }
      },
      {
        "path": "/health",
        "method": "GET",
        "weight": 5
      }
    ]
  },
  "load_profiles": {
    "smoke": {
      "virtual_users": 20,
      "duration": "2m",
      "ramp_up": "30s"
    },
    "baseline": {
      "virtual_users": 200,
      "duration": "10m",
      "ramp_up": "2m"
    },
    "stress": {
      "virtual_users": 1000,
      "duration": "15m",
      "ramp_up": "5m"
    },
    "spike": {
      "virtual_users": 2000,
      "duration": "5m",
      "ramp_up": "30s"
    }
  },
  "success_criteria": {
    "response_time": {
      "p95": 50,
      "p99": 100
    },
    "error_rate": {
      "max_percentage": 0.1
    },
    "throughput": {
      "min_decisions_per_sec": 4000
    }
  }
}
EOF

    success "Load test configurations created"
}

# Create K6 load test scripts
create_k6_scripts() {
    info "Creating K6 load test scripts..."
    
    # Auth Service K6 Script
    cat > "$LOAD_TEST_SCRIPTS_DIR/auth-service-k6.js" <<'EOF'
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
export let errorRate = new Rate('errors');
export let loginTrend = new Trend('login_duration');
export let refreshTrend = new Trend('token_refresh_duration');

// Test configuration
export let options = {
  stages: [
    { duration: '2m', target: 100 },
    { duration: '10m', target: 100 },
    { duration: '2m', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<200', 'p(99)<500'],
    http_req_failed: ['rate<0.01'],
    errors: ['rate<0.01'],
  },
};

// Test data
const BASE_URL = __ENV.BASE_URL || 'https://auth.example.com';
const users = [];

export function setup() {
  console.log('Setting up test data...');
  // Pre-create test users
  for (let i = 0; i < 1000; i++) {
    users.push({
      email: `loadtest${i}@example.com`,
      password: 'LoadTest123!',
      id: i
    });
  }
  return { users: users };
}

export default function(data) {
  const user = data.users[Math.floor(Math.random() * data.users.length)];
  
  // Login flow
  const loginResponse = http.post(`${BASE_URL}/login`, JSON.stringify({
    email: user.email,
    password: user.password
  }), {
    headers: { 'Content-Type': 'application/json' },
  });
  
  const loginSuccess = check(loginResponse, {
    'login status is 200': (r) => r.status === 200,
    'login response time < 200ms': (r) => r.timings.duration < 200,
    'has access token': (r) => r.json('access_token') !== undefined,
  });
  
  errorRate.add(!loginSuccess);
  loginTrend.add(loginResponse.timings.duration);
  
  if (loginSuccess && loginResponse.json('access_token')) {
    const token = loginResponse.json('access_token');
    const refreshToken = loginResponse.json('refresh_token');
    
    // Get user profile
    const profileResponse = http.get(`${BASE_URL}/user/profile`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    
    check(profileResponse, {
      'profile status is 200': (r) => r.status === 200,
      'profile response time < 100ms': (r) => r.timings.duration < 100,
    });
    
    // Refresh token (30% chance)
    if (Math.random() < 0.3 && refreshToken) {
      const refreshResponse = http.post(`${BASE_URL}/token/refresh`, JSON.stringify({
        refresh_token: refreshToken
      }), {
        headers: { 'Content-Type': 'application/json' },
      });
      
      const refreshSuccess = check(refreshResponse, {
        'refresh status is 200': (r) => r.status === 200,
        'refresh response time < 100ms': (r) => r.timings.duration < 100,
      });
      
      refreshTrend.add(refreshResponse.timings.duration);
    }
    
    // Logout (20% chance)
    if (Math.random() < 0.2) {
      http.post(`${BASE_URL}/logout`, null, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
    }
  }
  
  sleep(Math.random() * 2 + 1); // 1-3 second think time
}

export function teardown(data) {
  console.log('Cleaning up test data...');
}
EOF

    # Policy Service K6 Script
    cat > "$LOAD_TEST_SCRIPTS_DIR/policy-service-k6.js" <<'EOF'
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
export let errorRate = new Rate('errors');
export let authorizationTrend = new Trend('authorization_duration');

// Test configuration
export let options = {
  stages: [
    { duration: '2m', target: 200 },
    { duration: '10m', target: 200 },
    { duration: '2m', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<50', 'p(99)<100'],
    http_req_failed: ['rate<0.001'],
    errors: ['rate<0.001'],
  },
};

// Test data
const BASE_URL = __ENV.BASE_URL || 'https://policy.example.com';
const actions = ['read', 'write', 'delete', 'admin:read', 'admin:write'];
const resources = ['user_profile', 'admin_panel', 'user_data', 'system_config', 'audit_logs'];
const users = [];
const adminToken = __ENV.ADMIN_TOKEN || 'admin_token_placeholder';

export function setup() {
  console.log('Setting up policy test data...');
  for (let i = 0; i < 500; i++) {
    users.push(`user${i}@example.com`);
  }
  return { users: users };
}

export default function(data) {
  const user = data.users[Math.floor(Math.random() * data.users.length)];
  const action = actions[Math.floor(Math.random() * actions.length)];
  const resource = resources[Math.floor(Math.random() * resources.length)];
  
  // Authorization request
  const authRequest = {
    user: user,
    action: action,
    resource: resource,
    context: {
      ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
      time: new Date().toISOString(),
      department: Math.random() > 0.5 ? 'engineering' : 'marketing'
    }
  };
  
  const authResponse = http.post(`${BASE_URL}/authorize`, JSON.stringify(authRequest), {
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${adminToken}`
    },
  });
  
  const authSuccess = check(authResponse, {
    'authorization status is 200': (r) => r.status === 200,
    'authorization response time < 50ms': (r) => r.timings.duration < 50,
    'has decision': (r) => r.json('decision') !== undefined,
  });
  
  errorRate.add(!authSuccess);
  authorizationTrend.add(authResponse.timings.duration);
  
  // Health check (5% chance)
  if (Math.random() < 0.05) {
    const healthResponse = http.get(`${BASE_URL}/health`);
    check(healthResponse, {
      'health status is 200': (r) => r.status === 200,
    });
  }
  
  sleep(Math.random() * 0.5 + 0.1); // 0.1-0.6 second think time
}

export function teardown(data) {
  console.log('Policy test cleanup complete');
}
EOF

    success "K6 load test scripts created"
}

# Run load test
run_load_test() {
    local service=$1
    local profile=${2:-"baseline"}
    local config_file="$TEST_CONFIG_DIR/${service}-load-test.json"
    local script_file="$LOAD_TEST_SCRIPTS_DIR/${service}-k6.js"
    local result_file="$TEST_RESULTS_DIR/load-test-${service}-${profile}-$(date +%Y%m%d-%H%M%S).json"
    
    if [[ ! -f "$config_file" ]]; then
        error "Load test configuration not found: $config_file"
        return 1
    fi
    
    if [[ ! -f "$script_file" ]]; then
        error "Load test script not found: $script_file"
        return 1
    fi
    
    info "Running load test for $service with profile: $profile"
    
    # Extract test parameters from configuration
    local virtual_users=$(jq -r ".load_profiles.$profile.virtual_users" "$config_file")
    local duration=$(jq -r ".load_profiles.$profile.duration" "$config_file")
    local ramp_up=$(jq -r ".load_profiles.$profile.ramp_up" "$config_file")
    
    if [[ "$virtual_users" == "null" ]]; then
        error "Load profile '$profile' not found in configuration"
        return 1
    fi
    
    info "Test parameters: VUs=$virtual_users, Duration=$duration, Ramp-up=$ramp_up"
    
    # Check if K6 is available
    if ! command -v k6 >/dev/null 2>&1; then
        warn "K6 not found locally, using containerized version"
        run_containerized_k6_test "$service" "$profile" "$virtual_users" "$duration" "$ramp_up" "$result_file"
    else
        # Run K6 test directly
        local base_url=$(jq -r '.target.base_url' "$config_file")
        
        K6_PROMETHEUS_RW_SERVER_URL="http://prometheus.monitoring.svc.cluster.local:9090/api/v1/write" \
        BASE_URL="$base_url" \
        k6 run \
            --vus "$virtual_users" \
            --duration "$duration" \
            --ramp-up-duration "$ramp_up" \
            --out json="$result_file" \
            --out prometheus-remote-write \
            "$script_file"
    fi
    
    if [[ $? -eq 0 ]]; then
        success "Load test completed: $result_file"
        analyze_test_results "$service" "$result_file" "$config_file"
    else
        error "Load test failed for $service"
        return 1
    fi
    
    echo "$result_file"
}

# Run containerized K6 test
run_containerized_k6_test() {
    local service=$1
    local profile=$2
    local virtual_users=$3
    local duration=$4
    local ramp_up=$5
    local result_file=$6
    
    info "Running containerized K6 test..."
    
    # Create K6 test ConfigMap
    kubectl create configmap k6-test-script \
        --from-file="test.js=$LOAD_TEST_SCRIPTS_DIR/${service}-k6.js" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Create K6 test job
    cat > "/tmp/k6-job.yaml" <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: k6-load-test-${service}-$(date +%s)
  namespace: rust-security
spec:
  template:
    spec:
      containers:
      - name: k6
        image: grafana/k6:latest
        command: ["k6", "run"]
        args: [
          "--vus", "$virtual_users",
          "--duration", "$duration",
          "--ramp-up-duration", "$ramp_up",
          "--out", "json=/results/results.json",
          "/scripts/test.js"
        ]
        env:
        - name: BASE_URL
          value: "$(jq -r '.target.base_url' "$TEST_CONFIG_DIR/${service}-load-test.json")"
        - name: K6_PROMETHEUS_RW_SERVER_URL
          value: "http://prometheus.monitoring.svc.cluster.local:9090/api/v1/write"
        volumeMounts:
        - name: test-scripts
          mountPath: /scripts
        - name: test-results
          mountPath: /results
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 2000m
            memory: 2Gi
      volumes:
      - name: test-scripts
        configMap:
          name: k6-test-script
      - name: test-results
        emptyDir: {}
      restartPolicy: Never
  backoffLimit: 1
EOF

    # Run the job
    kubectl apply -f "/tmp/k6-job.yaml"
    
    # Wait for job completion
    local job_name=$(grep "name: k6-load-test" /tmp/k6-job.yaml | head -1 | awk '{print $2}')
    kubectl wait --for=condition=complete --timeout=3600s job/"$job_name" -n rust-security
    
    # Get results
    local pod_name=$(kubectl get pods -l job-name="$job_name" -n rust-security -o jsonpath='{.items[0].metadata.name}')
    kubectl cp "rust-security/$pod_name:/results/results.json" "$result_file"
    
    # Cleanup
    kubectl delete job "$job_name" -n rust-security
    kubectl delete configmap k6-test-script -n rust-security
    rm -f "/tmp/k6-job.yaml"
    
    success "Containerized K6 test completed"
}

# Analyze test results
analyze_test_results() {
    local service=$1
    local result_file=$2
    local config_file=$3
    
    info "Analyzing test results for $service"
    
    # Create analysis script
    local analyzer_script="/tmp/analyze_results.py"
    cat > "$analyzer_script" <<'EOF'
#!/usr/bin/env python3
import json
import sys
import statistics

def analyze_k6_results(result_file, config_file):
    """Analyze K6 JSON results against success criteria"""
    
    # Load results
    metrics = {}
    with open(result_file, 'r') as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                if data.get('type') == 'Point':
                    metric_name = data.get('metric')
                    if metric_name not in metrics:
                        metrics[metric_name] = []
                    metrics[metric_name].append(data.get('data', {}).get('value', 0))
    
    # Load success criteria
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    criteria = config.get('success_criteria', {})
    
    # Calculate key metrics
    results = {
        'service': config.get('name', 'unknown'),
        'timestamp': data.get('data', {}).get('time', ''),
        'success': True,
        'metrics': {},
        'violations': []
    }
    
    # Response time analysis
    if 'http_req_duration' in metrics:
        durations = sorted(metrics['http_req_duration'])
        if durations:
            p50 = durations[int(len(durations) * 0.5)]
            p95 = durations[int(len(durations) * 0.95)]
            p99 = durations[int(len(durations) * 0.99)]
            
            results['metrics']['response_time'] = {
                'p50': p50,
                'p95': p95,
                'p99': p99,
                'mean': statistics.mean(durations)
            }
            
            # Check against criteria
            rt_criteria = criteria.get('response_time', {})
            if 'p95' in rt_criteria and p95 > rt_criteria['p95']:
                results['success'] = False
                results['violations'].append({
                    'metric': 'response_time_p95',
                    'actual': p95,
                    'threshold': rt_criteria['p95']
                })
            
            if 'p99' in rt_criteria and p99 > rt_criteria['p99']:
                results['success'] = False
                results['violations'].append({
                    'metric': 'response_time_p99',
                    'actual': p99,
                    'threshold': rt_criteria['p99']
                })
    
    # Error rate analysis
    if 'http_req_failed' in metrics:
        error_rate = statistics.mean(metrics['http_req_failed']) * 100
        results['metrics']['error_rate'] = error_rate
        
        er_criteria = criteria.get('error_rate', {})
        if 'max_percentage' in er_criteria and error_rate > er_criteria['max_percentage']:
            results['success'] = False
            results['violations'].append({
                'metric': 'error_rate',
                'actual': error_rate,
                'threshold': er_criteria['max_percentage']
            })
    
    # Throughput analysis
    if 'http_reqs' in metrics:
        total_requests = sum(metrics['http_reqs'])
        # Estimate duration from data points
        duration_minutes = len(metrics['http_reqs']) / 60  # Assuming 1-second intervals
        rps = total_requests / (duration_minutes * 60) if duration_minutes > 0 else 0
        
        results['metrics']['throughput'] = {
            'rps': rps,
            'total_requests': total_requests
        }
        
        tp_criteria = criteria.get('throughput', {})
        if 'min_rps' in tp_criteria and rps < tp_criteria['min_rps']:
            results['success'] = False
            results['violations'].append({
                'metric': 'throughput',
                'actual': rps,
                'threshold': tp_criteria['min_rps']
            })
    
    return results

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: analyze_results.py <result_file> <config_file>")
        sys.exit(1)
    
    result_file = sys.argv[1]
    config_file = sys.argv[2]
    
    try:
        analysis = analyze_k6_results(result_file, config_file)
        print(json.dumps(analysis, indent=2))
        
        # Exit with error if test failed
        if not analysis['success']:
            sys.exit(1)
        
    except Exception as e:
        print(f"Error analyzing results: {e}", file=sys.stderr)
        sys.exit(1)
EOF

    # Run analysis
    local analysis_file="${result_file%.json}-analysis.json"
    
    if python3 "$analyzer_script" "$result_file" "$config_file" > "$analysis_file" 2>/dev/null; then
        success "Test results analysis completed"
        
        # Display summary
        echo ""
        echo "Load Test Results Summary:"
        echo "========================="
        jq -r '.metrics | to_entries[] | "\(.key): \(.value)"' "$analysis_file" 2>/dev/null || echo "Analysis saved to: $analysis_file"
        
        # Show violations if any
        local violations=$(jq -r '.violations[]? | "VIOLATION: \(.metric) - actual: \(.actual), threshold: \(.threshold)"' "$analysis_file" 2>/dev/null)
        if [[ -n "$violations" ]]; then
            echo ""
            echo "PERFORMANCE VIOLATIONS:"
            echo "$violations"
        fi
        
    else
        warn "Test results analysis failed"
    fi
    
    # Clean up
    rm -f "$analyzer_script"
    
    echo "$analysis_file"
}

# Schedule continuous testing
schedule_continuous_testing() {
    local schedule=${1:-"0 2 * * *"}  # Default: daily at 2 AM
    
    info "Scheduling continuous performance testing with cron: $schedule"
    
    # Create CronJob for continuous testing
    cat > "/tmp/performance-cronjob.yaml" <<EOF
apiVersion: batch/v1
kind: CronJob
metadata:
  name: performance-budget-monitor
  namespace: rust-security
spec:
  schedule: "$schedule"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: performance-monitor
            image: alpine:latest
            command: ["sh", "-c"]
            args:
            - |
              apk add --no-cache curl jq python3 py3-pip bash
              pip3 install statistics
              cd /scripts
              ./performance-budget-monitor.sh monitor 10m
              ./load-test-automation.sh run-suite baseline
            volumeMounts:
            - name: scripts
              mountPath: /scripts
            - name: results
              mountPath: /results
            resources:
              requests:
                cpu: 200m
                memory: 256Mi
              limits:
                cpu: 500m
                memory: 512Mi
          volumes:
          - name: scripts
            configMap:
              name: performance-scripts
              defaultMode: 0755
          - name: results
            persistentVolumeClaim:
              claimName: performance-results-pvc
          restartPolicy: OnFailure
      backoffLimit: 3
EOF

    # Create ConfigMap with scripts
    kubectl create configmap performance-scripts \
        --from-file="$SCRIPT_DIR/performance-budget-monitor.sh" \
        --from-file="$SCRIPT_DIR/load-test-automation.sh" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Apply CronJob
    kubectl apply -f "/tmp/performance-cronjob.yaml"
    
    success "Continuous performance testing scheduled"
    rm -f "/tmp/performance-cronjob.yaml"
}

# Run complete test suite
run_test_suite() {
    local profile=${1:-"baseline"}
    local services=("auth-service" "policy-service")
    local overall_success=true
    
    info "Running performance test suite with profile: $profile"
    
    # Ensure configurations exist
    create_test_configs
    create_k6_scripts
    
    for service in "${services[@]}"; do
        info "Testing $service..."
        
        if run_load_test "$service" "$profile"; then
            success "$service load test completed successfully"
        else
            error "$service load test failed"
            overall_success=false
        fi
        
        # Brief pause between tests
        sleep 30
    done
    
    # Run performance budget monitoring
    if "$SCRIPT_DIR/performance-budget-monitor.sh" monitor; then
        success "Performance budget monitoring completed"
    else
        warn "Performance budget violations detected"
        overall_success=false
    fi
    
    if [[ "$overall_success" == "true" ]]; then
        success "Complete performance test suite passed"
        return 0
    else
        warn "Performance test suite detected issues"
        return 1
    fi
}

# Usage information
usage() {
    cat << EOF
Automated Load Testing for Rust Security Platform

Usage: $0 <command> [arguments]

Commands:
    create-configs                          - Create load test configurations
    create-scripts                          - Create K6 load test scripts
    run-test <service> [profile]            - Run load test for specific service
    run-suite [profile]                     - Run complete test suite
    analyze <result_file> <config_file>     - Analyze test results
    schedule [cron_schedule]                - Schedule continuous testing
    
Services:
    auth-service     - Authentication service
    policy-service   - Authorization service

Load Profiles:
    smoke           - Quick smoke test (low load)
    baseline        - Standard baseline test
    stress          - High load stress test
    spike           - Sudden load spike test
    endurance       - Long duration test

Examples:
    $0 create-configs                       # Create test configurations
    $0 run-test auth-service baseline       # Run baseline test for auth service
    $0 run-suite stress                     # Run stress test suite
    $0 schedule "0 2 * * *"                # Schedule daily at 2 AM

EOF
}

# Main execution
main() {
    local command=${1:-""}
    
    case "$command" in
        "create-configs")
            create_test_configs
            ;;
        "create-scripts")
            create_k6_scripts
            ;;
        "run-test")
            if [[ $# -lt 2 ]]; then
                error "Service name required"
                usage
                exit 1
            fi
            run_load_test "$2" "${3:-baseline}"
            ;;
        "run-suite")
            run_test_suite "${2:-baseline}"
            ;;
        "analyze")
            if [[ $# -lt 3 ]]; then
                error "Result file and config file required"
                usage
                exit 1
            fi
            analyze_test_results "manual" "$2" "$3"
            ;;
        "schedule")
            schedule_continuous_testing "${2:-"0 2 * * *"}"
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