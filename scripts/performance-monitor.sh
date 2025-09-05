#!/bin/bash
# Performance monitoring script for MVP Auth Service
# Integrates with heap profiler and provides real-time monitoring

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
MONITORING_DURATION=${1:-300}  # Default 5 minutes
SERVICE_PID=""
SERVICE_PORT="8080"
RESULTS_DIR="performance-results/$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"

# Cleanup function
cleanup() {
    log_info "🧹 Cleaning up..."
    if [ -n "$SERVICE_PID" ] && kill -0 "$SERVICE_PID" 2>/dev/null; then
        log_info "Stopping auth service (PID: $SERVICE_PID)"
        kill "$SERVICE_PID" 2>/dev/null || true
        sleep 2
        kill -9 "$SERVICE_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Start the auth service with monitoring
start_auth_service() {
    log_info "🚀 Starting auth service for monitoring..."
    
    cd auth-service
    cargo build --release --features "redis-sessions,postgres"
    
    # Set environment variables for monitoring
    export RUST_LOG=info,auth_service::monitoring=debug
    export HEAP_PROFILER_ENABLED=true
    export MEMORY_MONITOR_INTERVAL=30
    export MEMORY_ALERT_THRESHOLD_MB=256
    
    # Start service in background
    ./target/release/auth-service --port "$SERVICE_PORT" &
    SERVICE_PID=$!
    cd ..
    
    log_info "Auth service started with PID: $SERVICE_PID"
    
    # Wait for service to be ready
    local max_attempts=30
    local attempt=0
    
    while ! curl -s "http://localhost:$SERVICE_PORT/health" >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [ $attempt -ge $max_attempts ]; then
            log_error "Auth service failed to start within 30 seconds"
            return 1
        fi
        sleep 1
    done
    
    log_success "Auth service is ready for monitoring"
}

# Monitor system resources
monitor_system_resources() {
    log_info "📊 Monitoring system resources for ${MONITORING_DURATION}s..."
    
    local end_time=$(($(date +%s) + MONITORING_DURATION))
    local sample_interval=5
    
    echo "timestamp,cpu_percent,memory_mb,heap_mb,rss_mb,handles" > "$RESULTS_DIR/system_resources.csv"
    
    while [ $(date +%s) -lt $end_time ]; do
        local timestamp=$(date +%s)
        
        # Get process stats for auth service
        if [ -n "$SERVICE_PID" ] && kill -0 "$SERVICE_PID" 2>/dev/null; then
            local ps_stats
            ps_stats=$(ps -p "$SERVICE_PID" -o pid,pcpu,pmem,rss,nlwp --no-headers 2>/dev/null || echo "0 0.0 0.0 0 0")
            
            local cpu_percent=$(echo "$ps_stats" | awk '{print $2}')
            local memory_percent=$(echo "$ps_stats" | awk '{print $3}')
            local rss_kb=$(echo "$ps_stats" | awk '{print $4}')
            local threads=$(echo "$ps_stats" | awk '{print $5}')
            
            local memory_mb=$((rss_kb / 1024))
            
            # Try to get heap info from /proc (Linux only)
            local heap_mb=0
            if [ -f "/proc/$SERVICE_PID/status" ]; then
                heap_mb=$(grep -E "VmData:" /proc/$SERVICE_PID/status 2>/dev/null | awk '{print int($2/1024)}' || echo "0")
            fi
            
            echo "$timestamp,$cpu_percent,$memory_mb,$heap_mb,$memory_mb,$threads" >> "$RESULTS_DIR/system_resources.csv"
            
            # Log alerts
            if (( $(echo "$memory_mb > 512" | bc -l 2>/dev/null || echo "0") )); then
                log_warning "🚨 High memory usage: ${memory_mb}MB"
            fi
            
            if (( $(echo "$cpu_percent > 80" | bc -l 2>/dev/null || echo "0") )); then
                log_warning "🚨 High CPU usage: ${cpu_percent}%"
            fi
        fi
        
        sleep $sample_interval
    done
}

# Run performance benchmarks
run_performance_benchmarks() {
    log_info "🏃 Running performance benchmarks..."
    
    # Run Auth0 comparison benchmarks
    cd benchmarks
    
    # Start the auth service first (if not already running)
    if [ -z "$SERVICE_PID" ] || ! kill -0 "$SERVICE_PID" 2>/dev/null; then
        start_auth_service
    fi
    
    # Run benchmarks with JSON output
    cargo bench --bench auth0_comparison -- --output-format json \
        > "../$RESULTS_DIR/benchmark_results.json" 2>&1 || {
        log_warning "Benchmarks failed, but continuing..."
        echo '{"error": "Benchmark execution failed"}' > "../$RESULTS_DIR/benchmark_results.json"
    }
    
    # Copy criterion HTML reports
    if [ -d "target/criterion" ]; then
        cp -r target/criterion "../$RESULTS_DIR/benchmark_reports"
    fi
    
    cd ..
    log_success "Performance benchmarks completed"
}

# Collect memory profiling data
collect_memory_profile() {
    log_info "🧠 Collecting memory profiling data..."
    
    if [ -n "$SERVICE_PID" ] && kill -0 "$SERVICE_PID" 2>/dev/null; then
        # Try to get heap dump if possible
        if command -v jmap >/dev/null 2>&1; then
            jmap -dump:format=b,file="$RESULTS_DIR/heap_dump.hprof" "$SERVICE_PID" 2>/dev/null || {
                log_warning "Could not create heap dump with jmap"
            }
        fi
        
        # Collect /proc memory info (Linux)
        if [ -d "/proc/$SERVICE_PID" ]; then
            cp "/proc/$SERVICE_PID/maps" "$RESULTS_DIR/memory_maps.txt" 2>/dev/null || true
            cp "/proc/$SERVICE_PID/smaps" "$RESULTS_DIR/memory_smaps.txt" 2>/dev/null || true
            cp "/proc/$SERVICE_PID/status" "$RESULTS_DIR/process_status.txt" 2>/dev/null || true
        fi
        
        # Get memory statistics via API if available
        if curl -s "http://localhost:$SERVICE_PORT/admin/memory-stats" -o "$RESULTS_DIR/api_memory_stats.json" 2>/dev/null; then
            log_success "Collected memory stats via API"
        else
            log_warning "Could not collect memory stats via API"
        fi
    fi
}

# Generate load and monitor performance
generate_load() {
    log_info "🔥 Generating load for performance testing..."
    
    local concurrent_users=${1:-10}
    local requests_per_user=${2:-50}
    local request_delay=${3:-0.1}
    
    # Create load generation script
    cat > "$RESULTS_DIR/load_generator.sh" << EOF
#!/bin/bash
# Load generator for performance testing

for i in \$(seq 1 $concurrent_users); do
    {
        for j in \$(seq 1 $requests_per_user); do
            curl -s -X POST http://localhost:$SERVICE_PORT/oauth/token \\
                -d "grant_type=client_credentials&client_id=test_client&client_secret=test_secret" \\
                -H "Content-Type: application/x-www-form-urlencoded" \\
                -w "user_\$i,request_\$j,%{time_total},%{http_code}\\n" \\
                -o /dev/null >> "$RESULTS_DIR/load_test_results.csv"
            
            sleep $request_delay
        done
    } &
done

wait
EOF
    
    chmod +x "$RESULTS_DIR/load_generator.sh"
    
    # Initialize CSV header
    echo "user_id,request_id,response_time,status_code" > "$RESULTS_DIR/load_test_results.csv"
    
    # Run load generator in background while monitoring
    "$RESULTS_DIR/load_generator.sh" &
    local load_pid=$!
    
    # Monitor while load is running
    monitor_system_resources &
    local monitor_pid=$!
    
    # Wait for load generation to complete
    wait $load_pid
    
    # Stop monitoring
    kill $monitor_pid 2>/dev/null || true
    
    log_success "Load generation completed"
}

# Analyze results and generate report
generate_report() {
    log_info "📋 Generating performance report..."
    
    cat > "$RESULTS_DIR/performance_report.md" << EOF
# Performance Monitoring Report

**Generated**: $(date)  
**Monitoring Duration**: ${MONITORING_DURATION}s  
**Service PID**: ${SERVICE_PID}  

## Test Configuration
- **Service Port**: $SERVICE_PORT
- **Results Directory**: $RESULTS_DIR

## Files Generated
EOF
    
    # List all generated files
    find "$RESULTS_DIR" -type f -name "*.csv" -o -name "*.json" -o -name "*.txt" | while read -r file; do
        local filename=$(basename "$file")
        local filesize=$(du -h "$file" | cut -f1)
        echo "- **$filename** ($filesize)" >> "$RESULTS_DIR/performance_report.md"
    done
    
    # Add system resource analysis if CSV exists
    if [ -f "$RESULTS_DIR/system_resources.csv" ]; then
        echo "" >> "$RESULTS_DIR/performance_report.md"
        echo "## Resource Usage Analysis" >> "$RESULTS_DIR/performance_report.md"
        
        # Calculate basic statistics from CSV
        local max_cpu=$(tail -n +2 "$RESULTS_DIR/system_resources.csv" | cut -d, -f2 | sort -n | tail -1)
        local max_memory=$(tail -n +2 "$RESULTS_DIR/system_resources.csv" | cut -d, -f3 | sort -n | tail -1)
        local avg_memory=$(tail -n +2 "$RESULTS_DIR/system_resources.csv" | cut -d, -f3 | awk '{sum+=$1; count++} END {if(count>0) print int(sum/count); else print 0}')
        
        echo "- **Peak CPU**: ${max_cpu}%" >> "$RESULTS_DIR/performance_report.md"
        echo "- **Peak Memory**: ${max_memory}MB" >> "$RESULTS_DIR/performance_report.md"
        echo "- **Average Memory**: ${avg_memory}MB" >> "$RESULTS_DIR/performance_report.md"
    fi
    
    # Add load test analysis if results exist
    if [ -f "$RESULTS_DIR/load_test_results.csv" ]; then
        echo "" >> "$RESULTS_DIR/performance_report.md"
        echo "## Load Test Analysis" >> "$RESULTS_DIR/performance_report.md"
        
        local total_requests=$(tail -n +2 "$RESULTS_DIR/load_test_results.csv" | wc -l)
        local successful_requests=$(tail -n +2 "$RESULTS_DIR/load_test_results.csv" | awk -F, '$4 == 200' | wc -l)
        local avg_response_time=$(tail -n +2 "$RESULTS_DIR/load_test_results.csv" | awk -F, '{sum+=$3; count++} END {if(count>0) printf "%.3f", sum/count; else print 0}')
        
        echo "- **Total Requests**: $total_requests" >> "$RESULTS_DIR/performance_report.md"
        echo "- **Successful Requests**: $successful_requests" >> "$RESULTS_DIR/performance_report.md"
        echo "- **Success Rate**: $(( successful_requests * 100 / total_requests ))%" >> "$RESULTS_DIR/performance_report.md"
        echo "- **Average Response Time**: ${avg_response_time}s" >> "$RESULTS_DIR/performance_report.md"
    fi
    
    log_success "Performance report generated: $RESULTS_DIR/performance_report.md"
}

# Main execution
main() {
    log_info "🔍 Starting comprehensive performance monitoring..."
    log_info "Results will be saved to: $RESULTS_DIR"
    
    case "${1:-full}" in
        "benchmark")
            start_auth_service
            run_performance_benchmarks
            ;;
        "monitor")
            start_auth_service
            monitor_system_resources
            ;;
        "load")
            start_auth_service
            generate_load 10 100 0.05  # 10 users, 100 requests each, 50ms delay
            ;;
        "profile")
            start_auth_service
            collect_memory_profile
            ;;
        "full"|*)
            start_auth_service
            run_performance_benchmarks
            generate_load 5 50 0.1  # Lighter load for full test
            collect_memory_profile
            ;;
    esac
    
    generate_report
    
    log_success "✅ Performance monitoring completed!"
    log_info "📊 View results: cat $RESULTS_DIR/performance_report.md"
}

# Handle script arguments
if [ "${1:-}" = "help" ] || [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  benchmark   Run performance benchmarks only"
    echo "  monitor     Monitor system resources only"
    echo "  load        Run load testing only"
    echo "  profile     Collect memory profiling data only"
    echo "  full        Run all monitoring (default)"
    echo "  help        Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  MONITORING_DURATION  Duration in seconds (default: 300)"
    exit 0
fi

main "$@"