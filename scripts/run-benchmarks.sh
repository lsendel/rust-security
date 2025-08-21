#!/bin/bash
# Comprehensive benchmarking script for auth-core and auth-service
# Measures performance across different scenarios and generates reports

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
BENCHMARK_RESULTS_DIR="benchmark-results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_SUBDIR="${BENCHMARK_RESULTS_DIR}/${TIMESTAMP}"

# Create results directory
mkdir -p "${RESULTS_SUBDIR}"

# Check if we're in the right directory
if [ ! -f Cargo.toml ]; then
    log_error "Please run this script from the project root directory"
    exit 1
fi

# Function to run benchmarks for a specific crate
run_crate_benchmarks() {
    local crate_name=$1
    local crate_dir=$2
    
    log_info "Running benchmarks for $crate_name..."
    
    if [ ! -d "$crate_dir" ]; then
        log_warning "Directory $crate_dir does not exist, skipping $crate_name"
        return 0
    fi
    
    cd "$crate_dir"
    
    # Check if benchmarks exist
    if [ ! -d "benches" ] || [ -z "$(ls -A benches 2>/dev/null)" ]; then
        log_warning "No benchmarks found for $crate_name, skipping"
        cd ..
        return 0
    fi
    
    # Run benchmarks
    log_info "Running Criterion benchmarks for $crate_name..."
    local bench_start=$(date +%s)
    
    # Run with different optimization levels
    log_info "Running with release optimization..."
    cargo bench --benches -- --output-format json > "../${RESULTS_SUBDIR}/${crate_name}_bench_results.json" 2>&1 || {
        log_warning "Benchmarks failed for $crate_name, continuing..."
        echo "{\"error\": \"Benchmarks failed for $crate_name\"}" > "../${RESULTS_SUBDIR}/${crate_name}_bench_results.json"
    }
    
    # Copy HTML reports if generated
    if [ -d "target/criterion" ]; then
        log_info "Copying HTML benchmark reports..."
        cp -r target/criterion "../${RESULTS_SUBDIR}/${crate_name}_criterion_reports" || true
    fi
    
    local bench_end=$(date +%s)
    local bench_duration=$((bench_end - bench_start))
    
    log_success "$crate_name benchmarks completed in ${bench_duration}s"
    
    cd ..
}

# Function to run load testing
run_load_tests() {
    log_info "Running load tests..."
    
    # Build auth-core in release mode
    log_info "Building auth-core for load testing..."
    cd auth-core
    cargo build --release --all-features
    cd ..
    
    # Create load test script
    cat > "${RESULTS_SUBDIR}/load_test.sh" << 'EOF'
#!/bin/bash
# Simple load test using curl
echo "Starting load test..."

# Start auth-core server in background
../auth-core/target/release/auth-core --port 8080 &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Run load test
echo "Running concurrent requests..."
for i in {1..100}; do
    curl -s -X POST http://localhost:8080/oauth/token \
        -d "grant_type=client_credentials&client_id=test&client_secret=secret" \
        -H "Content-Type: application/x-www-form-urlencoded" &
done

wait

# Stop server
kill $SERVER_PID 2>/dev/null || true

echo "Load test completed"
EOF
    
    chmod +x "${RESULTS_SUBDIR}/load_test.sh"
    
    # Run load test if server binary exists
    if [ -f "auth-core/target/release/auth-core" ]; then
        log_info "Running load test..."
        cd "${RESULTS_SUBDIR}"
        timeout 60 ./load_test.sh > load_test_results.txt 2>&1 || {
            log_warning "Load test timed out or failed"
        }
        cd ../..
    else
        log_warning "auth-core binary not found, skipping load test"
    fi
}

# Function to run memory profiling
run_memory_profile() {
    log_info "Running memory profiling..."
    
    cd auth-core
    
    # Check if valgrind is available
    if command -v valgrind >/dev/null 2>&1; then
        log_info "Running Valgrind memory check..."
        
        # Build with debug symbols
        cargo build --all-features
        
        # Run memory check (if binary exists)
        if [ -f "target/debug/auth-core" ]; then
            timeout 60 valgrind --tool=memcheck --leak-check=full \
                ./target/debug/auth-core --help \
                > "../${RESULTS_SUBDIR}/valgrind_memcheck.txt" 2>&1 || {
                log_warning "Valgrind memcheck failed or timed out"
            }
        fi
    else
        log_warning "Valgrind not available, skipping memory profiling"
    fi
    
    cd ..
}

# Function to generate summary report
generate_summary_report() {
    log_info "Generating summary report..."
    
    cat > "${RESULTS_SUBDIR}/benchmark_summary.md" << EOF
# Benchmark Results Summary

**Timestamp**: $(date)  
**Git Commit**: $(git rev-parse HEAD 2>/dev/null || echo "unknown")  
**Git Branch**: $(git branch --show-current 2>/dev/null || echo "unknown")  
**Rust Version**: $(rustc --version)

## Test Environment
- **OS**: $(uname -s)
- **Architecture**: $(uname -m)  
- **CPU**: $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs 2>/dev/null || echo "Unknown")
- **Memory**: $(free -h | awk '/^Mem:/ {print $2}' 2>/dev/null || echo "Unknown")

## Benchmark Results

### Auth-Core Performance
$([ -f "${RESULTS_SUBDIR}/auth-core_bench_results.json" ] && echo "✅ Auth-core benchmarks completed" || echo "❌ Auth-core benchmarks failed")

### Load Testing  
$([ -f "${RESULTS_SUBDIR}/load_test_results.txt" ] && echo "✅ Load tests completed" || echo "❌ Load tests skipped")

### Memory Profiling
$([ -f "${RESULTS_SUBDIR}/valgrind_memcheck.txt" ] && echo "✅ Memory profiling completed" || echo "❌ Memory profiling skipped")

## File Artifacts
EOF

    # List all generated files
    echo "### Generated Files" >> "${RESULTS_SUBDIR}/benchmark_summary.md"
    for file in "${RESULTS_SUBDIR}"/*; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            filesize=$(du -h "$file" | cut -f1)
            echo "- **$filename** ($filesize)" >> "${RESULTS_SUBDIR}/benchmark_summary.md"
        fi
    done

    # Add performance insights if JSON results exist
    if [ -f "${RESULTS_SUBDIR}/auth-core_bench_results.json" ]; then
        echo "" >> "${RESULTS_SUBDIR}/benchmark_summary.md"
        echo "### Performance Insights" >> "${RESULTS_SUBDIR}/benchmark_summary.md"
        echo "See detailed results in the JSON and HTML reports above." >> "${RESULTS_SUBDIR}/benchmark_summary.md"
    fi
}

# Main execution
main() {
    log_info "🚀 Starting comprehensive benchmark suite"
    log_info "Results will be saved to: ${RESULTS_SUBDIR}"
    
    local start_time=$(date +%s)
    
    # Run benchmarks for each crate
    run_crate_benchmarks "auth-core" "auth-core"
    run_crate_benchmarks "auth-service" "auth-service"
    
    # Run additional tests
    run_load_tests
    run_memory_profile
    
    # Generate summary
    generate_summary_report
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    log_success "✅ Benchmark suite completed in ${total_duration}s"
    log_info "📊 Results available at: ${RESULTS_SUBDIR}/benchmark_summary.md"
    
    # Create symlink to latest results
    rm -f "${BENCHMARK_RESULTS_DIR}/latest"
    ln -sf "${TIMESTAMP}" "${BENCHMARK_RESULTS_DIR}/latest"
    
    # Display quick summary
    echo ""
    echo "=== QUICK SUMMARY ==="
    if [ -f "${RESULTS_SUBDIR}/benchmark_summary.md" ]; then
        head -20 "${RESULTS_SUBDIR}/benchmark_summary.md" | tail -15
    fi
    echo "======================="
    echo ""
    log_info "🎯 View detailed results: cat ${RESULTS_SUBDIR}/benchmark_summary.md"
}

# Handle script arguments
case "${1:-all}" in
    auth-core)
        run_crate_benchmarks "auth-core" "auth-core"
        generate_summary_report
        ;;
    auth-service)
        run_crate_benchmarks "auth-service" "auth-service"
        generate_summary_report
        ;;
    load)
        run_load_tests
        generate_summary_report
        ;;
    memory)
        run_memory_profile
        generate_summary_report
        ;;
    all)
        main
        ;;
    clean)
        log_info "Cleaning benchmark results..."
        rm -rf "${BENCHMARK_RESULTS_DIR}"
        log_success "Benchmark results cleaned"
        ;;
    help|--help|-h)
        echo "Usage: $0 [OPTION]"
        echo ""
        echo "Options:"
        echo "  auth-core      Run auth-core benchmarks only"
        echo "  auth-service   Run auth-service benchmarks only" 
        echo "  load          Run load tests only"
        echo "  memory        Run memory profiling only"
        echo "  all           Run all benchmarks (default)"
        echo "  clean         Clean benchmark results"
        echo "  help          Show this help message"
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac