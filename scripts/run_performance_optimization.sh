#!/bin/bash

# Comprehensive Performance Optimization Script for Rust Security Auth Service
# This script runs benchmarks, optimizations, and performance tests

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTH_SERVICE_DIR="$PROJECT_ROOT/auth-service"
RESULTS_DIR="$PROJECT_ROOT/performance-results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create results directory
mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}🚀 Starting Comprehensive Performance Optimization Suite${NC}"
echo -e "${BLUE}Project Root: $PROJECT_ROOT${NC}"
echo -e "${BLUE}Results Directory: $RESULTS_DIR${NC}"
echo ""

# Function to print section headers
print_section() {
    echo -e "${YELLOW}===================================================${NC}"
    echo -e "${YELLOW}$1${NC}"
    echo -e "${YELLOW}===================================================${NC}"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to wait for service to be ready
wait_for_service() {
    local url="$1"
    local timeout="${2:-60}"
    local count=0
    
    echo -e "${BLUE}Waiting for service at $url to be ready...${NC}"
    
    while [ $count -lt $timeout ]; do
        if curl -sf "$url/health" >/dev/null 2>&1; then
            echo -e "${GREEN}✅ Service is ready!${NC}"
            return 0
        fi
        
        count=$((count + 1))
        sleep 1
        
        if [ $((count % 10)) -eq 0 ]; then
            echo -e "${YELLOW}Still waiting... ($count/$timeout seconds)${NC}"
        fi
    done
    
    echo -e "${RED}❌ Service failed to start within $timeout seconds${NC}"
    return 1
}

# Function to run benchmarks
run_benchmarks() {
    print_section "📊 Running Performance Benchmarks"
    
    cd "$AUTH_SERVICE_DIR"
    
    # Ensure benchmark features are enabled
    echo -e "${BLUE}Building with benchmark features...${NC}"
    cargo build --release --features="benchmarks,performance,simd" || {
        echo -e "${YELLOW}⚠️  Building without SIMD features...${NC}"
        cargo build --release --features="benchmarks,performance"
    }
    
    # Run the comprehensive security performance benchmarks
    echo -e "${BLUE}Running security performance benchmarks...${NC}"
    cargo bench --features="benchmarks,performance" --bench security_performance_bench \
        2>&1 | tee "$RESULTS_DIR/security_benchmarks_$TIMESTAMP.txt"
    
    # Run the original performance suite
    echo -e "${BLUE}Running general performance benchmarks...${NC}"
    cargo bench --features="benchmarks" --bench performance_suite \
        2>&1 | tee "$RESULTS_DIR/general_benchmarks_$TIMESTAMP.txt"
    
    echo -e "${GREEN}✅ Benchmarks completed${NC}"
}

# Function to run memory profiling
run_memory_profiling() {
    print_section "🧠 Memory Usage Profiling"
    
    if ! command_exists "valgrind"; then
        echo -e "${YELLOW}⚠️  Valgrind not found. Installing...${NC}"
        if command_exists "apt-get"; then
            sudo apt-get update && sudo apt-get install -y valgrind
        elif command_exists "brew"; then
            brew install valgrind
        else
            echo -e "${RED}❌ Cannot install valgrind automatically${NC}"
            return 1
        fi
    fi
    
    cd "$AUTH_SERVICE_DIR"
    
    # Build with debug symbols for profiling
    echo -e "${BLUE}Building debug version for memory profiling...${NC}"
    cargo build --features="performance"
    
    # Run memory profiling during a simple test
    echo -e "${BLUE}Running memory profiling...${NC}"
    timeout 30s valgrind --tool=massif --massif-out-file="$RESULTS_DIR/massif_$TIMESTAMP.out" \
        ./target/debug/auth-service &
    
    local service_pid=$!
    sleep 5
    
    # Send some test requests
    if wait_for_service "http://localhost:8080" 10; then
        echo -e "${BLUE}Sending test requests for memory profiling...${NC}"
        for i in {1..100}; do
            curl -s "http://localhost:8080/health" >/dev/null || true
        done
    fi
    
    # Stop the service
    kill $service_pid 2>/dev/null || true
    wait $service_pid 2>/dev/null || true
    
    # Generate memory report
    if command_exists "ms_print"; then
        ms_print "$RESULTS_DIR/massif_$TIMESTAMP.out" > "$RESULTS_DIR/memory_report_$TIMESTAMP.txt"
        echo -e "${GREEN}✅ Memory profiling completed${NC}"
    else
        echo -e "${YELLOW}⚠️  ms_print not available, raw massif output saved${NC}"
    fi
}

# Function to run CPU profiling
run_cpu_profiling() {
    print_section "⚡ CPU Performance Profiling"
    
    if ! command_exists "perf"; then
        echo -e "${YELLOW}⚠️  perf not found. Skipping CPU profiling...${NC}"
        return 0
    fi
    
    cd "$AUTH_SERVICE_DIR"
    
    # Build optimized version
    echo -e "${BLUE}Building optimized version for CPU profiling...${NC}"
    cargo build --release --features="performance"
    
    echo -e "${BLUE}Starting service for CPU profiling...${NC}"
    ./target/release/auth-service &
    local service_pid=$!
    
    if wait_for_service "http://localhost:8080" 15; then
        echo -e "${BLUE}Running CPU profiling for 30 seconds...${NC}"
        
        # Generate load while profiling
        {
            for i in {1..1000}; do
                curl -s -X POST "http://localhost:8080/oauth/token" \
                    -H "Content-Type: application/json" \
                    -d '{"grant_type":"client_credentials","client_id":"test","client_secret":"test"}' >/dev/null || true
                sleep 0.01
            done
        } &
        local load_pid=$!
        
        # Run perf for 30 seconds
        timeout 30s perf record -g -p $service_pid --output="$RESULTS_DIR/perf_$TIMESTAMP.data" 2>/dev/null || true
        
        # Stop load generation
        kill $load_pid 2>/dev/null || true
        
        # Generate perf report
        perf report --input="$RESULTS_DIR/perf_$TIMESTAMP.data" \
            --stdio > "$RESULTS_DIR/cpu_profile_$TIMESTAMP.txt" 2>/dev/null || true
        
        echo -e "${GREEN}✅ CPU profiling completed${NC}"
    fi
    
    # Stop the service
    kill $service_pid 2>/dev/null || true
    wait $service_pid 2>/dev/null || true
}

# Function to run load tests
run_load_tests() {
    print_section "🔥 Load Testing Security Endpoints"
    
    cd "$AUTH_SERVICE_DIR"
    
    # Start the service
    echo -e "${BLUE}Starting auth service for load testing...${NC}"
    RUST_LOG=info ./target/release/auth-service &
    local service_pid=$!
    
    if wait_for_service "http://localhost:8080" 30; then
        cd "$PROJECT_ROOT/load_test"
        
        # Compile load test tool
        echo -e "${BLUE}Building load test tool...${NC}"
        cargo build --release
        
        # Run different load test scenarios
        echo -e "${BLUE}Running token endpoint load test...${NC}"
        ./target/release/security_load_test token-endpoint \
            --base-url "http://localhost:8080" \
            --clients 50 \
            --duration 60 \
            --rps 10 \
            --output "$RESULTS_DIR/token_load_test_$TIMESTAMP.json"
        
        echo -e "${BLUE}Running introspection endpoint load test...${NC}"
        ./target/release/security_load_test introspection \
            --base-url "http://localhost:8080" \
            --clients 30 \
            --duration 60 \
            --rps 20 \
            --output "$RESULTS_DIR/introspection_load_test_$TIMESTAMP.json"
        
        echo -e "${BLUE}Running mixed workload test...${NC}"
        ./target/release/security_load_test mixed-workload \
            --base-url "http://localhost:8080" \
            --clients 40 \
            --duration 60 \
            --distribution "token:30,introspect:60,userinfo:10" \
            --output "$RESULTS_DIR/mixed_workload_test_$TIMESTAMP.json"
        
        echo -e "${BLUE}Running rate limit test...${NC}"
        ./target/release/security_load_test rate-limit-test \
            --base-url "http://localhost:8080" \
            --target-rps 500 \
            --duration 30 \
            --output "$RESULTS_DIR/rate_limit_test_$TIMESTAMP.json"
        
        echo -e "${BLUE}Running stress test...${NC}"
        ./target/release/security_load_test stress-test \
            --base-url "http://localhost:8080" \
            --start-rps 10 \
            --max-rps 200 \
            --increment-interval 15 \
            --output "$RESULTS_DIR/stress_test_$TIMESTAMP.json"
        
        # Attack simulations
        echo -e "${BLUE}Running attack simulations...${NC}"
        ./target/release/security_load_test attack-simulation \
            --base-url "http://localhost:8080" \
            --attack-type credential-stuffing \
            --clients 20 \
            --duration 30 \
            --output "$RESULTS_DIR/credential_stuffing_test_$TIMESTAMP.json"
        
        ./target/release/security_load_test attack-simulation \
            --base-url "http://localhost:8080" \
            --attack-type ddos \
            --clients 100 \
            --duration 30 \
            --output "$RESULTS_DIR/ddos_test_$TIMESTAMP.json"
        
        echo -e "${GREEN}✅ Load testing completed${NC}"
    else
        echo -e "${RED}❌ Service failed to start for load testing${NC}"
    fi
    
    # Stop the service
    kill $service_pid 2>/dev/null || true
    wait $service_pid 2>/dev/null || true
}

# Function to run database performance tests
run_database_tests() {
    print_section "🗄️  Database Performance Testing"
    
    # Check if Redis is available
    if ! command_exists "redis-cli"; then
        echo -e "${YELLOW}⚠️  Redis not found. Installing...${NC}"
        if command_exists "apt-get"; then
            sudo apt-get update && sudo apt-get install -y redis-server
        elif command_exists "brew"; then
            brew install redis
        else
            echo -e "${RED}❌ Cannot install Redis automatically${NC}"
            return 1
        fi
    fi
    
    # Start Redis if not running
    if ! redis-cli ping >/dev/null 2>&1; then
        echo -e "${BLUE}Starting Redis server...${NC}"
        redis-server --daemonize yes --port 6379
        sleep 2
    fi
    
    cd "$AUTH_SERVICE_DIR"
    
    # Set environment variables for Redis testing
    export REDIS_URL="redis://localhost:6379"
    export USE_REDIS_CACHE="true"
    
    # Run database-specific benchmarks
    echo -e "${BLUE}Running database performance tests...${NC}"
    cargo test --release --features="performance" database_performance_test \
        2>&1 | tee "$RESULTS_DIR/database_tests_$TIMESTAMP.txt"
    
    # Test connection pool performance
    echo -e "${BLUE}Testing connection pool performance...${NC}"
    cargo test --release --features="performance" connection_pool_performance \
        2>&1 | tee "$RESULTS_DIR/connection_pool_tests_$TIMESTAMP.txt"
    
    echo -e "${GREEN}✅ Database performance testing completed${NC}"
}

# Function to analyze results
analyze_results() {
    print_section "📈 Analyzing Performance Results"
    
    cd "$RESULTS_DIR"
    
    # Create summary report
    cat > "performance_summary_$TIMESTAMP.md" << EOF
# Performance Analysis Report
Generated: $(date)

## Test Environment
- Hostname: $(hostname)
- OS: $(uname -s) $(uname -r)
- CPU: $(nproc) cores
- Memory: $(free -h | awk '/^Mem:/ {print $2}')
- Rust Version: $(rustc --version)

## Files Generated
EOF
    
    # List all generated files
    for file in *_"$TIMESTAMP".*; do
        if [ -f "$file" ]; then
            echo "- $file" >> "performance_summary_$TIMESTAMP.md"
        fi
    done
    
    cat >> "performance_summary_$TIMESTAMP.md" << EOF

## Key Findings

### Benchmark Results
$(grep -h "time:" *benchmarks_$TIMESTAMP.txt 2>/dev/null | head -10 || echo "No benchmark results found")

### Load Test Summary
$(grep -h "Total Requests:" *load_test_$TIMESTAMP.json 2>/dev/null | head -5 || echo "No load test results found")

### Memory Usage
$(grep -h "peak" *memory_report_$TIMESTAMP.txt 2>/dev/null | head -3 || echo "No memory profiling results found")

## Recommendations

1. **Cryptographic Operations**: Use hardware acceleration where available
2. **Caching**: Implement multi-tier caching strategy
3. **Connection Pooling**: Optimize pool sizes based on load patterns
4. **Rate Limiting**: Fine-tune rate limits based on attack simulations
5. **Memory Management**: Monitor for memory leaks in long-running instances

EOF
    
    echo -e "${GREEN}✅ Performance analysis completed${NC}"
    echo -e "${BLUE}Summary report: $RESULTS_DIR/performance_summary_$TIMESTAMP.md${NC}"
}

# Function to generate optimization recommendations
generate_recommendations() {
    print_section "💡 Generating Optimization Recommendations"
    
    cat > "$RESULTS_DIR/optimization_recommendations_$TIMESTAMP.md" << 'EOF'
# Performance Optimization Recommendations

## Immediate Optimizations (Low Effort, High Impact)

### 1. Enable Hardware Acceleration
```toml
# Add to Cargo.toml
[features]
default = ["simd", "performance"]
simd = []
performance = ["mimalloc"]
```

### 2. Optimize Compilation Flags
```toml
# Add to Cargo.toml
[profile.release]
lto = true
codegen-units = 1
panic = "abort"
```

### 3. Configure Environment Variables
```bash
# Production environment
export RUST_LOG=warn
export MALLOC_ARENA_MAX=2
export MALLOC_MMAP_THRESHOLD_=131072
```

## Medium-Term Optimizations

### 1. Implement Connection Pooling
- Use deadpool or bb8 for Redis connections
- Configure pool size based on expected load
- Implement health checks for connections

### 2. Multi-Tier Caching Strategy
- L1: In-memory cache for frequently accessed data
- L2: Redis cache for shared data
- L3: CDN cache for static content

### 3. Async Optimization
- Use tokio's multi-threaded runtime
- Implement proper backpressure
- Optimize task scheduling

## Long-Term Optimizations

### 1. SIMD Acceleration
- Implement SIMD for batch token validation
- Use vectorized operations for cryptographic functions
- Leverage CPU-specific optimizations

### 2. Custom Memory Allocators
- Use mimalloc or jemalloc for better performance
- Implement arena allocators for specific use cases
- Monitor memory fragmentation

### 3. Database Optimizations
- Implement read replicas for scaling
- Use connection multiplexing
- Optimize query patterns

## Security Considerations

1. **Timing Attack Prevention**: Ensure constant-time operations
2. **Rate Limiting**: Implement adaptive rate limiting
3. **Circuit Breakers**: Prevent cascade failures
4. **Monitoring**: Comprehensive performance and security metrics

## Monitoring and Observability

### Key Metrics to Track
- Request latency (P50, P95, P99)
- Throughput (requests per second)
- Error rates and types
- Memory usage and garbage collection
- CPU utilization and context switches
- Database connection pool utilization

### Alerting Thresholds
- P95 latency > 500ms
- Error rate > 1%
- Memory usage > 80%
- CPU usage > 70%
- Rate limit hit rate > 10%

## Performance Testing Strategy

### Regular Testing
- Run benchmarks on every release
- Automated performance regression testing
- Load testing in staging environment

### Attack Simulation
- Regular penetration testing
- DDoS simulation
- Rate limiting effectiveness testing

EOF
    
    echo -e "${GREEN}✅ Optimization recommendations generated${NC}"
}

# Main execution flow
main() {
    # Check prerequisites
    if ! command_exists "cargo"; then
        echo -e "${RED}❌ Cargo not found. Please install Rust toolchain.${NC}"
        exit 1
    fi
    
    if ! command_exists "curl"; then
        echo -e "${RED}❌ curl not found. Please install curl.${NC}"
        exit 1
    fi
    
    # Change to auth service directory
    cd "$AUTH_SERVICE_DIR"
    
    # Parse command line arguments
    case "${1:-all}" in
        "benchmarks"|"bench")
            run_benchmarks
            ;;
        "memory"|"mem")
            run_memory_profiling
            ;;
        "cpu")
            run_cpu_profiling
            ;;
        "load"|"load-test")
            run_load_tests
            ;;
        "database"|"db")
            run_database_tests
            ;;
        "analyze")
            analyze_results
            ;;
        "recommendations"|"rec")
            generate_recommendations
            ;;
        "all"|*)
            echo -e "${BLUE}Running full performance optimization suite...${NC}"
            run_benchmarks
            run_memory_profiling
            run_cpu_profiling
            run_database_tests
            run_load_tests
            analyze_results
            generate_recommendations
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}🎉 Performance optimization suite completed!${NC}"
    echo -e "${BLUE}Results available in: $RESULTS_DIR${NC}"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo -e "${YELLOW}1. Review the performance summary report${NC}"
    echo -e "${YELLOW}2. Implement recommended optimizations${NC}"
    echo -e "${YELLOW}3. Set up continuous performance monitoring${NC}"
    echo -e "${YELLOW}4. Schedule regular performance testing${NC}"
}

# Show usage if help is requested
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all              Run full performance optimization suite (default)"
    echo "  benchmarks       Run performance benchmarks only"
    echo "  memory           Run memory profiling only"
    echo "  cpu              Run CPU profiling only"
    echo "  load             Run load testing only"
    echo "  database         Run database performance tests only"
    echo "  analyze          Analyze existing results"
    echo "  recommendations  Generate optimization recommendations"
    echo "  --help, -h       Show this help message"
    exit 0
fi

# Run main function
main "$@"