#!/bin/bash

# Fuzzing script for auth-service security testing
# This script runs various fuzz targets to find security vulnerabilities

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FUZZ_DIR="$PROJECT_ROOT/auth-service/fuzz"

echo "🔍 Starting security fuzzing for auth-service"
echo "Project root: $PROJECT_ROOT"
echo "Fuzz directory: $FUZZ_DIR"

# Check if cargo-fuzz is installed
if ! command -v cargo-fuzz &> /dev/null; then
    echo "📦 Installing cargo-fuzz..."
    cargo install cargo-fuzz
fi

cd "$FUZZ_DIR"

# Default fuzzing duration (can be overridden)
FUZZ_DURATION=${FUZZ_DURATION:-60}
PARALLEL_JOBS=${PARALLEL_JOBS:-$(nproc 2>/dev/null || echo 4)}

echo "⚙️  Configuration:"
echo "  Duration: ${FUZZ_DURATION} seconds per target"
echo "  Parallel jobs: ${PARALLEL_JOBS}"

# List of fuzz targets
FUZZ_TARGETS=(
    "fuzz_token_validation"
    "fuzz_client_credentials" 
    "fuzz_pkce_operations"
    "fuzz_request_signature"
    "fuzz_oauth_parsing"
    "fuzz_jwt_parsing"
    "fuzz_pii_redaction"
    "fuzz_scim_filter"
    "fuzz_config_parsing"
)

# Function to run a single fuzz target
run_fuzz_target() {
    local target="$1"
    local duration="$2"
    
    echo "🎯 Fuzzing target: $target (${duration}s)"
    
    # Create output directory for this target
    mkdir -p "corpus/$target"
    mkdir -p "artifacts/$target"
    
    # Run the fuzzer
    timeout "${duration}s" cargo fuzz run "$target" \
        --jobs="$PARALLEL_JOBS" \
        -- -max_total_time="$duration" \
        -artifact_prefix="artifacts/$target/" \
        || {
            local exit_code=$?
            if [ $exit_code -eq 124 ]; then
                echo "✅ Fuzzing completed for $target (timeout reached)"
            else
                echo "❌ Fuzzing failed for $target with exit code $exit_code"
                return $exit_code
            fi
        }
}

# Function to run all fuzz targets
run_all_targets() {
    echo "🚀 Running all fuzz targets..."
    
    for target in "${FUZZ_TARGETS[@]}"; do
        echo ""
        echo "=================="
        run_fuzz_target "$target" "$FUZZ_DURATION"
        echo "=================="
    done
}

# Function to run specific target
run_specific_target() {
    local target="$1"
    local duration="${2:-$FUZZ_DURATION}"
    
    if [[ " ${FUZZ_TARGETS[*]} " =~ " $target " ]]; then
        run_fuzz_target "$target" "$duration"
    else
        echo "❌ Unknown fuzz target: $target"
        echo "Available targets: ${FUZZ_TARGETS[*]}"
        exit 1
    fi
}

# Function to check for crashes and artifacts
check_artifacts() {
    echo "🔍 Checking for crashes and artifacts..."
    
    local found_artifacts=0
    
    for target in "${FUZZ_TARGETS[@]}"; do
        local artifact_dir="artifacts/$target"
        if [ -d "$artifact_dir" ] && [ "$(ls -A "$artifact_dir" 2>/dev/null)" ]; then
            echo "⚠️  Artifacts found for $target:"
            ls -la "$artifact_dir"
            found_artifacts=1
        fi
    done
    
    if [ $found_artifacts -eq 0 ]; then
        echo "✅ No crashes or artifacts found"
    else
        echo "❌ Artifacts found - please investigate!"
        return 1
    fi
}

# Function to clean up artifacts and corpus
clean_fuzzing_data() {
    echo "🧹 Cleaning fuzzing data..."
    rm -rf corpus artifacts
    echo "✅ Fuzzing data cleaned"
}

# Function to show coverage information
show_coverage() {
    echo "📊 Coverage information:"
    for target in "${FUZZ_TARGETS[@]}"; do
        if [ -f "coverage/$target/coverage.profdata" ]; then
            echo "  $target: Coverage data available"
        else
            echo "  $target: No coverage data"
        fi
    done
}

# Function to minimize corpus
minimize_corpus() {
    echo "🗜️  Minimizing corpus..."
    for target in "${FUZZ_TARGETS[@]}"; do
        if [ -d "corpus/$target" ] && [ "$(ls -A "corpus/$target" 2>/dev/null)" ]; then
            echo "Minimizing corpus for $target..."
            cargo fuzz cmin "$target"
        fi
    done
}

# Function to show help
show_help() {
    cat << EOF
Security Fuzzing Script for auth-service

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    run [TARGET]        Run fuzzing (all targets or specific target)
    check              Check for artifacts and crashes
    clean              Clean fuzzing data
    coverage           Show coverage information  
    minimize           Minimize corpus files
    help               Show this help

Environment Variables:
    FUZZ_DURATION      Duration in seconds for each target (default: 60)
    PARALLEL_JOBS      Number of parallel jobs (default: number of CPUs)

Examples:
    $0 run                           # Run all targets
    $0 run fuzz_token_validation     # Run specific target
    FUZZ_DURATION=300 $0 run         # Run for 5 minutes per target
    $0 check                         # Check for crashes
    $0 clean                         # Clean up fuzzing data

Available fuzz targets:
$(printf '    %s\n' "${FUZZ_TARGETS[@]}")
EOF
}

# Main script logic
main() {
    case "${1:-run}" in
        "run")
            if [ $# -eq 1 ]; then
                run_all_targets
            else
                run_specific_target "$2" "${3:-}"
            fi
            check_artifacts
            ;;
        "check")
            check_artifacts
            ;;
        "clean")
            clean_fuzzing_data
            ;;
        "coverage")
            show_coverage
            ;;
        "minimize")
            minimize_corpus
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            echo "❌ Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || ! grep -q "cargo-fuzz = true" Cargo.toml; then
    echo "❌ Error: Not in a cargo-fuzz directory or missing Cargo.toml"
    echo "Expected to be in: $FUZZ_DIR"
    exit 1
fi

# Ensure we have the necessary dependencies
echo "🔧 Checking dependencies..."
if ! cargo --version &>/dev/null; then
    echo "❌ Cargo is not installed"
    exit 1
fi

# Initialize fuzz targets if they don't exist
for target in "${FUZZ_TARGETS[@]}"; do
    if [ ! -f "fuzz_targets/${target}.rs" ]; then
        echo "⚠️  Fuzz target $target not found, creating..."
        cargo fuzz add "$target"
    fi
done

# Run the main logic
main "$@"

echo "🎉 Fuzzing session completed!"