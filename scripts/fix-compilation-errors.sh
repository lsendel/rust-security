#!/bin/bash
# Automated Compilation Error Fix Script
# Systematically fixes enum variant syntax errors

set -e

echo "🔧 Auto-fixing compilation errors..."

# Find all Rust files in auth-service
find auth-service/src -name "*.rs" -type f > /tmp/rust_files.txt

echo "Found $(wc -l < /tmp/rust_files.txt) Rust files to check"

# Fix ServiceUnavailable struct syntax to tuple syntax
echo "Fixing ServiceUnavailable enum variants..."
while IFS= read -r file; do
    if grep -q "ServiceUnavailable\s*{" "$file" 2>/dev/null; then
        echo "Fixing ServiceUnavailable in: $file"

        # Replace struct-style with tuple-style using sed with proper escaping
        sed -i.bak 's/ServiceUnavailable\s*{\s*reason:/ServiceUnavailable(/g' "$file"
        sed -i.bak 's/ServiceUnavailable\s*{\s*client_id:/ServiceUnavailable(/g' "$file"

        # Fix closing braces - replace } with ) at end of lines
        sed -i.bak 's/^\([[:space:]]*\)}\s*$/\1)/g' "$file"

        # Fix compiler placeholder comments
        sed -i.bak 's/ServiceUnavailable(\s*\/\* std::string::String \*\/\s*)/ServiceUnavailable("PLACEHOLDER_MESSAGE".to_string())/g' "$file"

        # Clean up backup files
        rm -f "${file}.bak"
    fi
done < /tmp/rust_files.txt

# Fix InvalidRequest struct syntax to tuple syntax
echo "Fixing InvalidRequest enum variants..."
while IFS= read -r file; do
    if grep -q "InvalidRequest\s*{" "$file" 2>/dev/null; then
        echo "Fixing InvalidRequest in: $file"

        sed -i.bak 's/InvalidRequest\s*{\s*reason:/InvalidRequest(/g' "$file"
        sed -i.bak 's/^\([[:space:]]*\)}\s*$/\1)/g' "$file"
        sed -i.bak 's/InvalidRequest(\s*\/\* std::string::String \*\/\s*)/InvalidRequest("PLACEHOLDER_MESSAGE".to_string())/g' "$file"
        rm -f "${file}.bak"
    fi
done < /tmp/rust_files.txt

# Fix UnauthorizedClient struct syntax to tuple syntax
echo "Fixing UnauthorizedClient enum variants..."
while IFS= read -r file; do
    if grep -q "UnauthorizedClient\s*{" "$file" 2>/dev/null; then
        echo "Fixing UnauthorizedClient in: $file"

        sed -i.bak 's/UnauthorizedClient\s*{\s*client_id:/UnauthorizedClient(/g' "$file"
        sed -i.bak 's/^\([[:space:]]*\)}\s*$/\1)/g' "$file"
        sed -i.bak 's/UnauthorizedClient(\s*\/\* std::string::String \*\/\s*)/UnauthorizedClient("PLACEHOLDER_MESSAGE".to_string())/g' "$file"
        rm -f "${file}.bak"
    fi
done < /tmp/rust_files.txt

# Fix CircuitBreaker error mappings
echo "Fixing CircuitBreaker error mappings..."
while IFS= read -r file; do
    if grep -q "CircuitBreakerError::" "$file" 2>/dev/null; then
        echo "Fixing CircuitBreaker in: $file"

        # Fix the mapping patterns
        sed -i.bak 's/CircuitBreakerError::Open\s*=>\s*Self::ServiceUnavailable\s*{\s*reason:/CircuitBreakerError::Open => Self::ServiceUnavailable(/g' "$file"
        sed -i.bak 's/CircuitBreakerError::Timeout\s*{\s*timeout\s*}\s*=>\s*Self::ServiceUnavailable\s*{\s*reason:/CircuitBreakerError::Timeout { timeout } => Self::ServiceUnavailable(/g' "$file"
        sed -i.bak 's/CircuitBreakerError::OperationFailed(msg)\s*=>\s*Self::ServiceUnavailable\s*{\s*reason:/CircuitBreakerError::OperationFailed(msg) => Self::ServiceUnavailable(/g' "$file"
        rm -f "${file}.bak"
    fi
done < /tmp/rust_files.txt

# Clean up any remaining placeholder comments
echo "Cleaning up placeholder comments..."
find auth-service/src -name "*.rs" -type f -exec sed -i 's/\/\* std::string::String \*\///g' {} \;

echo "✅ Auto-fixes applied. Running cargo check to verify..."

# Run cargo check to see remaining errors
cargo check --workspace 2>&1 | grep -c "error[" || echo "0"

echo "If errors remain, you may need to manually fix complex cases."
echo "Run: cargo check --workspace --message-format=short for detailed error messages."
