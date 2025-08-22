#!/bin/bash

echo "🔒 Running comprehensive security audit..."

# 1. Cargo audit for known vulnerabilities
echo "🔍 Checking for known vulnerabilities..."
if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit
else
    echo "⚠️  cargo-audit not installed. Installing..."
    cargo install cargo-audit
    cargo audit
fi

# 2. Dependency analysis
echo "📦 Analyzing dependencies for security issues..."
if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny check
else
    echo "📋 cargo-deny not found. Creating deny.toml configuration..."
    cat > deny.toml << 'EOF'
[graph]
targets = [
    { triple = "x86_64-unknown-linux-gnu" },
    { triple = "aarch64-apple-darwin" },
    { triple = "x86_64-apple-darwin" },
]

[licenses]
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-DFS-2016",
]
deny = [
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-1.0",
    "AGPL-3.0",
]

[bans]
multiple-versions = "warn"
wildcards = "deny"
deny = [
    { name = "openssl", version = "*" },  # Prefer rustls
    { name = "native-tls", version = "*" },  # Prefer rustls
]

[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"
EOF
    
    cargo install cargo-deny
    cargo deny check
fi

# 3. Check for unsafe code
echo "⚠️  Scanning for unsafe code blocks..."
find . -name "*.rs" -not -path "./target/*" -exec grep -l "unsafe" {} \; | while read file; do
    echo "📄 Unsafe code found in: $file"
    grep -n "unsafe" "$file" | head -3
done

# 4. Security-focused clippy lints
echo "🔧 Running security-focused clippy lints..."
cargo clippy -- \
    -W clippy::integer_arithmetic \
    -W clippy::panic \
    -W clippy::unwrap_used \
    -W clippy::expect_used \
    -W clippy::indexing_slicing \
    -W clippy::panic_in_result_fn \
    -W clippy::unreachable \
    -W clippy::todo \
    -W clippy::unimplemented \
    -W clippy::mem_forget \
    -W clippy::float_arithmetic \
    -W clippy::lossy_float_literal \
    -W clippy::imprecise_flops

# 5. Generate security report
echo "📊 Generating security report..."
cat > security-report.md << EOF
# Security Audit Report
Generated: $(date)

## Vulnerability Scan Results
$(cargo audit --format json 2>/dev/null | jq -r '.vulnerabilities | length') vulnerabilities found

## Dependency Analysis
- Total dependencies: $(cargo tree --depth 0 | wc -l)
- Direct dependencies: $(grep -c "^[a-zA-Z]" Cargo.toml || echo "N/A")

## Unsafe Code Blocks
$(find . -name "*.rs" -not -path "./target/*" -exec grep -c "unsafe" {} \; | awk -F: '{sum += $2} END {print sum}' || echo "0") unsafe blocks found

## Recommendations
1. Review all unsafe code blocks for memory safety
2. Consider replacing openssl with rustls where possible
3. Implement proper error handling instead of unwrap()
4. Add security tests for authentication flows
5. Enable additional security features in production builds

## Next Steps
- [ ] Address any HIGH/CRITICAL vulnerabilities
- [ ] Review and justify unsafe code usage
- [ ] Implement security testing framework
- [ ] Set up automated security scanning in CI/CD
EOF

echo "✅ Security audit completed!"
echo "📋 Report saved to security-report.md"
