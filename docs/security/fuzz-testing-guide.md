# Fuzz Testing Guide

This guide explains how to use the comprehensive fuzz testing suite for the Rust Security Platform to discover security vulnerabilities and improve input validation.

## Overview

Fuzz testing (fuzzing) is an automated software testing technique that provides invalid, unexpected, or random data as inputs to find security vulnerabilities, crashes, and edge cases. The Auth Service includes comprehensive fuzz testing for all critical parsing and security-sensitive components.

## Fuzz Testing Targets

### 1. JWT Parsing (`fuzz_jwt_parsing`)

**Purpose**: Tests JWT token parsing, validation, and edge cases  
**Critical Areas**:
- JWT header decoding
- JWT payload parsing
- Signature verification
- Algorithm confusion attacks
- Malformed token handling

**Security Impact**: High - JWT vulnerabilities can lead to authentication bypass

### 2. SCIM Filter Parsing (`fuzz_scim_filter`)

**Purpose**: Tests SCIM filter expression parsing  
**Critical Areas**:
- Filter expression syntax
- Attribute path parsing
- Operator validation
- Nested expressions
- Injection attack prevention

**Security Impact**: High - SCIM filter injection can lead to data exposure

### 3. OAuth Parameter Parsing (`fuzz_oauth_parsing`)

**Purpose**: Tests OAuth/OIDC parameter parsing and validation  
**Critical Areas**:
- Authorization request parameters
- Token request parameters
- PKCE parameter validation
- Redirect URI validation
- State parameter handling

**Security Impact**: High - OAuth vulnerabilities enable account takeover

### 4. Configuration Parsing (`fuzz_config_parsing`)

**Purpose**: Tests configuration file and environment variable parsing  
**Critical Areas**:
- TOML/JSON/YAML parsing
- Environment variable handling
- Configuration validation
- Type conversion
- Default value handling

**Security Impact**: Medium - Configuration vulnerabilities can affect service security

### 5. Client Credentials (`fuzz_client_credentials`)

**Purpose**: Tests client authentication and credential validation  
**Critical Areas**:
- Basic authentication parsing
- Client credential format validation
- Credential storage security
- Hash comparison timing

**Security Impact**: High - Client credential vulnerabilities enable unauthorized access

### 6. PKCE Operations (`fuzz_pkce_operations`)

**Purpose**: Tests PKCE (Proof Key for Code Exchange) implementation  
**Critical Areas**:
- Code verifier generation
- Code challenge creation
- Challenge method validation
- Verification process

**Security Impact**: High - PKCE bypass enables authorization code interception

### 7. Request Signature Validation (`fuzz_request_signature`)

**Purpose**: Tests HMAC request signature verification for admin endpoints  
**Critical Areas**:
- HMAC signature generation
- Signature verification
- Timestamp validation
- Timing attack resistance

**Security Impact**: Critical - Signature bypass enables admin endpoint access

### 8. Token Validation (`fuzz_token_validation`)

**Purpose**: Tests access token and refresh token validation  
**Critical Areas**:
- Token format validation
- Expiration checking
- Scope validation
- Token binding verification

**Security Impact**: High - Token validation bypass enables unauthorized access

### 9. PII Redaction (`fuzz_pii_redaction`)

**Purpose**: Tests personally identifiable information detection and redaction  
**Critical Areas**:
- Email pattern detection
- Phone number patterns
- SSN/credit card detection
- Unicode handling
- Performance with large inputs

**Security Impact**: Medium - PII leaks violate privacy regulations

## Installation and Setup

### Prerequisites

1. **Install cargo-fuzz**:
   ```bash
   cargo install cargo-fuzz
   ```

2. **Install additional tools** (optional):
   ```bash
   # For coverage analysis
   cargo install cargo-tarpaulin
   
   # For better output formatting
   cargo install cargo-watch
   ```

### Environment Setup

```bash
# Navigate to project root
cd /path/to/rust-security

# Verify fuzz targets
ls auth-service/fuzz/fuzz_targets/

# Check available targets
cd auth-service/fuzz
cargo fuzz list
```

## Running Fuzz Tests

### Quick Start

```bash
# Run all fuzz targets for 5 minutes each
./scripts/security/run_fuzzing.sh

# Run with custom duration (10 minutes per target)
FUZZ_DURATION=600 ./scripts/security/run_fuzzing.sh

# Run specific target
cd auth-service/fuzz
cargo fuzz run fuzz_jwt_parsing
```

### Manual Execution

```bash
cd auth-service/fuzz

# Run single target with custom settings
cargo fuzz run fuzz_scim_filter \
    --jobs=4 \
    --max-input-len=65536 \
    -- -max_len=65536 \
       -dict=fuzz_dict.txt \
       -only_ascii=0

# Run with timeout
timeout 300s cargo fuzz run fuzz_oauth_parsing

# Run with specific seed for reproducibility
cargo fuzz run fuzz_config_parsing -- -seed=12345
```

### Advanced Configuration

```bash
# High-intensity fuzzing
cargo fuzz run fuzz_jwt_parsing \
    --jobs=16 \
    --max-input-len=1048576 \
    -- -max_len=1048576 \
       -rss_limit_mb=8192 \
       -print_final_stats=1

# Structure-aware fuzzing with dictionaries
cargo fuzz run fuzz_scim_filter \
    -- -dict=scim_dict.txt \
       -use_value_profile=1 \
       -reduce_inputs=1

# Coverage-guided fuzzing
cargo fuzz run fuzz_oauth_parsing \
    -- -print_coverage=1 \
       -dump_coverage=1
```

## Creating Custom Dictionaries

Dictionaries improve fuzzing effectiveness by providing meaningful input patterns:

### SCIM Filter Dictionary

```bash
# Create auth-service/fuzz/scim_dict.txt
cat > auth-service/fuzz/scim_dict.txt << 'EOF'
"userName"
"email"
"displayName"
"eq"
"co"
"sw"
"and"
"or"
"not"
"emails[type eq \"work\"].value"
"addresses[primary eq true]"
EOF
```

### JWT Dictionary

```bash
# Create auth-service/fuzz/jwt_dict.txt
cat > auth-service/fuzz/jwt_dict.txt << 'EOF'
"eyJ"
"alg"
"typ"
"JWT"
"HS256"
"RS256"
"ES256"
"sub"
"exp"
"iat"
"iss"
"aud"
EOF
```

## Analyzing Results

### Crash Detection

When fuzzing finds crashes, they're stored in `fuzz/artifacts/<target>/`:

```bash
# Check for crashes
ls -la auth-service/fuzz/artifacts/

# Examine crash details
hexdump -C auth-service/fuzz/artifacts/fuzz_jwt_parsing/crash-12345

# Reproduce crash
cargo fuzz run fuzz_jwt_parsing auth-service/fuzz/artifacts/fuzz_jwt_parsing/crash-12345
```

### Minimizing Crashes

```bash
# Minimize crash input to smallest reproducing case
cargo fuzz tmin fuzz_jwt_parsing \
    auth-service/fuzz/artifacts/fuzz_jwt_parsing/crash-12345

# Verify minimized crash still reproduces
cargo fuzz run fuzz_jwt_parsing minimized-crash
```

### Coverage Analysis

```bash
# Generate coverage report
cd auth-service
cargo tarpaulin --manifest-path fuzz/Cargo.toml \
    --out html \
    --output-dir coverage_report

# View coverage
open coverage_report/tarpaulin-report.html
```

## Integration with CI/CD

### GitHub Actions Integration

```yaml
# .github/workflows/fuzz-testing.yml
name: Fuzz Testing

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
        
      - name: Run fuzz tests
        run: |
          FUZZ_DURATION=1800 ./scripts/security/run_fuzzing.sh
          
      - name: Upload artifacts
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: fuzz-artifacts
          path: auth-service/fuzz/artifacts/
```

### Local CI Integration

```bash
# Pre-commit hook for quick fuzzing
#!/bin/bash
# .git/hooks/pre-commit
cd auth-service/fuzz
timeout 30s cargo fuzz run fuzz_scim_filter || true
timeout 30s cargo fuzz run fuzz_jwt_parsing || true
```

## Security Best Practices

### 1. Regular Fuzzing Schedule

- **Daily**: Quick 5-minute runs on critical targets
- **Weekly**: Comprehensive 30-minute runs on all targets
- **Monthly**: Extended overnight fuzzing sessions
- **Pre-release**: Intensive fuzzing of all components

### 2. Target Prioritization

**Critical Priority** (Run Daily):
- `fuzz_jwt_parsing`
- `fuzz_request_signature`
- `fuzz_oauth_parsing`

**High Priority** (Run Weekly):
- `fuzz_scim_filter`
- `fuzz_client_credentials`
- `fuzz_pkce_operations`

**Medium Priority** (Run Monthly):
- `fuzz_config_parsing`
- `fuzz_token_validation`
- `fuzz_pii_redaction`

### 3. Crash Response Process

1. **Immediate Response**: Stop fuzzing, preserve artifacts
2. **Analysis**: Determine security impact and exploitability
3. **Classification**: 
   - **Critical**: Memory corruption, authentication bypass
   - **High**: Data exposure, privilege escalation
   - **Medium**: DoS, information disclosure
   - **Low**: Performance issues, edge cases
4. **Fix Development**: Create minimal reproducing test case
5. **Validation**: Verify fix prevents crash
6. **Regression Testing**: Add crash input to test suite

### 4. Performance Monitoring

Monitor fuzzing performance to detect regressions:

```bash
# Performance benchmarking
cargo fuzz run fuzz_scim_filter \
    -- -print_final_stats=1 \
       -print_corpus_stats=1 \
       -verbosity=2 \
    | grep "exec/s"
```

## Troubleshooting

### Common Issues

#### 1. Out of Memory Errors

```bash
# Increase memory limit
cargo fuzz run fuzz_jwt_parsing -- -rss_limit_mb=4096

# Reduce input size
cargo fuzz run fuzz_jwt_parsing --max-input-len=8192
```

#### 2. Slow Fuzzing Performance

```bash
# Use more jobs
cargo fuzz run fuzz_scim_filter --jobs=8

# Optimize for speed
cargo fuzz run fuzz_scim_filter -- -reduce_inputs=0
```

#### 3. No New Coverage

```bash
# Use structure-aware fuzzing
cargo fuzz run fuzz_oauth_parsing -- -use_value_profile=1

# Add custom dictionary
cargo fuzz run fuzz_oauth_parsing -- -dict=oauth_dict.txt
```

#### 4. False Positive Crashes

```bash
# Verify crash is reproducible
cargo fuzz run fuzz_jwt_parsing artifacts/crash-12345

# Check if it's an expected panic
grep -r "panic!" auth-service/src/
```

### Debug Mode

```bash
# Run with debug symbols
cd auth-service/fuzz
RUSTFLAGS="-g" cargo fuzz run fuzz_jwt_parsing

# Use with debugger
gdb --args target/x86_64-unknown-linux-gnu/release/fuzz_jwt_parsing
```

### Fuzzing with Sanitizers

```bash
# Address sanitizer (default in cargo-fuzz)
cargo fuzz run fuzz_scim_filter

# Memory sanitizer
RUSTFLAGS="-Z sanitizer=memory" cargo fuzz run fuzz_scim_filter

# Thread sanitizer
RUSTFLAGS="-Z sanitizer=thread" cargo fuzz run fuzz_scim_filter
```

## Custom Fuzz Target Development

### Creating New Targets

1. **Create target file**:
   ```rust
   // auth-service/fuzz/fuzz_targets/fuzz_new_parser.rs
   #![no_main]
   
   use libfuzzer_sys::fuzz_target;
   use auth_service::new_parser::parse_input;
   
   fuzz_target!(|data: &[u8]| {
       let input = String::from_utf8_lossy(data);
       let _ = parse_input(&input);
   });
   ```

2. **Add to Cargo.toml**:
   ```toml
   [[bin]]
   name = "fuzz_new_parser"
   path = "fuzz_targets/fuzz_new_parser.rs"
   test = false
   doc = false
   ```

3. **Test the target**:
   ```bash
   cargo fuzz run fuzz_new_parser
   ```

### Advanced Fuzzing Techniques

#### Structure-Aware Fuzzing

```rust
use arbitrary::{Arbitrary, Unstructured};

#[derive(Arbitrary, Debug)]
struct StructuredInput {
    field1: String,
    field2: u32,
    field3: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    if let Ok(input) = StructuredInput::arbitrary(&mut u) {
        test_function(input);
    }
});
```

#### Grammar-Based Fuzzing

```rust
// Define grammar for JWT-like tokens
fn generate_jwt_like(data: &[u8]) -> String {
    let header = base64::encode(&data[0..10.min(data.len())]);
    let payload = base64::encode(&data[10..20.min(data.len())]);
    let signature = base64::encode(&data[20..data.len()]);
    format!("{}.{}.{}", header, payload, signature)
}

fuzz_target!(|data: &[u8]| {
    if data.len() >= 30 {
        let jwt_like = generate_jwt_like(data);
        let _ = jsonwebtoken::decode_header(&jwt_like);
    }
});
```

## Metrics and Monitoring

### Fuzzing Metrics

Track fuzzing effectiveness:

- **Coverage Percentage**: Code coverage achieved
- **Executions per Second**: Fuzzing performance
- **Unique Crashes**: Number of distinct vulnerabilities
- **Corpus Size**: Number of interesting inputs found
- **Time to First Crash**: Speed of vulnerability discovery

### Automated Reporting

```bash
# Generate daily fuzzing report
#!/bin/bash
# scripts/generate-fuzz-report.sh

date=$(date +%Y-%m-%d)
report_file="fuzz-report-$date.html"

cat > "$report_file" << EOF
<html>
<head><title>Fuzz Report $date</title></head>
<body>
<h1>Daily Fuzz Testing Report</h1>
<h2>Summary</h2>
<ul>
EOF

for target in fuzz_*; do
    crashes=$(find "artifacts/$target" -type f 2>/dev/null | wc -l)
    echo "<li>$target: $crashes crashes</li>" >> "$report_file"
done

echo "</ul></body></html>" >> "$report_file"
```

## Security Integration

### Vulnerability Management

1. **Severity Classification**:
   - **P0 Critical**: Remote code execution, authentication bypass
   - **P1 High**: Privilege escalation, data exposure
   - **P2 Medium**: Denial of service, information disclosure
   - **P3 Low**: Edge cases, performance issues

2. **Response Times**:
   - **P0**: Immediate response, hotfix within 4 hours
   - **P1**: Response within 24 hours, fix within 1 week
   - **P2**: Response within 1 week, fix within 1 month
   - **P3**: Response within 1 month, fix in next release

3. **Documentation Requirements**:
   - Security advisory for P0/P1 issues
   - CVE assignment for external dependencies
   - Detailed remediation steps
   - Regression test creation

This comprehensive fuzz testing guide ensures systematic discovery and remediation of security vulnerabilities in the Rust Security Platform.