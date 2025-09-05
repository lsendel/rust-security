# Input Validation and Fuzzing Framework

A comprehensive input validation, sanitization, and fuzzing framework for the Rust Security Platform. This framework provides security-first input validation with DoS protection, injection attack prevention, and extensive fuzz testing capabilities.

## Features

### 🔒 Security-First Validation
- **Injection Attack Prevention**: Detects SQL injection, XSS, command injection, path traversal, LDAP injection, and NoSQL injection
- **Input Size Limits**: Configurable limits to prevent DoS attacks
- **Character Set Validation**: Strict character set rules per input type
- **Security Levels**: Production (strict), development (relaxed), and custom configurations

### 🧹 Comprehensive Sanitization
- **HTML/XML Sanitization**: Safe encoding and tag stripping
- **SQL Sanitization**: String escaping and comment removal
- **JSON Sanitization**: Recursive structure sanitization
- **URL Sanitization**: Safe URL parsing and validation
- **Idempotent Operations**: Sanitization results are consistent across multiple applications

### 🚀 High-Performance Parsing
- **SCIM Filter Parser**: RFC 7644 compliant with security enhancements
- **OAuth Parameter Parser**: RFC 6749 compliant with PKCE support
- **JWT Token Parser**: Structure validation with algorithm restrictions
- **Timeout Protection**: Configurable parsing timeouts
- **Memory Safety**: Bounded memory usage with configurable limits

### 🛡️ DoS Protection
- **Rate Limiting**: Token bucket algorithm with per-IP and global limits
- **Circuit Breaker**: Automatic failure protection with recovery
- **Resource Guards**: Concurrent request and validation operation limits
- **Size Limits**: Request body, field, and structure size restrictions

### 🔧 Web Framework Integration
- **Axum Middleware**: Drop-in security middleware with configurable rules
- **Security Headers**: Automatic security header injection
- **Request Validation**: Automatic extraction and validation of request data
- **Error Handling**: Structured error responses without information leakage

### 🧪 Comprehensive Testing
- **Fuzz Testing**: libFuzzer integration with structured input generation
- **Property-Based Testing**: QuickCheck and Proptest integration
- **Benchmark Suite**: Performance testing with Criterion
- **Integration Tests**: End-to-end security validation tests

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
input-validation = { path = "../input-validation", features = ["validation", "sanitization", "rate-limiting"] }
```

### Basic Validation

```rust
use input_validation::{SecurityValidator, ValidatorConfig, InputType};

// Create validator with production security settings
let validator = SecurityValidator::new(ValidatorConfig::production())?;

// Validate email address
let result = validator.validate("user@example.com", InputType::Email);
if result.is_valid() {
    println!("Email is valid!");
} else {
    println!("Validation errors: {:?}", result.errors);
}

// Check for injection attacks
let injection_patterns = validator.check_injection("'; DROP TABLE users --");
if !injection_patterns.is_empty() {
    println!("Injection attempt detected: {:?}", injection_patterns);
}
```

### Input Sanitization

```rust
use input_validation::{Sanitizer, SanitizationConfig, InputType};

// Create sanitizer with strict settings
let sanitizer = Sanitizer::strict();

// Sanitize potentially dangerous input
let result = sanitizer.sanitize("<script>alert('xss')</script>", InputType::Text)?;

println!("Original: {}", result.original_preview);
println!("Sanitized: {}", result.sanitized);
println!("Was sanitized: {}", result.was_sanitized);
println!("Operations: {:?}", result.operations);
```

### SCIM Filter Parsing

```rust
use input_validation::parsers::{ScimParser, SafeParser, ParserConfig};

// Create secure SCIM filter parser
let parser = ScimParser::new(ParserConfig::production())?;

// Parse SCIM filter with security validation
let result = parser.parse(r#"userName eq "john" and active eq true"#)?;
println!("Parsed filter: {:?}", result.value);
println!("Parse metadata: {:?}", result.metadata);
```

### OAuth Parameter Parsing

```rust
use input_validation::parsers::{OAuthParser, SafeParser, ParserConfig};

// Create secure OAuth parameter parser
let parser = OAuthParser::new(ParserConfig::production())?;

// Parse OAuth parameters with validation
let params = "grant_type=authorization_code&client_id=test123&redirect_uri=https%3A%2F%2Fexample.com";
let result = parser.parse(params)?;

println!("Grant type: {:?}", result.value.grant_type);
println!("Client ID: {:?}", result.value.client_id);
println!("Redirect URI: {:?}", result.value.redirect_uri);
```

### DoS Protection

```rust
use input_validation::{DoSProtection, DoSConfig};

// Create DoS protection with production settings
let dos_protection = DoSProtection::new(DoSConfig::production());

// Check request against DoS protection rules
let client_ip = "192.168.1.100";
let body_size = 1024;

let guard = dos_protection.check_request(client_ip, body_size).await?;

// Perform request processing...

// Record successful completion
guard.record_success().await;
```

### Web Middleware Integration

```rust
use input_validation::middleware::{SecurityMiddleware, SecurityMiddlewareConfig};
use axum::{Router, routing::get};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create security middleware
    let security_middleware = SecurityMiddleware::production()?;
    
    // Build router with security middleware
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .layer(axum::middleware::from_fn(move |req, next| {
            let middleware = security_middleware.clone();
            async move { middleware.apply(req, next).await }
        }));
    
    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}
```

## Fuzz Testing

### Using cargo-fuzz

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run SCIM filter fuzzing
cargo fuzz run scim_filter

# Run OAuth parameter fuzzing
cargo fuzz run oauth_params

# Run JWT token fuzzing
cargo fuzz run jwt_tokens

# Run general input validation fuzzing
cargo fuzz run input_validation
```

### Using the Fuzz Runner

```bash
# Run all fuzz targets with default settings
cargo run --bin fuzz-runner --features fuzzing

# Run specific target with custom iterations
cargo run --bin fuzz-runner --features fuzzing -- --target scim --iterations 50000

# Enable structured fuzzing and save results
cargo run --bin fuzz-runner --features fuzzing -- --structured --output results.json
```

### Fuzz Test Configuration

```rust
use input_validation::fuzzing::{FuzzTestSuite, FuzzConfig, ScimFilterFuzzTarget};
use std::time::Duration;

let config = FuzzConfig {
    max_iterations: 100000,
    max_input_size: 64 * 1024,
    total_timeout: Duration::from_secs(600),
    structured_fuzzing: true,
    ..Default::default()
};

let mut suite = FuzzTestSuite::new(config);
suite.add_target(ScimFilterFuzzTarget::new()?);

let results = suite.run_all();
for result in results {
    println!("Target: {}, Crashes: {}, Violations: {}", 
             result.target, result.crashes, result.security_violations);
}
```

## Property-Based Testing

### Using Proptest

```rust
use input_validation::property_testing::proptest_integration::*;
use proptest::prelude::*;

proptest! {
    #[test]
    fn validation_is_deterministic(input in arb_validation_string()) {
        assert!(prop_validation_deterministic(input, InputType::Text));
    }
    
    #[test]
    fn sanitization_preserves_safety(input in arb_validation_string()) {
        assert!(prop_sanitization_safety(input));
    }
}
```

### Using QuickCheck

```rust
use input_validation::property_testing::quickcheck_integration::*;
use quickcheck::quickcheck;

quickcheck! {
    fn validation_is_deterministic(input: String) -> bool {
        prop_validation_deterministic(input, InputType::Text)
    }
    
    fn size_limits_enforced(size: usize) -> bool {
        prop_size_limits_enforced(size)
    }
}
```

## Benchmarking

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark group
cargo bench validation
cargo bench sanitization
cargo bench parsing
cargo bench dos_protection

# Generate HTML reports
cargo bench -- --output-format html
```

## Configuration

### Security Levels

```rust
use input_validation::{ValidatorConfig, SanitizationConfig, DoSConfig};

// Production: Maximum security, minimal functionality
let prod_validator = ValidatorConfig::production();
let prod_sanitizer = SanitizationConfig::strict();
let prod_dos = DoSConfig::production();

// Development: Balanced security and functionality  
let dev_validator = ValidatorConfig::development();
let dev_sanitizer = SanitizationConfig::normal();
let dev_dos = DoSConfig::development();
```

### Custom Configuration

```rust
use input_validation::{ValidatorConfig, InputLimits, SecurityLevel};
use std::time::Duration;

let config = ValidatorConfig {
    input_limits: InputLimits {
        max_length: 2048,
        max_field_count: 50,
        max_depth: 5,
        max_array_size: 100,
        timeout: Duration::from_millis(200),
    },
    security_level: SecurityLevel::Strict,
    // ... other configuration
};
```

## Security Considerations

### Input Size Limits

The framework enforces multiple levels of size limits:

- **Request Level**: Total request body size
- **Field Level**: Individual field size
- **Structure Level**: JSON/XML nesting depth and array sizes
- **String Level**: Maximum string length per input type

### Injection Attack Prevention

The framework detects and prevents:

- **SQL Injection**: `'; DROP TABLE users --`
- **XSS**: `<script>alert('xss')</script>`
- **Command Injection**: `$(rm -rf /)`
- **Path Traversal**: `../../../etc/passwd`
- **LDAP Injection**: `*)(uid=*`
- **NoSQL Injection**: `{"$where": "function() { ... }"}`

### DoS Attack Mitigation

- **Rate Limiting**: Per-IP and global request limits
- **Resource Limiting**: Memory and CPU usage bounds
- **Timeout Protection**: Configurable operation timeouts
- **Circuit Breaker**: Automatic failure protection

### Error Handling

The framework provides structured error handling without information leakage:

- **Sanitized Error Messages**: No sensitive data in error responses
- **Error Classification**: Structured error codes and types
- **Logging Safety**: Secure logging without data exposure

## Performance

### Benchmarks

Performance benchmarks on a MacBook Pro M1:

- **Email Validation**: ~500,000 ops/sec
- **SCIM Filter Parsing**: ~50,000 ops/sec
- **OAuth Parameter Parsing**: ~100,000 ops/sec
- **XSS Sanitization**: ~200,000 ops/sec
- **Injection Detection**: ~300,000 ops/sec

### Memory Usage

- **Validator**: ~50KB baseline memory
- **Parser**: ~10KB per parser instance
- **Sanitizer**: ~5KB baseline memory
- **DoS Protection**: ~100KB for rate limiting state

### Concurrency

The framework is designed for high-concurrency environments:

- **Thread-Safe**: All components are thread-safe
- **Lock-Free**: Uses lock-free data structures where possible
- **Async Support**: Full async/await support
- **Resource Pooling**: Efficient resource reuse

## Testing

```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration_tests

# Run property-based tests
cargo test --features property-testing

# Run benchmarks
cargo bench

# Run fuzz tests
cargo run --bin fuzz-runner --features fuzzing
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add comprehensive tests for new functionality
4. Run the full test suite: `cargo test --all-features`
5. Run fuzz tests: `cargo run --bin fuzz-runner --features fuzzing`
6. Submit a pull request

## Security Reporting

For security vulnerabilities, please email security@rust-security-platform.com instead of using the issue tracker.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
