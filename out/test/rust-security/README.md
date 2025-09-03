# Comprehensive Test Suite for Rust Authentication Service

This directory contains a comprehensive test suite designed to ensure the security, reliability, and performance of the Rust authentication service.

## Test Structure

```
tests/
├── unit/                          # Unit tests for individual modules
│   ├── security_unit_tests.rs     # Security function unit tests
│   └── ...
├── integration/                   # Integration tests for complete flows  
│   ├── oauth_flow_tests.rs        # OAuth2/OIDC flow tests
│   └── ...
├── security/                      # Security-focused testing
│   ├── attack_simulation_tests.rs # Attack simulation and boundary tests
│   └── ...
├── performance/                   # Performance and load testing
│   ├── load_tests.rs              # Load testing and benchmarks
│   └── ...
├── mfa/                          # MFA-specific comprehensive tests
│   ├── mfa_comprehensive_tests.rs # TOTP, backup codes, replay protection
│   └── ...
├── property/                     # Property-based testing
│   ├── property_based_tests.rs   # Property-based and fuzzing tests
│   └── ...
├── coverage/                     # Coverage-focused tests
│   ├── coverage_tests.rs         # Tests to ensure high code coverage
│   └── ...
├── test_utils.rs                 # Shared test utilities and fixtures
├── test_config.toml              # Test configuration
└── README.md                     # This file
```

## Test Categories

### 1. Unit Tests (`unit/`)

**Purpose**: Test individual functions and modules in isolation.

**Key Features**:
- Mock external dependencies (Redis, HTTP clients)
- Test all error conditions and edge cases
- Validate security functions (PKCE, signatures, token binding)
- Property-based testing for crypto functions
- Achieve >90% code coverage for security-critical code

**Example Tests**:
- PKCE code generation and verification
- Request signature generation and validation
- Token input validation and sanitization
- Rate limiter functionality
- Key rotation and JWKS operations

### 2. Integration Tests (`integration/`)

**Purpose**: Test complete OAuth2/OIDC flows end-to-end.

**Key Features**:
- Spawn test HTTP servers
- Test complete authentication flows
- Validate token lifecycle management
- Test error handling across components
- Concurrent operation testing

**Example Tests**:
- Client credentials flow
- Authorization code flow with PKCE
- Refresh token flow and reuse detection
- Scope validation
- JWKS endpoint functionality

### 3. Security Tests (`security/`)

**Purpose**: Validate security boundaries and attack resistance.

**Key Features**:
- SQL injection attack simulation
- XSS and CSRF protection testing
- Timing attack resistance validation
- Rate limiting enforcement
- Input validation boundary testing

**Example Tests**:
- Malicious payload injection attempts
- Session fixation resistance
- Buffer overflow resistance
- Information disclosure prevention
- Concurrent attack simulation

### 4. Performance Tests (`performance/`)

**Purpose**: Validate performance characteristics under load.

**Key Features**:
- Token issuance latency measurement
- Concurrent user simulation
- Memory usage validation
- Database operation performance
- Rate limiter performance testing

**Example Tests**:
- Token generation throughput (>10 tokens/sec)
- Concurrent operation handling (50+ users)
- Memory usage per token (<1KB)
- Latency percentiles (P95 <200ms)

### 5. MFA Tests (`mfa/`)

**Purpose**: Comprehensive testing of MFA functionality.

**Key Features**:
- TOTP registration and verification
- Backup code generation and usage
- Replay attack protection
- Rate limiting for OTP requests
- Time window tolerance testing

**Example Tests**:
- TOTP code generation with time windows
- Backup code single-use enforcement
- OTP delivery via SMS/email
- MFA session verification
- Concurrent MFA operations

### 6. Property-Based Tests (`property/`)

**Purpose**: Use property-based testing to find edge cases.

**Key Features**:
- Generate random valid/invalid inputs
- Test invariants across all inputs
- Fuzzing for security functions
- State machine testing
- Timing consistency validation

**Example Tests**:
- Token format consistency properties
- PKCE verification properties
- Rate limiter fairness properties
- Error handling consistency

### 7. Coverage Tests (`coverage/`)

**Purpose**: Ensure comprehensive code coverage.

**Key Features**:
- Exercise all error code paths
- Test all configuration branches
- Validate all HTTP endpoints
- Test concurrent operations
- Error conversion coverage

## Test Utilities (`test_utils.rs`)

Provides shared utilities for all tests:

- **TestFixture**: Spawns test servers and provides HTTP clients
- **SecurityTestUtils**: Timing attack testing, random generation
- **PerformanceTestUtils**: Latency measurement, concurrent testing
- **PropertyTestUtils**: Random data generation for property tests
- **TestDataGenerator**: Malicious payloads, boundary values

## Running Tests

### Quick Validation

For fast feedback during development:

```bash
./scripts/quick_test_validation.sh
```

### Comprehensive Test Suite

For complete testing:

```bash
./scripts/run_comprehensive_tests.sh
```

### Individual Test Categories

```bash
# Unit tests only
cargo test --lib --bins unit --all-features

# Integration tests only  
cargo test --test '*' integration --all-features

# Security tests only
cargo test --test '*' security --all-features

# Performance tests only
cargo test --test '*' performance --all-features --release

# MFA tests only
cargo test --test '*' mfa --all-features

# Property-based tests only
cargo test --test '*' property --all-features
```

### With Coverage

```bash
cargo tarpaulin --all-features --out Html --output-dir coverage
```

## Test Configuration

Tests can be configured via environment variables:

```bash
# Test mode settings
export TEST_MODE=1
export RUST_BACKTRACE=1
export RUST_LOG=debug

# Security settings
export REQUEST_SIGNING_SECRET=test_secret
export DISABLE_RATE_LIMIT=1

# Property test settings
export PROPTEST_CASES=1000
export QUICKCHECK_TESTS=1000

# Performance test settings
export CONCURRENT_USERS=50
export OPERATIONS_PER_USER=10
```

## CI/CD Integration

The test suite integrates with GitHub Actions:

- **Quick validation**: Runs on every push
- **Full test suite**: Runs on PRs and daily schedule
- **Performance tests**: Optional, configurable via workflow inputs
- **Security audits**: Runs dependency and vulnerability checks
- **Coverage reporting**: Generates and uploads coverage reports

## Test Quality Standards

### Coverage Targets

- **Line Coverage**: >90% for security-critical modules
- **Branch Coverage**: >85% for all modules
- **Error Path Coverage**: 100% for error handling

### Performance Targets

- **Token Latency**: <100ms average, <200ms P95
- **Throughput**: >50 tokens/sec under load
- **Memory Usage**: <1KB per token
- **Concurrent Users**: Support 50+ simultaneous users

### Security Validation

- **Timing Attack Resistance**: <50% timing variance
- **Input Validation**: 100% malicious payload rejection
- **Rate Limiting**: Enforced under load
- **Replay Protection**: 100% duplicate detection

## Writing New Tests

### Unit Test Template

```rust
#[tokio::test]
async fn test_function_name() {
    // Arrange
    let input = "test_input";
    
    // Act
    let result = function_under_test(input);
    
    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), expected_value);
}
```

### Integration Test Template

```rust
#[tokio::test]
async fn test_integration_scenario() {
    let fixture = TestFixture::new().await;
    
    // Test complete flow
    let response = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
        .body("grant_type=client_credentials")
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
}
```

### Property-Based Test Template

```rust
#[tokio::test]
async fn test_property_invariant() {
    let test_cases = PropertyTestUtils::generate_valid_tokens(100);
    
    for token in test_cases {
        // Property: All valid tokens should pass validation
        let result = validate_token_input(&token);
        assert!(result.is_ok(), "Valid token should pass: {}", token);
    }
}
```

## Debugging Tests

### Viewing Test Output

```bash
# Run with verbose output
cargo test --test test_name -- --nocapture

# Run with debug logging
RUST_LOG=debug cargo test --test test_name -- --nocapture

# Run single test
cargo test --test test_name specific_test_function -- --nocapture
```

### Test Isolation

- Each test uses isolated state
- Mock external dependencies to prevent flaky tests
- Use unique test data to avoid conflicts
- Clean up resources after each test

### Performance Debugging

```bash
# Run performance tests with profiling
cargo test --test performance_tests --release -- --nocapture

# Generate flamegraphs (requires flame feature)
cargo test --features flame --test performance_tests --release
```

## Contributing

When adding new functionality:

1. **Write tests first** (TDD approach)
2. **Add unit tests** for the core logic
3. **Add integration tests** for new endpoints/flows
4. **Add security tests** if handling user input
5. **Add performance tests** if performance-critical
6. **Update this README** if adding new test categories

### Test Review Checklist

- [ ] Tests cover happy path and error cases
- [ ] Security boundaries are tested
- [ ] Performance characteristics are validated
- [ ] Tests are deterministic and not flaky
- [ ] Mock external dependencies appropriately
- [ ] Follow naming conventions
- [ ] Include descriptive assertions

## Troubleshooting

### Common Issues

1. **Redis Connection Errors**: Ensure Redis is running for integration tests
2. **Timing-sensitive Tests**: Use mocked time or increase tolerances
3. **Flaky Network Tests**: Add retries and proper error handling
4. **Memory Leaks in Tests**: Ensure proper cleanup of resources
5. **Slow Tests**: Profile and optimize test setup/teardown

### Getting Help

- Check test logs in `test-results/` directory
- Run individual test suites to isolate issues
- Use `RUST_LOG=debug` for detailed logging
- Check GitHub Actions for CI/CD test results

## Metrics and Monitoring

The test suite generates metrics for:

- **Test Execution Time**: Track performance trends
- **Coverage Percentage**: Ensure coverage targets
- **Failure Rates**: Monitor test reliability
- **Performance Benchmarks**: Track performance regressions

These metrics are collected in CI/CD and can be used for continuous monitoring of code quality and performance.