# Contributing to Rust Security Platform

Thank you for your interest in contributing to the Rust Security Platform! This document provides guidelines and instructions for contributing to our security-focused authentication and authorization services.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Security Requirements](#security-requirements)
- [Code Quality Standards](#code-quality-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation Standards](#documentation-standards)
- [Submitting Changes](#submitting-changes)
- [Review Process](#review-process)

## Code of Conduct

This project adheres to a strict security-first approach. All contributions must:

- Prioritize security over convenience
- Follow defensive programming practices
- Never introduce potential vulnerabilities
- Maintain backward compatibility unless security requires breaking changes

## Getting Started

### Prerequisites

- **Rust**: Install via [rustup](https://rustup.rs/) (minimum version 1.80)
- **PostgreSQL**: Version 15+ for local development
- **Redis**: Version 7+ for session storage
- **Git**: For version control

### Environment Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/lsendel/rust-security.git
   cd rust-security
   ```

2. **Install development tools:**
   ```bash
   # Install required cargo tools
   cargo install cargo-audit cargo-deny sqlx-cli cargo-fuzz
   
   # Install pre-commit hooks
   ./setup-git-hooks.sh
   ```

3. **Set up local environment:**
   ```bash
   # Copy sample configuration
   cp auth-service/config/sample.env .env
   
   # Start dependencies
   docker-compose up -d redis postgres
   
   # Run database migrations
   export DATABASE_URL=postgres://postgres:postgres@localhost:5432/auth_test
   sqlx migrate run --source auth-service/migrations
   ```

4. **Verify setup:**
   ```bash
   # Run tests to verify everything works
   make test
   ```

## Development Workflow

### Branch Strategy

- **main**: Production-ready code, protected branch
- **develop**: Integration branch for features
- **feature/**: Feature branches (`feature/security-enhancement`)
- **bugfix/**: Bug fix branches (`bugfix/auth-validation`)
- **security/**: Security fixes (`security/fix-timing-attack`)

### Commit Messages

Follow the Conventional Commits specification:

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New features
- `fix`: Bug fixes  
- `security`: Security improvements
- `perf`: Performance improvements
- `refactor`: Code refactoring
- `test`: Test additions/improvements
- `docs`: Documentation changes
- `ci`: CI/CD changes

**Examples:**
```bash
security(auth): implement constant-time comparison for tokens
feat(mfa): add WebAuthn support with hardware key validation
fix(session): prevent session fixation vulnerability
```

### Development Commands

```bash
# Code quality checks
make check          # Run all quality checks
make fmt           # Format code
make clippy        # Run clippy lints
make security-audit # Run security audit

# Testing
make test          # Run all tests
make test-unit     # Unit tests only
make test-integration # Integration tests
make test-fuzz     # Fuzz testing
make benchmark     # Performance benchmarks

# Development server
make dev           # Start development server with hot reload
make debug         # Start with debug logging
```

## Security Requirements

### Mandatory Security Practices

1. **Input Validation**: All inputs must be validated and sanitized
2. **Output Encoding**: All outputs must be properly encoded
3. **Secrets Management**: Never hardcode secrets or keys
4. **Timing Attacks**: Use constant-time operations for sensitive comparisons
5. **Error Handling**: Implement secure error handling that doesn't leak information
6. **Logging**: Use secure logging that sanitizes sensitive data

### Security Review Checklist

Before submitting code, ensure:

- [ ] No hardcoded secrets or credentials
- [ ] All user inputs are validated
- [ ] SQL injection prevention (use parameterized queries)
- [ ] XSS prevention (proper encoding)
- [ ] CSRF protection for state-changing operations
- [ ] Rate limiting for authentication endpoints
- [ ] Secure session management
- [ ] Proper access control checks
- [ ] Constant-time comparisons for sensitive data
- [ ] Secure random number generation

### Prohibited Patterns

**Never use these patterns:**

```rust
// ❌ Timing attack vulnerability
if token == expected_token {
    // ...
}

// ❌ Information disclosure
return Err(format!("Database error: {}", db_error));

// ❌ Hardcoded secrets
const API_KEY: &str = "sk-1234567890abcdef";

// ❌ SQL injection risk
format!("SELECT * FROM users WHERE id = {}", user_id)

// ❌ Insecure logging
info!("User login: {}", password);
```

**Use these instead:**

```rust
// ✅ Constant-time comparison
use constant_time_eq::constant_time_eq;
if constant_time_eq(token.as_bytes(), expected_token.as_bytes()) {
    // ...
}

// ✅ Secure error handling
return Err(AuthError::DatabaseError);

// ✅ Environment-based configuration
let api_key = std::env::var("API_KEY")?;

// ✅ Parameterized queries
sqlx::query!("SELECT * FROM users WHERE id = $1", user_id)

// ✅ Secure logging
info!("User login attempt from IP: {}", ip_addr);
```

## Code Quality Standards

### Rust-Specific Guidelines

1. **Error Handling**: Use `thiserror` for custom errors, `anyhow` for application errors
2. **Async Code**: Prefer `tokio` for async runtime
3. **Database**: Use `sqlx` with compile-time checked queries
4. **Serialization**: Use `serde` with security-conscious configuration
5. **Cryptography**: Use `ring` and other RustCrypto implementations
6. **HTTP**: Use `axum` for web services with security middleware

### Code Style

- **Formatting**: Use `rustfmt` with project configuration
- **Linting**: Address all `clippy` warnings
- **Documentation**: Document all public APIs
- **Comments**: Explain complex security logic
- **Naming**: Use clear, security-focused naming

### Architecture Principles

1. **Defense in Depth**: Multiple security layers
2. **Principle of Least Privilege**: Minimal permissions
3. **Fail Secure**: Secure defaults when errors occur  
4. **Zero Trust**: Verify everything, trust nothing
5. **Separation of Concerns**: Clear module boundaries

## Testing Guidelines

### Test Coverage Requirements

- **Unit Tests**: Minimum 80% coverage for security-critical code
- **Integration Tests**: All API endpoints must have integration tests
- **Security Tests**: Penetration testing for authentication flows
- **Property Tests**: Use `proptest` for input validation
- **Fuzz Tests**: Critical parsers must have fuzz tests

### Test Categories

1. **Unit Tests** (`tests/unit/`):
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       
       #[test]
       fn test_constant_time_comparison() {
           // Test security-critical functionality
       }
   }
   ```

2. **Integration Tests** (`tests/integration/`):
   ```rust
   #[tokio::test]
   async fn test_authentication_flow() {
       // Test complete authentication scenarios
   }
   ```

3. **Property Tests** (`tests/property/`):
   ```rust
   use proptest::prelude::*;
   
   proptest! {
       #[test]
       fn test_input_validation(input in ".*") {
           // Test with arbitrary inputs
       }
   }
   ```

4. **Security Tests** (`tests/security/`):
   ```rust
   #[tokio::test]
   async fn test_timing_attack_resistance() {
       // Verify constant-time operations
   }
   ```

### Test Data Security

- Use test-specific credentials and keys
- Never use production data in tests
- Sanitize test outputs to prevent information leakage
- Use deterministic random seeds for reproducible tests

## Documentation Standards

### Required Documentation

1. **API Documentation**: All public functions must have rustdoc comments
2. **Security Notes**: Document security implications
3. **Examples**: Provide secure usage examples
4. **Architecture Decisions**: Document security design choices

### Documentation Format

```rust
/// Validates and authenticates a JWT token using constant-time comparison.
///
/// # Security Note
/// This function uses constant-time comparison to prevent timing attacks.
/// The validation includes signature verification, expiration checks, and
/// issuer validation.
///
/// # Examples
/// ```
/// use auth_service::validate_jwt;
/// 
/// let result = validate_jwt(&token, &public_key).await?;
/// ```
///
/// # Errors
/// Returns `AuthError::InvalidToken` if token validation fails.
/// Returns `AuthError::ExpiredToken` if token has expired.
pub async fn validate_jwt(token: &str, key: &PublicKey) -> Result<Claims, AuthError> {
    // Implementation...
}
```

### Security Documentation

Document security considerations for each module:

```rust
//! # Security Considerations
//!
//! This module handles authentication tokens and includes the following
//! security measures:
//!
//! - Constant-time token comparison to prevent timing attacks
//! - Secure token generation using cryptographically secure RNG  
//! - Automatic token expiration with secure cleanup
//! - Rate limiting to prevent brute force attacks
```

## Submitting Changes

### Pull Request Process

1. **Create Feature Branch**:
   ```bash
   git checkout -b feature/security-enhancement
   ```

2. **Make Changes**: Follow all guidelines above

3. **Test Thoroughly**:
   ```bash
   make test
   make security-audit
   make benchmark
   ```

4. **Update Documentation**: Update relevant docs

5. **Security Self-Review**: Complete security checklist

6. **Create Pull Request**: Use the PR template

### Pull Request Template

```markdown
## Description
Brief description of changes and motivation.

## Security Impact
- [ ] No security implications
- [ ] Security improvement
- [ ] Potential security impact (explain below)

## Security Checklist
- [ ] No hardcoded secrets
- [ ] Input validation implemented
- [ ] Output encoding applied
- [ ] Constant-time operations used
- [ ] Secure error handling
- [ ] Logging sanitization
- [ ] Access control verified
- [ ] Tests cover security scenarios

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Security tests added/updated
- [ ] Manual testing completed

## Breaking Changes
- [ ] No breaking changes
- [ ] Breaking changes (describe below)

## Documentation
- [ ] Code documented
- [ ] README updated if needed
- [ ] Security implications documented
```

## Review Process

### Automated Checks

All PRs must pass:
- ✅ Compilation (stable and beta Rust)
- ✅ Formatting (`cargo fmt`)
- ✅ Linting (`cargo clippy`)
- ✅ Tests (unit, integration, security)
- ✅ Security audit (`cargo audit`)
- ✅ Dependency check (`cargo deny`)
- ✅ Documentation build
- ✅ Fuzz testing (for critical components)

### Manual Review

1. **Security Review**: All changes reviewed for security implications
2. **Code Review**: Architecture, performance, maintainability
3. **Documentation Review**: Accuracy and completeness
4. **Test Review**: Coverage and quality

### Review Criteria

**Security Review:**
- No introduction of vulnerabilities
- Proper implementation of security controls
- Adherence to secure coding practices
- Appropriate use of cryptographic libraries

**Code Review:**
- Follows Rust best practices
- Proper error handling
- Performance considerations
- Maintainable code structure

### Approval Requirements

- **2 approvals** required for all changes
- **Security team approval** for security-related changes
- **Maintainer approval** for breaking changes
- **Documentation approval** for significant doc updates

## Development Environment

### IDE Configuration

**VS Code Extensions:**
- rust-analyzer: Rust language support
- CodeLLDB: Debugging support
- Even Better TOML: TOML syntax highlighting
- Error Lens: Inline error display

**Configuration** (`.vscode/settings.json`):
```json
{
    "rust-analyzer.check.command": "clippy",
    "rust-analyzer.cargo.features": "all",
    "editor.formatOnSave": true,
    "files.exclude": {
        "**/target": true
    }
}
```

### Performance Monitoring

Monitor performance impact of changes:

```bash
# Run benchmarks
cargo bench

# Profile with perf (Linux)
perf record --call-graph=dwarf ./target/release/auth-service
perf report

# Memory profiling with valgrind
valgrind --tool=memcheck ./target/debug/auth-service
```

## Community Guidelines

### Getting Help

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Security Issues**: Email security@company.com for vulnerabilities

### Contributing Guidelines

1. **Start Small**: Begin with small, focused changes
2. **Ask Questions**: Don't hesitate to ask for clarification
3. **Follow Standards**: Adhere to all guidelines
4. **Be Patient**: Security reviews take time
5. **Learn Continuously**: Stay updated on security best practices

### Recognition

Contributors who make significant security improvements will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Eligible for security bounty rewards (if applicable)

## License

By contributing to this project, you agree that your contributions will be licensed under the same terms as the project (MIT OR Apache-2.0).

---

**Remember**: Security is everyone's responsibility. When in doubt, always choose the more secure option, even if it's less convenient.

For questions about these guidelines, please open a discussion or contact the maintainers.