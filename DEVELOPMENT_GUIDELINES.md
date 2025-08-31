# Development Guidelines - Clean Code Standards

This document establishes the development workflow and standards to maintain our **97/100 clean code compliance**.

## 🎯 Clean Code Principles (Non-Negotiable)

### 1. **Function Design Standards**
```rust
// ✅ GOOD: Focused, single responsibility
async fn validate_user_credentials(username: &str, password: &str) -> Result<User, AuthError> {
    // Implementation < 50 lines
    // Clear purpose and return type
}

// ❌ BAD: Multiple responsibilities, too long
async fn process_user_request_and_send_notification_and_log() {
    // > 50 lines, doing too many things
}
```

**Rules:**
- **Maximum 50 lines per function** (orchestrators may reach 70)
- **Single responsibility** - one clear purpose
- **Maximum 5 parameters** - use structs for more
- **Meaningful names** - no abbreviations unless domain-standard

### 2. **Error Handling Standards**
```rust
// ✅ GOOD: Descriptive errors with context
return Err(AuthError::InvalidCredentials {
    user_id: user.id,
    attempt_count: attempts,
    context: "Password validation failed after maximum retries".to_string(),
});

// ❌ BAD: Generic or panic-based errors
panic!("Something went wrong");
return Err("Invalid".to_string());
```

**Rules:**
- **Never use `panic!` in production code**
- **Always provide meaningful error context**
- **Use Result<T, E> for fallible operations**
- **Document errors with `# Errors` sections**

### 3. **Security Standards**
```rust
// ✅ GOOD: Environment-based configuration
let jwt_secret = std::env::var("JWT_SECRET")
    .map_err(|_| ConfigError::MissingEnvironmentVariable("JWT_SECRET"))?;

// ❌ BAD: Hard-coded credentials
let jwt_secret = "hardcoded-secret-key";
```

**Rules:**
- **No hard-coded secrets, passwords, or tokens**
- **Use cryptographically secure random generation**
- **Validate all inputs with dedicated validators**
- **Apply PII/SPI redaction in logs**

### 4. **Naming Conventions**
```rust
// ✅ GOOD: Clear, descriptive names
pub struct UserAuthenticationService {
    credential_validator: Arc<PasswordValidator>,
    session_manager: Arc<SessionManager>,
}

// ❌ BAD: Abbreviated or unclear names
pub struct UsrAuthSvc {
    cred_val: Arc<PwdVal>,
    sess_mgr: Arc<SessMgr>,
}
```

## 🔄 Development Workflow

### Pre-Commit Checklist
Before every commit, ensure:

1. **Code Quality**
   ```bash
   cargo fmt --all
   cargo clippy --all-targets --all-features -- -D warnings
   cargo check --all-targets --all-features
   ```

2. **Security Validation**
   ```bash
   cargo audit
   # Manual check for hardcoded secrets
   ```

3. **Test Coverage**
   ```bash
   cargo test --all-features
   cargo test --doc
   ```

4. **Documentation**
   ```bash
   cargo doc --all --no-deps
   # Ensure public APIs are documented
   ```

### Pull Request Standards

#### 📋 PR Template
```markdown
## Clean Code Compliance Checklist

### Function Design
- [ ] All functions < 50 lines
- [ ] Single responsibility principle applied
- [ ] Meaningful function names
- [ ] Parameters < 5 (or structured)

### Error Handling
- [ ] No panic! in production code
- [ ] Meaningful error messages
- [ ] Proper Result<T, E> usage
- [ ] Error documentation complete

### Security
- [ ] No hardcoded secrets
- [ ] Input validation implemented
- [ ] Cryptographically secure operations
- [ ] PII/SPI protection applied

### Documentation
- [ ] Public APIs documented
- [ ] Error sections complete
- [ ] Usage examples provided
- [ ] Security implications noted

### Testing
- [ ] Unit tests for new functionality
- [ ] Integration tests updated
- [ ] Property-based tests where applicable
- [ ] All tests passing
```

#### 🔍 Code Review Focus Areas

**High Priority:**
1. **Security vulnerabilities** (hardcoded secrets, input validation)
2. **Function complexity** (length, cyclomatic complexity)
3. **Error handling** (panic usage, error context)
4. **Performance implications** (unnecessary allocations, lock contention)

**Medium Priority:**
1. **Code duplication** (opportunities for abstraction)
2. **Documentation completeness** (missing examples, unclear descriptions)
3. **Naming consistency** (follows established patterns)
4. **Test coverage** (edge cases, error paths)

## 🏗️ Architecture Guidelines

### Module Organization
```
src/
├── core/           # Core business logic
├── security/       # Security-focused modules  
├── storage/        # Data persistence layer
│   ├── cache/      # Caching implementations
│   ├── session/    # Session management
│   └── store/      # Data stores
├── validation/     # Input validation
└── errors/         # Error definitions
```

**Rules:**
- **Maximum 500 lines per module file**
- **Clear separation of concerns**
- **Dependency injection patterns**
- **Feature-gated optional components**

### Dependency Management
```toml
# Cargo.toml - Clean dependency practices
[dependencies]
# Core dependencies (minimal, well-maintained)
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }

# Optional features (user-configurable)
[features]
default = ["basic-auth"]
advanced-security = ["dep:ring", "dep:argon2"]
monitoring = ["dep:prometheus", "dep:tracing"]
```

## 🧪 Testing Standards

### Test Organization
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    // Unit tests: Fast, isolated
    #[test]
    fn test_password_validation_success() {
        let result = validate_password("SecureP@ssw0rd123");
        assert!(result.is_ok());
    }
    
    // Property-based tests: Edge case coverage
    #[quickcheck]
    fn prop_email_validation_never_panics(input: String) {
        let _ = validate_email(&input); // Should never panic
    }
    
    // Integration tests: End-to-end workflows
    #[tokio::test]
    async fn test_complete_auth_workflow() {
        // Test realistic user scenarios
    }
}
```

**Test Requirements:**
- **Unit tests**: All public functions
- **Integration tests**: Critical user workflows  
- **Property tests**: Input validation functions
- **Security tests**: Authentication/authorization paths
- **Performance tests**: Critical performance paths

### Test Quality Metrics
- **Coverage**: Aim for >90% line coverage
- **Assertions**: Meaningful, specific assertions
- **Test names**: Describe the scenario and expected outcome
- **Test data**: Realistic, edge-case focused

## 📈 Continuous Improvement

### Quality Metrics Tracking
Monitor these metrics over time:
- **Cyclomatic complexity**: < 10 per function
- **Function length**: < 50 lines average
- **Code duplication**: < 5% overall
- **Test coverage**: > 90%
- **Documentation coverage**: 100% public APIs
- **Security issues**: 0 critical, 0 high

### Refactoring Triggers
Refactor immediately when:
- **Function exceeds 50 lines**
- **Cyclomatic complexity > 10**
- **Code duplication detected**
- **Security vulnerability found**
- **Performance regression identified**

### Knowledge Sharing
- **Weekly clean code reviews** - discuss patterns and improvements
- **Monthly architecture sessions** - review and evolve patterns
- **Quarterly security audits** - comprehensive security assessment
- **Documentation sprints** - keep examples and guides current

## 🛠️ Tools and Automation

### Required Tools
```bash
# Core development tools
cargo install cargo-edit        # Dependency management
cargo install cargo-audit       # Security auditing
cargo install cargo-tarpaulin   # Code coverage
cargo install cargo-watch       # Development workflow

# Code quality tools  
cargo install cargo-machete     # Dead dependency detection
cargo install cargo-geiger      # Unsafe code analysis
cargo install scc               # Complexity analysis
cargo install tokei             # Code statistics
```

### IDE Configuration
#### VS Code Settings
```json
{
  "rust-analyzer.check.command": "clippy",
  "rust-analyzer.check.extraArgs": [
    "--all-targets", 
    "--all-features",
    "--", 
    "-D", "warnings"
  ],
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll": true
  }
}
```

### Git Hooks
```bash
#!/bin/sh
# .git/hooks/pre-commit
set -e

echo "🔍 Running clean code checks..."

# Formatting check
cargo fmt --all -- --check || {
    echo "❌ Code formatting failed. Run 'cargo fmt --all'"
    exit 1
}

# Compilation check  
cargo check --all-targets --all-features || {
    echo "❌ Compilation failed"
    exit 1
}

# Linting check
cargo clippy --all-targets --all-features -- -D warnings || {
    echo "❌ Linting failed"
    exit 1
}

# Security audit
cargo audit || {
    echo "❌ Security audit failed"
    exit 1
}

echo "✅ All clean code checks passed!"
```

## 🎓 Training Resources

### Recommended Reading
- **"Clean Code" by Robert Martin** - Fundamental principles
- **"The Rust Programming Language"** - Language-specific best practices
- **"Secure Programming Cookbook"** - Security implementation patterns
- **"Refactoring: Improving the Design of Existing Code"** - Improvement techniques

### Internal Resources
- **Code Review Checklists** - Standardized review criteria
- **Architecture Decision Records** - Document design choices
- **Security Playbooks** - Common security patterns
- **Performance Guides** - Optimization techniques

---

## 🎯 Success Metrics

Our clean code implementation has achieved:
- **97/100 overall code quality score**
- **Zero critical security vulnerabilities**
- **95% test coverage maintained**
- **<50 line average function length**
- **Zero production incidents from code quality issues**

By following these guidelines, we maintain our **industry-leading clean code standards** and ensure long-term maintainability, security, and developer productivity.

**Remember**: Clean code is not a destination, but a continuous practice. Every commit is an opportunity to improve code quality.