# Red Team Security Exercises

A comprehensive suite of defensive security testing scenarios designed to validate authentication system security posture through controlled red team exercises.

## 🛡️ Purpose

This framework provides security professionals with realistic attack scenarios to:
- Test authentication system resilience 
- Identify security gaps before adversaries do
- Validate security controls effectiveness
- Generate actionable security reports

## ⚠️ Security Notice

**These tools are for defensive security testing only.** Only run against systems you own or have explicit written permission to test. Unauthorized testing is illegal and unethical.

## 🎯 Attack Scenarios

### Token Manipulation Attacks
- **JWT Manipulation**: Algorithm confusion, payload modification, signature bypass
- **JWT Timing Attacks**: Cryptographic timing leak detection and analysis
- **Token Substitution**: Common pattern testing and authorization header confusion  
- **Token Replay**: Immediate and cross-session replay detection
- **Token Enumeration**: Sequential pattern discovery with rate limit evasion
- **Token Binding Bypass**: IP and User-Agent binding circumvention
- **Token Validation Bypass**: SQL/NoSQL injection and path traversal testing

### OAuth2/OIDC Flow Attacks
- **Authorization Flow Manipulation**: Response type and parameter injection
- **PKCE Bypass**: Downgrade attacks and code challenge manipulation
- **Redirect URI Validation**: Bypass techniques and injection attacks
- **State Parameter CSRF**: Missing and predictable state testing
- **Scope Elevation**: Privilege escalation through scope manipulation
- **Client Authentication Bypass**: Weak secret and JWT none algorithm testing
- **Token Exchange Attacks**: Elevation and substitution via token exchange
- **OIDC-Specific**: Nonce manipulation and userinfo endpoint attacks
- **Authorization Code Injection**: Code injection and replay attacks

### Session Management Attacks  
- **Session Fixation**: Pre-set session ID acceptance testing
- **Session Hijacking**: Pattern-based session ID prediction
- **Session Enumeration**: Brute force session discovery
- **Concurrent Session Abuse**: Multiple session creation testing
- **Session Timeout Bypass**: Keep-alive mechanism abuse
- **Cross-Subdomain Attacks**: Session sharing and cookie injection
- **Session Token Manipulation**: Encoding/decoding bypass techniques

### MFA Bypass Attacks
- **TOTP Replay**: Time-based one-time password replay detection
- **TOTP Brute Force**: Statistical attack pattern testing
- **Backup Code Enumeration**: Recovery code weakness analysis
- **Time Window Exploitation**: Timing attack opportunities
- **Header Manipulation**: MFA bypass via request modification
- **OTP Interception**: SMS/Email interception simulation
- **MFA State Confusion**: Authentication state manipulation
- **WebAuthn Bypass**: Hardware token bypass attempts

### Rate Limiting Bypass
- **IP Rotation**: Distributed request source simulation
- **Header Manipulation**: X-Forwarded-For and proxy header abuse
- **Request Distribution**: Timing and volume evasion techniques
- **Endpoint Variation**: Alternative endpoint discovery
- **Token Bucket Overflow**: Rate limit algorithm testing

### IDOR (Insecure Direct Object Reference)
- **Resource Enumeration**: Sequential ID testing
- **Authorization Bypass**: Resource access validation
- **Parameter Injection**: ID parameter manipulation
- **Privilege Escalation**: Cross-user resource access

### Social Engineering Simulation
- **Phishing Simulation**: Credential harvesting detection
- **Pretexting**: Authority impersonation testing
- **Information Gathering**: OSINT simulation
- **Baiting**: Malicious link and attachment testing

### Authentication Flow Analysis
- **Multi-Step Authentication**: Flow bypass opportunities
- **Password Reset**: Token validation and hijacking
- **Account Registration**: Duplicate account creation
- **Login Attempt Analysis**: Brute force pattern detection

## 🚀 Usage

### Basic Usage

```rust
use red_team_exercises::{RedTeamFramework, RedTeamReporter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize framework
    let mut framework = RedTeamFramework::new("http://localhost:8080".to_string()).await?;
    let mut reporter = RedTeamReporter::new("security_assessment".to_string());

    // Run token manipulation scenarios
    red_team_exercises::scenarios::run_token_scenarios(&mut framework, &mut reporter, "medium").await?;
    
    // Generate comprehensive report
    let report = reporter.generate_report().await;
    println!("Security Assessment Complete: {} scenarios tested", report.scenario_results.len());
    
    Ok(())
}
```

### Intensity Levels

- **Low**: Basic testing with minimal requests (suitable for CI/CD)
- **Medium**: Moderate testing with realistic attack patterns  
- **High**: Comprehensive testing with extensive enumeration

### Command Line Interface

```bash
# Run all scenarios
cargo run --bin red-team-exercises -- --target http://localhost:8080 --intensity medium

# Run specific scenario categories
cargo run --bin red-team-exercises -- --target http://localhost:8080 --scenarios token,oauth,session

# Generate detailed report
cargo run --bin red-team-exercises -- --target http://localhost:8080 --output-format json --report-file security_report.json
```

## 📊 Reporting

The framework generates comprehensive reports including:

- **Executive Summary**: High-level security posture assessment
- **Vulnerability Details**: Specific findings with evidence
- **Risk Assessment**: CVSS scoring and impact analysis  
- **Remediation Guidance**: Actionable security recommendations
- **Timeline Analysis**: Attack pattern progression
- **Statistical Metrics**: Success rates and response times

### Report Formats

- **JSON**: Machine-readable for integration with SIEM/SOAR
- **HTML**: Human-readable dashboard with visualizations
- **SARIF**: Compatible with GitHub Security and code analysis tools
- **CSV**: Spreadsheet-compatible for analysis and tracking

## 🔧 Configuration

### Framework Configuration

```rust
let mut framework = RedTeamFramework::new("http://localhost:8080".to_string()).await?;

// Enable detection evasion techniques
framework.detection_evasion = true;

// Enable rate limit bypass methods  
framework.rate_limit_bypass = true;

// Configure request timeouts
framework.client = Client::builder()
    .timeout(Duration::from_secs(30))
    .build()?;
```

### Scenario Customization

```rust
// Custom attack patterns
let custom_patterns = vec![
    "custom_token_pattern_{}",
    "organization_specific_{}",
];

// Custom endpoints
let custom_endpoints = vec![
    "/api/v2/auth/validate",
    "/internal/session/verify",
];
```

## 🧪 Testing

### Unit Tests

```bash
# Run scenario unit tests
cargo test --lib

# Run integration tests
cargo test --test '*'

# Run with coverage
cargo llvm-cov --html
```

### Validation Tests

```bash
# Validate against test environment
cargo run --example validate_scenarios

# Benchmark performance
cargo bench

# Memory leak detection
cargo run --example memory_test
```

## 🔒 Security Considerations

### Safe Testing Practices

1. **Isolated Environments**: Always test in dedicated security testing environments
2. **Rate Limiting**: Built-in delays prevent overwhelming target systems
3. **Audit Logging**: All activities are logged for compliance and review
4. **Cleanup Procedures**: Automatic cleanup of test artifacts
5. **Permission Validation**: Explicit consent checking before execution

### Compliance Features

- **SOC 2 Compatible**: Audit trail and access controls
- **GDPR Compliant**: No PII storage or processing
- **HIPAA Friendly**: Healthcare-safe testing procedures
- **PCI DSS**: Payment system security validation

## 📈 Integration

### CI/CD Integration

```yaml
name: Security Testing
on: [push, pull_request]

jobs:
  red-team-exercises:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Security Tests
        run: |
          cargo run --bin red-team-exercises \
            --target http://localhost:8080 \
            --intensity low \
            --output-format sarif \
            --report-file security.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security.sarif
```

### SIEM Integration

```rust
// Send results to SIEM
let siem_client = SiemClient::new("https://siem.company.com");
siem_client.send_security_events(report.to_events()).await?;

// Webhook notifications
let webhook = WebhookClient::new("https://alerts.company.com/security");
webhook.send_alert(report.to_alert()).await?;
```

## 🏗️ Architecture

```
red-team-exercises/
├── src/
│   ├── attack_framework.rs      # Core attack execution engine
│   ├── reporting.rs             # Report generation and analysis
│   ├── scenarios/               # Attack scenario implementations
│   │   ├── token_manipulation.rs
│   │   ├── oauth_manipulation.rs
│   │   ├── session_attacks.rs
│   │   ├── mfa_bypass.rs
│   │   ├── rate_limit_bypass.rs
│   │   ├── idor_attacks.rs
│   │   └── social_engineering.rs
│   └── lib.rs                   # Public API
├── tests/                       # Integration tests
├── examples/                    # Usage examples
├── benches/                     # Performance benchmarks
└── docs/                        # Additional documentation
```

## 🤝 Contributing

We welcome contributions from security professionals:

1. **Security Scenarios**: New attack patterns and techniques
2. **Detection Methods**: Improved evasion and discovery algorithms  
3. **Reporting Features**: Enhanced analysis and visualization
4. **Integration Support**: New SIEM/SOAR connectors

### Development Guidelines

- All scenarios must be defensive in nature
- Include comprehensive test coverage
- Follow responsible disclosure practices
- Document security implications

## 📜 License

Licensed under the Apache License, Version 2.0. See LICENSE file for details.

## 🆘 Support

- **Documentation**: [docs.rs/red-team-exercises](https://docs.rs/red-team-exercises)
- **Issues**: [GitHub Issues](https://github.com/company/rust-security/issues)
- **Security**: security@company.com
- **Community**: [Security Slack Channel](https://company.slack.com/channels/security)

---

**Remember**: These tools are designed to improve security through controlled testing. Always obtain proper authorization before conducting security assessments.