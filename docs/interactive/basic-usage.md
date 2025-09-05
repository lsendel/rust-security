# Basic Usage Examples

This section provides interactive examples of basic usage patterns for the Rust Security Platform.

> **SECURITY:** All examples in this section demonstrate production-ready security patterns.

## OAuth 2.0 Token Request

Here's how to request an OAuth 2.0 token using the client credentials flow:

```rust
use serde_json::json;

// Create a token request
let token_request = json!({
    "grant_type": "client_credentials",
    "client_id": "mvp-client",
    "client_secret": "mvp-secret",
    "scope": "read write"
});

// In a real application, you would send this to the /oauth/token endpoint
println!("Token request: {}", serde_json::to_string_pretty(&token_request)?);
```

<div class="interactive-example">
<strong>Try this:</strong> Click the "Run" button above to see the token request structure.
</div>

## Input Validation

All inputs must be validated using the MVP tools validation framework:

```rust
use mvp_tools::validation::{validate_input, SecurityContext, ThreatLevel};

// Validate user input
let user_input = "user@example.com";
if let Err(e) = validate_input(user_input) {
    eprintln!("Validation failed: {}", e);
    return;
}

// Create security context for enhanced validation
let security_ctx = SecurityContext::new()
    .with_request_id("req-123".to_string())
    .with_client_info(
        Some("192.168.1.100".to_string()), 
        Some("Mozilla/5.0 (compatible)".to_string())
    )
    .with_threat_level(ThreatLevel::Low);

println!("Security context created with ID: {:?}", security_ctx.request_id());
```

<div class="security-note">
The validation framework automatically detects and blocks malicious input patterns including SQL injection, XSS attempts, and directory traversal attacks.
</div>

## Policy Engine Authorization

The policy engine determines whether requests should be authorized:

```rust
use mvp_tools::policy::MvpPolicyEngine;

// Initialize the policy engine
let policy_engine = MvpPolicyEngine::new();

// Check if the engine is properly initialized
if policy_engine.is_initialized() {
    println!("✅ Policy engine ready for authorization requests");
} else {
    eprintln!("❌ Policy engine initialization failed");
}

// In a real application, you would use the engine to make authorization decisions
// based on Cedar policies
```

<div class="security-success">
The policy engine uses Cedar Policy Language for fine-grained access control decisions with cryptographic verification of policy integrity.
</div>

## Error Handling Patterns

Proper error handling is essential for security:

```rust
use std::error::Error;

fn secure_operation() -> Result<String, Box<dyn Error>> {
    // Simulate a security-sensitive operation
    let user_input = "potentially_malicious_input";
    
    // Validate input first
    if user_input.contains("script") || user_input.contains("'") {
        return Err("Invalid input detected".into());
    }
    
    // Process valid input
    Ok(format!("Processed: {}", user_input))
}

// Usage with proper error handling
match secure_operation() {
    Ok(result) => println!("Success: {}", result),
    Err(e) => {
        eprintln!("Security error: {}", e);
        // Log security incident (in real application)
    }
}
```

<div class="security-warning">
Never expose detailed error information to clients as it may leak sensitive system information to attackers.
</div>

## Configuration Patterns

Security configuration should follow these patterns:

```rust
use std::collections::HashMap;

// Example configuration structure
let mut security_config = HashMap::new();

// JWT configuration
security_config.insert("jwt_expiry_seconds", "3600");
security_config.insert("jwt_algorithm", "EdDSA");
security_config.insert("jwt_issuer", "rust-security-platform");

// Rate limiting configuration  
security_config.insert("rate_limit_per_minute", "60");
security_config.insert("rate_limit_burst", "10");

// Database configuration (with secure defaults)
security_config.insert("database_pool_size", "10");
security_config.insert("database_timeout_seconds", "30");

println!("Security configuration loaded with {} parameters", 
         security_config.len());
```

## Next Steps

- [Advanced Security Examples](./advanced-security.md) - Complex security patterns
- [Integration Patterns](./integration-patterns.md) - How to integrate with external systems
- [API Reference](../API_REFERENCE.md) - Complete API documentation

<div class="status-badge stable">Production Ready</div> All examples in this section are production-tested and secure by default.