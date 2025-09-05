# MVP Tools - Enhanced Security Validation

Essential utilities for the Auth-as-a-Service MVP with enterprise-grade security features.

## Features

### 🔒 Enhanced Security Validation
- **Threat Level Classification**: Low, Medium, High, Critical threat detection
- **DoS Protection**: Payload size, depth, and complexity limits
- **Injection Prevention**: SQL, XSS, and script injection detection  
- **Input Sanitization**: Control character filtering and string validation
- **Security Context**: Client IP, User-Agent, and request tracking

### 🛡️ Policy Validation & Authorization
- **Simplified Policy Engine**: MVP-focused Cedar policy implementation
- **Default Security Policies**: Pre-configured authenticated access control
- **Authorization Requests**: Complete request/response handling
- **Policy Conflict Detection**: Basic conflict analysis for policies
- **Security Integration**: Validation with security context logging

### 📋 API Contract Utilities
- **OpenAPI Generation**: API specification generation and validation
- **Contract Testing**: API contract validation utilities

### 🧪 Testing Utilities
- **Test Environment Setup**: Comprehensive testing helpers
- **Security Test Cases**: Pre-built security validation tests

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
mvp-tools = { path = "../mvp-tools" }
```

### Basic Input Validation

```rust
use mvp_tools::validation::{validate_input, validate_request_id};

// Validate basic input
if let Err(e) = validate_input("user input") {
    eprintln!("Invalid input: {}", e);
}

// Validate request IDs with security checks
if let Err(e) = validate_request_id("req-12345") {
    eprintln!("Invalid request ID: {}", e);
}
```

### Security Context Usage

```rust
use mvp_tools::validation::{SecurityContext, ThreatLevel};

let mut ctx = SecurityContext::new()
    .with_request_id("req-123".to_string())
    .with_client_info(
        Some("192.168.1.100".to_string()), 
        Some("Mozilla/5.0".to_string())
    )
    .with_threat_level(ThreatLevel::Medium);

ctx.log_security_incident("Suspicious activity detected");
```

### Policy Authorization

```rust
use mvp_tools::policy::{MvpPolicyEngine, AuthorizationRequest};
use serde_json::json;

let engine = MvpPolicyEngine::new();

let request = AuthorizationRequest {
    request_id: "auth-123".to_string(),
    principal: json!({
        "type": "User",
        "id": "alice",
        "attrs": {"authenticated": true, "role": "user"}
    }),
    action: "read".to_string(),
    resource: json!({
        "type": "Document", 
        "id": "public-doc",
        "attrs": {"sensitive": false}
    }),
    context: json!({}),
};

match engine.authorize(&request) {
    Ok(response) => println!("Decision: {}", response.decision),
    Err(e) => eprintln!("Authorization failed: {}", e),
}
```

## Security Validation Features

### Input Validation
- **Request ID**: Length limits, control character detection
- **Action Strings**: Injection pattern detection, length limits
- **Entity Structures**: Required field validation, ID format checks
- **JSON Payloads**: Depth limits, size limits, key count limits

### Threat Detection
- **Suspicious Patterns**: Script tags, JavaScript URLs, eval functions
- **Control Characters**: Null bytes, control codes, dangerous characters
- **Payload Attacks**: Oversized requests, deeply nested objects
- **Injection Attempts**: SQL injection, XSS attempts, command injection

### Security Limits
- Max Request ID Length: 128 characters
- Max Entity ID Length: 512 characters  
- Max Action Length: 256 characters
- Max JSON Depth: 10 levels
- Max JSON Size: 1MB
- Max Context Keys: 50
- Max String Length: 16KB

## Policy Engine

### Default Policies
1. **Admin Access**: Admins can perform any action
2. **Authenticated Reads**: Authenticated users can read non-sensitive resources
3. **Owner Access**: Users can access their own resources
4. **Sensitive Denial**: Deny access to sensitive resources without clearance

### Policy Examples

```rust
// Allow authenticated users to read public resources
permit(principal, action == Action::"read", resource) 
when { 
    principal has authenticated && 
    principal.authenticated == true &&
    resource has sensitive &&
    resource.sensitive == false
};

// Allow admins full access
permit(principal, action, resource) 
when { 
    principal has role && 
    principal.role == "admin" 
};
```

## Examples

Run the demonstration:

```bash
cargo run --example enhanced_validation_demo
```

This example shows:
- Basic input validation with threat detection
- Request ID and action string validation
- Entity structure validation
- Security context logging
- Policy engine authorization decisions

## Testing

```bash
# Run all tests
cargo test -p mvp-tools

# Run validation tests
cargo test -p mvp-tools validation

# Run policy tests  
cargo test -p mvp-tools policy
```

## Architecture

### Validation Module (`src/validation.rs`)
- Core security validation functions
- Threat level classification
- Security context management
- Input sanitization utilities

### Policy Module (`src/policy.rs`)
- MVP policy engine implementation
- Authorization request handling
- Policy conflict detection
- Default security policies

### Security Utils
- IP address validation
- Client information extraction
- String sanitization
- Suspicious pattern detection

## Integration with Auth Service

The mvp-tools validation can be integrated with the auth-service:

```rust
use mvp_tools::validation::{validate_with_security_context, SecurityContext};

// In your auth service handler
let mut security_ctx = SecurityContext::new()
    .with_request_id(request_id)
    .with_client_info(client_ip, user_agent);

if let Err(e) = validate_with_security_context(&input, "field", &mut security_ctx) {
    // Handle security violation
    return Err(SecurityError::ValidationFailed(e.to_string()));
}
```

## MVP Focus

This implementation is specifically designed for MVP deployment with:
- **Simplified API**: Easy-to-use validation functions
- **Essential Security**: Core security features without complexity
- **Performance**: Optimized for MVP-scale workloads
- **Extensibility**: Ready for enterprise features post-MVP

## License

MIT OR Apache-2.0