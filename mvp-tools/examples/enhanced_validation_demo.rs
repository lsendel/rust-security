//! Enhanced validation demonstration for MVP tools
//!
//! This example shows how to use the enhanced security validation
//! and policy modules integrated into mvp-tools.

use mvp_tools::policy::{AuthorizationRequest, MvpPolicyEngine};
use mvp_tools::validation::{
    validate_action_string, validate_entity_structure, validate_input, validate_request_id,
    SecurityContext, ThreatLevel,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== MVP Tools Enhanced Validation Demo ===\n");

    // 1. Basic input validation
    println!("1. Testing basic input validation:");

    match validate_input("Hello, World!") {
        Ok(_) => println!("✓ Valid input accepted"),
        Err(e) => println!("✗ Input rejected: {}", e),
    }

    match validate_input("Malicious\x00Input") {
        Ok(_) => println!("✓ Input accepted (unexpected!)"),
        Err(e) => println!("✓ Malicious input properly rejected: {}", e),
    }

    // 2. Request ID validation
    println!("\n2. Testing request ID validation:");

    match validate_request_id("req-12345-valid") {
        Ok(_) => println!("✓ Valid request ID accepted"),
        Err(e) => println!("✗ Request ID rejected: {}", e),
    }

    match validate_request_id("req\x00malicious") {
        Ok(_) => println!("✗ Malicious request ID accepted (unexpected!)"),
        Err(e) => println!("✓ Malicious request ID properly rejected: {}", e),
    }

    // 3. Action string validation
    println!("\n3. Testing action validation:");

    match validate_action_string("Document::read") {
        Ok(_) => println!("✓ Valid action accepted"),
        Err(e) => println!("✗ Action rejected: {}", e),
    }

    match validate_action_string("DROP TABLE users") {
        Ok(_) => println!("✗ SQL injection attempt accepted (unexpected!)"),
        Err(e) => println!("✓ SQL injection attempt rejected: {}", e),
    }

    // 4. Entity structure validation
    println!("\n4. Testing entity structure validation:");

    let valid_entity = json!({
        "type": "User",
        "id": "alice"
    });

    match validate_entity_structure(&valid_entity, "principal") {
        Ok(_) => println!("✓ Valid entity structure accepted"),
        Err(e) => println!("✗ Entity rejected: {}", e),
    }

    let invalid_entity = json!({
        "id": "alice"
        // Missing "type" field
    });

    match validate_entity_structure(&invalid_entity, "principal") {
        Ok(_) => println!("✗ Invalid entity accepted (unexpected!)"),
        Err(e) => println!("✓ Invalid entity properly rejected: {}", e),
    }

    // 5. Security context demonstration
    println!("\n5. Testing security context:");

    let security_ctx = SecurityContext::new()
        .with_request_id("demo-request-123".to_string())
        .with_client_info(
            Some("192.168.1.100".to_string()),
            Some("Mozilla/5.0".to_string()),
        )
        .with_threat_level(ThreatLevel::Medium);

    security_ctx.log_security_incident("Demonstration of security context logging");

    // 6. Policy engine demonstration
    println!("\n6. Testing MVP policy engine:");

    let policy_engine = MvpPolicyEngine::new();
    println!(
        "Policy engine initialized with {} policies and {} entities",
        policy_engine.policy_count(),
        policy_engine.entity_count()
    );

    // Test admin access (should be allowed)
    let admin_request = AuthorizationRequest {
        request_id: "admin-test-1".to_string(),
        principal: json!({
            "type": "User",
            "id": "admin",
            "attrs": {
                "authenticated": true,
                "role": "admin"
            }
        }),
        action: "write".to_string(),
        resource: json!({
            "type": "Resource",
            "id": "sensitive-document",
            "attrs": {
                "sensitive": true
            }
        }),
        context: json!({}),
    };

    match policy_engine.authorize(&admin_request) {
        Ok(response) => println!(
            "✓ Admin authorization: {} (Request: {})",
            response.decision, response.request_id
        ),
        Err(e) => println!("✗ Admin authorization failed: {}", e),
    }

    // Test regular user accessing sensitive resource (should be denied)
    let user_request = AuthorizationRequest {
        request_id: "user-test-1".to_string(),
        principal: json!({
            "type": "User",
            "id": "alice",
            "attrs": {
                "authenticated": true,
                "role": "user"
            }
        }),
        action: "read".to_string(),
        resource: json!({
            "type": "Resource",
            "id": "sensitive-document",
            "attrs": {
                "sensitive": true
            }
        }),
        context: json!({}),
    };

    match policy_engine.authorize(&user_request) {
        Ok(response) => println!(
            "✓ User authorization: {} (Request: {})",
            response.decision, response.request_id
        ),
        Err(e) => println!("✗ User authorization failed: {}", e),
    }

    // Test regular user accessing public resource (should be allowed)
    let public_request = AuthorizationRequest {
        request_id: "public-test-1".to_string(),
        principal: json!({
            "type": "User",
            "id": "alice",
            "attrs": {
                "authenticated": true,
                "role": "user"
            }
        }),
        action: "read".to_string(),
        resource: json!({
            "type": "Resource",
            "id": "public-document",
            "attrs": {
                "sensitive": false
            }
        }),
        context: json!({}),
    };

    match policy_engine.authorize(&public_request) {
        Ok(response) => println!(
            "✓ Public resource authorization: {} (Request: {})",
            response.decision, response.request_id
        ),
        Err(e) => println!("✗ Public resource authorization failed: {}", e),
    }

    println!("\n=== Demo completed successfully! ===");
    println!("\nMVP Tools now includes:");
    println!("- Enterprise-grade input validation with threat detection");
    println!("- DoS protection (payload size, depth, complexity limits)");
    println!("- Injection attack prevention (SQL, XSS, script detection)");
    println!("- Control character filtering and input sanitization");
    println!("- Security context tracking with client information");
    println!("- Simplified Cedar policy engine for authorization");
    println!("- Policy conflict detection capabilities");

    Ok(())
}
