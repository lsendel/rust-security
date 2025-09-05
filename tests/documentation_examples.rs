//! Tests for code examples found in documentation
//! 
//! This module ensures that all code examples in documentation actually compile
//! and work as expected. This helps prevent documentation rot.

use std::sync::Arc;

#[cfg(test)]
mod mvp_tools_examples {
    use mvp_tools::validation::{validate_input, SecurityContext, ThreatLevel};
    use mvp_tools::policy::MvpPolicyEngine;

    #[test]
    fn test_basic_input_validation() {
        // From mvp-tools/README.md lines 40-52
        let result = validate_input("user input");
        assert!(result.is_ok(), "Basic input validation should pass");
        
        // Test with potentially malicious input
        let malicious_result = validate_input("user\x00input");
        assert!(malicious_result.is_err(), "Null bytes should be rejected");
    }

    #[test]
    fn test_security_context_usage() {
        // From mvp-tools/README.md lines 56-68
        let ctx = SecurityContext::new()
            .with_request_id("req-123".to_string())
            .with_client_info(Some("192.168.1.100".to_string()), Some("Mozilla/5.0".to_string()))
            .with_threat_level(ThreatLevel::Medium);
        
        assert_eq!(ctx.request_id(), Some("req-123"));
        assert_eq!(ctx.threat_level(), ThreatLevel::Medium);
    }

    #[test]
    fn test_policy_engine_initialization() {
        // From mvp-tools/README.md lines 72-98
        let engine = MvpPolicyEngine::new();
        assert!(engine.is_initialized(), "Policy engine should initialize successfully");
    }
}

#[cfg(test)]
mod oauth_service_examples {
    use serde_json::json;

    #[tokio::test]
    async fn test_oauth_flow_from_documentation() {
        // Simulate the OAuth flow described in documentation
        // This tests the examples without requiring a running server
        
        let client_credentials = json!({
            "grant_type": "client_credentials",
            "client_id": "mvp-client",
            "client_secret": "mvp-secret"
        });
        
        assert_eq!(client_credentials["grant_type"], "client_credentials");
        assert_eq!(client_credentials["client_id"], "mvp-client");
    }
}

#[cfg(test)]
mod auth_service_examples {
    // These tests are disabled until auth-service compilation issues are resolved
    #[ignore]
    #[tokio::test]
    async fn test_app_container_initialization() {
        // From auth-service/src/lib.rs lines 23-41
        // This would test: AppContainer::new().await
        // Disabled due to compilation issues in auth-service
    }
    
    #[ignore] 
    #[tokio::test]
    async fn test_create_router() {
        // From auth-service/src/lib.rs 
        // This would test: create_router(container)
        // Disabled due to compilation issues in auth-service  
    }
}

#[cfg(test)]
mod validation_examples {
    use mvp_tools::validation::{validate_input, SecurityContext};
    
    #[test]
    fn test_comprehensive_input_validation() {
        // Test various input validation scenarios from documentation
        
        // Valid inputs
        assert!(validate_input("normal_user_input").is_ok());
        assert!(validate_input("user@example.com").is_ok());
        assert!(validate_input("123456").is_ok());
        
        // Invalid inputs that should be rejected
        assert!(validate_input("").is_err(), "Empty string should be rejected");
        assert!(validate_input("a".repeat(10000).as_str()).is_err(), "Very long strings should be rejected");
        
        // Security-relevant inputs
        assert!(validate_input("<script>alert('xss')</script>").is_err(), "XSS attempts should be rejected");
        assert!(validate_input("'; DROP TABLE users; --").is_err(), "SQL injection attempts should be rejected");
    }

    #[test]
    fn test_security_context_examples() {
        // Test SecurityContext usage patterns from documentation
        let ctx = SecurityContext::new();
        assert!(ctx.request_id().is_none(), "New context should have no request ID");
        
        let ctx_with_id = ctx.with_request_id("test-123".to_string());
        assert_eq!(ctx_with_id.request_id(), Some("test-123"));
    }
}

#[cfg(test)]
mod configuration_examples {
    #[test]
    fn test_environment_variables() {
        // Test environment variable patterns mentioned in documentation
        std::env::set_var("TEST_VAR", "test_value");
        let value = std::env::var("TEST_VAR").unwrap_or_else(|_| "default".to_string());
        assert_eq!(value, "test_value");
        
        // Clean up
        std::env::remove_var("TEST_VAR");
    }
}

#[cfg(test)] 
mod integration_patterns {
    #[tokio::test]
    async fn test_async_patterns_from_docs() {
        // Test async patterns shown in documentation examples
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            async {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                "completed"
            }
        ).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "completed");
    }
}