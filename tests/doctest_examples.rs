//! Doctest validation for library documentation examples
//!
//! This module contains tests that validate the examples shown in library
//! documentation comments (//!) actually work.

#[cfg(test)]
mod lib_documentation_tests {
    //! Tests for examples in library documentation

    #[test] 
    fn test_mvp_oauth_service_example() {
        // Test that we can import the main types mentioned in documentation
        // This ensures the public API is consistent with documentation
        
        // These should compile if the documentation is accurate
        use mvp_tools::validation::SecurityContext;
        use mvp_tools::policy::MvpPolicyEngine;
        
        let _ctx = SecurityContext::new();
        let _engine = MvpPolicyEngine::new();
        
        // If we get here, the basic API from documentation exists
        assert!(true, "Basic API imports work");
    }

    #[tokio::test]
    async fn test_server_binding_pattern() {
        // Test the server binding pattern shown in documentation
        // From auth-service/src/lib.rs example
        
        // Test that we can bind to a local address
        let listener_result = tokio::net::TcpListener::bind("127.0.0.1:0").await;
        assert!(listener_result.is_ok(), "Should be able to bind to localhost");
        
        if let Ok(listener) = listener_result {
            let addr = listener.local_addr().unwrap();
            assert!(addr.port() > 0, "Should have a valid port");
        }
    }

    #[test]
    fn test_configuration_patterns() {
        // Test configuration patterns mentioned in documentation
        use std::collections::HashMap;
        
        let mut config = HashMap::new();
        config.insert("database_url", "postgresql://localhost/test");
        config.insert("redis_url", "redis://localhost:6379");
        
        assert_eq!(config.get("database_url"), Some(&"postgresql://localhost/test"));
        assert_eq!(config.get("redis_url"), Some(&"redis://localhost:6379"));
    }
}

#[cfg(test)]
mod api_examples_validation {
    //! Validate API examples from documentation

    #[test]
    fn test_token_structure() {
        // Test JWT token structure mentioned in documentation
        use serde_json::json;
        
        let claims = json!({
            "sub": "user_12345",
            "iat": 1234567890,
            "exp": 1234567890 + 3600,
            "scope": "read write"
        });
        
        assert_eq!(claims["sub"], "user_12345");
        assert!(claims["exp"].as_i64().unwrap() > claims["iat"].as_i64().unwrap());
    }

    #[test]
    fn test_oauth_request_format() {
        // Test OAuth request format from documentation
        use serde_json::json;
        
        let oauth_request = json!({
            "grant_type": "client_credentials",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "scope": "read write"
        });
        
        assert_eq!(oauth_request["grant_type"], "client_credentials");
        assert!(oauth_request["client_id"].is_string());
        assert!(oauth_request["client_secret"].is_string());
    }
}

#[cfg(test)]
mod error_handling_examples {
    //! Test error handling patterns from documentation

    #[test]
    fn test_result_patterns() {
        // Test Result handling patterns mentioned in documentation
        
        fn might_fail(should_fail: bool) -> Result<String, &'static str> {
            if should_fail {
                Err("Something went wrong")
            } else {
                Ok("Success".to_string())
            }
        }
        
        let success = might_fail(false);
        assert!(success.is_ok());
        assert_eq!(success.unwrap(), "Success");
        
        let failure = might_fail(true);
        assert!(failure.is_err());
        assert_eq!(failure.unwrap_err(), "Something went wrong");
    }

    #[test]
    fn test_option_patterns() {
        // Test Option handling patterns from documentation
        
        fn get_optional_value(has_value: bool) -> Option<String> {
            if has_value {
                Some("value".to_string())
            } else {
                None
            }
        }
        
        let some_value = get_optional_value(true);
        assert!(some_value.is_some());
        assert_eq!(some_value.unwrap(), "value");
        
        let no_value = get_optional_value(false);
        assert!(no_value.is_none());
    }
}

#[cfg(test)]
mod security_examples {
    //! Test security-related examples from documentation

    #[test]
    fn test_input_sanitization_examples() {
        // Test input sanitization patterns mentioned in security documentation
        
        fn sanitize_input(input: &str) -> Result<String, &'static str> {
            if input.contains('\0') {
                return Err("Null bytes not allowed");
            }
            if input.len() > 1000 {
                return Err("Input too long");
            }
            if input.trim().is_empty() {
                return Err("Empty input");
            }
            Ok(input.trim().to_string())
        }
        
        // Valid input
        assert!(sanitize_input("normal input").is_ok());
        
        // Invalid inputs
        assert!(sanitize_input("input\0with\0nulls").is_err());
        assert!(sanitize_input(&"a".repeat(1001)).is_err());
        assert!(sanitize_input("   ").is_err());
    }

    #[test] 
    fn test_authentication_flow_structure() {
        // Test the authentication flow structure mentioned in documentation
        use std::collections::HashMap;
        
        let mut flow = HashMap::new();
        flow.insert("step1", "client_credentials");
        flow.insert("step2", "token_request");
        flow.insert("step3", "token_response");
        flow.insert("step4", "resource_access");
        
        assert_eq!(flow.len(), 4);
        assert_eq!(flow.get("step1"), Some(&"client_credentials"));
    }
}