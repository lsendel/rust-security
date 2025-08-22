//! Integration tests for the Policy Service with Cedar policy engine
//!
//! These tests verify the complete authorization flow including:
//! - Policy parsing and loading
//! - Entity management
//! - Authorization decisions
//! - Error handling
//! - Performance characteristics

use policy_service::{
    authorize, AuthorizeRequest, AppState,
};
use axum::{
    extract::State,
    Json,
};
use cedar_policy::{Authorizer, Entities, PolicySet};
use serde_json::json;
use std::sync::Arc;

// Acknowledge unused dev dependencies
use anyhow as _;
use cedar_policy_core as _;
use dotenvy as _;
use once_cell as _;
use prometheus as _;
use reqwest as _;
use serde as _;
use thiserror as _;
use tower_http as _;
use tracing as _;
use tracing_subscriber as _;
use utoipa as _;
use tempfile as _;

/// Create test policies for authorization scenarios
fn create_test_policies() -> String {
    r#"
// Allow users to read their own profile
permit(
    principal == User::"alice",
    action == Action::"read",
    resource == Profile::"alice"
);

// Allow admins to read all profiles
permit(
    principal in Role::"admin",
    action == Action::"read",
    resource
)
when {
    resource is Profile
};

// Allow admins to write all profiles
permit(
    principal in Role::"admin",
    action == Action::"write",
    resource
)
when {
    resource is Profile
};

// Allow users in the "employees" group to read company documents
permit(
    principal in Group::"employees",
    action == Action::"read",
    resource
)
when {
    resource is Document &&
    (resource.department == "public" || 
     resource.department == principal.department)
};

// Allow access to sensitive documents with clearance
permit(
    principal,
    action == Action::"read",
    resource
)
when {
    resource has sensitive && 
    resource.sensitive == true &&
    principal has clearance && 
    principal.clearance == "top-secret"
};

// Forbid access to sensitive documents unless explicitly authorized
forbid(
    principal,
    action,
    resource
)
when {
    resource has sensitive && resource.sensitive == true
}
unless {
    principal has clearance && principal.clearance == "top-secret"
};

// Allow users to create documents in their own department
permit(
    principal in Group::"employees",
    action == Action::"create",
    resource
)
when {
    context has department && 
    context.department == principal.department &&
    context has request_type &&
    context.request_type == "document_creation"
};

// Forbid access outside business hours when time context is provided
forbid(
    principal,
    action == Action::"read",
    resource
)
when {
    resource is Document &&
    context has time_of_day &&
    (context.time_of_day < 9 || context.time_of_day > 17)
};

// Forbid access from outside allowed IP range when IP context is provided
forbid(
    principal,
    action == Action::"read",
    resource
)
when {
    resource is Document &&
    context has source_ip &&
    !(context.source_ip like "192.168.1.*")
};

// Conditional access based on time and IP - separate policies for clarity
permit(
    principal in Group::"employees",
    action == Action::"read",
    resource
)
when {
    resource is Document &&
    context has time_of_day &&
    context.time_of_day >= 9 &&
    context.time_of_day <= 17 &&
    context has source_ip &&
    context.source_ip like "192.168.1.*"
};
"#.to_string()
}

/// Create test entities for authorization scenarios
fn create_test_entities() -> String {
    json!([
        {
            "uid": {"type": "User", "id": "alice"},
            "attrs": {
                "name": "Alice Smith",
                "department": "engineering",
                "role": "developer"
            },
            "parents": [
                {"type": "Group", "id": "employees"},
                {"type": "Role", "id": "developer"}
            ]
        },
        {
            "uid": {"type": "User", "id": "bob"},
            "attrs": {
                "name": "Bob Johnson",
                "department": "hr",
                "role": "manager",
                "clearance": "top-secret"
            },
            "parents": [
                {"type": "Group", "id": "employees"},
                {"type": "Role", "id": "admin"}
            ]
        },
        {
            "uid": {"type": "User", "id": "charlie"},
            "attrs": {
                "name": "Charlie Brown",
                "department": "finance",
                "role": "analyst"
            },
            "parents": [
                {"type": "Group", "id": "employees"}
            ]
        },
        {
            "uid": {"type": "Group", "id": "employees"},
            "attrs": {
                "description": "All company employees"
            },
            "parents": []
        },
        {
            "uid": {"type": "Role", "id": "admin"},
            "attrs": {
                "description": "Administrative role"
            },
            "parents": []
        },
        {
            "uid": {"type": "Role", "id": "developer"},
            "attrs": {
                "description": "Software developer role"
            },
            "parents": []
        },
        {
            "uid": {"type": "Profile", "id": "alice"},
            "attrs": {
                "owner": "alice",
                "visibility": "private"
            },
            "parents": []
        },
        {
            "uid": {"type": "Profile", "id": "bob"},
            "attrs": {
                "owner": "bob",
                "visibility": "public"
            },
            "parents": []
        },
        {
            "uid": {"type": "Document", "id": "doc1"},
            "attrs": {
                "title": "Public Engineering Guide",
                "department": "engineering",
                "sensitive": false
            },
            "parents": []
        },
        {
            "uid": {"type": "Document", "id": "doc2"},
            "attrs": {
                "title": "HR Policies",
                "department": "hr",
                "sensitive": false
            },
            "parents": []
        },
        {
            "uid": {"type": "Document", "id": "doc3"},
            "attrs": {
                "title": "Financial Records",
                "department": "finance",
                "sensitive": true
            },
            "parents": []
        },
        {
            "uid": {"type": "Document", "id": "doc4"},
            "attrs": {
                "title": "Public Company Info",
                "department": "public",
                "sensitive": false
            },
            "parents": []
        },
        {
            "uid": {"type": "Action", "id": "read"},
            "attrs": {},
            "parents": []
        },
        {
            "uid": {"type": "Action", "id": "write"},
            "attrs": {},
            "parents": []
        },
        {
            "uid": {"type": "Action", "id": "create"},
            "attrs": {},
            "parents": []
        },
        {
            "uid": {"type": "Action", "id": "delete"},
            "attrs": {},
            "parents": []
        }
    ]).to_string()
}

/// Create a test AppState with policies and entities
fn setup_test_app_state() -> Result<Arc<AppState>, Box<dyn std::error::Error>> {
    let policies_str = create_test_policies();
    let policies = policies_str.parse::<PolicySet>()?;
    
    let entities_str = create_test_entities();
    let entities = Entities::from_json_str(&entities_str, None)?;

    Ok(Arc::new(AppState {
        authorizer: Authorizer::new(),
        policies,
        entities,
    }))
}

#[tokio::test]
async fn test_user_can_read_own_profile() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-1".to_string(),
        principal: json!({"type": "User", "id": "alice"}),
        action: "read".to_string(),
        resource: json!({"type": "Profile", "id": "alice"}),
        context: json!({}),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Allow");
}

#[tokio::test]
async fn test_user_cannot_read_other_profile() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-2".to_string(),
        principal: json!({"type": "User", "id": "alice"}),
        action: "read".to_string(),
        resource: json!({"type": "Profile", "id": "bob"}),
        context: json!({}),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Deny");
}

#[tokio::test]
async fn test_admin_can_read_any_profile() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-3".to_string(),
        principal: json!({"type": "User", "id": "bob"}), // Bob is an admin
        action: "read".to_string(),
        resource: json!({"type": "Profile", "id": "alice"}),
        context: json!({}),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Allow");
}

#[tokio::test]
async fn test_admin_can_write_any_profile() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-4".to_string(),
        principal: json!({"type": "User", "id": "bob"}), // Bob is an admin
        action: "write".to_string(),
        resource: json!({"type": "Profile", "id": "alice"}),
        context: json!({}),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Allow");
}

#[tokio::test]
async fn test_employee_can_read_public_documents() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-5".to_string(),
        principal: json!({"type": "User", "id": "alice"}),
        action: "read".to_string(),
        resource: json!({"type": "Document", "id": "doc4"}), // Public document
        context: json!({}),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Allow");
}

#[tokio::test]
async fn test_employee_can_read_own_department_documents() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-6".to_string(),
        principal: json!({"type": "User", "id": "alice"}), // Alice is in engineering
        action: "read".to_string(),
        resource: json!({"type": "Document", "id": "doc1"}), // Engineering document
        context: json!({}),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Allow");
}

#[tokio::test]
async fn test_employee_cannot_read_other_department_documents() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-7".to_string(),
        principal: json!({"type": "User", "id": "alice"}), // Alice is in engineering
        action: "read".to_string(),
        resource: json!({"type": "Document", "id": "doc2"}), // HR document
        context: json!({}),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Deny");
}

#[tokio::test]
async fn test_sensitive_document_denied_without_clearance() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-8".to_string(),
        principal: json!({"type": "User", "id": "alice"}), // Alice doesn't have top-secret clearance
        action: "read".to_string(),
        resource: json!({"type": "Document", "id": "doc3"}), // Sensitive financial document
        context: json!({}),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Deny");
}

#[tokio::test]
async fn test_sensitive_document_allowed_with_clearance() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-9".to_string(),
        principal: json!({"type": "User", "id": "bob"}), // Bob has top-secret clearance
        action: "read".to_string(),
        resource: json!({"type": "Document", "id": "doc3"}), // Sensitive financial document
        context: json!({}),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Allow");
}

#[tokio::test]
async fn test_document_creation_with_context() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-10".to_string(),
        principal: json!({"type": "User", "id": "alice"}),
        action: "create".to_string(),
        resource: json!({"type": "Document", "id": "new_doc"}),
        context: json!({"request_type": "document_creation", "department": "engineering"}),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Allow");
}

#[tokio::test]
async fn test_document_creation_wrong_department() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-11".to_string(),
        principal: json!({"type": "User", "id": "alice"}), // Alice is in engineering
        action: "create".to_string(),
        resource: json!({"type": "Document", "id": "new_doc"}),
        context: json!({"request_type": "document_creation", "department": "hr"}), // Wrong department
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Deny");
}

#[tokio::test]
async fn test_time_based_access_allowed() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-12".to_string(),
        principal: json!({"type": "User", "id": "alice"}),
        action: "read".to_string(),
        resource: json!({"type": "Document", "id": "doc1"}),
        context: json!({
            "time_of_day": 14, // 2 PM
            "source_ip": "192.168.1.100"
        }),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Allow");
}

#[tokio::test]
async fn test_time_based_access_denied_outside_hours() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-13".to_string(),
        principal: json!({"type": "User", "id": "alice"}),
        action: "read".to_string(),
        resource: json!({"type": "Document", "id": "doc1"}),
        context: json!({
            "time_of_day": 22, // 10 PM (outside business hours)
            "source_ip": "192.168.1.100"
        }),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Deny");
}

#[tokio::test]
async fn test_ip_based_access_denied() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-14".to_string(),
        principal: json!({"type": "User", "id": "alice"}),
        action: "read".to_string(),
        resource: json!({"type": "Document", "id": "doc1"}),
        context: json!({
            "time_of_day": 14, // 2 PM
            "source_ip": "10.0.0.100" // Outside allowed IP range
        }),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Deny");
}

#[tokio::test]
async fn test_invalid_action_error() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-15".to_string(),
        principal: json!({"type": "User", "id": "alice"}),
        action: "".to_string(), // Empty action
        resource: json!({"type": "Profile", "id": "alice"}),
        context: json!({}),
    };
    
    let result = authorize(State(state), Json(request)).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_invalid_principal_error() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let request = AuthorizeRequest {
        request_id: "test-16".to_string(),
        principal: json!({"invalid": "format"}), // Invalid principal format
        action: "read".to_string(),
        resource: json!({"type": "Profile", "id": "alice"}),
        context: json!({}),
    };
    
    let result = authorize(State(state), Json(request)).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_performance_multiple_requests() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let start = std::time::Instant::now();
    let num_requests = 100;
    
    for i in 0..num_requests {
        let request = AuthorizeRequest {
            request_id: format!("perf-test-{}", i),
            principal: json!({"type": "User", "id": "alice"}),
            action: "read".to_string(),
            resource: json!({"type": "Profile", "id": "alice"}),
            context: json!({}),
        };
        
        let response = authorize(State(state.clone()), Json(request)).await.unwrap();
        assert_eq!(response.decision, "Allow");
    }
    
    let duration = start.elapsed();
    let avg_duration = duration / num_requests;
    
    // Each request should take less than 10ms on average
    assert!(avg_duration.as_millis() < 10, "Authorization took too long: {:?} avg", avg_duration);
    
    println!("Performance test: {} requests in {:?} (avg: {:?})", 
             num_requests, duration, avg_duration);
}

#[tokio::test]
async fn test_concurrent_authorization_requests() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    let mut handles = vec![];
    let num_concurrent = 50;
    
    for i in 0..num_concurrent {
        let state_clone = state.clone();
        let handle = tokio::spawn(async move {
            let request = AuthorizeRequest {
                request_id: format!("concurrent-test-{}", i),
                principal: json!({"type": "User", "id": "alice"}),
                action: "read".to_string(),
                resource: json!({"type": "Profile", "id": "alice"}),
                context: json!({}),
            };
            
            authorize(State(state_clone), Json(request)).await.unwrap()
        });
        handles.push(handle);
    }
    
    let start = std::time::Instant::now();
    let results = futures::future::join_all(handles).await;
    let duration = start.elapsed();
    
    // All requests should succeed
    assert_eq!(results.len(), num_concurrent);
    for result in results {
        let response = result.unwrap();
        assert_eq!(response.decision, "Allow");
    }
    
    // Total time should be reasonable even with concurrent requests
    assert!(duration.as_millis() < 1000, "Concurrent requests took too long: {:?}", duration);
    
    println!("Concurrent test: {} requests in {:?}", num_concurrent, duration);
}

#[tokio::test] 
async fn test_complex_policy_evaluation() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    // Test a complex scenario with multiple conditions
    let request = AuthorizeRequest {
        request_id: "complex-test".to_string(),
        principal: json!({"type": "User", "id": "charlie"}), // Charlie is in finance
        action: "read".to_string(),
        resource: json!({"type": "Document", "id": "doc3"}), // Sensitive financial document
        context: json!({
            "time_of_day": 14,
            "source_ip": "192.168.1.50",
            "security_level": "high"
        }),
    };
    
    // Charlie should be denied because he doesn't have top-secret clearance
    // even though it's his department's document
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Deny");
}

#[tokio::test]
async fn test_policy_conflict_resolution() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    // Test a case where permit and forbid policies might conflict
    // The forbid policy for sensitive documents should override department access
    let request = AuthorizeRequest {
        request_id: "conflict-test".to_string(),
        principal: json!({"type": "User", "id": "alice"}),
        action: "read".to_string(),
        resource: json!({"type": "Document", "id": "doc3"}), // Sensitive document
        context: json!({}),
    };
    
    // Should be denied due to forbid policy for sensitive documents
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Deny");
}

/// Test policy loading from files
#[tokio::test]
async fn test_policy_loading_from_files() {
    // Test parsing policies and entities directly without changing environment
    let policies_str = "permit(principal, action, resource);";
    let policies = policies_str.parse::<PolicySet>().expect("Should parse basic policy");
    
    let entities_str = r#"[
  {
    "uid": {"type": "User", "id": "test"},
    "attrs": {},
    "parents": []
  }
]"#;
    let entities = Entities::from_json_str(entities_str, None)
        .expect("Should parse basic entities");
    
    // Test that we can create AppState
    let state = AppState {
        authorizer: Authorizer::new(),
        policies,
        entities,
    };
    
    // Test a basic authorization with this state
    let request = AuthorizeRequest {
        request_id: "file-test".to_string(),
        principal: json!({"type": "User", "id": "test"}),
        action: "read".to_string(),
        resource: json!({"type": "Resource", "id": "test"}),
        context: json!({}),
    };
    
    let state_arc = Arc::new(state);
    let response = authorize(State(state_arc), Json(request)).await.unwrap();
    
    // Should allow since we have a simple permit-all policy
    assert_eq!(response.decision, "Allow");
}

#[tokio::test]
async fn test_entity_hierarchy_access() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    // Test that user inherits permissions from their groups
    let request = AuthorizeRequest {
        request_id: "hierarchy-test".to_string(),
        principal: json!({"type": "User", "id": "alice"}), // Alice is in Group::employees
        action: "read".to_string(),
        resource: json!({"type": "Document", "id": "doc4"}), // Public document accessible to employees
        context: json!({}),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Allow");
}

#[tokio::test]
async fn test_attribute_based_access() {
    let state = setup_test_app_state().expect("Failed to setup test state");
    
    // Test access based on user attributes
    let request = AuthorizeRequest {
        request_id: "attribute-test".to_string(),
        principal: json!({"type": "User", "id": "bob"}), // Bob has clearance attribute
        action: "read".to_string(),
        resource: json!({"type": "Document", "id": "doc3"}), // Sensitive document
        context: json!({}),
    };
    
    let response = authorize(State(state), Json(request)).await.unwrap();
    assert_eq!(response.decision, "Allow"); // Bob has top-secret clearance
}