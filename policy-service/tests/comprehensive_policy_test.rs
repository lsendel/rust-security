use policy_service::{app, load_policies_and_entities, AuthorizeRequest, AuthorizeResponse};
use reqwest::header::CONTENT_TYPE;
use serde_json::{json, Value};
use tokio::net::TcpListener;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let state = load_policies_and_entities().unwrap();
    let app = app(state);
    
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn test_policy_authorization_allow() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Test case that should be allowed based on policies.cedar
    let request = AuthorizeRequest {
        request_id: "test_req_1".to_string(),
        principal: json!({"type": "User", "id": "u1"}),
        action: "orders:read".to_string(),
        resource: json!({"type": "Order", "id": "o1"}),
        context: json!({}),
    };

    let response = client
        .post(format!("{}/v1/authorize", base))
        .header(CONTENT_TYPE, "application/json")
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    
    let auth_response: AuthorizeResponse = response.json().await.unwrap();
    assert_eq!(auth_response.decision, "Allow");
}

#[tokio::test]
async fn test_policy_authorization_deny() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Test case that should be denied (user u1 trying to access order o2)
    let request = AuthorizeRequest {
        request_id: "test_req_2".to_string(),
        principal: json!({"type": "User", "id": "u1"}),
        action: "orders:read".to_string(),
        resource: json!({"type": "Order", "id": "o2"}), // o2 has brandZ which u1 doesn't have access to
        context: json!({}),
    };

    let response = client
        .post(format!("{}/v1/authorize", base))
        .header(CONTENT_TYPE, "application/json")
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    
    let auth_response: AuthorizeResponse = response.json().await.unwrap();
    assert_eq!(auth_response.decision, "Deny");
}

#[tokio::test]
async fn test_multi_tenant_isolation() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // User from tenant t1 trying to access resource from tenant t2
    let request = AuthorizeRequest {
        request_id: "test_req_3".to_string(),
        principal: json!({"type": "User", "id": "u1"}), // u1 is in tenant t1
        action: "orders:read".to_string(),
        resource: json!({"type": "Order", "id": "o3"}), // o3 is in tenant t2
        context: json!({}),
    };

    let response = client
        .post(format!("{}/v1/authorize", base))
        .header(CONTENT_TYPE, "application/json")
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    
    let auth_response: AuthorizeResponse = response.json().await.unwrap();
    assert_eq!(auth_response.decision, "Deny");
}

#[tokio::test]
async fn test_attribute_based_access_control() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // User u2 accessing order o3 (should be allowed based on attributes)
    let request = AuthorizeRequest {
        request_id: "test_req_4".to_string(),
        principal: json!({"type": "User", "id": "u2"}),
        action: "orders:read".to_string(),
        resource: json!({"type": "Order", "id": "o3"}),
        context: json!({}),
    };

    let response = client
        .post(format!("{}/v1/authorize", base))
        .header(CONTENT_TYPE, "application/json")
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    
    let auth_response: AuthorizeResponse = response.json().await.unwrap();
    assert_eq!(auth_response.decision, "Allow");
}

#[tokio::test]
async fn test_invalid_principal_format() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Test with invalid principal format
    let request = AuthorizeRequest {
        request_id: "test_req_5".to_string(),
        principal: json!({"invalid": "format"}),
        action: "orders:read".to_string(),
        resource: json!({"type": "Order", "id": "o1"}),
        context: json!({}),
    };

    let response = client
        .post(format!("{}/v1/authorize", base))
        .header(CONTENT_TYPE, "application/json")
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 500); // Should return error for invalid format
}

#[tokio::test]
async fn test_invalid_action_format() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Test with invalid action (empty string)
    let request = AuthorizeRequest {
        request_id: "test_req_6".to_string(),
        principal: json!({"type": "User", "id": "u1"}),
        action: "".to_string(),
        resource: json!({"type": "Order", "id": "o1"}),
        context: json!({}),
    };

    let response = client
        .post(format!("{}/v1/authorize", base))
        .header(CONTENT_TYPE, "application/json")
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 500); // Should return error for invalid action
}

#[tokio::test]
async fn test_health_endpoint() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/health", base))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    
    let health_response: Value = response.json().await.unwrap();
    assert_eq!(health_response.get("status").unwrap().as_str().unwrap(), "ok");
}

#[tokio::test]
async fn test_openapi_endpoint() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/openapi.json", base))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    
    let openapi_response: Value = response.json().await.unwrap();
    assert!(openapi_response.get("openapi").is_some());
    assert!(openapi_response.get("paths").is_some());
}

#[tokio::test]
async fn test_context_based_authorization() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Test authorization with context
    let request = AuthorizeRequest {
        request_id: "test_req_7".to_string(),
        principal: json!({"type": "User", "id": "u1"}),
        action: "orders:read".to_string(),
        resource: json!({"type": "Order", "id": "o1"}),
        context: json!({
            "time": "2023-01-01T12:00:00Z",
            "ip_address": "192.168.1.1"
        }),
    };

    let response = client
        .post(format!("{}/v1/authorize", base))
        .header(CONTENT_TYPE, "application/json")
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    
    let auth_response: AuthorizeResponse = response.json().await.unwrap();
    // Should still be allowed as context doesn't affect the basic policy
    assert_eq!(auth_response.decision, "Allow");
}
