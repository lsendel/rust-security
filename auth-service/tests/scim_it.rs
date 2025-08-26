use auth_service::jwks_rotation::{InMemoryKeyStorage, JwksManager};
use auth_service::session_store::RedisSessionStore;
use auth_service::store::HybridStore;
use auth_service::{api_key_store::ApiKeyStore, app, AppState};
use common::TokenRecord;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Bypass SCIM basic auth and rate limiting in tests
    std::env::set_var("TEST_MODE", "1");
    std::env::set_var("DISABLE_RATE_LIMIT", "1");
    let api_key_store = ApiKeyStore::new("sqlite::memory:").await.unwrap();

    let store = Arc::new(HybridStore::new().await);
    let session_store = Arc::new(RedisSessionStore::new(None).await);
    let jwks_manager = Arc::new(
        JwksManager::new(Default::default(), Arc::new(InMemoryKeyStorage::new()))
            .await
            .unwrap(),
    );

    let app = app(AppState {
        store,
        session_store,
        token_store: Arc::new(std::sync::RwLock::new(HashMap::<String, TokenRecord>::new())),
        client_credentials: Arc::new(std::sync::RwLock::new(HashMap::new())),
        allowed_scopes: Arc::new(std::sync::RwLock::new(HashSet::new())),
        authorization_codes: Arc::new(std::sync::RwLock::new(HashMap::<String, String>::new())),
        policy_cache: std::sync::Arc::new(auth_service::policy_cache::PolicyCache::new(
            auth_service::policy_cache::PolicyCacheConfig::default(),
        )),
        backpressure_state: Arc::new(std::sync::RwLock::new(false)),
        api_key_store: Arc::new(api_key_store),
        jwks_manager,
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ScimUser {
    id: String,
    #[serde(rename = "userName")]
    user_name: String,
    active: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ScimGroup {
    id: String,
    #[serde(rename = "displayName")]
    display_name: String,
    members: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListResponse<T> {
    #[serde(rename = "totalResults")]
    total_results: usize,
    #[serde(rename = "startIndex")]
    start_index: usize,
    #[serde(rename = "itemsPerPage")]
    items_per_page: usize,
    #[serde(rename = "Resources")]
    resources: Vec<T>,
}

// SCIM Bulk Operations structures for testing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
enum BulkOperationMethod {
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BulkOperation {
    method: BulkOperationMethod,
    #[serde(rename = "bulkId")]
    bulk_id: Option<String>,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BulkRequest {
    schemas: Vec<String>,
    #[serde(rename = "Operations")]
    operations: Vec<BulkOperation>,
    #[serde(rename = "failOnErrors", skip_serializing_if = "Option::is_none")]
    fail_on_errors: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BulkOperationResponse {
    method: BulkOperationMethod,
    #[serde(rename = "bulkId", skip_serializing_if = "Option::is_none")]
    bulk_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<serde_json::Value>,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BulkResponse {
    schemas: Vec<String>,
    #[serde(rename = "Operations")]
    operations: Vec<BulkOperationResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScimError {
    schemas: Vec<String>,
    detail: String,
    status: String,
    #[serde(rename = "scimType", skip_serializing_if = "Option::is_none")]
    scim_type: Option<String>,
}

#[tokio::test]
async fn scim_users_pagination_and_filter() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // create users
    for i in 0..10 {
        let u = ScimUser {
            id: String::new(),
            user_name: format!("user{}", i),
            active: true,
        };
        let res = client
            .post(format!("{}/scim/v2/Users", base))
            .json(&u)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    // page 1
    let page1: ListResponse<ScimUser> = client
        .get(format!("{}/scim/v2/Users?startIndex=1&count=3", base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page1.start_index, 1);
    assert_eq!(page1.items_per_page, 3);
    assert_eq!(page1.total_results, 10);
    assert_eq!(page1.resources.len(), 3);

    // page 2
    let page2: ListResponse<ScimUser> = client
        .get(format!("{}/scim/v2/Users?startIndex=4&count=3", base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page2.start_index, 4);
    assert_eq!(page2.items_per_page, 3);

    // filter contains
    let filtered: ListResponse<ScimUser> = client
        .get(format!(
            "{}/scim/v2/Users?filter=userName%20co%20%22user1%22",
            base
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(filtered.total_results >= 1);
    assert!(filtered
        .resources
        .iter()
        .all(|u| u.user_name.contains("user1")));
}

#[tokio::test]
async fn scim_groups_pagination_and_filter() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // create groups
    for i in 0..5 {
        let g = ScimGroup {
            id: String::new(),
            display_name: format!("group{}", i),
            members: vec![],
        };
        let res = client
            .post(format!("{}/scim/v2/Groups", base))
            .json(&g)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    let filtered: ListResponse<ScimGroup> = client
        .get(format!(
            "{}/scim/v2/Groups?filter=displayName%20co%20%22group",
            base
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(filtered.total_results, 5);
    assert!(filtered
        .resources
        .iter()
        .all(|g| g.display_name.contains("group")));
}

// === SCIM Bulk Operations Tests ===

#[tokio::test]
async fn test_bulk_create_users() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let bulk_request = BulkRequest {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:BulkRequest".to_string()],
        operations: vec![
            BulkOperation {
                method: BulkOperationMethod::Post,
                bulk_id: Some("user1".to_string()),
                path: "/Users".to_string(),
                data: Some(serde_json::json!({
                    "userName": "john.doe",
                    "active": true
                })),
                version: None,
            },
            BulkOperation {
                method: BulkOperationMethod::Post,
                bulk_id: Some("user2".to_string()),
                path: "/Users".to_string(),
                data: Some(serde_json::json!({
                    "userName": "jane.smith",
                    "active": true
                })),
                version: None,
            },
        ],
        fail_on_errors: None,
    };

    let response = client
        .post(format!("{}/scim/v2/Bulk", base))
        .json(&bulk_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bulk_response: BulkResponse = response.json().await.unwrap();
    assert_eq!(bulk_response.operations.len(), 2);

    // Check first user creation
    assert_eq!(
        bulk_response.operations[0].method,
        BulkOperationMethod::Post
    );
    assert_eq!(
        bulk_response.operations[0].bulk_id,
        Some("user1".to_string())
    );
    assert_eq!(bulk_response.operations[0].status, "201");
    assert!(bulk_response.operations[0].location.is_some());

    // Check second user creation
    assert_eq!(
        bulk_response.operations[1].method,
        BulkOperationMethod::Post
    );
    assert_eq!(
        bulk_response.operations[1].bulk_id,
        Some("user2".to_string())
    );
    assert_eq!(bulk_response.operations[1].status, "201");
    assert!(bulk_response.operations[1].location.is_some());
}

#[tokio::test]
async fn test_bulk_create_groups() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let bulk_request = BulkRequest {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:BulkRequest".to_string()],
        operations: vec![
            BulkOperation {
                method: BulkOperationMethod::Post,
                bulk_id: Some("group1".to_string()),
                path: "/Groups".to_string(),
                data: Some(serde_json::json!({
                    "displayName": "Administrators",
                    "members": []
                })),
                version: None,
            },
            BulkOperation {
                method: BulkOperationMethod::Post,
                bulk_id: Some("group2".to_string()),
                path: "/Groups".to_string(),
                data: Some(serde_json::json!({
                    "displayName": "Users",
                    "members": []
                })),
                version: None,
            },
        ],
        fail_on_errors: None,
    };

    let response = client
        .post(format!("{}/scim/v2/Bulk", base))
        .json(&bulk_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bulk_response: BulkResponse = response.json().await.unwrap();
    assert_eq!(bulk_response.operations.len(), 2);

    // Verify both groups were created successfully
    for operation in &bulk_response.operations {
        assert_eq!(operation.method, BulkOperationMethod::Post);
        assert_eq!(operation.status, "201");
        assert!(operation.location.is_some());
    }
}

#[tokio::test]
async fn test_bulk_mixed_operations() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // First create a user to update/delete later
    let user = ScimUser {
        id: String::new(),
        user_name: "existing.user".to_string(),
        active: true,
    };
    let create_response = client
        .post(format!("{}/scim/v2/Users", base))
        .json(&user)
        .send()
        .await
        .unwrap();
    assert_eq!(create_response.status(), StatusCode::OK);
    let created_user: ScimUser = create_response.json().await.unwrap();

    // Mixed operations: create, update, and delete
    let bulk_request = BulkRequest {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:BulkRequest".to_string()],
        operations: vec![
            // Create new user
            BulkOperation {
                method: BulkOperationMethod::Post,
                bulk_id: Some("new_user".to_string()),
                path: "/Users".to_string(),
                data: Some(serde_json::json!({
                    "userName": "new.user",
                    "active": true
                })),
                version: None,
            },
            // Update existing user
            BulkOperation {
                method: BulkOperationMethod::Patch,
                bulk_id: None,
                path: format!("/Users/{}", created_user.id),
                data: Some(serde_json::json!({
                    "active": false
                })),
                version: None,
            },
            // Delete the updated user
            BulkOperation {
                method: BulkOperationMethod::Delete,
                bulk_id: None,
                path: format!("/Users/{}", created_user.id),
                data: None,
                version: None,
            },
        ],
        fail_on_errors: None,
    };

    let response = client
        .post(format!("{}/scim/v2/Bulk", base))
        .json(&bulk_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bulk_response: BulkResponse = response.json().await.unwrap();
    assert_eq!(bulk_response.operations.len(), 3);

    // Verify create operation
    assert_eq!(
        bulk_response.operations[0].method,
        BulkOperationMethod::Post
    );
    assert_eq!(bulk_response.operations[0].status, "201");
    assert!(bulk_response.operations[0].location.is_some());

    // Verify update operation
    assert_eq!(
        bulk_response.operations[1].method,
        BulkOperationMethod::Patch
    );
    assert_eq!(bulk_response.operations[1].status, "200");

    // Verify delete operation
    assert_eq!(
        bulk_response.operations[2].method,
        BulkOperationMethod::Delete
    );
    assert_eq!(bulk_response.operations[2].status, "204");
}

#[tokio::test]
async fn test_bulk_error_handling() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let bulk_request = BulkRequest {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:BulkRequest".to_string()],
        operations: vec![
            // Valid operation
            BulkOperation {
                method: BulkOperationMethod::Post,
                bulk_id: Some("valid_user".to_string()),
                path: "/Users".to_string(),
                data: Some(serde_json::json!({
                    "userName": "valid.user",
                    "active": true
                })),
                version: None,
            },
            // Invalid operation - missing data
            BulkOperation {
                method: BulkOperationMethod::Post,
                bulk_id: Some("invalid_user".to_string()),
                path: "/Users".to_string(),
                data: None,
                version: None,
            },
            // Invalid path
            BulkOperation {
                method: BulkOperationMethod::Post,
                bulk_id: Some("bad_path".to_string()),
                path: "/InvalidResource".to_string(),
                data: Some(serde_json::json!({
                    "name": "test"
                })),
                version: None,
            },
        ],
        fail_on_errors: None,
    };

    let response = client
        .post(format!("{}/scim/v2/Bulk", base))
        .json(&bulk_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bulk_response: BulkResponse = response.json().await.unwrap();
    assert_eq!(bulk_response.operations.len(), 3);

    // First operation should succeed
    assert_eq!(bulk_response.operations[0].status, "201");

    // Second operation should fail (missing data)
    assert_eq!(bulk_response.operations[1].status, "400");

    // Third operation should fail (invalid path)
    assert_eq!(bulk_response.operations[2].status, "404");
}

#[tokio::test]
async fn test_bulk_fail_on_errors() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let bulk_request = BulkRequest {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:BulkRequest".to_string()],
        operations: vec![
            // This should fail
            BulkOperation {
                method: BulkOperationMethod::Post,
                bulk_id: None,
                path: "/Users".to_string(),
                data: None, // Missing data
                version: None,
            },
            // This should not be processed due to fail_on_errors=1
            BulkOperation {
                method: BulkOperationMethod::Post,
                bulk_id: None,
                path: "/Users".to_string(),
                data: Some(serde_json::json!({
                    "userName": "should.not.process",
                    "active": true
                })),
                version: None,
            },
        ],
        fail_on_errors: Some(1),
    };

    let response = client
        .post(format!("{}/scim/v2/Bulk", base))
        .json(&bulk_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bulk_response: BulkResponse = response.json().await.unwrap();
    // Should only have one operation result due to early termination
    assert_eq!(bulk_response.operations.len(), 1);
    assert_eq!(bulk_response.operations[0].status, "400");
}

#[tokio::test]
async fn test_bulk_invalid_schema() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let bulk_request = BulkRequest {
        schemas: vec!["invalid:schema".to_string()],
        operations: vec![BulkOperation {
            method: BulkOperationMethod::Post,
            bulk_id: None,
            path: "/Users".to_string(),
            data: Some(serde_json::json!({
                "userName": "test.user",
                "active": true
            })),
            version: None,
        }],
        fail_on_errors: None,
    };

    let response = client
        .post(format!("{}/scim/v2/Bulk", base))
        .json(&bulk_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let error_response: ScimError = response.json().await.unwrap();
    assert_eq!(error_response.status, "400");
    assert!(error_response.detail.contains("Invalid schema"));
}

#[tokio::test]
async fn test_bulk_empty_operations() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let bulk_request = BulkRequest {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:BulkRequest".to_string()],
        operations: vec![],
        fail_on_errors: None,
    };

    let response = client
        .post(format!("{}/scim/v2/Bulk", base))
        .json(&bulk_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let error_response: ScimError = response.json().await.unwrap();
    assert_eq!(error_response.status, "400");
    assert!(error_response.detail.contains("No operations provided"));
}

#[tokio::test]
async fn test_bulk_duplicate_bulk_ids() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let bulk_request = BulkRequest {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:BulkRequest".to_string()],
        operations: vec![
            BulkOperation {
                method: BulkOperationMethod::Post,
                bulk_id: Some("duplicate_id".to_string()),
                path: "/Users".to_string(),
                data: Some(serde_json::json!({
                    "userName": "user1",
                    "active": true
                })),
                version: None,
            },
            BulkOperation {
                method: BulkOperationMethod::Post,
                bulk_id: Some("duplicate_id".to_string()), // Duplicate bulk ID
                path: "/Users".to_string(),
                data: Some(serde_json::json!({
                    "userName": "user2",
                    "active": true
                })),
                version: None,
            },
        ],
        fail_on_errors: None,
    };

    let response = client
        .post(format!("{}/scim/v2/Bulk", base))
        .json(&bulk_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let error_response: ScimError = response.json().await.unwrap();
    assert_eq!(error_response.status, "400");
    assert!(error_response.detail.contains("Bulk ID conflict"));
}

#[tokio::test]
async fn test_bulk_update_nonexistent_resource() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let bulk_request = BulkRequest {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:BulkRequest".to_string()],
        operations: vec![BulkOperation {
            method: BulkOperationMethod::Put,
            bulk_id: None,
            path: "/Users/nonexistent-id".to_string(),
            data: Some(serde_json::json!({
                "userName": "updated.user",
                "active": false
            })),
            version: None,
        }],
        fail_on_errors: None,
    };

    let response = client
        .post(format!("{}/scim/v2/Bulk", base))
        .json(&bulk_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bulk_response: BulkResponse = response.json().await.unwrap();
    assert_eq!(bulk_response.operations.len(), 1);
    assert_eq!(bulk_response.operations[0].status, "404");
    assert!(bulk_response.operations[0].response.is_some());
}

#[tokio::test]
async fn test_bulk_large_operation_count() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Create a request with too many operations (exceeding MAX_BULK_OPERATIONS = 1000)
    let mut operations = Vec::new();
    for i in 0..1001 {
        operations.push(BulkOperation {
            method: BulkOperationMethod::Post,
            bulk_id: Some(format!("user_{}", i)),
            path: "/Users".to_string(),
            data: Some(serde_json::json!({
                "userName": format!("user_{}", i),
                "active": true
            })),
            version: None,
        });
    }

    let bulk_request = BulkRequest {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:BulkRequest".to_string()],
        operations,
        fail_on_errors: None,
    };

    let response = client
        .post(format!("{}/scim/v2/Bulk", base))
        .json(&bulk_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let error_response: ScimError = response.json().await.unwrap();
    assert_eq!(error_response.status, "413");
    assert!(error_response.detail.contains("Too many operations"));
}

#[tokio::test]
async fn scim_security_headers_present() {
    let base = spawn_app().await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    // Ensure at least one user exists so list returns JSON with content-type
    let _ = client
        .post(format!("{}/scim/v2/Users", base))
        .json(&ScimUser {
            id: String::new(),
            user_name: "sec.user".into(),
            active: true,
        })
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{}/scim/v2/Users?startIndex=1&count=1", base))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let headers = resp.headers();

    // Core security headers added by middleware
    assert!(headers.contains_key("Content-Security-Policy"));
    assert_eq!(
        headers.get("X-Frame-Options").and_then(|v| v.to_str().ok()),
        Some("SAMEORIGIN").or(Some("DENY"))
    );
    assert_eq!(
        headers
            .get("X-Content-Type-Options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert!(headers.contains_key("Referrer-Policy"));
    assert!(headers.contains_key("Permissions-Policy"));
    assert!(headers.contains_key("Cross-Origin-Embedder-Policy"));
    assert!(headers.contains_key("Cross-Origin-Opener-Policy"));
    assert!(headers.contains_key("Cross-Origin-Resource-Policy"));
    assert_eq!(
        headers.get("Server").and_then(|v| v.to_str().ok()),
        Some("Rust-Security-Service")
    );
}
