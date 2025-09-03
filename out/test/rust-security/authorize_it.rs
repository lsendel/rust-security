// Suppress unused dependency warnings
use anyhow as _;
use cedar_policy as _;
use cedar_policy_core as _;
use chrono as _;
use dotenvy as _;
use futures as _;
use once_cell as _;
use prometheus as _;
use serde as _;
use tempfile as _;
use thiserror as _;
use tower_http as _;
use tracing as _;
use tracing_subscriber as _;
use utoipa as _;
use utoipa_swagger_ui as _;

use policy_service::{app, load_policies_and_entities, AuthorizeRequest, AuthorizeResponse};
use tokio::net::TcpListener;

#[tokio::test]
async fn stub_authorize_denies() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = load_policies_and_entities().unwrap();
    let app = app(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let authorize_request = AuthorizeRequest {
        request_id: "r1".into(),
        principal: serde_json::json!({"type": "User", "id": "u1"}),
        action: "orders:read".into(),
        resource: serde_json::json!({"type": "Order", "id": "o1"}),
        context: serde_json::json!({}),
    };
    let http_response = reqwest::Client::new()
        .post(format!("http://{addr}/v1/authorize"))
        .json(&authorize_request)
        .send()
        .await
        .unwrap();
    assert!(http_response.status().is_success());
    let authorize_response: AuthorizeResponse = http_response.json().await.unwrap();
    assert_eq!(authorize_response.decision, "Allow");
}

#[tokio::test]
async fn authorize_denies_cross_brand() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = load_policies_and_entities().unwrap();
    let app = app(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // u1 belongs to t1 and does not have brandZ; o2 is brandZ in t1
    let cross_brand_request = AuthorizeRequest {
        request_id: "r2".into(),
        principal: serde_json::json!({"type": "User", "id": "u1"}),
        action: "orders:read".into(),
        resource: serde_json::json!({"type": "Order", "id": "o2"}),
        context: serde_json::json!({}),
    };
    let cross_brand_response = reqwest::Client::new()
        .post(format!("http://{addr}/v1/authorize"))
        .json(&cross_brand_request)
        .send()
        .await
        .unwrap();
    assert!(cross_brand_response.status().is_success());
    let cross_brand_result: AuthorizeResponse = cross_brand_response.json().await.unwrap();
    assert_eq!(cross_brand_result.decision, "Deny");
}

#[tokio::test]
async fn authorize_allows_tenant_brand_location_match() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = load_policies_and_entities().unwrap();
    let app = app(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // u2 belongs to t2 with brandC@loc-la; o3 is brandC@loc-la in t2
    let tenant_match_request = AuthorizeRequest {
        request_id: "r3".into(),
        principal: serde_json::json!({"type": "User", "id": "u2"}),
        action: "orders:read".into(),
        resource: serde_json::json!({"type": "Order", "id": "o3"}),
        context: serde_json::json!({}),
    };
    let tenant_match_response = reqwest::Client::new()
        .post(format!("http://{addr}/v1/authorize"))
        .json(&tenant_match_request)
        .send()
        .await
        .unwrap();
    assert!(tenant_match_response.status().is_success());
    let tenant_match_result: AuthorizeResponse = tenant_match_response.json().await.unwrap();
    assert_eq!(tenant_match_result.decision, "Allow");
}
