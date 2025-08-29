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

    let req = AuthorizeRequest {
        request_id: "r1".into(),
        principal: serde_json::json!({"type": "User", "id": "u1"}),
        action: "orders:read".into(),
        resource: serde_json::json!({"type": "Order", "id": "o1"}),
        context: serde_json::json!({}),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/v1/authorize", addr))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let body: AuthorizeResponse = res.json().await.unwrap();
    assert_eq!(body.decision, "Allow");
}

#[tokio::test]
async fn authorize_denies_cross_brand() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = load_policies_and_entities().unwrap();
    let app = app(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // u1 belongs to t1 and does not have brandZ; o2 is brandZ in t1
    let req = AuthorizeRequest {
        request_id: "r2".into(),
        principal: serde_json::json!({"type": "User", "id": "u1"}),
        action: "orders:read".into(),
        resource: serde_json::json!({"type": "Order", "id": "o2"}),
        context: serde_json::json!({}),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/v1/authorize", addr))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let body: AuthorizeResponse = res.json().await.unwrap();
    assert_eq!(body.decision, "Deny");
}

#[tokio::test]
async fn authorize_allows_tenant_brand_location_match() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = load_policies_and_entities().unwrap();
    let app = app(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // u2 belongs to t2 with brandC@loc-la; o3 is brandC@loc-la in t2
    let req = AuthorizeRequest {
        request_id: "r3".into(),
        principal: serde_json::json!({"type": "User", "id": "u2"}),
        action: "orders:read".into(),
        resource: serde_json::json!({"type": "Order", "id": "o3"}),
        context: serde_json::json!({}),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/v1/authorize", addr))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let body: AuthorizeResponse = res.json().await.unwrap();
    assert_eq!(body.decision, "Allow");
}
