use axum::{body, body::Body, http::Request};
use policy_service::{app, load_policies_and_entities};
use tower::util::ServiceExt; // for `oneshot`

#[tokio::test]
async fn admin_metrics_read_allowed_for_readonly() {
    let state = load_policies_and_entities().expect("load policies");
    let router = app(state);

    let body = serde_json::json!({
        "request_id": "t-allow-metrics",
        "principal": {"type": "Admin", "id": "alice_admin"},
        "action": "Admin::metrics_read",
        "resource": {"type": "AdminEndpoint", "id": "/admin/metrics"},
        "context": {"method": "GET"}
    });

    let req = Request::builder()
        .uri("/v1/authorize")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert!(resp.status().is_success());
}

#[tokio::test]
async fn admin_users_delete_denied_for_non_superadmin() {
    let state = load_policies_and_entities().expect("load policies");
    let router = app(state);

    let body = serde_json::json!({
        "request_id": "t-deny-delete",
        "principal": {"type": "Admin", "id": "alice_admin"},
        "action": "Admin::users_delete_one",
        "resource": {"type": "AdminEndpoint", "id": "/admin/users/123"},
        "context": {"method": "DELETE"}
    });

    let req = Request::builder()
        .uri("/v1/authorize")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert!(resp.status().is_success());
    // Body contains decision; parse and assert deny
    let bytes = body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["decision"], "Deny");
}

#[tokio::test]
async fn admin_users_delete_allowed_for_superadmin() {
    let state = load_policies_and_entities().expect("load policies");
    let router = app(state);

    let body = serde_json::json!({
        "request_id": "t-allow-delete-super",
        "principal": {"type": "Admin", "id": "bob_super"},
        "action": "Admin::users_delete_one",
        "resource": {"type": "AdminEndpoint", "id": "/admin/users/123"},
        "context": {"method": "DELETE"}
    });

    let req = Request::builder()
        .uri("/v1/authorize")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert!(resp.status().is_success());
    let bytes = body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["decision"], "Allow");
}
