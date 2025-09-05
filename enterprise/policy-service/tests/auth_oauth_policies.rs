use axum::{body, body::Body, http::Request};
use policy_service::{app, load_policies_and_entities};
use tower::util::ServiceExt;

#[tokio::test]
async fn user_read_own_profile_allowed() {
    let state = load_policies_and_entities().expect("load policies");
    let router = app(state);

    let body = serde_json::json!({
        "request_id": "t-user-profile",
        "principal": {"type": "User", "id": "alice_user"},
        "action": "User::read_profile",
        "resource": {"type": "User", "id": "alice_user"},
        "context": {}
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

#[tokio::test]
async fn oauth_authorize_allowed_for_registered_client() {
    let state = load_policies_and_entities().expect("load policies");
    let router = app(state);

    let body = serde_json::json!({
        "request_id": "t-oauth-authz",
        "principal": {"type": "Client", "id": "mvp-client"},
        "action": "OAuth::authorize",
        "resource": {"type": "OAuthClient", "id": "mvp-client"},
        "context": {}
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
