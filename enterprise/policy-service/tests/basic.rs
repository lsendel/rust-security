use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use policy_service::{app, load_policies_and_entities};
use tower::util::ServiceExt; // for `oneshot`

#[tokio::test]
async fn health_endpoint_works() {
    let state = load_policies_and_entities().expect("load policies");
    let router = app(state);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn authorize_allows_authenticated_user() {
    let state = load_policies_and_entities().expect("load policies");
    let router = app(state);

    let body = serde_json::json!({
        "request_id": "test-1",
        "principal": {"type": "User", "id": "mvp-user"},
        "action": "read",
        "resource": {"type": "Resource", "id": "mvp-resource"},
        "context": {}
    });

    let request = Request::builder()
        .uri("/v1/authorize")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
