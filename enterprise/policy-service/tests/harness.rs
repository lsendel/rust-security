use axum::{body::Body, http::{Method, Request}, Router};
use tower::ServiceExt;

pub fn make_policy_router() -> Router {
    let state = policy_service::load_policies_and_entities().expect("load policies");
    policy_service::app(state)
}

pub async fn request(app: &Router, method: Method, uri: &str, body: Option<&str>) -> axum::http::Response<axum::body::Body> {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(match body { Some(b) => Body::from(b.to_string()), None => Body::empty() })
        .unwrap();

    app.clone().oneshot(req).await.unwrap()
}

