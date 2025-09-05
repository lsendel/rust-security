use axum::body;
use axum::{
    http::{HeaderMap, HeaderValue},
    routing::{get, post},
    Json, Router,
};
use tower::ServiceExt;

#[tokio::test]
async fn csrf_blocks_without_token() {
    let app = Router::new()
        .route(
            "/csrf/token",
            get(auth_service::middleware::csrf::issue_csrf_token),
        )
        .route(
            "/test/protected",
            post(|| async { Json(serde_json::json!({"ok": true})) }),
        )
        .layer(axum::middleware::from_fn(
            auth_service::middleware::csrf::csrf_protect,
        ));

    let res = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/test/protected")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn csrf_allows_with_matching_cookie_and_header() {
    let app = Router::new()
        .route(
            "/csrf/token",
            get(auth_service::middleware::csrf::issue_csrf_token),
        )
        .route(
            "/test/protected",
            post(|| async { Json(serde_json::json!({"ok": true})) }),
        )
        .layer(axum::middleware::from_fn(
            auth_service::middleware::csrf::csrf_protect,
        ));

    // Fetch CSRF token and cookie
    let res = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/csrf/token")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let headers = res.headers();
    let set_cookie = headers
        .get(axum::http::header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let token_json = body::to_bytes(res.into_body(), 1_048_576).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&token_json).unwrap();
    let csrf = v.get("csrf").and_then(|x| x.as_str()).unwrap().to_string();

    // POST with matching cookie and header
    let res2 = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/test/protected")
                .header(
                    axum::http::header::COOKIE,
                    HeaderValue::from_str(set_cookie.split(';').next().unwrap()).unwrap(),
                )
                .header("X-CSRF-Token", HeaderValue::from_str(&csrf).unwrap())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res2.status(), axum::http::StatusCode::OK);
}
