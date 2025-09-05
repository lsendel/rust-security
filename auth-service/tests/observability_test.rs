#![cfg(feature = "metrics")]
use axum::body;
use axum::{routing::get, Router};
use tower::ServiceExt; // for `oneshot`

#[tokio::test]
async fn metrics_endpoint_exposes_prometheus_after_requests() {
    // Build a minimal router with metrics middleware and endpoint
    let app = Router::new()
        .route(
            "/ping",
            get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
        )
        .route(
            "/metrics",
            get(|| async { auth_service::metrics::metrics_handler() }),
        )
        .layer(axum::middleware::from_fn(
            auth_service::metrics::metrics_middleware,
        ));

    // Issue a request to generate some metrics
    let response = app
        .clone()
        .oneshot(
            http::Request::builder()
                .method("GET")
                .uri("/ping")
                .header("client-id", "test-client")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);

    // Fetch metrics and verify key series exist
    let metrics_res = app
        .oneshot(
            http::Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metrics_res.status(), http::StatusCode::OK);

    let bytes = body::to_bytes(metrics_res.into_body(), 1_048_576)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();

    // Verify counters/histograms are present
    assert!(body.contains("auth_http_requests_total"));
    assert!(body.contains("auth_http_request_duration_seconds"));
}
