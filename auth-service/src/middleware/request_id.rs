use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use tracing::Level;

/// Ensures an `x-request-id` header exists, propagates it to the response,
/// and emits a concise access log with latency.
pub async fn request_id_middleware(
    mut request: Request,
    next: Next,
) -> Result<Response, crate::shared::error::AppError> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    // Ensure a request ID exists
    let req_id_val = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Insert/overwrite header for downstream use
    if let Ok(hv) = HeaderValue::from_str(&req_id_val) {
        request.headers_mut().insert("x-request-id", hv);
    }

    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let latency = start.elapsed();

    // Attach request id to response for propagation
    let mut response = response;
    if let Ok(hv) = HeaderValue::from_str(&req_id_val) {
        response.headers_mut().insert("x-request-id", hv);
    }

    // Emit minimal structured log
    tracing::event!(
        Level::INFO,
        req_id = %req_id_val,
        method = %method,
        path = %path,
        status = %response.status().as_u16(),
        latency_ms = %latency.as_millis(),
        "request_completed"
    );

    Ok(response)
}
