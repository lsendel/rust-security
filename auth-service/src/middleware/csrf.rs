use axum::{extract::Request, middleware::Next, response::Response};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Method};

/// Issue a CSRF token and set cookie
pub async fn issue_csrf_token() -> Result<(HeaderMap, axum::Json<serde_json::Value>), (StatusCode, &'static str)> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 32];
    
    // Try multiple times before failing
    let mut attempts = 0;
    loop {
        match SystemRandom::new().fill(&mut bytes) {
            Ok(()) => break,
            Err(_) if attempts < 3 => {
                attempts += 1;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            }
            Err(_) => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate secure CSRF token")),
        }
    }
    
    let token = hex::encode(bytes);
    let mut headers = HeaderMap::new();
    let secure = if std::env::var("APP_ENV").unwrap_or_default().eq_ignore_ascii_case("development") { "" } else { " Secure;" };
    let cookie = format!("csrf_token={}; Path=/;{} SameSite=Strict; Max-Age=3600", token, secure);
    
    match HeaderValue::from_str(&cookie) {
        Ok(cookie_value) => {
            headers.insert(axum::http::header::SET_COOKIE, cookie_value);
            Ok((headers, axum::Json(serde_json::json!({"csrf": token}))))
        }
        Err(_) => Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to create secure cookie header")),
    }
}

/// CSRF protection for state-changing requests using double-submit cookie pattern
pub async fn csrf_protect(request: Request, next: Next) -> Response {
    // Allow safe methods and exempted paths
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let exempt = matches!(method, Method::GET | Method::HEAD | Method::OPTIONS)
        || path.starts_with("/csrf/token")
        || path.starts_with("/health")
        || path.starts_with("/api/v1/status")
        || path.starts_with("/.well-known/jwks.json")
        || path.starts_with("/jwks.json")
        || path.starts_with("/oauth/authorize")
        || path.starts_with("/api/v1/auth/login")
        || path.starts_with("/api/v1/auth/register");

    if exempt {
        return next.run(request).await;
    }

    let headers = request.headers();
    let cookie_header = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let csrf_cookie = cookie_header
        .split(';')
        .map(|s| s.trim())
        .find_map(|kv| kv.strip_prefix("csrf_token="))
        .unwrap_or("");
    let csrf_header = headers
        .get("X-CSRF-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if csrf_cookie.is_empty() || csrf_header.is_empty() || csrf_cookie != csrf_header {
        return match axum::http::Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(axum::body::Body::from("CSRF validation failed"))
        {
            Ok(response) => response,
            Err(_) => {
                // Fallback response if builder fails
                axum::http::Response::new(axum::body::Body::from("CSRF validation failed"))
            }
        };
    }

    next.run(request).await
}

