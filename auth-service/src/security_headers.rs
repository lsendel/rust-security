use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Enhanced security headers middleware
/// Implements comprehensive security headers following OWASP recommendations
pub async fn add_security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers_present = response.headers().contains_key("content-type");
    let headers = response.headers_mut();

    // Content Security Policy - Strict policy for security applications
    headers.insert(
        "Content-Security-Policy",
        "default-src 'none'; \
         frame-ancestors 'none'; \
         base-uri 'none'"
            .parse()
            .unwrap(),
    );

    // Strict Transport Security - Force HTTPS for 1 year
    headers.insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload"
            .parse()
            .unwrap(),
    );

    // Prevent clickjacking
    headers.insert(
        "X-Frame-Options",
        "DENY".parse().unwrap(),
    );

    // Prevent MIME type sniffing
    headers.insert(
        "X-Content-Type-Options",
        "nosniff".parse().unwrap(),
    );

    // XSS Protection (legacy but still useful)
    // Keep legacy X-XSS-Protection header for backward compatibility with existing clients/tests
    headers.insert(
        "X-XSS-Protection",
        "1; mode=block".parse().unwrap(),
    );

    // Referrer Policy - Limit referrer information
    headers.insert(
        "Referrer-Policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );

    // Permissions Policy - Restrict browser features
    headers.insert(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), \
         magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=(), \
         autoplay=(), encrypted-media=(), fullscreen=(), picture-in-picture=()"
            .parse()
            .unwrap(),
    );

    // Cross-Origin Embedder Policy
    headers.insert(
        "Cross-Origin-Embedder-Policy",
        "require-corp".parse().unwrap(),
    );

    // Cross-Origin Opener Policy
    headers.insert(
        "Cross-Origin-Opener-Policy",
        "same-origin".parse().unwrap(),
    );

    // Cross-Origin Resource Policy
    headers.insert(
        "Cross-Origin-Resource-Policy",
        "same-origin".parse().unwrap(),
    );

    // Server identification (minimal information disclosure)
    headers.insert(
        "Server",
        "Rust-Security-Service".parse().unwrap(),
    );

    // Cache control for sensitive endpoints
    // Avoid borrowing response immutably again; check based on header presence instead
    if headers_present {
        headers.insert(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private".parse().unwrap(),
        );
        headers.insert(
            "Pragma",
            "no-cache".parse().unwrap(),
        );
        headers.insert(
            "Expires",
            "0".parse().unwrap(),
        );
    }

    // Add timestamp for security monitoring
    if let Ok(timestamp) = SystemTime::now().duration_since(UNIX_EPOCH) {
        headers.insert(
            "X-Response-Time",
            timestamp.as_secs().to_string().parse().unwrap(),
        );
    }

    response
}

/// Security headers for API responses
pub async fn add_api_security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // API-specific security headers
    headers.insert(
        "X-Content-Type-Options",
        "nosniff".parse().unwrap(),
    );

    headers.insert(
        "X-Frame-Options",
        "DENY".parse().unwrap(),
    );

    // Prevent caching of API responses
    headers.insert(
        "Cache-Control",
        "no-store, no-cache, must-revalidate".parse().unwrap(),
    );

    // CORS headers for API (restrictive by default)
    headers.insert(
        "Access-Control-Allow-Origin",
        "null".parse().unwrap(), // Will be overridden by CORS middleware if configured
    );

    headers.insert(
        "Access-Control-Allow-Methods",
        "GET, POST, OPTIONS".parse().unwrap(),
    );

    headers.insert(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, X-Requested-With".parse().unwrap(),
    );

    headers.insert(
        "Access-Control-Max-Age",
        "86400".parse().unwrap(), // 24 hours
    );

    response
}

/// Rate limiting headers
pub fn add_rate_limit_headers(response: &mut Response, limit: u32, remaining: u32, reset_time: u64) {
    let headers = response.headers_mut();

    headers.insert(
        "X-RateLimit-Limit",
        limit.to_string().parse().unwrap(),
    );

    headers.insert(
        "X-RateLimit-Remaining",
        remaining.to_string().parse().unwrap(),
    );

    headers.insert(
        "X-RateLimit-Reset",
        reset_time.to_string().parse().unwrap(),
    );

    if remaining == 0 {
        headers.insert(
            "Retry-After",
            "60".parse().unwrap(), // Retry after 1 minute
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        response::Response,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "test response"
    }

    #[tokio::test]
    async fn test_security_headers() {
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn(add_security_headers));

        let request = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert!(headers.contains_key("Content-Security-Policy"));
        assert!(headers.contains_key("Strict-Transport-Security"));
        assert!(headers.contains_key("X-Frame-Options"));
        assert!(headers.contains_key("X-Content-Type-Options"));
        assert!(headers.contains_key("X-XSS-Protection"));
        assert!(headers.contains_key("Referrer-Policy"));
        assert!(headers.contains_key("Permissions-Policy"));
    }

    #[tokio::test]
    async fn test_api_security_headers() {
        let app = Router::new()
            .route("/api/test", get(test_handler))
            .layer(middleware::from_fn(add_api_security_headers));

        let request = Request::builder()
            .uri("/api/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert!(headers.contains_key("Cache-Control"));
        assert!(headers.contains_key("Access-Control-Allow-Origin"));
        assert!(headers.contains_key("Access-Control-Allow-Methods"));
    }
}
