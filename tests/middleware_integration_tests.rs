use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use rust_security::{
    threat_intel::{ThreatIndicator, ThreatIntelService, ThreatType},
    integration::threat_auth::configure_threat_auth_integration,
};
use tower::ServiceExt;

#[tokio::test]
async fn test_middleware_blocks_malicious_ip() {
    let threat_intel = ThreatIntelService::new();
    
    // Add malicious IP
    threat_intel.add_indicator(ThreatIndicator {
        ip: "192.168.1.100".to_string(),
        risk_score: 95,
        threat_type: ThreatType::Malware,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    }).await;

    let app = configure_threat_auth_integration(
        Router::new().route("/test", get(|| async { "success" })),
        threat_intel,
    );

    let request = Request::builder()
        .uri("/test")
        .header("x-forwarded-for", "192.168.1.100")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_middleware_allows_clean_ip() {
    let threat_intel = ThreatIntelService::new();

    let app = configure_threat_auth_integration(
        Router::new().route("/test", get(|| async { "success" })),
        threat_intel,
    );

    let request = Request::builder()
        .uri("/test")
        .header("x-forwarded-for", "8.8.8.8")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_middleware_handles_missing_ip() {
    let threat_intel = ThreatIntelService::new();

    let app = configure_threat_auth_integration(
        Router::new().route("/test", get(|| async { "success" })),
        threat_intel,
    );

    let request = Request::builder()
        .uri("/test")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_middleware_respects_threshold() {
    let threat_intel = ThreatIntelService::new();
    
    // Add low-risk IP
    threat_intel.add_indicator(ThreatIndicator {
        ip: "10.0.0.1".to_string(),
        risk_score: 50, // Below default threshold of 70
        threat_type: ThreatType::Suspicious,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    }).await;

    let app = configure_threat_auth_integration(
        Router::new().route("/test", get(|| async { "success" })),
        threat_intel,
    );

    let request = Request::builder()
        .uri("/test")
        .header("x-forwarded-for", "10.0.0.1")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK); // Should pass due to low risk
}
