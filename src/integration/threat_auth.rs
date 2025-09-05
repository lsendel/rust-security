use axum::{middleware, Router};
use crate::auth::middleware::AuthMiddleware;
use crate::threat_intel::ThreatIntelService;

pub fn configure_threat_auth_integration(
    router: Router,
    threat_intel: ThreatIntelService,
) -> Router {
    let auth_middleware = AuthMiddleware::new(threat_intel);
    
    router.layer(middleware::from_fn_with_state(
        auth_middleware,
        AuthMiddleware::check_threat_intel,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_intel::{ThreatIndicator, ThreatType};
    use axum::{http::StatusCode, routing::get, Json};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_blocked_ip() {
        let threat_intel = ThreatIntelService::new();
        
        threat_intel.add_indicator(ThreatIndicator {
            ip: "192.168.1.100".to_string(),
            risk_score: 90,
            threat_type: ThreatType::Malware,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        }).await;

        let app = configure_threat_auth_integration(
            Router::new().route("/test", get(|| async { "ok" })),
            threat_intel,
        );

        let request = axum::http::Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "192.168.1.100")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
