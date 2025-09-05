use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::net::IpAddr;
use crate::threat_intel::ThreatIntelService;

pub struct AuthMiddleware {
    threat_intel: ThreatIntelService,
    block_threshold: u8,
}

impl AuthMiddleware {
    pub fn new(threat_intel: ThreatIntelService) -> Self {
        Self {
            threat_intel,
            block_threshold: 70, // Block IPs with risk score >= 70
        }
    }

    pub async fn check_threat_intel(
        State(middleware): State<AuthMiddleware>,
        mut request: Request,
        next: Next,
    ) -> Result<Response, StatusCode> {
        let client_ip = extract_client_ip(&request);
        
        if let Some(ip) = client_ip {
            if middleware.threat_intel.is_blocked(&ip, middleware.block_threshold).await {
                return Err(StatusCode::FORBIDDEN);
            }
        }

        Ok(next.run(request).await)
    }
}

fn extract_client_ip(request: &Request) -> Option<String> {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|hv| hv.to_str().ok())
                .map(|s| s.to_string())
        })
}
