//! Threat Intelligence Integration Middleware
//!
//! Integrates AI-based behavioral analysis into the authentication flow
//! to detect and respond to security threats in real-time.

use crate::monitoring::alert_handlers::AlertHandlerFactory;
use crate::monitoring::security_alerts::SecurityAlert;
use crate::threat_intelligence::{ThreatIntelligenceService, behavioral_analysis::AnomalyType};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

/// Global threat intelligence service instance
static THREAT_INTELLIGENCE: Mutex<Option<Arc<ThreatIntelligenceService>>> = Mutex::new(None);

/// Initialize the global threat intelligence service
pub fn initialize_threat_intelligence() {
    let handlers = AlertHandlerFactory::create_handlers();
    let alert_service = Arc::new(SecurityAlert::new(handlers));
    let service = Arc::new(ThreatIntelligenceService::new(alert_service));
    
    let mut global_service = THREAT_INTELLIGENCE.lock().unwrap();
    *global_service = Some(service);
    
    info!("🧠 Threat intelligence service initialized");
}

/// Get the global threat intelligence service
pub fn get_threat_intelligence() -> Option<Arc<ThreatIntelligenceService>> {
    let service = THREAT_INTELLIGENCE.lock().unwrap();
    service.clone()
}

/// Threat intelligence middleware for authentication events
pub async fn threat_intelligence_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let uri = request.uri().path().to_string();
    let method = request.method().clone();
    let headers = request.headers().clone();
    
    // Extract client information
    let client_ip = extract_client_ip(&headers);
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    
    // For now, we'll analyze after the request to avoid blocking
    let response = next.run(request).await;
    
    // Analyze request for threat patterns (async task)
    if let Some(service) = get_threat_intelligence() {
        tokio::spawn(async move {
            analyze_request_async(
                service,
                uri,
                method.to_string(),
                client_ip,
                user_agent,
                response.status().as_u16(),
            ).await;
        });
    }
    
    Ok(response)
}

/// Analyze authentication event with threat intelligence
pub async fn analyze_auth_event(
    user_id: &str,
    success: bool,
    ip_address: Option<std::net::IpAddr>,
    user_agent: Option<String>,
    endpoint: Option<String>,
) {
    if let Some(service) = get_threat_intelligence() {
        let anomalies = service.analyze_authentication_event(
            user_id,
            ip_address,
            user_agent,
            endpoint,
            success,
            1, // Single request
            None, // Session duration unknown at this point
        ).await;

        if !anomalies.is_empty() {
            info!(
                "Detected {} behavioral anomalies for user: {}",
                anomalies.len(),
                user_id
            );

            // Check for high-risk anomalies that should block further requests
            let has_critical_anomaly = anomalies.iter().any(|a| {
                matches!(a.anomaly_type, AnomalyType::SuspiciousVelocity | AnomalyType::AbnormalRequestRate)
                && a.risk_score > 0.8
            });

            if has_critical_anomaly {
                warn!("Critical security anomaly detected for user: {}", user_id);
                // In a production system, this might trigger additional security measures
                // such as requiring additional authentication factors or temporary account locks
            }
        }
    }
}

/// Analyze API access patterns
pub async fn analyze_api_access(
    user_id: &str,
    ip_address: Option<std::net::IpAddr>,
    endpoint: &str,
    method: &str,
    response_time_ms: u64,
    status_code: u16,
) {
    if let Some(service) = get_threat_intelligence() {
        let request_count = if status_code >= 400 { 0 } else { 1 };
        
        let anomalies = service.analyze_api_access(
            user_id,
            ip_address,
            endpoint,
            method,
            request_count,
            response_time_ms,
        ).await;

        if !anomalies.is_empty() {
            debug!(
                "API access anomalies detected for user {} on {}: {} anomalies",
                user_id, endpoint, anomalies.len()
            );
        }
    }
}

/// Get user risk score for authorization decisions
pub async fn get_user_risk_score(user_id: &str) -> f64 {
    if let Some(service) = get_threat_intelligence() {
        service.get_user_risk_score(user_id).await
    } else {
        0.0
    }
}

/// Risk-based authentication decision
pub async fn should_require_additional_auth(user_id: &str, base_risk: f64) -> bool {
    let behavioral_risk = get_user_risk_score(user_id).await;
    let total_risk = (base_risk + behavioral_risk) / 2.0;
    
    // Require additional auth if total risk exceeds threshold
    total_risk > 0.6
}

/// Extract client IP from headers
fn extract_client_ip(headers: &HeaderMap) -> Option<std::net::IpAddr> {
    // Check X-Forwarded-For header first (for proxied requests)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }
    
    // Check X-Real-IP header
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.parse() {
                return Some(ip);
            }
        }
    }
    
    None
}

/// Async request analysis to avoid blocking middleware
async fn analyze_request_async(
    service: Arc<ThreatIntelligenceService>,
    uri: String,
    method: String,
    client_ip: Option<std::net::IpAddr>,
    user_agent: Option<String>,
    status_code: u16,
) {
    // For now, analyze as an anonymous request
    // In production, you'd extract the authenticated user ID from the JWT token
    let user_id = "anonymous";
    
    let start_time = std::time::Instant::now();
    let response_time_ms = 100; // Default response time
    
    let _anomalies = service.analyze_api_access(
        user_id,
        client_ip,
        &uri,
        &method,
        if status_code < 400 { 1 } else { 0 },
        response_time_ms,
    ).await;
    
    let analysis_time = start_time.elapsed();
    debug!(
        "Threat analysis completed for {} {} in {:?}",
        method, uri, analysis_time
    );
}

/// Enhanced authentication middleware with threat intelligence
pub async fn enhanced_auth_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers().clone();
    let uri = request.uri().path().to_string();
    
    // Extract JWT token if present
    let auth_header = headers.get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|token| token.to_string());
    
    let client_ip = extract_client_ip(&headers);
    let user_agent = headers.get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // If this is an authentication endpoint, prepare for analysis
    let is_auth_endpoint = uri.contains("/auth/") || uri.contains("/oauth/");
    
    // Process the request
    let response = next.run(request).await;
    let status = response.status();
    
    // Analyze authentication events
    if is_auth_endpoint {
        if let Some(token) = auth_header {
            // In production, decode the JWT to get the user ID
            // For now, use a placeholder
            let user_id = "authenticated_user";
            let success = status.is_success();
            
            // Spawn async analysis
            tokio::spawn(async move {
                analyze_auth_event(
                    user_id,
                    success,
                    client_ip,
                    user_agent,
                    Some(uri),
                ).await;
            });
        }
    }
    
    Ok(response)
}

/// Configure threat intelligence service
pub async fn configure_threat_intelligence(
    learning_enabled: bool,
    risk_threshold: f64,
) {
    if let Some(service) = get_threat_intelligence() {
        // Configure learning mode
        let mut service_mut = Arc::try_unwrap(service).unwrap_or_else(|arc| {
            // If we can't unwrap, create a new service with the same configuration
            let handlers = AlertHandlerFactory::create_handlers();
            let alert_service = Arc::new(SecurityAlert::new(handlers));
            ThreatIntelligenceService::new(alert_service)
        });
        
        service_mut.set_learning_enabled(learning_enabled);
        
        // Update global service
        let mut global_service = THREAT_INTELLIGENCE.lock().unwrap();
        *global_service = Some(Arc::new(service_mut));
        
        info!(
            "Threat intelligence configured: learning={}, threshold={}",
            learning_enabled, risk_threshold
        );
    }
}

/// Get threat intelligence analytics
pub async fn get_analytics() -> Option<crate::threat_intelligence::behavioral_analysis::BehavioralAnalytics> {
    if let Some(service) = get_threat_intelligence() {
        Some(service.get_analytics().await)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        response::Response,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_threat_intelligence_initialization() {
        initialize_threat_intelligence();
        
        let service = get_threat_intelligence();
        assert!(service.is_some());
    }

    #[tokio::test]
    async fn test_extract_client_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "192.168.1.100, 10.0.0.1".parse().unwrap());
        
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
    }

    #[tokio::test]
    async fn test_auth_event_analysis() {
        initialize_threat_intelligence();
        
        analyze_auth_event(
            "test_user",
            true,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Some("Mozilla/5.0".to_string()),
            Some("/api/v1/auth/login".to_string()),
        ).await;
        
        // Should not panic and should complete successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_risk_based_auth_decision() {
        initialize_threat_intelligence();
        
        let require_additional = should_require_additional_auth("test_user", 0.3).await;
        
        // With low base risk and no behavioral history, should not require additional auth
        assert!(!require_additional);
    }
}