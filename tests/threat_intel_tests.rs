use rust_security::{
    threat_intel::{ThreatIndicator, ThreatIntelService, ThreatType},
    integration::service::ThreatAuthService,
};
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_threat_indicator_blocking() {
    let service = ThreatIntelService::new();
    
    let indicator = ThreatIndicator {
        ip: "192.168.1.100".to_string(),
        risk_score: 90,
        threat_type: ThreatType::Malware,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };
    
    service.add_indicator(indicator).await;
    
    assert!(service.is_blocked("192.168.1.100", 70).await);
    assert!(!service.is_blocked("192.168.1.101", 70).await);
}

#[tokio::test]
async fn test_expired_indicators() {
    let service = ThreatIntelService::new();
    
    let expired_indicator = ThreatIndicator {
        ip: "192.168.1.200".to_string(),
        risk_score: 95,
        threat_type: ThreatType::Botnet,
        expires_at: chrono::Utc::now() - chrono::Duration::hours(1),
    };
    
    service.add_indicator(expired_indicator).await;
    
    assert!(!service.is_blocked("192.168.1.200", 70).await);
}

#[tokio::test]
async fn test_brute_force_detection() {
    let threat_service = ThreatAuthService::new(vec![]);
    let test_ip = "10.0.0.1";
    
    // Simulate 5 failed login attempts
    for _ in 0..5 {
        threat_service.handle_auth_failure(test_ip).await;
    }
    
    // Should be blocked after 5 attempts
    assert!(threat_service.intel_service.is_blocked(test_ip, 70).await);
}

#[tokio::test]
async fn test_risk_assessment() {
    let threat_service = ThreatAuthService::new(vec![]);
    
    // Test suspicious user agent
    let risk_score = threat_service.assess_risk("10.0.0.2", "bot").await;
    assert!(risk_score >= 30);
    
    // Test normal user agent
    let normal_risk = threat_service.assess_risk("10.0.0.3", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)").await;
    assert!(normal_risk < 30);
}

#[tokio::test]
async fn test_cleanup_expired_indicators() {
    let service = ThreatIntelService::new();
    
    // Add expired indicator
    let expired = ThreatIndicator {
        ip: "1.1.1.1".to_string(),
        risk_score: 80,
        threat_type: ThreatType::Suspicious,
        expires_at: chrono::Utc::now() - chrono::Duration::minutes(1),
    };
    
    // Add valid indicator
    let valid = ThreatIndicator {
        ip: "2.2.2.2".to_string(),
        risk_score: 80,
        threat_type: ThreatType::Malware,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };
    
    service.add_indicator(expired).await;
    service.add_indicator(valid).await;
    
    service.cleanup_expired().await;
    
    assert!(service.check_ip("1.1.1.1").await.is_none());
    assert!(service.check_ip("2.2.2.2").await.is_some());
}
