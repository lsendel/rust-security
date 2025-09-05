use rust_security::{
    threat_intel::{ThreatIndicator, ThreatIntelService, ThreatType},
    integration::service::ThreatAuthService,
};
use std::time::Instant;
use tokio::task::JoinSet;

#[tokio::test]
async fn test_concurrent_threat_checks() {
    let service = ThreatIntelService::new();
    
    // Add 1000 threat indicators
    for i in 0..1000 {
        service.add_indicator(ThreatIndicator {
            ip: format!("192.168.{}.{}", i / 256, i % 256),
            risk_score: (i % 100) as u8,
            threat_type: ThreatType::Suspicious,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        }).await;
    }

    let start = Instant::now();
    let mut tasks = JoinSet::new();

    // Spawn 100 concurrent tasks checking different IPs
    for i in 0..100 {
        let service_clone = service.clone();
        tasks.spawn(async move {
            let ip = format!("10.0.{}.{}", i / 256, i % 256);
            service_clone.is_blocked(&ip, 50).await
        });
    }

    // Wait for all tasks to complete
    while let Some(_) = tasks.join_next().await {}

    let duration = start.elapsed();
    println!("100 concurrent checks took: {:?}", duration);
    
    // Should complete within reasonable time
    assert!(duration.as_millis() < 1000);
}

#[tokio::test]
async fn test_brute_force_performance() {
    let threat_service = ThreatAuthService::new(vec![]);
    let start = Instant::now();

    // Simulate 1000 failed login attempts from different IPs
    for i in 0..1000 {
        let ip = format!("172.16.{}.{}", i / 256, i % 256);
        threat_service.handle_auth_failure(&ip).await;
    }

    let duration = start.elapsed();
    println!("1000 brute force detections took: {:?}", duration);
    
    // Should handle high volume efficiently
    assert!(duration.as_millis() < 5000);
}

#[tokio::test]
async fn test_risk_assessment_performance() {
    let threat_service = ThreatAuthService::new(vec![]);
    let start = Instant::now();

    let mut tasks = JoinSet::new();

    // Perform 500 concurrent risk assessments
    for i in 0..500 {
        let service_clone = threat_service.clone();
        tasks.spawn(async move {
            let ip = format!("203.0.113.{}", i % 256);
            let user_agent = "Mozilla/5.0 (Test)";
            service_clone.assess_risk(&ip, user_agent).await
        });
    }

    while let Some(_) = tasks.join_next().await {}

    let duration = start.elapsed();
    println!("500 concurrent risk assessments took: {:?}", duration);
    
    // Should maintain sub-second performance
    assert!(duration.as_millis() < 2000);
}
