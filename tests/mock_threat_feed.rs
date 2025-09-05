use axum::{routing::get, Json, Router};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub async fn start_mock_feed_server() -> String {
    let app = Router::new()
        .route("/v1/indicators", get(mock_threat_indicators));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    url
}

async fn mock_threat_indicators() -> Json<Value> {
    Json(json!({
        "indicators": [
            {
                "ip": "192.168.1.100",
                "risk_score": 95,
                "type": "malware"
            },
            {
                "ip": "10.0.0.50",
                "risk_score": 80,
                "type": "botnet"
            },
            {
                "ip": "172.16.0.10",
                "risk_score": 60,
                "type": "suspicious"
            }
        ]
    }))
}

#[tokio::test]
async fn test_feed_integration() {
    use rust_security::threat_intel::feeds::ThreatFeedManager;
    use rust_security::threat_intel::ThreatIntelService;

    let feed_url = start_mock_feed_server().await;
    let service = ThreatIntelService::new();
    let feed_manager = ThreatFeedManager::new(service.clone(), vec![feed_url]);

    // Manually trigger one update
    feed_manager.update_from_feed(&feed_manager.feeds[0]).await.unwrap();

    // Check that indicators were loaded
    assert!(service.check_ip("192.168.1.100").await.is_some());
    assert!(service.check_ip("10.0.0.50").await.is_some());
    assert!(service.check_ip("172.16.0.10").await.is_some());
    
    // Verify risk scores
    let indicator = service.check_ip("192.168.1.100").await.unwrap();
    assert_eq!(indicator.risk_score, 95);
}
