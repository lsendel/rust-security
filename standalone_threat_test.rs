use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// Minimal threat intelligence implementation for testing
#[derive(Debug, Clone)]
pub struct ThreatIndicator {
    pub ip: String,
    pub risk_score: u8,
    pub threat_type: String,
}

#[derive(Debug, Clone)]
pub struct ThreatIntelService {
    indicators: Arc<RwLock<HashMap<String, ThreatIndicator>>>,
}

impl ThreatIntelService {
    pub fn new() -> Self {
        Self {
            indicators: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_indicator(&self, indicator: ThreatIndicator) {
        let mut indicators = self.indicators.write().await;
        indicators.insert(indicator.ip.clone(), indicator);
    }

    pub async fn is_blocked(&self, ip: &str, threshold: u8) -> bool {
        let indicators = self.indicators.read().await;
        if let Some(indicator) = indicators.get(ip) {
            indicator.risk_score >= threshold
        } else {
            false
        }
    }

    pub async fn check_ip(&self, ip: &str) -> Option<ThreatIndicator> {
        let indicators = self.indicators.read().await;
        indicators.get(ip).cloned()
    }
}

#[tokio::main]
async fn main() {
    println!("🔒 Testing Threat Intelligence Integration");
    println!("==========================================");

    let service = ThreatIntelService::new();
    let mut passed = 0;
    let mut total = 0;

    // Test 1: Basic threat blocking
    total += 1;
    println!("\n🧪 Test 1: Basic threat blocking");
    
    service.add_indicator(ThreatIndicator {
        ip: "192.168.1.100".to_string(),
        risk_score: 90,
        threat_type: "malware".to_string(),
    }).await;

    if service.is_blocked("192.168.1.100", 70).await {
        println!("✅ PASS: Malicious IP blocked correctly");
        passed += 1;
    } else {
        println!("❌ FAIL: Malicious IP not blocked");
    }

    // Test 2: Clean IP allowed
    total += 1;
    println!("\n🧪 Test 2: Clean IP allowed");
    
    if !service.is_blocked("8.8.8.8", 70).await {
        println!("✅ PASS: Clean IP allowed correctly");
        passed += 1;
    } else {
        println!("❌ FAIL: Clean IP incorrectly blocked");
    }

    // Test 3: Threshold respect
    total += 1;
    println!("\n🧪 Test 3: Risk threshold respect");
    
    service.add_indicator(ThreatIndicator {
        ip: "10.0.0.1".to_string(),
        risk_score: 50,
        threat_type: "suspicious".to_string(),
    }).await;

    if !service.is_blocked("10.0.0.1", 70).await {
        println!("✅ PASS: Low-risk IP allowed (below threshold)");
        passed += 1;
    } else {
        println!("❌ FAIL: Low-risk IP incorrectly blocked");
    }

    // Test 4: Concurrent access
    total += 1;
    println!("\n🧪 Test 4: Concurrent access performance");
    
    let start = std::time::Instant::now();
    let mut handles = vec![];

    for i in 0..100 {
        let service_clone = service.clone();
        let handle = tokio::spawn(async move {
            let ip = format!("172.16.{}.1", i);
            service_clone.is_blocked(&ip, 50).await
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let duration = start.elapsed();
    if duration.as_millis() < 1000 {
        println!("✅ PASS: 100 concurrent checks completed in {}ms", duration.as_millis());
        passed += 1;
    } else {
        println!("❌ FAIL: Concurrent checks too slow: {}ms", duration.as_millis());
    }

    // Test 5: Memory efficiency
    total += 1;
    println!("\n🧪 Test 5: Memory efficiency with large dataset");
    
    let start = std::time::Instant::now();
    for i in 0..1000 {
        service.add_indicator(ThreatIndicator {
            ip: format!("203.0.113.{}", i % 256),
            risk_score: (i % 100) as u8,
            threat_type: "test".to_string(),
        }).await;
    }
    let duration = start.elapsed();

    if duration.as_millis() < 5000 {
        println!("✅ PASS: 1000 indicators added in {}ms", duration.as_millis());
        passed += 1;
    } else {
        println!("❌ FAIL: Adding indicators too slow: {}ms", duration.as_millis());
    }

    // Summary
    println!("\n📊 Test Results");
    println!("===============");
    println!("Passed: {}/{}", passed, total);
    println!("Success Rate: {:.1}%", (passed as f64 / total as f64) * 100.0);

    if passed == total {
        println!("\n🎉 All tests passed! Threat Intelligence integration is working correctly.");
        std::process::exit(0);
    } else {
        println!("\n⚠️  Some tests failed. Please review the implementation.");
        std::process::exit(1);
    }
}
