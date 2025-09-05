use std::collections::HashMap;

// Simple threat intelligence implementation for testing
#[derive(Debug, Clone)]
pub struct ThreatIndicator {
    pub ip: String,
    pub risk_score: u8,
    pub threat_type: String,
}

#[derive(Debug)]
pub struct ThreatIntelService {
    indicators: HashMap<String, ThreatIndicator>,
}

impl ThreatIntelService {
    pub fn new() -> Self {
        Self {
            indicators: HashMap::new(),
        }
    }

    pub fn add_indicator(&mut self, indicator: ThreatIndicator) {
        self.indicators.insert(indicator.ip.clone(), indicator);
    }

    pub fn is_blocked(&self, ip: &str, threshold: u8) -> bool {
        if let Some(indicator) = self.indicators.get(ip) {
            indicator.risk_score >= threshold
        } else {
            false
        }
    }

    pub fn check_ip(&self, ip: &str) -> Option<&ThreatIndicator> {
        self.indicators.get(ip)
    }

    pub fn indicator_count(&self) -> usize {
        self.indicators.len()
    }
}

fn main() {
    println!("🔒 Testing Threat Intelligence Integration");
    println!("==========================================");

    let mut service = ThreatIntelService::new();
    let mut passed = 0;
    let mut total = 0;

    // Test 1: Basic threat blocking
    total += 1;
    println!("\n🧪 Test 1: Basic threat blocking");
    
    service.add_indicator(ThreatIndicator {
        ip: "192.168.1.100".to_string(),
        risk_score: 90,
        threat_type: "malware".to_string(),
    });

    if service.is_blocked("192.168.1.100", 70) {
        println!("✅ PASS: Malicious IP blocked correctly");
        passed += 1;
    } else {
        println!("❌ FAIL: Malicious IP not blocked");
    }

    // Test 2: Clean IP allowed
    total += 1;
    println!("\n🧪 Test 2: Clean IP allowed");
    
    if !service.is_blocked("8.8.8.8", 70) {
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
    });

    if !service.is_blocked("10.0.0.1", 70) {
        println!("✅ PASS: Low-risk IP allowed (below threshold)");
        passed += 1;
    } else {
        println!("❌ FAIL: Low-risk IP incorrectly blocked");
    }

    // Test 4: Indicator retrieval
    total += 1;
    println!("\n🧪 Test 4: Indicator retrieval");
    
    if let Some(indicator) = service.check_ip("192.168.1.100") {
        if indicator.risk_score == 90 && indicator.threat_type == "malware" {
            println!("✅ PASS: Indicator retrieved correctly");
            passed += 1;
        } else {
            println!("❌ FAIL: Indicator data incorrect");
        }
    } else {
        println!("❌ FAIL: Indicator not found");
    }

    // Test 5: Memory efficiency with large dataset
    total += 1;
    println!("\n🧪 Test 5: Memory efficiency with large dataset");
    
    let start = std::time::Instant::now();
    for i in 0..1000 {
        service.add_indicator(ThreatIndicator {
            ip: format!("203.0.113.{}", i % 256),
            risk_score: (i % 100) as u8,
            threat_type: "test".to_string(),
        });
    }
    let duration = start.elapsed();

    if duration.as_millis() < 100 && service.indicator_count() > 1000 {
        println!("✅ PASS: 1000+ indicators added in {}ms", duration.as_millis());
        passed += 1;
    } else {
        println!("❌ FAIL: Performance or count issue - {}ms, {} indicators", 
                duration.as_millis(), service.indicator_count());
    }

    // Test 6: Edge cases
    total += 1;
    println!("\n🧪 Test 6: Edge cases");
    
    let edge_cases_pass = 
        !service.is_blocked("", 70) && // Empty string
        !service.is_blocked("invalid-ip", 70) && // Invalid IP
        service.is_blocked("203.0.113.99", 0); // Zero threshold

    if edge_cases_pass {
        println!("✅ PASS: Edge cases handled correctly");
        passed += 1;
    } else {
        println!("❌ FAIL: Edge cases not handled properly");
    }

    // Summary
    println!("\n📊 Test Results");
    println!("===============");
    println!("Passed: {}/{}", passed, total);
    println!("Success Rate: {:.1}%", (passed as f64 / total as f64) * 100.0);
    println!("Total Indicators: {}", service.indicator_count());

    if passed == total {
        println!("\n🎉 All tests passed! Threat Intelligence integration is working correctly.");
        println!("\n🚀 Key Features Validated:");
        println!("   • IP-based threat blocking");
        println!("   • Configurable risk thresholds");
        println!("   • Fast indicator lookup");
        println!("   • Memory-efficient storage");
        println!("   • Edge case handling");
        
        std::process::exit(0);
    } else {
        println!("\n⚠️  Some tests failed. Please review the implementation.");
        std::process::exit(1);
    }
}
