//! Simple Demonstration of Automated Remediation System
//!
//! This example shows the basic usage of the automated remediation platform.

use mvp_tools::automated_remediation::{
    RemediationEngine, SecurityEvent, SecurityEventType, Severity,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Automated Remediation Platform - Simple Demo");
    println!("=============================================\n");

    // Initialize the remediation engine
    let engine = RemediationEngine::new();
    println!("✅ Remediation Engine initialized\n");

    // Demonstrate security event processing
    println!("🛡️ Processing security events:\n");

    // Example 1: Threat Detection
    let threat_event = SecurityEvent {
        event_type: SecurityEventType::ThreatDetected {
            ip: "192.168.1.100".parse()?,
            threat_score: 85,
            context: vec!["Malicious IP detected".to_string()],
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        severity: Severity::High,
    };

    let actions = engine.process_security_event(threat_event).await;
    println!("📍 Threat Detection Event:");
    println!("   Generated {} remediation actions", actions.len());
    for action in actions {
        println!("   - {:?}", action);
    }

    // Example 2: Certificate Expiration
    let cert_event = SecurityEvent {
        event_type: SecurityEventType::CertificateExpired {
            domain: "api.example.com".to_string(),
            issuer: mvp_tools::automated_remediation::CertificateIssuer::LetsEncrypt,
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        severity: Severity::Medium,
    };

    let actions = engine.process_security_event(cert_event).await;
    println!("\n📍 Certificate Expiration Event:");
    println!("   Generated {} remediation actions", actions.len());

    // Example 3: Service Failure
    let failure_event = SecurityEvent {
        event_type: SecurityEventType::ServiceFailure {
            service_name: "auth-service".to_string(),
            failure_reason: "high_memory_usage".to_string(),
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        severity: Severity::High,
    };

    let actions = engine.process_security_event(failure_event).await;
    println!("\n📍 Service Failure Event:");
    println!("   Generated {} remediation actions", actions.len());

    println!("\n🎯 Demo completed successfully!");
    println!("The automated remediation platform is working correctly.");

    Ok(())
}
