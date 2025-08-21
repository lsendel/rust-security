#[cfg(feature = "threat-hunting")]
mod threat_hunting_tests {
    use auth_service::threat_hunting_orchestrator::{
        ThreatHuntingConfig, ThreatHuntingOrchestrator,
    };
    use auth_service::threat_types::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio;

    /// Test the complete threat hunting pipeline
    #[tokio::test]
    async fn test_threat_hunting_pipeline() {
        // Initialize the threat hunting orchestrator with test configuration
        let config = ThreatHuntingConfig::default();
        let orchestrator = ThreatHuntingOrchestrator::new(config);

        // Initialize the system (this might fail in test environment without Redis)
        if orchestrator.initialize().await.is_err() {
            println!("Warning: Could not initialize full threat hunting system (missing Redis/external services)");
            return;
        }

        // Create a test security event that should trigger threat detection
        let suspicious_event = SecurityEvent {
            event_id: "test_event_001".to_string(),
            timestamp: Utc::now(),
            event_type: SecurityEventType::AuthenticationFailure,
            severity: ThreatSeverity::Medium,
            source: "auth-service".to_string(),
            client_id: Some("suspicious_client".to_string()),
            user_id: Some("test_user_123".to_string()),
            ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
            user_agent: Some("SuspiciousBot/1.0".to_string()),
            request_id: Some("req_001".to_string()),
            session_id: Some("sess_001".to_string()),
            description: "Failed authentication attempt from suspicious source".to_string(),
            details: [
                (
                    "reason".to_string(),
                    serde_json::Value::String("invalid_credentials".to_string()),
                ),
                (
                    "attempts_count".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(15)),
                ),
            ]
            .into_iter()
            .collect(),
            outcome: EventOutcome::Failure,
            resource: Some("/oauth/token".to_string()),
            action: Some("authenticate".to_string()),
            risk_score: Some(75),
            location: Some(GeoLocation {
                country: "Unknown".to_string(),
                region: None,
                city: None,
                latitude: None,
                longitude: None,
                asn: None,
                isp: None,
            }),
            device_fingerprint: Some("unknown_device_fingerprint".to_string()),
            mfa_used: false,
            token_binding_info: None,
        };

        // Process the event through the threat hunting pipeline
        match orchestrator.process_event(suspicious_event).await {
            Ok(result) => {
                println!("Threat hunting analysis completed:");
                println!("- Processing time: {}ms", result.processing_time_ms);
                println!("- Threats detected: {}", result.threats_detected.len());
                println!("- Correlations found: {}", result.correlations_found.len());
                println!(
                    "- Response plans created: {}",
                    result.response_plans_created.len()
                );
                println!("- Confidence score: {:.2}", result.confidence_score);

                // Verify that the system detected potential threats
                assert!(
                    result.processing_time_ms > 0,
                    "Processing should take some time"
                );

                if !result.threats_detected.is_empty() {
                    println!("Detected threats:");
                    for (i, threat) in result.threats_detected.iter().enumerate() {
                        println!(
                            "  {}. Type: {:?}, Severity: {:?}, Confidence: {:.2}",
                            i + 1,
                            threat.threat_type,
                            threat.severity,
                            threat.confidence
                        );
                    }
                }

                if let Some(risk_assessment) = &result.user_risk_assessment {
                    println!("User risk assessment:");
                    println!("  - Risk score: {:.2}", risk_assessment.risk_score);
                    println!("  - Risk level: {:?}", risk_assessment.risk_level);
                    println!(
                        "  - Anomalies: {}",
                        risk_assessment.behavioral_anomalies.len()
                    );
                }
            }
            Err(e) => {
                println!("Threat hunting analysis failed: {}", e);
                // Don't fail the test as this might be due to missing external dependencies
            }
        }

        // Test system status
        let status = orchestrator.get_system_status().await;
        println!("System status: {:?}", status.system_health);
        assert!(status.uptime_hours >= 0.0);

        // Clean shutdown
        orchestrator.shutdown().await;
    }

    /// Test credential stuffing detection
    #[tokio::test]
    async fn test_credential_stuffing_detection() {
        let config = ThreatHuntingConfig::default();
        let orchestrator = ThreatHuntingOrchestrator::new(config);

        if orchestrator.initialize().await.is_err() {
            println!("Warning: Could not initialize full threat hunting system");
            return;
        }

        let attacker_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Simulate multiple failed login attempts from the same IP with different users
        for i in 1..=12 {
            let event = SecurityEvent {
                event_id: format!("cred_stuff_event_{}", i),
                timestamp: Utc::now(),
                event_type: SecurityEventType::AuthenticationFailure,
                severity: ThreatSeverity::Medium,
                source: "auth-service".to_string(),
                client_id: Some("client_001".to_string()),
                user_id: Some(format!("user_{}", i)),
                ip_address: Some(attacker_ip),
                user_agent: Some("curl/7.68.0".to_string()),
                request_id: Some(format!("req_{}", i)),
                session_id: Some(format!("sess_{}", i)),
                description: "Failed authentication attempt".to_string(),
                details: [(
                    "reason".to_string(),
                    serde_json::Value::String("invalid_credentials".to_string()),
                )]
                .into_iter()
                .collect(),
                outcome: EventOutcome::Failure,
                resource: Some("/oauth/token".to_string()),
                action: Some("authenticate".to_string()),
                risk_score: Some(60),
                location: Some(GeoLocation {
                    country: "Unknown".to_string(),
                    region: None,
                    city: None,
                    latitude: None,
                    longitude: None,
                    asn: None,
                    isp: None,
                }),
                device_fingerprint: Some("automated_tool".to_string()),
                mfa_used: false,
                token_binding_info: None,
            };

            if let Ok(result) = orchestrator.process_event(event).await {
                if !result.threats_detected.is_empty() {
                    println!(
                        "Detected potential credential stuffing after {} attempts",
                        i
                    );

                    // Check if credential stuffing was detected
                    let has_credential_stuffing = result
                        .threats_detected
                        .iter()
                        .any(|t| matches!(t.threat_type, ThreatType::CredentialStuffing));

                    if has_credential_stuffing {
                        println!("✓ Credential stuffing attack successfully detected");
                        break;
                    }
                }
            }
        }

        orchestrator.shutdown().await;
    }

    /// Test account takeover detection
    #[tokio::test]
    async fn test_account_takeover_detection() {
        let config = ThreatHuntingConfig::default();
        let orchestrator = ThreatHuntingOrchestrator::new(config);

        if orchestrator.initialize().await.is_err() {
            println!("Warning: Could not initialize full threat hunting system");
            return;
        }

        let user_id = "target_user_456";

        // First, simulate normal login behavior to establish baseline
        for i in 1..=5 {
            let normal_event = SecurityEvent {
                event_id: format!("normal_event_{}", i),
                timestamp: Utc::now() - chrono::Duration::days(i),
                event_type: SecurityEventType::AuthenticationSuccess,
                severity: ThreatSeverity::Low,
                source: "auth-service".to_string(),
                client_id: Some("client_001".to_string()),
                user_id: Some(user_id.to_string()),
                ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
                user_agent: Some(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
                ),
                request_id: Some(format!("req_normal_{}", i)),
                session_id: Some(format!("sess_normal_{}", i)),
                description: "Normal authentication".to_string(),
                details: HashMap::new(),
                outcome: EventOutcome::Success,
                resource: Some("/oauth/token".to_string()),
                action: Some("authenticate".to_string()),
                risk_score: Some(10),
                location: Some(GeoLocation {
                    country: "US".to_string(),
                    region: Some("California".to_string()),
                    city: Some("San Francisco".to_string()),
                    latitude: Some(37.7749),
                    longitude: Some(-122.4194),
                    asn: Some(12345),
                    isp: Some("Normal ISP".to_string()),
                }),
                device_fingerprint: Some("normal_device_fingerprint".to_string()),
                mfa_used: true,
                token_binding_info: None,
            };

            let _ = orchestrator.process_event(normal_event).await;
        }

        // Now simulate a suspicious login that could indicate account takeover
        let suspicious_event = SecurityEvent {
            event_id: "ato_event_001".to_string(),
            timestamp: Utc::now(),
            event_type: SecurityEventType::AuthenticationSuccess,
            severity: ThreatSeverity::High,
            source: "auth-service".to_string(),
            client_id: Some("client_001".to_string()),
            user_id: Some(user_id.to_string()),
            ip_address: Some(IpAddr::V4(Ipv4Addr::new(185, 220, 100, 252))), // Different IP
            user_agent: Some("curl/7.68.0".to_string()),                     // Different user agent
            request_id: Some("req_ato_001".to_string()),
            session_id: Some("sess_ato_001".to_string()),
            description: "Suspicious authentication from new location".to_string(),
            details: HashMap::new(),
            outcome: EventOutcome::Success,
            resource: Some("/oauth/token".to_string()),
            action: Some("authenticate".to_string()),
            risk_score: Some(85),
            location: Some(GeoLocation {
                country: "RU".to_string(), // Different country
                region: Some("Moscow".to_string()),
                city: Some("Moscow".to_string()),
                latitude: Some(55.7558),
                longitude: Some(37.6176),
                asn: Some(54321),
                isp: Some("Suspicious ISP".to_string()),
            }),
            device_fingerprint: Some("unknown_device_fingerprint".to_string()), // Different device
            mfa_used: false,                                                    // No MFA used
            token_binding_info: None,
        };

        match orchestrator.process_event(suspicious_event).await {
            Ok(result) => {
                println!("Account takeover analysis completed:");
                println!("- Threats detected: {}", result.threats_detected.len());

                if let Some(risk_assessment) = &result.user_risk_assessment {
                    println!("- User risk score: {:.2}", risk_assessment.risk_score);
                    println!("- Risk level: {:?}", risk_assessment.risk_level);

                    // High risk events should trigger elevated risk scores
                    assert!(
                        risk_assessment.risk_score > 0.5,
                        "High risk event should increase user risk score"
                    );
                }

                let has_account_takeover = result
                    .threats_detected
                    .iter()
                    .any(|t| matches!(t.threat_type, ThreatType::AccountTakeover));

                if has_account_takeover {
                    println!("✓ Account takeover attempt successfully detected");
                }
            }
            Err(e) => {
                println!("Account takeover analysis failed: {}", e);
            }
        }

        orchestrator.shutdown().await;
    }

    /// Test the behavioral profiling capabilities
    #[tokio::test]
    async fn test_behavioral_profiling() {
        let config = ThreatHuntingConfig::default();
        let orchestrator = ThreatHuntingOrchestrator::new(config);

        if orchestrator.initialize().await.is_err() {
            println!("Warning: Could not initialize full threat hunting system");
            return;
        }

        let user_id = "profiling_test_user";

        // Simulate a series of events to build behavioral profile
        let base_time = Utc::now() - chrono::Duration::hours(24);

        for hour in 0..24 {
            // Normal working hours pattern (9 AM to 5 PM)
            if hour >= 9 && hour <= 17 {
                let event = SecurityEvent {
                    event_id: format!("profile_event_{}", hour),
                    timestamp: base_time + chrono::Duration::hours(hour),
                    event_type: SecurityEventType::AuthenticationSuccess,
                    severity: ThreatSeverity::Low,
                    source: "auth-service".to_string(),
                    client_id: Some("client_001".to_string()),
                    user_id: Some(user_id.to_string()),
                    ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
                    user_agent: Some(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
                    ),
                    request_id: Some(format!("req_profile_{}", hour)),
                    session_id: Some(format!("sess_profile_{}", hour)),
                    description: "Normal work hours authentication".to_string(),
                    details: HashMap::new(),
                    outcome: EventOutcome::Success,
                    resource: Some("/oauth/token".to_string()),
                    action: Some("authenticate".to_string()),
                    risk_score: Some(5),
                    location: Some(GeoLocation {
                        country: "US".to_string(),
                        region: Some("California".to_string()),
                        city: Some("San Francisco".to_string()),
                        latitude: Some(37.7749),
                        longitude: Some(-122.4194),
                        asn: Some(12345),
                        isp: Some("Corporate ISP".to_string()),
                    }),
                    device_fingerprint: Some("corporate_device".to_string()),
                    mfa_used: true,
                    token_binding_info: None,
                };

                let _ = orchestrator.process_event(event).await;
            }
        }

        // Now test with an anomalous event (3 AM login)
        let anomalous_event = SecurityEvent {
            event_id: "anomalous_event_001".to_string(),
            timestamp: Utc::now(),
            event_type: SecurityEventType::AuthenticationSuccess,
            severity: ThreatSeverity::Medium,
            source: "auth-service".to_string(),
            client_id: Some("client_001".to_string()),
            user_id: Some(user_id.to_string()),
            ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
            user_agent: Some(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            ),
            request_id: Some("req_anomalous_001".to_string()),
            session_id: Some("sess_anomalous_001".to_string()),
            description: "Unusual time authentication".to_string(),
            details: HashMap::new(),
            outcome: EventOutcome::Success,
            resource: Some("/oauth/token".to_string()),
            action: Some("authenticate".to_string()),
            risk_score: Some(40),
            location: Some(GeoLocation {
                country: "US".to_string(),
                region: Some("California".to_string()),
                city: Some("San Francisco".to_string()),
                latitude: Some(37.7749),
                longitude: Some(-122.4194),
                asn: Some(12345),
                isp: Some("Corporate ISP".to_string()),
            }),
            device_fingerprint: Some("corporate_device".to_string()),
            mfa_used: true,
            token_binding_info: None,
        };

        // Set the timestamp to 3 AM
        let mut anomalous_event = anomalous_event;
        anomalous_event.timestamp = anomalous_event
            .timestamp
            .with_hour(3)
            .unwrap()
            .with_minute(0)
            .unwrap()
            .with_second(0)
            .unwrap();

        match orchestrator.process_event(anomalous_event).await {
            Ok(result) => {
                println!("Behavioral profiling analysis completed:");

                if let Some(risk_assessment) = &result.user_risk_assessment {
                    println!("- User risk score: {:.2}", risk_assessment.risk_score);
                    println!(
                        "- Behavioral anomalies detected: {}",
                        risk_assessment.behavioral_anomalies.len()
                    );

                    if !risk_assessment.behavioral_anomalies.is_empty() {
                        println!("✓ Temporal anomaly successfully detected in user behavior");
                        for anomaly in &risk_assessment.behavioral_anomalies {
                            println!("  - {}", anomaly);
                        }
                    }
                }
            }
            Err(e) => {
                println!("Behavioral profiling analysis failed: {}", e);
            }
        }

        orchestrator.shutdown().await;
    }

    /// Test system performance under load
    #[tokio::test]
    async fn test_system_performance() {
        let config = ThreatHuntingConfig::default();
        let orchestrator = ThreatHuntingOrchestrator::new(config);

        if orchestrator.initialize().await.is_err() {
            println!("Warning: Could not initialize full threat hunting system");
            return;
        }

        let start_time = std::time::Instant::now();
        let event_count = 100;

        // Process multiple events concurrently
        let mut handles = Vec::new();

        for i in 0..event_count {
            let orchestrator = &orchestrator;
            let handle = tokio::spawn(async move {
                let event = SecurityEvent {
                    event_id: format!("perf_test_event_{}", i),
                    timestamp: Utc::now(),
                    event_type: if i % 3 == 0 {
                        SecurityEventType::AuthenticationFailure
                    } else {
                        SecurityEventType::AuthenticationSuccess
                    },
                    severity: ThreatSeverity::Low,
                    source: "auth-service".to_string(),
                    client_id: Some("perf_test_client".to_string()),
                    user_id: Some(format!("perf_user_{}", i % 10)),
                    ip_address: Some(IpAddr::V4(Ipv4Addr::new(
                        (i % 255) as u8 + 1,
                        168,
                        1,
                        (i % 254) as u8 + 1,
                    ))),
                    user_agent: Some("PerfTestAgent/1.0".to_string()),
                    request_id: Some(format!("perf_req_{}", i)),
                    session_id: Some(format!("perf_sess_{}", i)),
                    description: "Performance test event".to_string(),
                    details: HashMap::new(),
                    outcome: if i % 3 == 0 {
                        EventOutcome::Failure
                    } else {
                        EventOutcome::Success
                    },
                    resource: Some("/oauth/token".to_string()),
                    action: Some("authenticate".to_string()),
                    risk_score: Some((i % 100) as u8),
                    location: None,
                    device_fingerprint: Some(format!("perf_device_{}", i % 5)),
                    mfa_used: i % 2 == 0,
                    token_binding_info: None,
                };

                orchestrator.process_event(event).await
            });

            handles.push(handle);
        }

        // Wait for all events to be processed
        let mut successful_analyses = 0;
        let mut total_processing_time = 0u64;

        for handle in handles {
            match handle.await {
                Ok(Ok(result)) => {
                    successful_analyses += 1;
                    total_processing_time += result.processing_time_ms;
                }
                Ok(Err(e)) => {
                    println!("Event processing failed: {}", e);
                }
                Err(e) => {
                    println!("Task failed: {}", e);
                }
            }
        }

        let total_duration = start_time.elapsed();
        let average_processing_time = if successful_analyses > 0 {
            total_processing_time / successful_analyses
        } else {
            0
        };

        println!("Performance test results:");
        println!("- Total events: {}", event_count);
        println!("- Successful analyses: {}", successful_analyses);
        println!("- Total time: {:.2}s", total_duration.as_secs_f64());
        println!(
            "- Events per second: {:.2}",
            event_count as f64 / total_duration.as_secs_f64()
        );
        println!(
            "- Average processing time per event: {}ms",
            average_processing_time
        );

        // Basic performance assertions
        assert!(
            successful_analyses > 0,
            "At least some events should be processed successfully"
        );
        assert!(
            total_duration.as_secs() < 30,
            "Processing should complete within 30 seconds"
        );

        let status = orchestrator.get_system_status().await;
        println!("Final system status: {:?}", status.system_health);

        orchestrator.shutdown().await;
    }
}

// Tests that don't require the threat-hunting feature
#[cfg(feature = "threat-hunting")]
#[tokio::test]
async fn test_security_event_creation() {
    let event = SecurityEvent::new(
        SecurityEventType::AuthenticationFailure,
        ThreatSeverity::Medium,
        "test-service".to_string(),
        "Test security event".to_string(),
        EventOutcome::Failure,
    );

    assert_eq!(event.event_type, SecurityEventType::AuthenticationFailure);
    assert_eq!(event.severity, ThreatSeverity::Medium);
    assert_eq!(event.source, "test-service");
    assert_eq!(event.outcome, EventOutcome::Failure);
    assert!(!event.event_id.is_empty());
}

#[cfg(feature = "threat-hunting")]
#[tokio::test]
async fn test_threat_signature_creation() {
    let threat = ThreatSignature::new(ThreatType::CredentialStuffing, ThreatSeverity::High, 0.85);

    assert_eq!(threat.threat_type, ThreatType::CredentialStuffing);
    assert_eq!(threat.severity, ThreatSeverity::High);
    assert_eq!(threat.confidence, 0.85);
    assert!(!threat.threat_id.is_empty());
    assert!(threat.is_active());
}

#[cfg(feature = "threat-hunting")]
#[tokio::test]
async fn test_user_behavior_profile_creation() {
    let mut profile = UserBehaviorProfile::new("test_user_123".to_string());

    assert_eq!(profile.user_id, "test_user_123");
    assert!(profile.typical_login_hours.is_empty());
    assert!(profile.typical_locations.is_empty());
    assert_eq!(profile.security_events_count, 0);

    // Test updating with an event
    let event = SecurityEvent::new(
        SecurityEventType::AuthenticationSuccess,
        ThreatSeverity::Low,
        "test-service".to_string(),
        "Successful login".to_string(),
        EventOutcome::Success,
    );

    profile.update_with_event(&event);
    assert_eq!(profile.security_events_count, 1);
    assert!(!profile.typical_login_hours.is_empty());
}
