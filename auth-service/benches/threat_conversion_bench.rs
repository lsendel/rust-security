#![allow(clippy::default_trait_access, clippy::semicolon_if_nothing_returned)]
//! Performance benchmarks for threat detection conversion

use auth_service::core::auth::AuthContext;
use auth_service::core::security::{
    SecurityContext, SecurityEvent, SecurityEventType, SecurityLevel, ViolationSeverity,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

use auth_service::event_conversion::convert_security_events;

fn create_benchmark_event() -> SecurityEvent {
    SecurityEvent {
        timestamp: SystemTime::now().into(),
        event_type: SecurityEventType::AuthenticationFailure,
        security_context: SecurityContext {
            client_ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
            user_agent: "Benchmark Agent".to_string(),
            fingerprint: "bench-fingerprint".to_string(),
            security_level: SecurityLevel::Standard,
            risk_score: 0.5,
            threat_indicators: vec![],
            flags: Default::default(),
            metadata: HashMap::new(),
        },
        auth_context: Some(AuthContext {
            user_id: "bench-user".to_string(),
            session_id: "bench-session".to_string(),
            authenticated_at: SystemTime::now(),
            expires_at: SystemTime::now(),
            scopes: vec!["read".to_string()],
            claims: HashMap::new(),
        }),
        details: HashMap::new(),
        severity: ViolationSeverity::Medium,
        user_id: Some("bench-user".to_string()),
        session_id: Some("bench-session".to_string()),
        ip_address: Some("192.168.1.1".parse::<IpAddr>().unwrap()),
        location: None,
        device_fingerprint: Some("bench-fingerprint".to_string()),
        risk_score: Some(50),
        outcome: Some("failure".to_string()),
        mfa_used: false,
        user_agent: Some("Benchmark Agent".to_string()),
    }
}

fn bench_single_conversion(c: &mut Criterion) {
    let event = create_benchmark_event();

    c.bench_function("single_event_conversion", |b| {
        b.iter(|| {
            let threat_event: auth_service::threat_types::ThreatSecurityEvent =
                black_box(&event).into();
            black_box(threat_event);
        })
    });
}

fn bench_batch_conversion(c: &mut Criterion) {
    let events: Vec<SecurityEvent> = (0..100).map(|_| create_benchmark_event()).collect();

    c.bench_function("batch_conversion_100", |b| {
        b.iter(|| {
            let threat_events = convert_security_events(black_box(&events));
            black_box(threat_events);
        })
    });
}

fn bench_process_with_conversion(_c: &mut Criterion) {}

fn bench_no_feature(c: &mut Criterion) {
    let event = create_benchmark_event();

    c.bench_function("no_feature_baseline", |b| {
        b.iter(|| {
            black_box(&event);
        });
    });
}

criterion_group!(
    benches,
    bench_single_conversion,
    bench_batch_conversion,
    bench_process_with_conversion,
    bench_no_feature
);

criterion_main!(benches);
