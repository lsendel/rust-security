//! Performance benchmarks for threat detection conversion

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use auth_service::core::security::{SecurityEvent, SecurityEventType, SecurityContext, SecurityLevel, ViolationSeverity};
use auth_service::core::auth::AuthContext;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

#[cfg(feature = "threat-hunting")]
use auth_service::{
    event_conversion::convert_security_events,
    threat_adapter::process_with_conversion,
};

fn create_benchmark_event() -> SecurityEvent {
    SecurityEvent {
        timestamp: SystemTime::now(),
        event_type: SecurityEventType::AuthenticationFailure,
        security_context: SecurityContext {
            client_ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
            user_agent: "Benchmark Agent".to_string(),
            fingerprint: "bench-fingerprint".to_string(),
            security_level: SecurityLevel::Medium,
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
    }
}

#[cfg(feature = "threat-hunting")]
fn bench_single_conversion(c: &mut Criterion) {
    let event = create_benchmark_event();
    
    c.bench_function("single_event_conversion", |b| {
        b.iter(|| {
            let threat_event: auth_service::threat_types::ThreatSecurityEvent = black_box(&event).into();
            black_box(threat_event);
        })
    });
}

#[cfg(feature = "threat-hunting")]
fn bench_batch_conversion(c: &mut Criterion) {
    let events: Vec<SecurityEvent> = (0..100).map(|_| create_benchmark_event()).collect();
    
    c.bench_function("batch_conversion_100", |b| {
        b.iter(|| {
            let threat_events = convert_security_events(black_box(&events));
            black_box(threat_events);
        })
    });
}

#[cfg(feature = "threat-hunting")]
fn bench_process_with_conversion(c: &mut Criterion) {
    let event = create_benchmark_event();
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    c.bench_function("process_with_conversion", |b| {
        b.to_async(&rt).iter(|| async {
            let result = process_with_conversion(black_box(&event), |threat_event| async move {
                black_box(threat_event);
                Ok(())
            }).await;
            black_box(result);
        })
    });
}

#[cfg(not(feature = "threat-hunting"))]
fn bench_no_feature(c: &mut Criterion) {
    let event = create_benchmark_event();
    
    c.bench_function("no_feature_baseline", |b| {
        b.iter(|| {
            black_box(&event);
        })
    });
}

#[cfg(feature = "threat-hunting")]
criterion_group!(
    benches,
    bench_single_conversion,
    bench_batch_conversion,
    bench_process_with_conversion
);

#[cfg(not(feature = "threat-hunting"))]
criterion_group!(benches, bench_no_feature);

criterion_main!(benches);
