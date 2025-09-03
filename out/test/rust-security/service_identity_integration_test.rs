//! Integration tests for Service Identity Management
//!
//! Tests the complete flow of service identity registration,
//! JIT token issuance, and security monitoring.

use auth_service::infrastructure::security::security_monitoring::SecurityAlert;
use std::sync::Arc;
use uuid::Uuid;

use auth_service::{
    jit_token_manager::{JitConfig, JitTokenManager, TokenBindingContext},
    non_human_monitoring::{NonHumanIdentityMonitor, NonHumanMonitoringConfig},
    // security_monitoring::SecurityAlert, // Module not available
    service_identity::{
        BehavioralBaseline, Environment, IdentityConfig, IdentityStatus, IdentityType,
        JitAccessRequest, RequestContext, ServiceIdentity, ServiceIdentityManager,
    },
    service_identity_api::{convert_identity_type, *},
};

use async_trait::async_trait;

// Mock implementations for testing

struct MockSecurityMonitoring;

#[async_trait]
impl auth_service::service_identity::SecurityMonitoring for MockSecurityMonitoring {
    async fn log_authentication(&self, _identity: &ServiceIdentity, _success: bool) {}

    async fn check_anomaly(&self, _identity: &ServiceIdentity, _context: &RequestContext) -> bool {
        // Return false for normal tests, true for anomaly tests
        false
    }

    async fn raise_alert(&self, _alert: SecurityAlert) {}

    async fn update_baseline(&self, _identity_id: Uuid, _metrics: BehavioralBaseline) {}
}

#[allow(dead_code)]
struct MockAnomalyDetector;

#[async_trait]
impl auth_service::jit_token_manager::AnomalyDetector for MockAnomalyDetector {
    async fn check_token_usage(
        &self,
        _usage: &auth_service::jit_token_manager::TokenUsage,
    ) -> bool {
        false
    }

    async fn check_request_pattern(
        &self,
        _identity: &ServiceIdentity,
        _requests: &[auth_service::jit_token_manager::RequestInfo],
    ) -> bool {
        false
    }

    async fn calculate_risk_score(
        &self,
        _identity: &ServiceIdentity,
        _context: &TokenBindingContext,
    ) -> f32 {
        0.0
    }
}

struct MockAlertHandler;

#[async_trait]
impl auth_service::non_human_monitoring::AlertHandler for MockAlertHandler {
    async fn send_alert(&self, _alert: SecurityAlert) -> Result<(), auth_service::AppError> {
        Ok(())
    }

    async fn get_alert_history(&self, _identity_id: Uuid) -> Vec<SecurityAlert> {
        vec![]
    }
}

struct MockGeoResolver;

#[async_trait]
impl auth_service::non_human_monitoring::GeoResolver for MockGeoResolver {
    async fn resolve_country(&self, _ip: &str) -> Option<String> {
        Some("US".to_string())
    }

    async fn resolve_city(&self, _ip: &str) -> Option<String> {
        Some("New York".to_string())
    }

    async fn is_suspicious_location(&self, ip: &str) -> bool {
        // Mark private IPs as suspicious for testing
        ip.starts_with("192.168")
    }
}

// Test fixtures

fn create_test_identity_manager() -> ServiceIdentityManager {
    ServiceIdentityManager::new(Arc::new(MockSecurityMonitoring))
}

#[allow(dead_code)]
fn create_test_jit_manager() -> JitTokenManager {
    JitTokenManager::new(
        "test-secret-key-for-jwt-signing",
        JitConfig::default(),
        Arc::new(MockAnomalyDetector),
    )
}

fn create_test_monitor() -> NonHumanIdentityMonitor {
    NonHumanIdentityMonitor::new(
        NonHumanMonitoringConfig::default(),
        Arc::new(MockAlertHandler),
        Arc::new(MockGeoResolver),
    )
}

// Integration Tests

#[tokio::test]
async fn test_service_account_registration_flow() {
    let manager = create_test_identity_manager();

    // Register a production service account
    let identity_type = IdentityType::ServiceAccount {
        service_name: "payment-processor".to_string(),
        environment: Environment::Production,
        owner_team: "payments".to_string(),
    };

    let config = IdentityConfig {
        allowed_scopes: ["payment:read", "payment:write"]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        allowed_ips: Some(vec!["10.0.1.0/24".to_string()]),
        allowed_hours: Some((9, 17)), // Business hours
    };

    let identity = manager
        .register_identity(identity_type, config)
        .await
        .unwrap();

    // Verify identity properties
    assert_eq!(identity.status, IdentityStatus::Active);
    assert_eq!(identity.max_token_lifetime_seconds, 3600); // 1 hour for prod services
    assert!(identity.requires_continuous_auth);
    assert!(!identity.requires_attestation);
    assert!(identity.allowed_scopes.contains("payment:read"));
    assert!(identity.allowed_scopes.contains("payment:write"));
}

#[tokio::test]
async fn test_ai_agent_registration_with_strict_limits() {
    let manager = create_test_identity_manager();

    // Register an AI agent
    let identity_type = IdentityType::AiAgent {
        agent_id: "claude-agent-001".to_string(),
        model_type: "claude-3-opus".to_string(),
        capabilities: vec!["text-analysis".to_string(), "data-extraction".to_string()],
    };

    let config = IdentityConfig {
        allowed_scopes: std::iter::once("read:documents".to_string()).collect(),
        allowed_ips: None,
        allowed_hours: None,
    };

    let identity = manager
        .register_identity(identity_type, config)
        .await
        .unwrap();

    // AI agents should have the most restrictive settings
    assert_eq!(identity.max_token_lifetime_seconds, 300); // 5 minutes max
    assert!(identity.requires_attestation);
    assert!(identity.requires_continuous_auth);
    assert_eq!(identity.allowed_scopes.len(), 1);
}

#[tokio::test]
async fn test_jit_token_request_flow() {
    let manager = create_test_identity_manager();

    // Register a service account
    let identity_type = IdentityType::ServiceAccount {
        service_name: "data-processor".to_string(),
        environment: Environment::Staging,
        owner_team: "data".to_string(),
    };

    let config = IdentityConfig {
        allowed_scopes: ["data:read", "data:process"]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        allowed_ips: None,
        allowed_hours: None,
    };

    let identity = manager
        .register_identity(identity_type, config)
        .await
        .unwrap();

    // Request JIT token
    let jit_request = JitAccessRequest {
        identity_id: identity.id,
        requested_scopes: vec!["data:read".to_string()],
        justification: "Processing daily batch job".to_string(),
        duration_seconds: 1800, // 30 minutes
        request_context: RequestContext {
            source_ip: "10.0.1.100".to_string(),
            user_agent: Some("data-processor/1.0".to_string()),
            request_id: "req-123".to_string(),
            parent_span_id: None,
            attestation_data: None,
        },
        approval_required: false,
    };

    let token = manager.request_jit_access(jit_request).await.unwrap();

    // Verify token properties
    assert_eq!(token.identity_id, identity.id);
    assert_eq!(token.granted_scopes, vec!["data:read"]);
    assert!(token.expires_at > token.issued_at);
    assert!(token.revocable);
}

#[tokio::test]
async fn test_jit_token_scope_filtering() {
    let manager = create_test_identity_manager();

    // Register identity with limited scopes
    let identity_type = IdentityType::ApiKey {
        client_id: "external-partner".to_string(),
        integration_type: "webhook".to_string(),
    };

    let config = IdentityConfig {
        allowed_scopes: std::iter::once("webhook:receive".to_string()).collect(),
        allowed_ips: None,
        allowed_hours: None,
    };

    let identity = manager
        .register_identity(identity_type, config)
        .await
        .unwrap();

    // Request token with broader scopes than allowed
    let jit_request = JitAccessRequest {
        identity_id: identity.id,
        requested_scopes: vec![
            "webhook:receive".to_string(),
            "admin:delete".to_string(), // Not allowed
            "user:create".to_string(),  // Not allowed
        ],
        justification: "Webhook processing".to_string(),
        duration_seconds: 300,
        request_context: RequestContext {
            source_ip: "203.0.113.1".to_string(),
            user_agent: None,
            request_id: "req-456".to_string(),
            parent_span_id: None,
            attestation_data: None,
        },
        approval_required: false,
    };

    let token = manager.request_jit_access(jit_request).await.unwrap();

    // Should only grant allowed scopes
    assert_eq!(token.granted_scopes, vec!["webhook:receive"]);
}

#[tokio::test]
async fn test_token_lifetime_enforcement() {
    let manager = create_test_identity_manager();

    // Register AI agent (shortest lifetime)
    let identity_type = IdentityType::AiAgent {
        agent_id: "test-agent".to_string(),
        model_type: "gpt-4".to_string(),
        capabilities: vec!["analysis".to_string()],
    };

    let config = IdentityConfig {
        allowed_scopes: std::iter::once("read:data".to_string()).collect(),
        allowed_ips: None,
        allowed_hours: None,
    };

    let identity = manager
        .register_identity(identity_type, config)
        .await
        .unwrap();

    // Request token with longer duration than allowed
    let jit_request = JitAccessRequest {
        identity_id: identity.id,
        requested_scopes: vec!["read:data".to_string()],
        justification: "Data analysis task".to_string(),
        duration_seconds: 3600, // Request 1 hour
        request_context: RequestContext {
            source_ip: "127.0.0.1".to_string(),
            user_agent: Some("ai-agent/1.0".to_string()),
            request_id: "req-789".to_string(),
            parent_span_id: None,
            attestation_data: None,
        },
        approval_required: false,
    };

    let token = manager.request_jit_access(jit_request).await.unwrap();

    // Should be limited to AI agent max (5 minutes = 300 seconds)
    let actual_lifetime: u64 = (token.expires_at - token.issued_at)
        .num_seconds()
        .try_into()
        .unwrap_or(0);
    assert_eq!(actual_lifetime, 300);
}

#[tokio::test]
async fn test_behavioral_monitoring_integration() {
    let monitor = create_test_monitor();

    let identity_id = Uuid::new_v4();
    let context = RequestContext {
        source_ip: "10.0.1.50".to_string(),
        user_agent: Some("service-client/2.1".to_string()),
        request_id: "req-monitoring".to_string(),
        parent_span_id: None,
        attestation_data: None,
    };

    // Simulate multiple API requests to establish pattern
    for i in 0..50 {
        monitor
            .log_request(identity_id, "/api/v1/data", &context, 200, 1024, 2048, 100)
            .await
            .unwrap();

        // Add some variation
        if i % 5 == 0 {
            monitor
                .log_request(identity_id, "/api/v1/status", &context, 200, 512, 1024, 50)
                .await
                .unwrap();
        }
    }

    // Establish baseline
    let baseline = monitor.establish_baseline(identity_id).await.unwrap();

    // Verify baseline was established
    assert!(baseline.confidence_score > 0.0);
    assert!(!baseline.common_endpoints.is_empty());
    assert!(baseline.avg_requests_per_minute > 0.0);
}

#[tokio::test]
async fn test_anomaly_detection_and_response() {
    let monitor = create_test_monitor();

    let identity = ServiceIdentity {
        id: Uuid::new_v4(),
        identity_type: IdentityType::ServiceAccount {
            service_name: "test-service".to_string(),
            environment: Environment::Production,
            owner_team: "test".to_string(),
        },
        created_at: chrono::Utc::now(),
        last_authenticated: None,
        last_rotated: None,
        max_token_lifetime_seconds: 3600,
        allowed_scopes: std::iter::once("test:read".to_string()).collect(),
        allowed_ips: None,
        allowed_hours: None,
        risk_score: 0.0,
        requires_attestation: false,
        requires_continuous_auth: true,
        baseline_established: true,
        baseline_metrics: Some(BehavioralBaseline {
            avg_requests_per_minute: 5.0,
            common_endpoints: vec!["/api/v1/normal".to_string()],
            typical_request_sizes: (1000, 2000),
            typical_hours: vec![9, 10, 11, 14, 15, 16],
            typical_source_ips: std::iter::once("10.0.1.100".to_string()).collect(),
            established_at: chrono::Utc::now() - chrono::Duration::hours(24),
            confidence_score: 0.8,
        }),
        status: IdentityStatus::Active,
        suspension_reason: None,
    };

    // Test geographic anomaly detection
    let suspicious_context = RequestContext {
        source_ip: "192.168.1.1".to_string(), // MockGeoResolver marks this as suspicious
        user_agent: Some("normal-agent".to_string()),
        request_id: "req-suspicious".to_string(),
        parent_span_id: None,
        attestation_data: None,
    };

    let risk_score = monitor
        .calculate_anomaly_score(&identity, &suspicious_context)
        .await;
    assert!(risk_score > 0.0, "Should detect geographic anomaly");
}

#[tokio::test]
async fn test_token_revocation_flow() {
    let manager = create_test_identity_manager();

    // Register identity
    let identity_type = IdentityType::ServiceAccount {
        service_name: "test-service".to_string(),
        environment: Environment::Development,
        owner_team: "test".to_string(),
    };

    let config = IdentityConfig {
        allowed_scopes: std::iter::once("test:read".to_string()).collect(),
        allowed_ips: None,
        allowed_hours: None,
    };

    let identity = manager
        .register_identity(identity_type, config)
        .await
        .unwrap();

    // Issue some tokens
    for i in 0..3 {
        let jit_request = JitAccessRequest {
            identity_id: identity.id,
            requested_scopes: vec!["test:read".to_string()],
            justification: format!("Test request {i}"),
            duration_seconds: 600,
            request_context: RequestContext {
                source_ip: "10.0.1.1".to_string(),
                user_agent: Some("test-client".to_string()),
                request_id: format!("req-{i}"),
                parent_span_id: None,
                attestation_data: None,
            },
            approval_required: false,
        };

        manager.request_jit_access(jit_request).await.unwrap();
    }

    // Revoke all tokens for the identity
    let revoked_count = manager.revoke_identity_tokens(identity.id).await.unwrap();

    // Should have revoked all 3 tokens
    assert_eq!(revoked_count, 3);
}

#[tokio::test]
async fn test_api_endpoint_registration() {
    // Test the API endpoint data structures
    let request = RegisterIdentityRequest {
        identity_type: IdentityTypeDto::ServiceAccount {
            service_name: "test-service".to_string(),
            environment: "production".to_string(),
            owner_team: "platform".to_string(),
        },
        allowed_scopes: vec!["read:data".to_string(), "write:logs".to_string()],
        allowed_ips: Some(vec!["10.0.0.0/8".to_string()]),
        allowed_hours: Some((8, 18)),
        metadata: Some(std::iter::once(("version".to_string(), "1.0".to_string())).collect()),
    };

    // Verify conversion works
    let identity_type = convert_identity_type(request.identity_type).unwrap();

    match identity_type {
        IdentityType::ServiceAccount {
            service_name,
            environment,
            owner_team,
        } => {
            assert_eq!(service_name, "test-service");
            assert_eq!(environment, Environment::Production);
            assert_eq!(owner_team, "platform");
        }
        _ => panic!("Wrong identity type"),
    }
}

#[tokio::test]
async fn test_jit_token_api_request() {
    let request = JitTokenRequest {
        identity_id: Uuid::new_v4(),
        requested_scopes: vec!["read:data".to_string()],
        duration_seconds: Some(900),
        justification: "Scheduled data processing".to_string(),
        source_ip: Some("10.0.1.50".to_string()),
        user_agent: Some("data-processor/2.0".to_string()),
        attestation_data: Some(
            std::iter::once(("workload_id".to_string(), "pod-123".to_string())).collect(),
        ),
    };

    // Verify structure is correct
    assert_eq!(request.requested_scopes.len(), 1);
    assert_eq!(request.duration_seconds.unwrap(), 900);
    assert!(request.attestation_data.is_some());
}

// Performance test
#[tokio::test]
async fn test_high_volume_token_requests() {
    let manager = create_test_identity_manager();

    // Register a service account
    let identity_type = IdentityType::ServiceAccount {
        service_name: "high-volume-service".to_string(),
        environment: Environment::Staging,
        owner_team: "performance".to_string(),
    };

    let config = IdentityConfig {
        allowed_scopes: std::iter::once("api:call".to_string()).collect(),
        allowed_ips: None,
        allowed_hours: None,
    };

    let identity = manager
        .register_identity(identity_type, config)
        .await
        .unwrap();

    // Issue many tokens concurrently
    let mut handles = Vec::new();

    for i in 0..100 {
        let manager = manager.clone();
        let identity_id = identity.id;

        let handle: tokio::task::JoinHandle<
            Result<auth_service::service_identity::JitToken, auth_service::AppError>,
        > = tokio::spawn(async move {
            let jit_request = JitAccessRequest {
                identity_id,
                requested_scopes: vec!["api:call".to_string()],
                justification: format!("Bulk request {i}"),
                duration_seconds: 300,
                request_context: RequestContext {
                    source_ip: "10.0.1.100".to_string(),
                    user_agent: Some("bulk-client/1.0".to_string()),
                    request_id: format!("bulk-req-{i}"),
                    parent_span_id: None,
                    attestation_data: None,
                },
                approval_required: false,
            };

            manager.request_jit_access(jit_request).await
        });

        handles.push(handle);
    }

    // Wait for all requests to complete
    let results = futures::future::join_all(handles).await;

    // All should succeed
    let success_count = results.into_iter().flat_map(|r| r.unwrap()).count();

    assert_eq!(success_count, 100, "All token requests should succeed");
}
