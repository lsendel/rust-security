# Migration Guide: Upgrading to Enhanced OAuth Security

This guide helps you migrate your existing authentication system to use the new service identity management and JIT token features to prevent OAuth token compromise attacks.

## Overview

The new security features address critical vulnerabilities exposed in the Salesloft Drift breach:
- **Service Identity Management**: Distinguish between human and non-human identities
- **JIT (Just-In-Time) Tokens**: Short-lived, narrowly-scoped tokens
- **Enhanced Monitoring**: Behavioral analysis and anomaly detection
- **Zero Trust Architecture**: Continuous verification of all identities

## Migration Timeline

### Phase 1: Preparation (Week 1)
1. [Audit existing tokens](#audit-existing-tokens)
2. [Identify service accounts](#identify-service-accounts)
3. [Plan migration strategy](#migration-strategy)

### Phase 2: Core Implementation (Weeks 2-3)
1. [Deploy new modules](#deploy-modules)
2. [Configure monitoring](#configure-monitoring)
3. [Migrate critical services](#migrate-services)

### Phase 3: Full Migration (Weeks 4-6)
1. [Migrate remaining services](#migrate-remaining)
2. [Enforce new policies](#enforce-policies)
3. [Monitor and optimize](#monitor-optimize)

## Pre-Migration Assessment

### Audit Existing Tokens

First, identify all active tokens in your system:

```bash
# Check token database for long-lived tokens
sqlite3 tokens.db "
SELECT 
    token_type,
    client_id,
    created_at,
    expires_at,
    (julianday(expires_at) - julianday('now')) * 24 * 60 as minutes_remaining
FROM tokens 
WHERE expires_at > datetime('now')
ORDER BY minutes_remaining DESC
LIMIT 50;
"

# Look for tokens with excessive lifetimes
sqlite3 tokens.db "
SELECT COUNT(*) as count, 
       AVG((julianday(expires_at) - julianday(created_at)) * 24) as avg_hours
FROM tokens 
WHERE expires_at > datetime('now')
GROUP BY token_type;
"
```

### Identify Service Accounts

Catalog all non-human identities:

```sql
-- Find service accounts by usage patterns
SELECT 
    client_id,
    user_agent,
    source_ip,
    COUNT(*) as request_count,
    COUNT(DISTINCT DATE(timestamp)) as active_days
FROM access_logs 
WHERE timestamp > datetime('now', '-30 days')
GROUP BY client_id, user_agent, source_ip
HAVING request_count > 1000  -- High volume indicates automation
ORDER BY request_count DESC;
```

### Migration Strategy

Based on your audit, classify identities:

1. **Critical Services** (migrate first): Payment processing, authentication services
2. **High-Volume APIs** (migrate second): Data processing, integrations
3. **Low-Risk Services** (migrate last): Reporting, monitoring

## Implementation Steps

### Deploy Modules

1. **Update Cargo.toml** dependencies:

```toml
[dependencies]
# Existing dependencies...
uuid = "1.0"
chrono = { version = "0.4", features = ["serde"] }
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
axum = "0.6"
jsonwebtoken = "8.0"

[features]
default = ["service-identity", "jit-tokens", "monitoring"]
service-identity = []
jit-tokens = []
monitoring = []
```

2. **Add to main.rs**:

```rust
use auth_service::{
    service_identity_api::{ServiceIdentityApiState, configure_routes},
    service_identity::ServiceIdentityManager,
    jit_token_manager::JitTokenManager,
    non_human_monitoring::NonHumanIdentityMonitor,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize new components
    let identity_manager = Arc::new(ServiceIdentityManager::new(
        Arc::new(SecurityMonitoringImpl)
    ));
    
    let jit_manager = Arc::new(JitTokenManager::new(
        &env::var("JWT_SECRET")?,
        JitConfig::default(),
        Arc::new(AnomalyDetectorImpl),
    ));
    
    let monitor = Arc::new(NonHumanIdentityMonitor::new(
        NonHumanMonitoringConfig::default(),
        Arc::new(AlertHandlerImpl),
        Arc::new(GeoResolverImpl),
    ));
    
    // Set up API state
    let api_state = Arc::new(ServiceIdentityApiState {
        identity_manager,
        jit_manager,
        monitor,
    });
    
    // Configure routes
    let app = Router::new()
        .merge(configure_routes())
        .with_state(api_state);
    
    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}
```

### Configure Monitoring

1. **Set environment variables**:

```bash
export SECURITY_MONITORING_ENABLED=true
export ANOMALY_DETECTION_SENSITIVITY=0.7
export BASELINE_LEARNING_HOURS=24
export AUTO_SUSPEND_CRITICAL=true
```

2. **Configure Prometheus metrics**:

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'auth-service'
    static_configs:
      - targets: ['auth-service:8080']
    metrics_path: /metrics
    scrape_interval: 10s
```

3. **Set up alerts** (alertmanager.yml):

```yaml
route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'security-team'

receivers:
  - name: 'security-team'
    webhook_configs:
      - url: 'http://slack-webhook-url'
        title: 'Security Alert: {{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
```

### Migrate Services

#### 1. Register Service Identities

For each service account, make a registration request:

```bash
# Register a payment service
curl -X POST http://auth-service:8080/api/v1/identities \
  -H "Content-Type: application/json" \
  -d '{
    "identity_type": {
      "type": "ServiceAccount",
      "service_name": "payment-processor",
      "environment": "production",
      "owner_team": "payments"
    },
    "allowed_scopes": ["payment:read", "payment:write"],
    "allowed_ips": ["10.0.1.0/24"],
    "allowed_hours": [9, 17],
    "metadata": {
      "version": "2.1.0",
      "criticality": "high"
    }
  }'

# Response contains identity_id and security settings
{
  "identity_id": "550e8400-e29b-41d4-a716-446655440000",
  "max_token_lifetime_seconds": 3600,
  "requires_attestation": false,
  "requires_continuous_auth": true,
  "api_key": null
}
```

#### 2. Update Client Code

Replace long-lived tokens with JIT token requests:

```rust
// Before: Long-lived token
pub struct OldClient {
    access_token: String, // Never expires!
}

impl OldClient {
    pub fn new(token: String) -> Self {
        Self { access_token: token }
    }
}

// After: JIT token client
pub struct NewClient {
    identity_id: Uuid,
    auth_service_url: String,
    current_token: Option<TokenInfo>,
}

struct TokenInfo {
    token: String,
    expires_at: DateTime<Utc>,
    scopes: Vec<String>,
}

impl NewClient {
    pub fn new(identity_id: Uuid, auth_service_url: String) -> Self {
        Self {
            identity_id,
            auth_service_url,
            current_token: None,
        }
    }
    
    pub async fn get_token(&mut self, scopes: &[String]) -> Result<String, Error> {
        // Check if current token is valid
        if let Some(token_info) = &self.current_token {
            if token_info.expires_at > Utc::now() + Duration::minutes(2) {
                // Token still valid with 2-minute buffer
                if scopes.iter().all(|s| token_info.scopes.contains(s)) {
                    return Ok(token_info.token.clone());
                }
            }
        }
        
        // Request new JIT token
        let request = JitTokenRequest {
            identity_id: self.identity_id,
            requested_scopes: scopes.to_vec(),
            duration_seconds: Some(900), // 15 minutes
            justification: "API operation".to_string(),
            source_ip: Some(get_local_ip()?),
            user_agent: Some("service-client/2.0".to_string()),
            attestation_data: None,
        };
        
        let response: TokenResponse = reqwest::Client::new()
            .post(&format!("{}/api/v1/tokens/jit", self.auth_service_url))
            .json(&request)
            .send()
            .await?
            .json()
            .await?;
        
        self.current_token = Some(TokenInfo {
            token: response.access_token.clone(),
            expires_at: Utc::now() + Duration::seconds(response.expires_in as i64),
            scopes: response.scopes,
        });
        
        Ok(response.access_token)
    }
    
    pub async fn api_call(&mut self, endpoint: &str, scopes: &[String]) -> Result<Response, Error> {
        let token = self.get_token(scopes).await?;
        
        reqwest::Client::new()
            .get(endpoint)
            .bearer_auth(token)
            .send()
            .await
    }
}
```

#### 3. Establish Baselines

After migration, let services run for 24 hours to establish behavioral baselines:

```bash
# Trigger baseline establishment
curl -X POST http://auth-service:8080/api/v1/identities/{identity_id}/baseline
```

## Configuration Examples

### Production Configuration

```toml
# config/production.toml
[security]
jwt_access_token_ttl_seconds = 300  # 5 minutes
jwt_refresh_token_ttl_seconds = 3600  # 1 hour
auto_revoke_on_anomaly = true
require_continuous_auth = true

[monitoring]
enable_baseline_learning = true
baseline_learning_hours = 48  # Longer for production
anomaly_sensitivity = 0.8
enable_geo_anomaly = true
enable_temporal_analysis = true

[identity_types.service_account]
max_token_lifetime_seconds = 3600  # 1 hour
requires_attestation = false
requires_continuous_auth = true

[identity_types.ai_agent]
max_token_lifetime_seconds = 300  # 5 minutes
requires_attestation = true
requires_continuous_auth = true

[identity_types.api_key]
max_token_lifetime_seconds = 1800  # 30 minutes
requires_attestation = false
requires_continuous_auth = false
```

### Development Configuration

```toml
# config/development.toml
[security]
jwt_access_token_ttl_seconds = 900  # 15 minutes (more lenient)
jwt_refresh_token_ttl_seconds = 7200  # 2 hours
auto_revoke_on_anomaly = false  # Don't auto-suspend in dev
require_continuous_auth = false

[monitoring]
enable_baseline_learning = true
baseline_learning_hours = 4  # Shorter for faster dev cycles
anomaly_sensitivity = 0.5  # Less sensitive
enable_geo_anomaly = false  # Local development
enable_temporal_analysis = false

[identity_types.service_account]
max_token_lifetime_seconds = 7200  # 2 hours
requires_attestation = false
requires_continuous_auth = false
```

## Database Migration Scripts

### Add New Tables

```sql
-- Service identities
CREATE TABLE service_identities (
    id UUID PRIMARY KEY,
    identity_type TEXT NOT NULL,
    identity_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_authenticated TIMESTAMP WITH TIME ZONE,
    last_rotated TIMESTAMP WITH TIME ZONE,
    max_token_lifetime_seconds INTEGER NOT NULL,
    allowed_scopes TEXT[] NOT NULL,
    allowed_ips TEXT[],
    allowed_hours INTEGER[],
    risk_score FLOAT DEFAULT 0.0,
    requires_attestation BOOLEAN DEFAULT FALSE,
    requires_continuous_auth BOOLEAN DEFAULT FALSE,
    baseline_established BOOLEAN DEFAULT FALSE,
    baseline_metrics JSONB,
    status TEXT DEFAULT 'active',
    suspension_reason TEXT
);

-- JIT tokens
CREATE TABLE jit_tokens (
    token_id UUID PRIMARY KEY,
    identity_id UUID REFERENCES service_identities(id),
    granted_scopes TEXT[] NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    request_context JSONB NOT NULL,
    revocable BOOLEAN DEFAULT TRUE,
    usage_count INTEGER DEFAULT 0,
    max_usage INTEGER
);

-- Activity logs
CREATE TABLE identity_activity_logs (
    id BIGSERIAL PRIMARY KEY,
    identity_id UUID REFERENCES service_identities(id),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    action TEXT NOT NULL,
    endpoint TEXT,
    source_ip INET,
    response_code INTEGER,
    request_size BIGINT,
    response_size BIGINT,
    latency_ms BIGINT
);

-- Create indexes
CREATE INDEX idx_service_identities_type ON service_identities(identity_type);
CREATE INDEX idx_service_identities_status ON service_identities(status);
CREATE INDEX idx_jit_tokens_identity_id ON jit_tokens(identity_id);
CREATE INDEX idx_jit_tokens_expires_at ON jit_tokens(expires_at);
CREATE INDEX idx_activity_logs_identity_id ON identity_activity_logs(identity_id);
CREATE INDEX idx_activity_logs_timestamp ON identity_activity_logs(timestamp);
```

### Migrate Existing Data

```sql
-- Migrate existing OAuth clients to service identities
INSERT INTO service_identities (
    id,
    identity_type,
    identity_data,
    created_at,
    max_token_lifetime_seconds,
    allowed_scopes,
    requires_continuous_auth
)
SELECT 
    gen_random_uuid(),
    'ServiceAccount',
    jsonb_build_object(
        'service_name', client_id,
        'environment', 'production',
        'owner_team', 'legacy'
    ),
    created_at,
    3600, -- 1 hour max
    string_to_array(scope, ' '),
    TRUE
FROM oauth_clients
WHERE client_type = 'service_account';

-- Mark old tokens for revocation
UPDATE oauth_tokens 
SET expires_at = NOW() + INTERVAL '24 hours'  -- Grace period
WHERE expires_at > NOW() + INTERVAL '24 hours';
```

## Monitoring and Alerting

### Key Metrics to Monitor

```promql
# Token issuance rate
rate(jit_tokens_issued_total[5m])

# Average token lifetime
avg(jit_token_lifetime_seconds)

# Anomaly detection rate
rate(behavioral_anomalies_detected_total[1h])

# Token revocation rate
rate(tokens_revoked_total[5m])

# Service account errors
rate(service_account_auth_failures_total[5m]) by (identity_type)
```

### Critical Alerts

```yaml
# High token revocation rate
- alert: HighTokenRevocationRate
  expr: rate(tokens_revoked_total[5m]) > 10
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "High token revocation rate detected"
    description: "Token revocation rate is {{ $value }} tokens/minute"

# Behavioral anomaly spike
- alert: BehavioralAnomalySpike
  expr: rate(behavioral_anomalies_detected_total[5m]) > 5
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "Behavioral anomaly detection spike"
    description: "Anomaly detection rate: {{ $value }} anomalies/minute"

# Service account compromise indicators
- alert: ServiceAccountCompromise
  expr: |
    (
      rate(service_account_auth_failures_total[1m]) > 5
    ) and (
      rate(service_account_new_ip_access[5m]) > 0
    )
  for: 30s
  labels:
    severity: critical
  annotations:
    summary: "Potential service account compromise"
    description: "Service account showing signs of compromise"
```

## Rollback Plan

If issues arise during migration:

### Immediate Rollback (< 1 hour)

```bash
# 1. Stop new JIT token issuance
kubectl set env deployment/auth-service JIT_TOKENS_ENABLED=false

# 2. Re-enable long-lived tokens temporarily
kubectl set env deployment/auth-service LEGACY_TOKENS_ENABLED=true

# 3. Restore from backup if needed
kubectl apply -f backup/pre-migration-deployment.yaml
```

### Partial Rollback (specific services)

```bash
# Revert specific service to old authentication
curl -X POST http://auth-service:8080/api/v1/identities/{identity_id}/suspend
```

## Testing Strategy

### Pre-Migration Testing

```bash
# Test JIT token flow
./scripts/test-jit-tokens.sh

# Test monitoring integration
./scripts/test-monitoring.sh

# Load test new endpoints
./scripts/load-test-identity-api.sh
```

### Post-Migration Validation

```bash
# Verify all services are using JIT tokens
./scripts/validate-migration.sh

# Check baseline establishment
./scripts/check-baselines.sh

# Verify monitoring is working
./scripts/test-alert-generation.sh
```

## Troubleshooting

### Common Issues

#### 1. High Token Request Rate
**Symptom**: Services frequently requesting new tokens
**Cause**: Token lifetime too short for service usage pattern
**Solution**: 
```bash
# Increase token lifetime for specific identity
curl -X PATCH http://auth-service:8080/api/v1/identities/{id} \
  -d '{"max_token_lifetime_seconds": 1800}'
```

#### 2. False Positive Anomalies
**Symptom**: Legitimate services being flagged as anomalous
**Cause**: Insufficient baseline data or overly sensitive detection
**Solution**:
```bash
# Extend baseline learning period
curl -X POST http://auth-service:8080/api/v1/identities/{id}/baseline-reset
```

#### 3. Geographic Anomalies for Remote Services
**Symptom**: Services deployed in multiple regions triggering geo alerts
**Solution**: Update allowed IPs or disable geo-anomaly for specific identities

### Debug Commands

```bash
# Check identity status
curl http://auth-service:8080/api/v1/identities/{id}

# View recent activity
curl http://auth-service:8080/api/v1/identities/{id}/metrics

# Check active alerts
curl http://auth-service:8080/api/v1/monitoring/alerts

# View token usage
curl http://auth-service:8080/api/v1/tokens/usage/{token_id}
```

## Success Metrics

Track these KPIs to measure migration success:

- **Security**: 
  - Average token lifetime reduced to < 1 hour
  - 100% of service accounts using JIT tokens
  - Zero long-lived tokens (>24 hours) in production

- **Reliability**:
  - < 1% increase in authentication errors
  - < 100ms additional latency for token requests
  - 99.9% uptime during migration

- **Monitoring**:
  - 95% of identities have established baselines
  - < 5% false positive rate for anomaly detection
  - Alert response time < 5 minutes

## Support and Maintenance

### Team Responsibilities

- **Security Team**: Monitor alerts, investigate anomalies, policy updates
- **Platform Team**: Maintain auth service, monitor performance, handle scaling
- **Development Teams**: Migrate client applications, report issues, update documentation

### Regular Maintenance Tasks

- **Weekly**: Review anomaly detection accuracy, adjust thresholds
- **Monthly**: Audit service identity permissions, clean up unused identities  
- **Quarterly**: Security assessment, penetration testing, policy review

## Conclusion

This migration significantly enhances your OAuth security posture by:
- Eliminating long-lived token risks
- Providing continuous monitoring of non-human identities
- Enabling rapid response to suspicious activities
- Implementing zero-trust principles

The phased approach ensures minimal disruption while maximizing security benefits. Monitor the key metrics and be prepared to adjust configurations based on your specific usage patterns.