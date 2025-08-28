//! REST API endpoints for Service Identity Management
//!
//! Provides HTTP endpoints for managing non-human identities,
//! JIT tokens, and monitoring.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    errors::AuthError,
    jit_token_manager::{
        JitTokenManager, TokenResponse,
    },
    non_human_monitoring::{NonHumanIdentityMonitor, NonHumanMetrics},
    service_identity::{
        Environment, IdentityConfig, IdentityType, JitAccessRequest, RequestContext,
        ServiceIdentity, ServiceIdentityManager,
    },
};

/// Register a new service identity
#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterIdentityRequest {
    pub identity_type: IdentityTypeDto,
    pub allowed_scopes: Vec<String>,
    pub allowed_ips: Option<Vec<String>>,
    pub allowed_hours: Option<(u8, u8)>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum IdentityTypeDto {
    ServiceAccount {
        service_name: String,
        environment: String,
        owner_team: String,
    },
    ApiKey {
        client_id: String,
        integration_type: String,
    },
    AiAgent {
        agent_id: String,
        model_type: String,
        capabilities: Vec<String>,
    },
    MachineWorkload {
        workload_id: String,
        orchestrator: String,
        namespace: String,
    },
}

#[derive(Debug, Serialize)]
pub struct RegisterIdentityResponse {
    pub identity_id: Uuid,
    pub max_token_lifetime_seconds: u64,
    pub requires_attestation: bool,
    pub requires_continuous_auth: bool,
    pub api_key: Option<String>, // Only for API key type, contains the unhashed key
}

/// Request JIT token
#[derive(Debug, Deserialize)]
pub struct JitTokenRequest {
    pub identity_id: Uuid,
    pub requested_scopes: Vec<String>,
    pub duration_seconds: Option<u64>,
    pub justification: String,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub attestation_data: Option<HashMap<String, String>>,
}

/// Get identity details
#[derive(Debug, Serialize)]
pub struct IdentityDetailsResponse {
    pub identity: ServiceIdentity,
    pub active_tokens: u32,
    pub last_activity: Option<String>,
    pub risk_score: f32,
    pub baseline_established: bool,
}

/// List identities with filters
#[derive(Debug, Deserialize)]
pub struct ListIdentitiesQuery {
    pub identity_type: Option<String>,
    pub status: Option<String>,
    pub risk_threshold: Option<f32>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Rotate credentials
#[derive(Debug, Serialize)]
pub struct RotateCredentialsResponse {
    pub new_api_key: Option<String>,
    pub rotation_completed_at: String,
    pub tokens_revoked: u32,
}

/// Identity metrics
#[derive(Debug, Serialize)]
pub struct IdentityMetricsResponse {
    pub metrics: NonHumanMetrics,
    pub anomaly_score: f32,
    pub recent_alerts: Vec<SecurityAlertSummary>,
}

#[derive(Debug, Serialize)]
pub struct SecurityAlertSummary {
    pub alert_id: String,
    pub timestamp: String,
    pub severity: String,
    pub description: String,
}

/// API handler state
pub struct ServiceIdentityApiState {
    pub identity_manager: Arc<ServiceIdentityManager>,
    pub jit_manager: Arc<JitTokenManager>,
    pub monitor: Arc<NonHumanIdentityMonitor>,
}

// API Handlers

/// POST /api/v1/identities - Register new service identity
pub async fn register_identity(
    State(state): State<Arc<ServiceIdentityApiState>>,
    Json(request): Json<RegisterIdentityRequest>,
) -> Result<Json<RegisterIdentityResponse>, ApiError> {
    info!("Registering new service identity");

    let identity_type = convert_identity_type(request.identity_type)?;

    let config = IdentityConfig {
        allowed_scopes: request.allowed_scopes.into_iter().collect(),
        allowed_ips: request.allowed_ips,
        allowed_hours: request.allowed_hours,
    };

    let identity = state
        .identity_manager
        .register_identity(identity_type.clone(), config)
        .await
        .map_err(|e| {
            error!("Failed to register identity: {}", e);
            ApiError::InternalError
        })?;

    // Generate API key for API key type
    let api_key = if matches!(identity_type, IdentityType::ApiKey { .. }) {
        Some(generate_secure_api_key())
    } else {
        None
    };

    Ok(Json(RegisterIdentityResponse {
        identity_id: identity.id,
        max_token_lifetime_seconds: identity.max_token_lifetime_seconds,
        requires_attestation: identity.requires_attestation,
        requires_continuous_auth: identity.requires_continuous_auth,
        api_key,
    }))
}

/// POST /api/v1/tokens/jit - Request JIT token
pub async fn request_jit_token(
    State(state): State<Arc<ServiceIdentityApiState>>,
    Json(request): Json<JitTokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    info!("JIT token requested for identity: {}", request.identity_id);

    // Build JIT access request
    let jit_request = JitAccessRequest {
        identity_id: request.identity_id,
        requested_scopes: request.requested_scopes.clone(),
        justification: request.justification.clone(),
        duration_seconds: request.duration_seconds.unwrap_or(300),
        request_context: RequestContext {
            source_ip: request.source_ip.unwrap_or_else(|| "unknown".to_string()),
            user_agent: request.user_agent,
            request_id: Uuid::new_v4().to_string(),
            parent_span_id: None,
            attestation_data: request.attestation_data,
        },
        approval_required: false,
    };

    // Request token from identity manager
    let jit_token = state
        .identity_manager
        .request_jit_access(jit_request)
        .await
        .map_err(|e| {
            warn!("JIT token request failed: {}", e);
            match e {
                AuthError::IdentityNotFound => ApiError::NotFound,
                AuthError::IdentitySuspended => ApiError::Forbidden,
                AuthError::AnomalyDetected => ApiError::TooManyRequests,
                _ => ApiError::InternalError,
            }
        })?;

    // Convert to token response
    let token_response = TokenResponse {
        access_token: format!("jit_{}", jit_token.token_id), // In production, would be properly signed JWT
        token_type: "Bearer".to_string(),
        expires_in: (jit_token.expires_at.timestamp() - jit_token.issued_at.timestamp()) as u64,
        scopes: jit_token.granted_scopes,
        token_id: jit_token.token_id.to_string(),
        refresh_token: None,
        requires_step_up: false,
    };

    Ok(Json(token_response))
}

/// GET /api/v1/identities/:id - Get identity details
pub async fn get_identity(
    State(_state): State<Arc<ServiceIdentityApiState>>,
    Path(_id): Path<Uuid>,
) -> Result<Json<IdentityDetailsResponse>, ApiError> {
    // In production, would fetch from identity manager
    Err(ApiError::NotImplemented)
}

/// GET /api/v1/identities - List identities
pub async fn list_identities(
    State(_state): State<Arc<ServiceIdentityApiState>>,
    Query(_query): Query<ListIdentitiesQuery>,
) -> Result<Json<Vec<ServiceIdentity>>, ApiError> {
    // In production, would query from identity manager with filters
    Err(ApiError::NotImplemented)
}

/// POST /api/v1/identities/:id/rotate - Rotate credentials
pub async fn rotate_credentials(
    State(state): State<Arc<ServiceIdentityApiState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<RotateCredentialsResponse>, ApiError> {
    info!("Rotating credentials for identity: {}", id);

    state
        .identity_manager
        .rotate_credentials(id)
        .await
        .map_err(|e| {
            error!("Failed to rotate credentials: {}", e);
            ApiError::InternalError
        })?;

    let tokens_revoked = state
        .identity_manager
        .revoke_identity_tokens(id)
        .await
        .unwrap_or(0);

    Ok(Json(RotateCredentialsResponse {
        new_api_key: None, // Would generate new key in production
        rotation_completed_at: chrono::Utc::now().to_rfc3339(),
        tokens_revoked,
    }))
}

/// DELETE /api/v1/identities/:id/tokens - Revoke all tokens
pub async fn revoke_tokens(
    State(state): State<Arc<ServiceIdentityApiState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<RevokeTokensResponse>, ApiError> {
    info!("Revoking all tokens for identity: {}", id);

    let count = state
        .identity_manager
        .revoke_identity_tokens(id)
        .await
        .map_err(|e| {
            error!("Failed to revoke tokens: {}", e);
            ApiError::InternalError
        })?;

    Ok(Json(RevokeTokensResponse {
        tokens_revoked: count,
        revoked_at: chrono::Utc::now().to_rfc3339(),
    }))
}

#[derive(Debug, Serialize)]
pub struct RevokeTokensResponse {
    pub tokens_revoked: u32,
    pub revoked_at: String,
}

/// GET /api/v1/identities/:id/metrics - Get identity metrics
pub async fn get_identity_metrics(
    State(_state): State<Arc<ServiceIdentityApiState>>,
    Path(_id): Path<Uuid>,
) -> Result<Json<IdentityMetricsResponse>, ApiError> {
    // In production, would fetch from monitoring system
    Err(ApiError::NotImplemented)
}

/// POST /api/v1/identities/:id/baseline - Establish behavioral baseline
pub async fn establish_baseline(
    State(state): State<Arc<ServiceIdentityApiState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    info!("Establishing baseline for identity: {}", id);

    state.monitor.establish_baseline(id).await.map_err(|e| {
        warn!("Failed to establish baseline: {}", e);
        ApiError::InsufficientData
    })?;

    Ok(StatusCode::NO_CONTENT)
}

// Helper functions

pub fn convert_identity_type(dto: IdentityTypeDto) -> Result<IdentityType, ApiError> {
    match dto {
        IdentityTypeDto::ServiceAccount {
            service_name,
            environment,
            owner_team,
        } => {
            let env = match environment.as_str() {
                "development" => Environment::Development,
                "staging" => Environment::Staging,
                "production" => Environment::Production,
                _ => return Err(ApiError::ValidationError("Invalid environment".to_string())),
            };
            Ok(IdentityType::ServiceAccount {
                service_name,
                environment: env,
                owner_team,
            })
        }
        IdentityTypeDto::ApiKey {
            client_id,
            integration_type,
        } => Ok(IdentityType::ApiKey {
            client_id,
            integration_type,
        }),
        IdentityTypeDto::AiAgent {
            agent_id,
            model_type,
            capabilities,
        } => Ok(IdentityType::AiAgent {
            agent_id,
            model_type,
            capabilities,
        }),
        IdentityTypeDto::MachineWorkload {
            workload_id,
            orchestrator,
            namespace,
        } => Ok(IdentityType::MachineWorkload {
            workload_id,
            orchestrator,
            namespace,
        }),
    }
}

fn generate_secure_api_key() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let key_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    format!(
        "sk_{}",
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&key_bytes)
    )
}

/// API Error types
#[derive(Debug)]
pub enum ApiError {
    NotFound,
    Forbidden,
    TooManyRequests,
    ValidationError(String),
    InsufficientData,
    NotImplemented,
    InternalError,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, "Identity not found"),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "Access denied"),
            ApiError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "Anomaly detected"),
            ApiError::ValidationError(msg) => {
                return (StatusCode::BAD_REQUEST, msg).into_response()
            }
            ApiError::InsufficientData => (
                StatusCode::PRECONDITION_FAILED,
                "Insufficient data for operation",
            ),
            ApiError::NotImplemented => (StatusCode::NOT_IMPLEMENTED, "Not yet implemented"),
            ApiError::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
        };
        (status, message).into_response()
    }
}

/// Configure routes
pub fn configure_routes() -> axum::Router<Arc<ServiceIdentityApiState>> {
    use axum::routing::{delete, get, post};

    axum::Router::new()
        .route("/api/v1/identities", post(register_identity))
        .route("/api/v1/identities", get(list_identities))
        .route("/api/v1/identities/:id", get(get_identity))
        .route("/api/v1/identities/:id/rotate", post(rotate_credentials))
        .route("/api/v1/identities/:id/tokens", delete(revoke_tokens))
        .route("/api/v1/identities/:id/metrics", get(get_identity_metrics))
        .route("/api/v1/identities/:id/baseline", post(establish_baseline))
        .route("/api/v1/tokens/jit", post(request_jit_token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_type_conversion() {
        let dto = IdentityTypeDto::AiAgent {
            agent_id: "test-agent".to_string(),
            model_type: "gpt-4".to_string(),
            capabilities: vec!["read".to_string()],
        };

        let result = convert_identity_type(dto);
        assert!(result.is_ok());
    }

    #[test]
    fn test_api_key_generation() {
        let key = generate_secure_api_key();
        assert!(key.starts_with("sk_"));
        assert!(key.len() > 40);
    }
}
