//! Service contracts and interface definitions

use crate::{errors::ContractError, ApiVersion, RequestContext};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Base trait for all service contracts
#[async_trait]
pub trait ServiceContract {
    /// Service name
    fn service_name(&self) -> &str;

    /// Supported API versions
    fn supported_versions(&self) -> Vec<ApiVersion>;

    /// Health check endpoint
    async fn health_check(&self, ctx: &RequestContext) -> Result<HealthStatus, ContractError>;

    /// Service information
    fn service_info(&self) -> ServiceInfo;
}

/// Service health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: HealthState,
    pub timestamp: DateTime<Utc>,
    pub version: ApiVersion,
    pub dependencies: HashMap<String, DependencyHealth>,
    pub metrics: Option<HealthMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyHealth {
    pub name: String,
    pub status: HealthState,
    pub response_time_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f64,
    pub active_connections: u32,
    pub requests_per_second: f64,
}

/// Service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: ApiVersion,
    pub description: String,
    pub endpoints: Vec<EndpointInfo>,
    pub dependencies: Vec<String>,
    pub contact: ContactInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub path: String,
    pub method: String,
    pub description: String,
    pub version: ApiVersion,
    pub deprecated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    pub team: String,
    pub email: String,
    pub documentation: String,
}

/// Authentication service contract
#[async_trait]
pub trait AuthServiceContract: ServiceContract {
    /// Authenticate user credentials
    async fn authenticate(
        &self,
        ctx: &RequestContext,
        request: AuthenticationRequest,
    ) -> Result<AuthenticationResponse, ContractError>;

    /// Issue access token
    async fn issue_token(
        &self,
        ctx: &RequestContext,
        request: TokenRequest,
    ) -> Result<TokenResponse, ContractError>;

    /// Validate token
    async fn validate_token(
        &self,
        ctx: &RequestContext,
        token: String,
    ) -> Result<TokenValidationResponse, ContractError>;

    /// Refresh token
    async fn refresh_token(
        &self,
        ctx: &RequestContext,
        refresh_token: String,
    ) -> Result<TokenResponse, ContractError>;

    /// Revoke token
    async fn revoke_token(&self, ctx: &RequestContext, token: String) -> Result<(), ContractError>;

    /// Get user profile
    async fn get_user_profile(
        &self,
        ctx: &RequestContext,
        user_id: Uuid,
    ) -> Result<UserProfile, ContractError>;

    /// Update user profile
    async fn update_user_profile(
        &self,
        ctx: &RequestContext,
        user_id: Uuid,
        profile: UserProfileUpdate,
    ) -> Result<UserProfile, ContractError>;
}

/// Policy service contract
#[async_trait]
pub trait PolicyServiceContract: ServiceContract {
    /// Evaluate policy
    async fn evaluate_policy(
        &self,
        ctx: &RequestContext,
        request: PolicyEvaluationRequest,
    ) -> Result<PolicyEvaluationResponse, ContractError>;

    /// Create policy
    async fn create_policy(
        &self,
        ctx: &RequestContext,
        policy: PolicyDefinition,
    ) -> Result<Policy, ContractError>;

    /// Get policy
    async fn get_policy(
        &self,
        ctx: &RequestContext,
        policy_id: Uuid,
    ) -> Result<Policy, ContractError>;

    /// Update policy
    async fn update_policy(
        &self,
        ctx: &RequestContext,
        policy_id: Uuid,
        policy: PolicyDefinition,
    ) -> Result<Policy, ContractError>;

    /// Delete policy
    async fn delete_policy(
        &self,
        ctx: &RequestContext,
        policy_id: Uuid,
    ) -> Result<(), ContractError>;

    /// List policies
    async fn list_policies(
        &self,
        ctx: &RequestContext,
        filter: PolicyFilter,
    ) -> Result<PolicyList, ContractError>;
}

// ============================================================================
// Authentication Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    pub method: AuthenticationMethod,
    pub credentials: AuthenticationCredentials,
    pub client_info: ClientInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationMethod {
    Password,
    OAuth,
    Saml,
    MultiFactorAuthentication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthenticationCredentials {
    Password { username: String, password: String },
    OAuth { code: String, redirect_uri: String },
    Saml { assertion: String },
    Mfa { token: String, factor: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub client_id: String,
    pub user_agent: String,
    pub ip_address: String,
    pub device_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    pub success: bool,
    pub user_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub token: Option<String>,
    pub error: Option<AuthenticationError>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationError {
    pub code: String,
    pub message: String,
    pub retry_after: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: GrantType,
    pub client_id: String,
    pub scope: Vec<String>,
    pub subject: Option<Uuid>,
    pub audience: Option<String>,
    pub expires_in: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
    DeviceCode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenValidationResponse {
    pub valid: bool,
    pub user_id: Option<Uuid>,
    pub client_id: Option<String>,
    pub scope: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfileUpdate {
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
}

// ============================================================================
// Policy Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationRequest {
    pub policy_id: Option<Uuid>,
    pub policy_set: Option<String>,
    pub principal: Principal,
    pub action: Action,
    pub resource: Resource,
    pub context: PolicyContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: Uuid,
    pub type_: PrincipalType,
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrincipalType {
    User,
    Service,
    Group,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub name: String,
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub type_: String,
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub environment: HashMap<String, serde_json::Value>,
    pub request_time: DateTime<Utc>,
    pub client_info: Option<ClientInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResponse {
    pub decision: PolicyDecision,
    pub reason: String,
    pub policies_evaluated: Vec<Uuid>,
    pub obligations: Vec<PolicyObligation>,
    pub advice: Vec<PolicyAdvice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyDecision {
    Permit,
    Deny,
    NotApplicable,
    Indeterminate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyObligation {
    pub id: String,
    pub action: String,
    pub parameters: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAdvice {
    pub id: String,
    pub message: String,
    pub parameters: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefinition {
    pub name: String,
    pub description: String,
    pub version: String,
    pub policy_language: PolicyLanguage,
    pub content: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyLanguage {
    Cedar,
    Xacml,
    Opa,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub definition: PolicyDefinition,
    pub status: PolicyStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyStatus {
    Draft,
    Active,
    Inactive,
    Deprecated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFilter {
    pub name: Option<String>,
    pub status: Option<PolicyStatus>,
    pub language: Option<PolicyLanguage>,
    pub created_by: Option<Uuid>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyList {
    pub policies: Vec<Policy>,
    pub total_count: u64,
    pub has_more: bool,
}

// ============================================================================
// Service Separation and Ownership
// ============================================================================

/// Service ownership and responsibility matrix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceOwnership {
    pub auth_service_responsibilities: Vec<String>,
    pub policy_service_responsibilities: Vec<String>,
    pub shared_responsibilities: Vec<String>,
    pub data_ownership: DataOwnershipMatrix,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataOwnershipMatrix {
    pub auth_service_data: Vec<String>,
    pub policy_service_data: Vec<String>,
    pub shared_data: Vec<String>,
}

impl Default for ServiceOwnership {
    fn default() -> Self {
        Self {
            auth_service_responsibilities: vec![
                "User authentication".to_string(),
                "Token issuance and validation".to_string(),
                "Session management".to_string(),
                "User profile management".to_string(),
                "Multi-factor authentication".to_string(),
                "Password policy enforcement".to_string(),
                "Authentication audit logging".to_string(),
            ],
            policy_service_responsibilities: vec![
                "Policy evaluation".to_string(),
                "Policy definition management".to_string(),
                "Authorization decisions".to_string(),
                "Policy version control".to_string(),
                "Policy conflict resolution".to_string(),
                "Authorization audit logging".to_string(),
                "Policy compliance reporting".to_string(),
            ],
            shared_responsibilities: vec![
                "Request context propagation".to_string(),
                "Distributed tracing".to_string(),
                "Rate limiting".to_string(),
                "Security monitoring".to_string(),
                "Error handling".to_string(),
            ],
            data_ownership: DataOwnershipMatrix {
                auth_service_data: vec![
                    "User credentials".to_string(),
                    "User profiles".to_string(),
                    "Authentication sessions".to_string(),
                    "OAuth tokens".to_string(),
                    "MFA tokens".to_string(),
                ],
                policy_service_data: vec![
                    "Policy definitions".to_string(),
                    "Policy evaluation results".to_string(),
                    "Authorization cache".to_string(),
                    "Policy metadata".to_string(),
                ],
                shared_data: vec![
                    "Audit logs".to_string(),
                    "Rate limiting counters".to_string(),
                    "System configuration".to_string(),
                ],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_serialization() {
        let health = HealthStatus {
            status: HealthState::Healthy,
            timestamp: Utc::now(),
            version: ApiVersion::new(1, 0, 0),
            dependencies: HashMap::new(),
            metrics: None,
        };

        let json = serde_json::to_string(&health).unwrap();
        let parsed: HealthStatus = serde_json::from_str(&json).unwrap();

        assert!(matches!(parsed.status, HealthState::Healthy));
    }

    #[test]
    fn test_authentication_request() {
        let request = AuthenticationRequest {
            method: AuthenticationMethod::Password,
            credentials: AuthenticationCredentials::Password {
                username: "test".to_string(),
                password: "password".to_string(),
            },
            client_info: ClientInfo {
                client_id: "test-client".to_string(),
                user_agent: "test-agent".to_string(),
                ip_address: "127.0.0.1".to_string(),
                device_fingerprint: None,
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: AuthenticationRequest = serde_json::from_str(&json).unwrap();

        assert!(matches!(parsed.method, AuthenticationMethod::Password));
    }

    #[test]
    fn test_policy_evaluation_request() {
        let request = PolicyEvaluationRequest {
            policy_id: Some(Uuid::new_v4()),
            policy_set: None,
            principal: Principal {
                id: Uuid::new_v4(),
                type_: PrincipalType::User,
                attributes: HashMap::new(),
            },
            action: Action {
                name: "read".to_string(),
                attributes: HashMap::new(),
            },
            resource: Resource {
                id: "document-123".to_string(),
                type_: "document".to_string(),
                attributes: HashMap::new(),
            },
            context: PolicyContext {
                environment: HashMap::new(),
                request_time: Utc::now(),
                client_info: None,
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: PolicyEvaluationRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.action.name, "read");
        assert_eq!(parsed.resource.type_, "document");
    }
}
