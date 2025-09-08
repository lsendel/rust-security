//! OAuth 2.0 Dynamic Client Registration implementation
//!
//! Implements RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol
//! with enterprise-grade security features including:
//! - Automatic client secret generation and rotation
//! - Policy-based registration controls
//! - Client metadata validation
//! - Audit logging and monitoring

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Duration, Utc};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Pool, Postgres, Row};
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;
use validator::{Validate, ValidationError};

/// OAuth client registration request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ClientRegistrationRequest {
    /// Array of redirection URI strings for use in redirect-based flows
    #[validate(length(min = 1, message = "At least one redirect URI is required"))]
    pub redirect_uris: Vec<String>,

    /// Array of OAuth 2.0 response type strings
    pub response_types: Option<Vec<String>>,

    /// Array of OAuth 2.0 grant type strings
    pub grant_types: Option<Vec<String>>,

    /// Kind of the application (web, native, etc.)
    pub application_type: Option<String>,

    /// Array of contact email addresses
    pub contacts: Option<Vec<String>>,

    /// Human-readable name of the client
    #[validate(length(min = 1, max = 100))]
    pub client_name: Option<String>,

    /// URL that references a logo for the client
    #[validate(url)]
    pub logo_uri: Option<String>,

    /// URL of the home page of the client
    #[validate(url)]
    pub client_uri: Option<String>,

    /// URL that the client provides to the end-user for policy information
    #[validate(url)]
    pub policy_uri: Option<String>,

    /// URL that the client provides to the end-user for terms of service
    #[validate(url)]
    pub tos_uri: Option<String>,

    /// URL for the client's JSON Web Key Set
    #[validate(url)]
    pub jwks_uri: Option<String>,

    /// Client's JSON Web Key Set document
    pub jwks: Option<serde_json::Value>,

    /// Requested Authentication Context Class Reference values
    pub default_acr_values: Option<Vec<String>>,

    /// Default Maximum Authentication Age
    pub default_max_age: Option<u32>,

    /// Boolean value specifying whether the authorization server requires the auth_time claim
    pub require_auth_time: Option<bool>,

    /// Requested client authentication method for the token endpoint
    pub token_endpoint_auth_method: Option<String>,

    /// JWS signing algorithm for the ID Token
    pub id_token_signed_response_alg: Option<String>,

    /// Array of scope values that the client can use when requesting access tokens
    pub scope: Option<String>,

    /// A unique identifier string assigned by the client developer
    pub software_id: Option<String>,

    /// A version identifier string for the client software
    pub software_version: Option<String>,

    /// A software statement containing client metadata values
    pub software_statement: Option<String>,
}

/// OAuth client registration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationResponse {
    /// OAuth 2.0 client identifier string
    pub client_id: String,

    /// OAuth 2.0 client secret string
    pub client_secret: Option<String>,

    /// Time at which the client secret will expire or 0 if it will not expire
    pub client_secret_expires_at: u64,

    /// Array of redirection URI strings for use in redirect-based flows
    pub redirect_uris: Vec<String>,

    /// Array of OAuth 2.0 response type strings
    pub response_types: Option<Vec<String>>,

    /// Array of OAuth 2.0 grant type strings
    pub grant_types: Option<Vec<String>>,

    /// Kind of the application
    pub application_type: Option<String>,

    /// Array of contact email addresses
    pub contacts: Option<Vec<String>>,

    /// Human-readable name of the client
    pub client_name: Option<String>,

    /// URL that references a logo for the client
    pub logo_uri: Option<String>,

    /// URL of the home page of the client
    pub client_uri: Option<String>,

    /// URL for policy information
    pub policy_uri: Option<String>,

    /// URL for terms of service
    pub tos_uri: Option<String>,

    /// URL for the client's JSON Web Key Set
    pub jwks_uri: Option<String>,

    /// Client's JSON Web Key Set document
    pub jwks: Option<serde_json::Value>,

    /// Requested Authentication Context Class Reference values
    pub default_acr_values: Option<Vec<String>>,

    /// Default Maximum Authentication Age
    pub default_max_age: Option<u32>,

    /// Boolean value specifying whether auth_time claim is required
    pub require_auth_time: Option<bool>,

    /// Client authentication method for the token endpoint
    pub token_endpoint_auth_method: Option<String>,

    /// JWS signing algorithm for the ID Token
    pub id_token_signed_response_alg: Option<String>,

    /// Scope values that the client can use
    pub scope: Option<String>,

    /// Software identifier
    pub software_id: Option<String>,

    /// Software version
    pub software_version: Option<String>,

    /// Registration access token for managing this client
    pub registration_access_token: String,

    /// Client configuration endpoint URL
    pub registration_client_uri: String,

    /// Timestamp when the client was created
    pub client_id_issued_at: u64,
}

/// Client registration policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationPolicy {
    /// Whether dynamic registration is enabled
    pub enabled: bool,

    /// Whether authentication is required for registration
    pub require_authentication: bool,

    /// Maximum number of redirect URIs allowed
    pub max_redirect_uris: usize,

    /// Allowed grant types
    pub allowed_grant_types: Vec<String>,

    /// Allowed response types
    pub allowed_response_types: Vec<String>,

    /// Allowed application types
    pub allowed_application_types: Vec<String>,

    /// Allowed scopes for dynamic registration
    pub allowed_scopes: Vec<String>,

    /// Required fields for registration
    pub required_fields: Vec<String>,

    /// Whether software statements are required
    pub require_software_statement: bool,

    /// Trusted software statement issuers
    pub trusted_software_issuers: Vec<String>,

    /// Client secret expiry duration in seconds
    pub client_secret_ttl: u64,

    /// Maximum number of clients per IP per day
    pub rate_limit_per_ip: u32,

    /// Allowed domains for redirect URIs
    pub allowed_redirect_domains: Vec<String>,

    /// Whether to validate redirect URI domains
    pub validate_redirect_domains: bool,
}

impl Default for ClientRegistrationPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            require_authentication: false,
            max_redirect_uris: 10,
            allowed_grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
                "client_credentials".to_string(),
            ],
            allowed_response_types: vec![
                "code".to_string(),
                "token".to_string(),
                "id_token".to_string(),
            ],
            allowed_application_types: vec!["web".to_string(), "native".to_string()],
            allowed_scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "offline_access".to_string(),
            ],
            required_fields: vec!["redirect_uris".to_string(), "client_name".to_string()],
            require_software_statement: false,
            trusted_software_issuers: vec![],
            client_secret_ttl: 86400 * 365, // 1 year
            rate_limit_per_ip: 10,
            allowed_redirect_domains: vec![],
            validate_redirect_domains: false,
        }
    }
}

/// Registered OAuth client information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredClient {
    pub client_id: String,
    pub client_secret_hash: String,
    pub client_secret_expires_at: DateTime<Utc>,
    pub registration_access_token_hash: String,
    pub redirect_uris: Vec<String>,
    pub response_types: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub application_type: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub client_name: Option<String>,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub jwks_uri: Option<String>,
    pub jwks: Option<serde_json::Value>,
    pub default_acr_values: Option<Vec<String>>,
    pub default_max_age: Option<u32>,
    pub require_auth_time: Option<bool>,
    pub token_endpoint_auth_method: Option<String>,
    pub id_token_signed_response_alg: Option<String>,
    pub scope: Option<String>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by_ip: Option<String>,
    pub status: String, // active, suspended, revoked
}

/// OAuth client registration manager
pub struct ClientRegistrationManager {
    db_pool: Pool<Postgres>,
    policy: ClientRegistrationPolicy,
    base_url: String,
}

impl ClientRegistrationManager {
    pub fn new(
        db_pool: Pool<Postgres>,
        policy: ClientRegistrationPolicy,
        base_url: String,
    ) -> Self {
        Self {
            db_pool,
            policy,
            base_url,
        }
    }

    /// Register a new OAuth client
    pub async fn register_client(
        &self,
        request: ClientRegistrationRequest,
        client_ip: Option<String>,
    ) -> Result<ClientRegistrationResponse, ClientRegistrationError> {
        // Validate policy compliance
        if !self.policy.enabled {
            return Err(ClientRegistrationError::RegistrationDisabled);
        }

        // Rate limiting check
        if let Some(ip) = &client_ip {
            if !self.check_rate_limit(ip).await? {
                return Err(ClientRegistrationError::RateLimitExceeded);
            }
        }


        // Extracted: Validate request
        self.validate_registration_request(&request)?;
        self.validate_against_policy(&request)?;

        // Extracted: Generate credentials
        let (client_id, client_secret, _registration_access_token, client_secret_hash, registration_access_token_hash, secret_expires_at, now) =
            self.generate_client_credentials()?;

        // Extracted: Prepare client data
        let client = self.prepare_client_data(
            &client_id,
            &client_secret_hash,
            &registration_access_token_hash,
            &secret_expires_at,
            &request,
            &client_ip,
            now,
        );

        // Store in database
        self.store_client(&client).await?;

        // Record registration event
        self.record_registration_event(&client_id, &client_ip).await?;

        info!(
            "OAuth client registered: {} from IP: {:?}",
            client_id, client_ip
        );

        // Extracted: Build response
        Ok(self.build_registration_response(
            &client_id,
            &client_secret,
            &secret_expires_at,
            &request,
            now,
        ))
    }

    // Helper to generate credentials
    fn generate_client_credentials(&self) -> Result<(String, String, String, String, String, chrono::DateTime<Utc>, chrono::DateTime<Utc>), ClientRegistrationError> {
        let client_id = format!("client_{}", Uuid::new_v4().simple());
        let client_secret = generate_client_secret();
        let registration_access_token = generate_registration_access_token();
        let client_secret_hash = hash_secret(&client_secret);
        let registration_access_token_hash = hash_secret(&registration_access_token);
        let now = Utc::now();
        let secret_expires_at = now + chrono::Duration::seconds(self.policy.client_secret_ttl as i64);
        Ok((client_id, client_secret, registration_access_token, client_secret_hash, registration_access_token_hash, secret_expires_at, now))
    }

    // Helper to prepare client data
    fn prepare_client_data(
        &self,
        client_id: &str,
        client_secret_hash: &str,
        registration_access_token_hash: &str,
        secret_expires_at: &chrono::DateTime<Utc>,
        request: &ClientRegistrationRequest,
        client_ip: &Option<String>,
        now: chrono::DateTime<Utc>,
    ) -> RegisteredClient {
        RegisteredClient {
            client_id: client_id.to_string(),
            client_secret_hash: client_secret_hash.to_string(),
            client_secret_expires_at: *secret_expires_at,
            registration_access_token_hash: registration_access_token_hash.to_string(),
            redirect_uris: request.redirect_uris.clone(),
            response_types: request.response_types.clone(),
            grant_types: request.grant_types.clone(),
            application_type: request.application_type.clone(),
            contacts: request.contacts.clone(),
            client_name: request.client_name.clone(),
            logo_uri: request.logo_uri.clone(),
            client_uri: request.client_uri.clone(),
            policy_uri: request.policy_uri.clone(),
            tos_uri: request.tos_uri.clone(),
            jwks_uri: request.jwks_uri.clone(),
            jwks: request.jwks.clone(),
            default_acr_values: request.default_acr_values.clone(),
            default_max_age: request.default_max_age,
            require_auth_time: request.require_auth_time,
            token_endpoint_auth_method: request.token_endpoint_auth_method.clone(),
            id_token_signed_response_alg: request.id_token_signed_response_alg.clone(),
            scope: request.scope.clone(),
            software_id: request.software_id.clone(),
            software_version: request.software_version.clone(),
            created_at: now,
            updated_at: now,
            created_by_ip: client_ip.clone(),
            status: "active".to_string(),
        }
    }

    // Helper to build response
    fn build_registration_response(
        &self,
        client_id: &str,
        client_secret: &str,
        secret_expires_at: &chrono::DateTime<Utc>,
        request: &ClientRegistrationRequest,
        now: chrono::DateTime<Utc>,
    ) -> ClientRegistrationResponse {
        ClientRegistrationResponse {
            client_id: client_id.to_string(),
            client_secret: Some(client_secret.to_string()),
            client_secret_expires_at: secret_expires_at.timestamp() as u64,
            redirect_uris: request.redirect_uris.clone(),
            response_types: request.response_types.clone(),
            grant_types: request.grant_types.clone(),
            application_type: request.application_type.clone(),
            contacts: request.contacts.clone(),
            client_name: request.client_name.clone(),
            logo_uri: request.logo_uri.clone(),
            client_uri: request.client_uri.clone(),
            policy_uri: request.policy_uri.clone(),
            tos_uri: request.tos_uri.clone(),
            jwks_uri: request.jwks_uri.clone(),
            jwks: request.jwks.clone(),
            default_acr_values: request.default_acr_values.clone(),
            default_max_age: request.default_max_age,
            require_auth_time: request.require_auth_time,
            token_endpoint_auth_method: request.token_endpoint_auth_method.clone(),
            id_token_signed_response_alg: request.id_token_signed_response_alg.clone(),
            scope: request.scope.clone(),
            software_id: request.software_id.clone(),
            software_version: request.software_version.clone(),
            registration_access_token: generate_registration_access_token(),
            registration_client_uri: format!("{}/clients/{}", self.base_url, client_id),
            client_id_issued_at: now.timestamp() as u64,
        }
    }

    /// Get client configuration
    pub async fn get_client_configuration(
        &self,
        client_id: &str,
        access_token: &str,
    ) -> Result<ClientRegistrationResponse, ClientRegistrationError> {
        let client = self.get_client_by_id(client_id).await?;

        // Verify access token
        if !verify_registration_access_token(access_token, &client.registration_access_token_hash) {
            return Err(ClientRegistrationError::InvalidAccessToken);
        }

        // Build response (without client_secret)
        Ok(ClientRegistrationResponse {
            client_id: client.client_id.clone(),
            client_secret: None, // Don't return secret in configuration
            client_secret_expires_at: client.client_secret_expires_at.timestamp() as u64,
            redirect_uris: client.redirect_uris,
            response_types: client.response_types,
            grant_types: client.grant_types,
            application_type: client.application_type,
            contacts: client.contacts,
            client_name: client.client_name,
            logo_uri: client.logo_uri,
            client_uri: client.client_uri,
            policy_uri: client.policy_uri,
            tos_uri: client.tos_uri,
            jwks_uri: client.jwks_uri,
            jwks: client.jwks,
            default_acr_values: client.default_acr_values,
            default_max_age: client.default_max_age,
            require_auth_time: client.require_auth_time,
            token_endpoint_auth_method: client.token_endpoint_auth_method,
            id_token_signed_response_alg: client.id_token_signed_response_alg,
            scope: client.scope,
            software_id: client.software_id,
            software_version: client.software_version,
            registration_access_token: "***".to_string(), // Redacted
            registration_client_uri: format!(
                "{}/oauth/register/{}",
                self.base_url, client.client_id
            ),
            client_id_issued_at: client.created_at.timestamp() as u64,
        })
    }

    /// Update client configuration
    pub async fn update_client_configuration(
        &self,
        client_id: &str,
        access_token: &str,
        request: ClientRegistrationRequest,
    ) -> Result<ClientRegistrationResponse, ClientRegistrationError> {
        let mut client = self.get_client_by_id(client_id).await?;

        // Verify access token
        if !verify_registration_access_token(access_token, &client.registration_access_token_hash) {
            return Err(ClientRegistrationError::InvalidAccessToken);
        }

        // Validate request manually
        self.validate_registration_request(&request)?;

        // Policy-based validation
        self.validate_against_policy(&request)?;

        // Update client data
        client.redirect_uris = request.redirect_uris.clone();
        client.response_types = request.response_types.clone();
        client.grant_types = request.grant_types.clone();
        client.application_type = request.application_type.clone();
        client.contacts = request.contacts.clone();
        client.client_name = request.client_name.clone();
        client.logo_uri = request.logo_uri.clone();
        client.client_uri = request.client_uri.clone();
        client.policy_uri = request.policy_uri.clone();
        client.tos_uri = request.tos_uri.clone();
        client.jwks_uri = request.jwks_uri.clone();
        client.jwks = request.jwks.clone();
        client.default_acr_values = request.default_acr_values.clone();
        client.default_max_age = request.default_max_age;
        client.require_auth_time = request.require_auth_time;
        client.token_endpoint_auth_method = request.token_endpoint_auth_method.clone();
        client.id_token_signed_response_alg = request.id_token_signed_response_alg.clone();
        client.scope = request.scope.clone();
        client.software_id = request.software_id.clone();
        client.software_version = request.software_version.clone();
        client.updated_at = Utc::now();

        // Update in database
        self.update_client(&client).await?;

        info!("OAuth client updated: {}", client_id);

        // Build response
        Ok(ClientRegistrationResponse {
            client_id: client.client_id.clone(),
            client_secret: None, // Don't return secret in update
            client_secret_expires_at: client.client_secret_expires_at.timestamp() as u64,
            redirect_uris: client.redirect_uris,
            response_types: client.response_types,
            grant_types: client.grant_types,
            application_type: client.application_type,
            contacts: client.contacts,
            client_name: client.client_name,
            logo_uri: client.logo_uri,
            client_uri: client.client_uri,
            policy_uri: client.policy_uri,
            tos_uri: client.tos_uri,
            jwks_uri: client.jwks_uri,
            jwks: client.jwks,
            default_acr_values: client.default_acr_values,
            default_max_age: client.default_max_age,
            require_auth_time: client.require_auth_time,
            token_endpoint_auth_method: client.token_endpoint_auth_method,
            id_token_signed_response_alg: client.id_token_signed_response_alg,
            scope: client.scope,
            software_id: client.software_id,
            software_version: client.software_version,
            registration_access_token: "***".to_string(), // Redacted
            registration_client_uri: format!(
                "{}/oauth/register/{}",
                self.base_url, client.client_id
            ),
            client_id_issued_at: client.created_at.timestamp() as u64,
        })
    }

    /// Delete client registration
    pub async fn delete_client(
        &self,
        client_id: &str,
        access_token: &str,
    ) -> Result<(), ClientRegistrationError> {
        let client = self.get_client_by_id(client_id).await?;

        // Verify access token
        if !verify_registration_access_token(access_token, &client.registration_access_token_hash) {
            return Err(ClientRegistrationError::InvalidAccessToken);
        }

        // Delete from database
        sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
            .bind(client_id)
            .execute(&self.db_pool)
            .await
            .map_err(|e| ClientRegistrationError::DatabaseError(e.to_string()))?;

        info!("OAuth client deleted: {}", client_id);
        Ok(())
    }

    /// Manual validation of registration request
    fn validate_registration_request(
        &self,
        request: &ClientRegistrationRequest,
    ) -> Result<(), ClientRegistrationError> {
        // Basic validation
        if request.redirect_uris.is_empty() {
            return Err(ClientRegistrationError::ValidationFailed(
                "At least one redirect URI is required".to_string(),
            ));
        }

        // Validate redirect URIs format
        for uri in &request.redirect_uris {
            if url::Url::parse(uri).is_err() {
                return Err(ClientRegistrationError::ValidationFailed(format!(
                    "Invalid redirect URI format: {}",
                    uri
                )));
            }
        }

        // Validate contact emails if provided
        if let Some(contacts) = &request.contacts {
            for contact in contacts {
                if !contact.contains('@') {
                    return Err(ClientRegistrationError::ValidationFailed(format!(
                        "Invalid email format in contacts: {}",
                        contact
                    )));
                }
            }
        }

        // Validate URLs if provided
        if let Some(uri) = &request.logo_uri {
            if url::Url::parse(uri).is_err() {
                return Err(ClientRegistrationError::ValidationFailed(
                    "Invalid logo_uri format".to_string(),
                ));
            }
        }

        if let Some(uri) = &request.client_uri {
            if url::Url::parse(uri).is_err() {
                return Err(ClientRegistrationError::ValidationFailed(
                    "Invalid client_uri format".to_string(),
                ));
            }
        }

        if let Some(uri) = &request.policy_uri {
            if url::Url::parse(uri).is_err() {
                return Err(ClientRegistrationError::ValidationFailed(
                    "Invalid policy_uri format".to_string(),
                ));
            }
        }

        if let Some(uri) = &request.tos_uri {
            if url::Url::parse(uri).is_err() {
                return Err(ClientRegistrationError::ValidationFailed(
                    "Invalid tos_uri format".to_string(),
                ));
            }
        }

        if let Some(uri) = &request.jwks_uri {
            if url::Url::parse(uri).is_err() {
                return Err(ClientRegistrationError::ValidationFailed(
                    "Invalid jwks_uri format".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate request against policy
    fn validate_against_policy(
        &self,
        request: &ClientRegistrationRequest,
    ) -> Result<(), ClientRegistrationError> {
        // Check redirect URI count
        if request.redirect_uris.len() > self.policy.max_redirect_uris {
            return Err(ClientRegistrationError::PolicyViolation(format!(
                "Too many redirect URIs. Maximum allowed: {}",
                self.policy.max_redirect_uris
            )));
        }

        // Validate grant types
        if let Some(grant_types) = &request.grant_types {
            for grant_type in grant_types {
                if !self.policy.allowed_grant_types.contains(grant_type) {
                    return Err(ClientRegistrationError::PolicyViolation(format!(
                        "Grant type '{}' is not allowed",
                        grant_type
                    )));
                }
            }
        }

        // Validate response types
        if let Some(response_types) = &request.response_types {
            for response_type in response_types {
                if !self.policy.allowed_response_types.contains(response_type) {
                    return Err(ClientRegistrationError::PolicyViolation(format!(
                        "Response type '{}' is not allowed",
                        response_type
                    )));
                }
            }
        }

        // Validate application type
        if let Some(app_type) = &request.application_type {
            if !self.policy.allowed_application_types.contains(app_type) {
                return Err(ClientRegistrationError::PolicyViolation(format!(
                    "Application type '{}' is not allowed",
                    app_type
                )));
            }
        }

        // Validate redirect domains if enabled
        if self.policy.validate_redirect_domains && !self.policy.allowed_redirect_domains.is_empty()
        {
            for uri in &request.redirect_uris {
                if let Ok(url) = url::Url::parse(uri) {
                    if let Some(domain) = url.domain() {
                        if !self.policy.allowed_redirect_domains.iter().any(|allowed| {
                            domain == allowed || domain.ends_with(&format!(".{}", allowed))
                        }) {
                            return Err(ClientRegistrationError::PolicyViolation(format!(
                                "Redirect URI domain '{}' is not allowed",
                                domain
                            )));
                        }
                    }
                }
            }
        }

        // Check required fields
        for field in &self.policy.required_fields {
            match field.as_str() {
                "client_name" => {
                    if request.client_name.is_none() {
                        return Err(ClientRegistrationError::PolicyViolation(
                            "client_name is required".to_string(),
                        ));
                    }
                }
                "contacts" => {
                    if request.contacts.as_ref().map_or(true, |c| c.is_empty()) {
                        return Err(ClientRegistrationError::PolicyViolation(
                            "contacts is required".to_string(),
                        ));
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Check rate limit for IP address
    async fn check_rate_limit(&self, ip: &str) -> Result<bool, ClientRegistrationError> {
        let today = Utc::now().date_naive();

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oauth_client_registrations
             WHERE created_by_ip = $1 AND DATE(created_at) = $2",
        )
        .bind(ip)
        .bind(today)
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| ClientRegistrationError::DatabaseError(e.to_string()))?;

        Ok(count < self.policy.rate_limit_per_ip as i64)
    }

    /// Store client in database
    async fn store_client(&self, client: &RegisteredClient) -> Result<(), ClientRegistrationError> {
        sqlx::query(
            r#"
            INSERT INTO oauth_clients (
                client_id, client_secret_hash, client_secret_expires_at,
                registration_access_token_hash, redirect_uris, response_types,
                grant_types, application_type, contacts, client_name,
                logo_uri, client_uri, policy_uri, tos_uri, jwks_uri,
                jwks, default_acr_values, default_max_age, require_auth_time,
                token_endpoint_auth_method, id_token_signed_response_alg,
                scope, software_id, software_version, created_at,
                updated_at, created_by_ip, status
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, $18, $19,
                $20, $21, $22, $23, $24, $25, $26, $27, $28
            )
            "#,
        )
        .bind(&client.client_id)
        .bind(&client.client_secret_hash)
        .bind(&client.client_secret_expires_at)
        .bind(&client.registration_access_token_hash)
        .bind(&client.redirect_uris)
        .bind(&client.response_types)
        .bind(&client.grant_types)
        .bind(&client.application_type)
        .bind(&client.contacts)
        .bind(&client.client_name)
        .bind(&client.logo_uri)
        .bind(&client.client_uri)
        .bind(&client.policy_uri)
        .bind(&client.tos_uri)
        .bind(&client.jwks_uri)
        .bind(&client.jwks)
        .bind(&client.default_acr_values)
        .bind(&client.default_max_age.map(|v| v as i32))
        .bind(&client.require_auth_time)
        .bind(&client.token_endpoint_auth_method)
        .bind(&client.id_token_signed_response_alg)
        .bind(&client.scope)
        .bind(&client.software_id)
        .bind(&client.software_version)
        .bind(&client.created_at)
        .bind(&client.updated_at)
        .bind(&client.created_by_ip)
        .bind(&client.status)
        .execute(&self.db_pool)
        .await
        .map_err(|e| ClientRegistrationError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Update client in database
    async fn update_client(
        &self,
        client: &RegisteredClient,
    ) -> Result<(), ClientRegistrationError> {
        sqlx::query(
            r#"
            UPDATE oauth_clients SET
                redirect_uris = $2, response_types = $3, grant_types = $4,
                application_type = $5, contacts = $6, client_name = $7,
                logo_uri = $8, client_uri = $9, policy_uri = $10,
                tos_uri = $11, jwks_uri = $12, jwks = $13,
                default_acr_values = $14, default_max_age = $15,
                require_auth_time = $16, token_endpoint_auth_method = $17,
                id_token_signed_response_alg = $18, scope = $19,
                software_id = $20, software_version = $21, updated_at = $22
            WHERE client_id = $1
            "#,
        )
        .bind(&client.client_id)
        .bind(&client.redirect_uris)
        .bind(&client.response_types)
        .bind(&client.grant_types)
        .bind(&client.application_type)
        .bind(&client.contacts)
        .bind(&client.client_name)
        .bind(&client.logo_uri)
        .bind(&client.client_uri)
        .bind(&client.policy_uri)
        .bind(&client.tos_uri)
        .bind(&client.jwks_uri)
        .bind(&client.jwks)
        .bind(&client.default_acr_values)
        .bind(&client.default_max_age.map(|v| v as i32))
        .bind(&client.require_auth_time)
        .bind(&client.token_endpoint_auth_method)
        .bind(&client.id_token_signed_response_alg)
        .bind(&client.scope)
        .bind(&client.software_id)
        .bind(&client.software_version)
        .bind(&client.updated_at)
        .execute(&self.db_pool)
        .await
        .map_err(|e| ClientRegistrationError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get client by ID
    async fn get_client_by_id(
        &self,
        client_id: &str,
    ) -> Result<RegisteredClient, ClientRegistrationError> {
        let row =
            sqlx::query("SELECT * FROM oauth_clients WHERE client_id = $1 AND status = 'active'")
                .bind(client_id)
                .fetch_optional(&self.db_pool)
                .await
                .map_err(|e| ClientRegistrationError::DatabaseError(e.to_string()))?;

        let row = row.ok_or(ClientRegistrationError::ClientNotFound)?;

        Ok(RegisteredClient {
            client_id: row.get("client_id"),
            client_secret_hash: row.get("client_secret_hash"),
            client_secret_expires_at: row.get("client_secret_expires_at"),
            registration_access_token_hash: row.get("registration_access_token_hash"),
            redirect_uris: row.get("redirect_uris"),
            response_types: row.get("response_types"),
            grant_types: row.get("grant_types"),
            application_type: row.get("application_type"),
            contacts: row.get("contacts"),
            client_name: row.get("client_name"),
            logo_uri: row.get("logo_uri"),
            client_uri: row.get("client_uri"),
            policy_uri: row.get("policy_uri"),
            tos_uri: row.get("tos_uri"),
            jwks_uri: row.get("jwks_uri"),
            jwks: row.get("jwks"),
            default_acr_values: row.get("default_acr_values"),
            default_max_age: row
                .get::<Option<i32>, _>("default_max_age")
                .map(|v| v as u32),
            require_auth_time: row.get("require_auth_time"),
            token_endpoint_auth_method: row.get("token_endpoint_auth_method"),
            id_token_signed_response_alg: row.get("id_token_signed_response_alg"),
            scope: row.get("scope"),
            software_id: row.get("software_id"),
            software_version: row.get("software_version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            created_by_ip: row.get("created_by_ip"),
            status: row.get("status"),
        })
    }

    /// Record registration event for auditing
    async fn record_registration_event(
        &self,
        client_id: &str,
        ip: &Option<String>,
    ) -> Result<(), ClientRegistrationError> {
        sqlx::query(
            r#"
            INSERT INTO oauth_client_registrations (
                client_id, created_by_ip, created_at, event_type
            ) VALUES ($1, $2, $3, 'registered')
            "#,
        )
        .bind(client_id)
        .bind(ip)
        .bind(Utc::now())
        .execute(&self.db_pool)
        .await
        .map_err(|e| ClientRegistrationError::DatabaseError(e.to_string()))?;

        Ok(())
    }
}

/// Client registration errors
#[derive(Debug, thiserror::Error)]
pub enum ClientRegistrationError {
    #[error("Dynamic client registration is disabled")]
    RegistrationDisabled,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Client not found")]
    ClientNotFound,

    #[error("Invalid access token")]
    InvalidAccessToken,

    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl IntoResponse for ClientRegistrationError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ClientRegistrationError::RegistrationDisabled => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Dynamic client registration is disabled",
            ),
            ClientRegistrationError::RateLimitExceeded => {
                (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded")
            }
            ClientRegistrationError::ValidationFailed(_) => {
                (StatusCode::BAD_REQUEST, "Invalid request")
            }
            ClientRegistrationError::PolicyViolation(_) => {
                (StatusCode::BAD_REQUEST, "Policy violation")
            }
            ClientRegistrationError::ClientNotFound => (StatusCode::NOT_FOUND, "Client not found"),
            ClientRegistrationError::InvalidAccessToken => {
                (StatusCode::UNAUTHORIZED, "Invalid access token")
            }
            ClientRegistrationError::DatabaseError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        };

        error!("Client registration error: {}", self);
        (status, message).into_response()
    }
}

/// Validation functions
#[allow(dead_code)]
fn validate_redirect_uris(uris: &[String]) -> Result<(), ValidationError> {
    for uri in uris {
        if let Err(_) = url::Url::parse(uri) {
            return Err(ValidationError::new("Invalid redirect URI format"));
        }

        if let Ok(url) = url::Url::parse(uri) {
            if url.scheme() != "https" && url.scheme() != "http" && url.scheme() != "custom" {
                return Err(ValidationError::new("Invalid redirect URI scheme"));
            }
        } else {
            return Err(ValidationError::new("Invalid redirect URI scheme"));
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_response_types(types: &[String]) -> Result<(), ValidationError> {
    let valid_types = ["code", "token", "id_token"];
    for response_type in types {
        let parts: Vec<&str> = response_type.split_whitespace().collect();
        for part in parts {
            if !valid_types.contains(&part) {
                return Err(ValidationError::new("Invalid response type"));
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_grant_types(types: &[String]) -> Result<(), ValidationError> {
    let valid_types = [
        "authorization_code",
        "implicit",
        "password",
        "client_credentials",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "urn:ietf:params:oauth:grant-type:saml2-bearer",
    ];

    for grant_type in types {
        if !valid_types.contains(&grant_type.as_str()) {
            return Err(ValidationError::new("Invalid grant type"));
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_contacts(contacts: &[String]) -> Result<(), ValidationError> {
    for contact in contacts {
        if !contact.contains('@') {
            return Err(ValidationError::new("Invalid email format in contacts"));
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_scope(scope: &str) -> Result<(), ValidationError> {
    // Basic scope validation - space-separated tokens
    let parts: Vec<&str> = scope.split_whitespace().collect();
    if parts.is_empty() {
        return Err(ValidationError::new("Scope cannot be empty"));
    }

    for part in parts {
        if part.is_empty() || part.contains(' ') {
            return Err(ValidationError::new("Invalid scope format"));
        }
    }

    Ok(())
}

/// Utility functions
fn generate_client_secret() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

fn generate_registration_access_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(128)
        .map(char::from)
        .collect()
}

fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn verify_registration_access_token(token: &str, hash: &str) -> bool {
    let token_hash = hash_secret(token);
    crate::services::constant_time_compare(&token_hash, hash)
}

/// Axum handlers
pub async fn register_client_handler(
    headers: HeaderMap,
    State(manager): State<Arc<ClientRegistrationManager>>,
    Json(request): Json<ClientRegistrationRequest>,
) -> Result<Json<ClientRegistrationResponse>, ClientRegistrationError> {
    let client_ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let response = manager.register_client(request, client_ip).await?;
    Ok(Json(response))
}

pub async fn get_client_configuration_handler(
    Path(client_id): Path<String>,
    headers: HeaderMap,
    State(manager): State<Arc<ClientRegistrationManager>>,
) -> Result<Json<ClientRegistrationResponse>, ClientRegistrationError> {
    let access_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ClientRegistrationError::InvalidAccessToken)?;

    let response = manager
        .get_client_configuration(&client_id, access_token)
        .await?;
    Ok(Json(response))
}

pub async fn update_client_configuration_handler(
    Path(client_id): Path<String>,
    headers: HeaderMap,
    State(manager): State<Arc<ClientRegistrationManager>>,
    Json(request): Json<ClientRegistrationRequest>,
) -> Result<Json<ClientRegistrationResponse>, ClientRegistrationError> {
    let access_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ClientRegistrationError::InvalidAccessToken)?;

    let response = manager
        .update_client_configuration(&client_id, access_token, request)
        .await?;
    Ok(Json(response))
}

pub async fn delete_client_handler(
    Path(client_id): Path<String>,
    headers: HeaderMap,
    State(manager): State<Arc<ClientRegistrationManager>>,
) -> Result<StatusCode, ClientRegistrationError> {
    let access_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ClientRegistrationError::InvalidAccessToken)?;

    manager.delete_client(&client_id, access_token).await?;
    Ok(StatusCode::NO_CONTENT)
}
