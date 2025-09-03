//! Request and trace context propagation for distributed systems

use crate::errors::ContractError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Request context containing tracing and user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    /// Unique request identifier
    pub request_id: String,
    /// Trace identifier for distributed tracing
    pub trace_id: String,
    /// Parent span identifier
    pub span_id: Option<String>,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
    /// User context if authenticated
    pub user_context: Option<UserContext>,
    /// Service context information
    pub service_context: ServiceContext,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl RequestContext {
    /// Create a new request context
    pub fn new(service_name: String) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            trace_id: Uuid::new_v4().to_string(),
            span_id: None,
            timestamp: Utc::now(),
            user_context: None,
            service_context: ServiceContext {
                service_name,
                instance_id: std::env::var("INSTANCE_ID")
                    .unwrap_or_else(|_| Uuid::new_v4().to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            metadata: HashMap::new(),
        }
    }

    /// Create context from headers
    pub fn from_headers(
        headers: &HashMap<String, String>,
        service_name: String,
    ) -> Result<Self, ContractError> {
        let mut context = Self::new(service_name);

        if let Some(request_id) = headers.get("x-request-id") {
            context.request_id = request_id.clone();
        }

        if let Some(trace_id) = headers.get("x-trace-id") {
            context.trace_id = trace_id.clone();
        }

        if let Some(span_id) = headers.get("x-span-id") {
            context.span_id = Some(span_id.clone());
        }

        Ok(context)
    }

    /// Convert context to headers for propagation
    pub fn to_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("x-request-id".to_string(), self.request_id.clone());
        headers.insert("x-trace-id".to_string(), self.trace_id.clone());

        if let Some(span_id) = &self.span_id {
            headers.insert("x-span-id".to_string(), span_id.clone());
        }

        headers
    }

    /// Check if the request is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.user_context.is_some()
    }
}

/// User context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    /// User identifier
    pub user_id: String,
    /// User roles
    pub roles: Vec<String>,
    /// User permissions
    pub permissions: Vec<String>,
    /// Tenant identifier for multi-tenant systems
    pub tenant_id: Option<String>,
}

impl UserContext {
    /// Check if user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }

    /// Check if user has a specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }
}

/// Service context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceContext {
    /// Service name
    pub service_name: String,
    /// Service instance identifier
    pub instance_id: String,
    /// Service version
    pub version: String,
}

/// Context propagation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPropagationConfig {
    /// Whether to propagate trace context
    pub propagate_trace: bool,
    /// Whether to propagate user context
    pub propagate_user: bool,
    /// Custom headers to propagate
    pub custom_headers: Vec<String>,
    /// Service name for tracing
    pub service_name: String,
}

impl Default for ContextPropagationConfig {
    fn default() -> Self {
        Self {
            propagate_trace: true,
            propagate_user: true,
            custom_headers: vec![],
            service_name: "rust-security-platform".to_string(),
        }
    }
}

/// Initialize context propagation with the given configuration
pub fn init_context_propagation(_config: &ContextPropagationConfig) -> Result<(), ContractError> {
    // TODO: Implement context propagation initialization
    // This could include setting up tracing, configuring headers, etc.
    Ok(())
}

/// Context propagation handler
#[derive(Debug, Clone)]
pub struct ContextPropagation {
    config: ContextPropagationConfig,
}

impl ContextPropagation {
    /// Create new context propagation handler
    pub fn new(config: ContextPropagationConfig) -> Self {
        Self { config }
    }

    /// Extract context from headers
    pub fn extract_from_headers(&self, headers: &HashMap<String, String>) -> RequestContext {
        RequestContext::from_headers(headers, self.config.service_name.clone())
            .unwrap_or_else(|_| RequestContext::new(self.config.service_name.clone()))
    }

    /// Inject context into headers
    pub fn inject_into_headers(&self, context: &RequestContext) -> HashMap<String, String> {
        context.to_headers()
    }
}

impl ContextPropagationConfig {
    /// Service name for context propagation
    pub fn service_name(&self) -> &str {
        "rust-security-platform"
    }
}
