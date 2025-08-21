//! Request and trace context propagation for distributed systems

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::{ContextPropagationConfig, errors::ContractError};

/// Request context containing tracing and user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    /// Unique request identifier
    pub request_id: Uuid,
    /// Distributed trace context
    pub trace_context: Option<TraceContext>,
    /// User context if authenticated
    pub user_context: Option<UserContext>,
    /// Service context
    pub service_context: ServiceContext,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl RequestContext {
    /// Create a new request context
    pub fn new(service_name: String) -> Self {
        Self {
            request_id: Uuid::new_v4(),
            trace_context: None,
            user_context: None,
            service_context: ServiceContext {
                service_name,
                instance_id: std::env::var("INSTANCE_ID").unwrap_or_else(|_| Uuid::new_v4().to_string()),
                version: std::env::var("SERVICE_VERSION").unwrap_or_else(|_| "unknown".to_string()),
            },
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }
    
    /// Create context with trace information
    pub fn with_trace(mut self, trace_context: TraceContext) -> Self {
        self.trace_context = Some(trace_context);
        self
    }
    
    /// Create context with user information
    pub fn with_user(mut self, user_context: UserContext) -> Self {
        self.user_context = Some(user_context);
        self
    }
    
    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Get trace ID if available
    pub fn trace_id(&self) -> Option<&str> {
        self.trace_context.as_ref().map(|ctx| ctx.trace_id.as_str())
    }
    
    /// Get span ID if available
    pub fn span_id(&self) -> Option<&str> {
        self.trace_context.as_ref().map(|ctx| ctx.span_id.as_str())
    }
    
    /// Get user ID if authenticated
    pub fn user_id(&self) -> Option<Uuid> {
        self.user_context.as_ref().map(|ctx| ctx.user_id)
    }
    
    /// Check if user is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.user_context.is_some()
    }
    
    /// Create child context for downstream calls
    pub fn create_child(&self, service_name: String) -> Self {
        let mut child = RequestContext::new(service_name);
        child.request_id = self.request_id; // Keep same request ID
        child.trace_context = self.trace_context.as_ref().map(|ctx| ctx.create_child());
        child.user_context = self.user_context.clone();
        child.metadata = self.metadata.clone();
        child
    }
}

/// Distributed tracing context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    /// Trace identifier
    pub trace_id: String,
    /// Span identifier
    pub span_id: String,
    /// Parent span identifier
    pub parent_span_id: Option<String>,
    /// Trace flags
    pub trace_flags: u8,
    /// Trace state
    pub trace_state: Option<String>,
    /// Baggage
    pub baggage: HashMap<String, String>,
}

impl TraceContext {
    /// Create a new trace context
    pub fn new() -> Self {
        Self {
            trace_id: generate_trace_id(),
            span_id: generate_span_id(),
            parent_span_id: None,
            trace_flags: 1, // Sampled
            trace_state: None,
            baggage: HashMap::new(),
        }
    }
    
    /// Create from traceparent header
    pub fn from_traceparent(traceparent: &str) -> Result<Self, ContractError> {
        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() != 4 {
            return Err(ContractError::InvalidTraceContext("Invalid traceparent format".to_string()));
        }
        
        let version = parts[0];
        if version != "00" {
            return Err(ContractError::InvalidTraceContext("Unsupported traceparent version".to_string()));
        }
        
        Ok(Self {
            trace_id: parts[1].to_string(),
            span_id: generate_span_id(), // New span for this service
            parent_span_id: Some(parts[2].to_string()),
            trace_flags: u8::from_str_radix(parts[3], 16)
                .map_err(|_| ContractError::InvalidTraceContext("Invalid trace flags".to_string()))?,
            trace_state: None,
            baggage: HashMap::new(),
        })
    }
    
    /// Convert to traceparent header
    pub fn to_traceparent(&self) -> String {
        format!("00-{}-{}-{:02x}", self.trace_id, self.span_id, self.trace_flags)
    }
    
    /// Create child span
    pub fn create_child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            span_id: generate_span_id(),
            parent_span_id: Some(self.span_id.clone()),
            trace_flags: self.trace_flags,
            trace_state: self.trace_state.clone(),
            baggage: self.baggage.clone(),
        }
    }
    
    /// Add baggage
    pub fn with_baggage(mut self, key: String, value: String) -> Self {
        self.baggage.insert(key, value);
        self
    }
    
    /// Is sampled?
    pub fn is_sampled(&self) -> bool {
        self.trace_flags & 1 == 1
    }
}

/// User context for authenticated requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    /// User identifier
    pub user_id: Uuid,
    /// Username
    pub username: String,
    /// User roles
    pub roles: Vec<String>,
    /// User permissions
    pub permissions: Vec<String>,
    /// Session identifier
    pub session_id: Option<Uuid>,
    /// Client identifier
    pub client_id: Option<String>,
    /// Tenant identifier for multi-tenant scenarios
    pub tenant_id: Option<String>,
    /// Authentication method used
    pub auth_method: String,
    /// Authentication time
    pub auth_time: DateTime<Utc>,
}

impl UserContext {
    /// Check if user has role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }
    
    /// Check if user has permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }
    
    /// Check if user has any of the roles
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|role| self.has_role(role))
    }
    
    /// Check if user has all permissions
    pub fn has_all_permissions(&self, permissions: &[&str]) -> bool {
        permissions.iter().all(|perm| self.has_permission(perm))
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

/// Context propagation utility
#[derive(Debug, Clone)]
pub struct ContextPropagation {
    config: ContextPropagationConfig,
}

impl ContextPropagation {
    /// Create new context propagation utility
    pub fn new(config: ContextPropagationConfig) -> Self {
        Self { config }
    }
    
    /// Extract context from HTTP headers
    pub fn extract_from_headers(&self, headers: &HashMap<String, String>) -> RequestContext {
        let mut context = RequestContext::new(self.config.service_name.clone());
        
        // Extract request ID
        if let Some(request_id) = headers.get(&self.config.request_id_header) {
            if let Ok(id) = Uuid::parse_str(request_id) {
                context.request_id = id;
            }
        }
        
        // Extract trace context
        if self.config.enable_tracing {
            if let Some(traceparent) = headers.get(&self.config.trace_header) {
                if let Ok(trace_ctx) = TraceContext::from_traceparent(traceparent) {
                    context.trace_context = Some(trace_ctx);
                }
            }
        }
        
        // Extract user context
        if let Some(user_context_header) = headers.get(&self.config.user_context_header) {
            if let Ok(user_ctx) = serde_json::from_str::<UserContext>(user_context_header) {
                context.user_context = Some(user_ctx);
            }
        }
        
        context
    }
    
    /// Inject context into HTTP headers
    pub fn inject_into_headers(&self, context: &RequestContext) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        
        // Inject request ID
        headers.insert(
            self.config.request_id_header.clone(),
            context.request_id.to_string(),
        );
        
        // Inject trace context
        if self.config.enable_tracing {
            if let Some(trace_ctx) = &context.trace_context {
                headers.insert(
                    self.config.trace_header.clone(),
                    trace_ctx.to_traceparent(),
                );
            }
        }
        
        // Inject user context (be careful with sensitive data)
        if let Some(user_ctx) = &context.user_context {
            // Only inject essential user context
            let safe_user_ctx = SafeUserContext {
                user_id: user_ctx.user_id,
                roles: user_ctx.roles.clone(),
                tenant_id: user_ctx.tenant_id.clone(),
            };
            
            if let Ok(user_ctx_json) = serde_json::to_string(&safe_user_ctx) {
                headers.insert(
                    self.config.user_context_header.clone(),
                    user_ctx_json,
                );
            }
        }
        
        headers
    }
    
    /// Create outbound request context
    pub fn create_outbound_context(&self, context: &RequestContext, target_service: &str) -> RequestContext {
        context.create_child(target_service.to_string())
    }
}

/// Safe user context for header propagation (excludes sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SafeUserContext {
    user_id: Uuid,
    roles: Vec<String>,
    tenant_id: Option<String>,
}

/// Generate a new trace ID
fn generate_trace_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

/// Generate a new span ID
fn generate_span_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

/// Initialize context propagation
pub fn init_context_propagation(config: &ContextPropagationConfig) -> Result<ContextPropagation, ContractError> {
    Ok(ContextPropagation::new(config.clone()))
}

/// Context propagation middleware factory
pub fn create_context_middleware(propagation: ContextPropagation) -> impl Fn(HashMap<String, String>) -> RequestContext {
    move |headers| propagation.extract_from_headers(&headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_context_creation() {
        let context = RequestContext::new("test-service".to_string());
        assert_eq!(context.service_context.service_name, "test-service");
        assert!(!context.is_authenticated());
    }

    #[test]
    fn test_trace_context_traceparent() {
        let trace_ctx = TraceContext::new();
        let traceparent = trace_ctx.to_traceparent();
        
        let parsed = TraceContext::from_traceparent(&traceparent).unwrap();
        assert_eq!(parsed.trace_id, trace_ctx.trace_id);
        assert_eq!(parsed.trace_flags, trace_ctx.trace_flags);
    }

    #[test]
    fn test_user_context_permissions() {
        let user_ctx = UserContext {
            user_id: Uuid::new_v4(),
            username: "test".to_string(),
            roles: vec!["admin".to_string(), "user".to_string()],
            permissions: vec!["read".to_string(), "write".to_string()],
            session_id: None,
            client_id: None,
            tenant_id: None,
            auth_method: "password".to_string(),
            auth_time: Utc::now(),
        };
        
        assert!(user_ctx.has_role("admin"));
        assert!(user_ctx.has_permission("read"));
        assert!(!user_ctx.has_role("guest"));
        assert!(!user_ctx.has_permission("delete"));
    }

    #[test]
    fn test_context_propagation() {
        let config = ContextPropagationConfig::default();
        let propagation = ContextPropagation::new(config);
        
        let mut headers = HashMap::new();
        headers.insert("x-request-id".to_string(), Uuid::new_v4().to_string());
        headers.insert("traceparent".to_string(), "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string());
        
        let context = propagation.extract_from_headers(&headers);
        assert!(context.trace_context.is_some());
        
        let out_headers = propagation.inject_into_headers(&context);
        assert!(out_headers.contains_key("x-request-id"));
        assert!(out_headers.contains_key("traceparent"));
    }
}