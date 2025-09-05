# API Contracts and Versioning Framework

A comprehensive API versioning and service contracts framework for the Rust Security Platform, providing formal API specifications, context propagation, and backward compatibility management.

## 🎯 Features

### 📋 **Service Contracts (Task 3)**
- **Clear API boundaries** between auth-service and policy-service
- **Type-safe contracts** with async trait definitions
- **Service ownership matrix** defining responsibilities
- **Data ownership boundaries** for multi-service architecture
- **Health check interfaces** with dependency monitoring

### 🔢 **API Versioning (Task 4)**
- **Semantic versioning** with major.minor.patch format
- **OpenAPI/utoipa integration** for documentation generation
- **Deprecation policies** with timeline management
- **Migration strategies** and backward compatibility
- **Version resolution** with compatibility checking

### 🔗 **Context Propagation (Task 8)**
- **Distributed tracing** with W3C traceparent headers
- **Request ID propagation** across service boundaries
- **User context sharing** with security-safe serialization
- **Service metadata** for observability
- **Automatic header injection/extraction**

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         API Contracts Framework                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        │
│  │   Versioning    │    │    Contracts    │    │     Context     │        │
│  │                 │    │                 │    │   Propagation   │        │
│  │ • Semantic Ver  │    │ • Auth Service  │    │ • Trace Context │        │
│  │ • Deprecation   │    │ • Policy Service│    │ • User Context  │        │
│  │ • Migration     │    │ • Health Checks │    │ • Request ID    │        │
│  │ • OpenAPI       │    │ • Service Info  │    │ • Metadata      │        │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘        │
│           │                       │                       │               │
│           └───────────────────────┼───────────────────────┘               │
│                                   │                                       │
│  ┌─────────────────────────────────────────────────────────────────────── │
│  │                           Middleware Layer                             │
│  │                                                                         │
│  │ • Version Resolution      • Context Extraction     • Error Handling    │
│  │ • Header Management       • Trace Propagation      • Response Headers  │
│  │ • Deprecation Warnings    • Security Filtering     • Documentation     │
│  └─────────────────────────────────────────────────────────────────────── │
│           │                       │                       │               │
│           ▼                       ▼                       ▼               │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        │
│  │   Auth Service  │    │ Policy Service  │    │  Other Services │        │
│  │                 │    │                 │    │                 │        │
│  │ • v1.0, v1.1    │    │ • v1.0, v1.1    │    │ • Versioned APIs│        │
│  │ • Authentication│    │ • Authorization │    │ • Context Aware │        │
│  │ • Token Management│   │ • Policy Eval   │    │ • Type Safe     │        │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### 1. Add to Dependencies

```toml
[dependencies]
api-contracts = { path = "./api-contracts", features = ["openapi", "tracing"] }
```

### 2. Initialize Framework

```rust
use api_contracts::{ApiConfig, init_api_framework};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ApiConfig::default();
    init_api_framework(config).await?;
    Ok(())
}
```

### 3. Implement Service Contract

```rust
use api_contracts::{AuthServiceContract, RequestContext, AuthenticationRequest, AuthenticationResponse};
use async_trait::async_trait;

pub struct MyAuthService;

#[async_trait]
impl AuthServiceContract for MyAuthService {
    async fn authenticate(
        &self,
        ctx: &RequestContext,
        request: AuthenticationRequest,
    ) -> Result<AuthenticationResponse, ContractError> {
        // Implementation here
        todo!()
    }
    
    // Other required methods...
}
```

### 4. Add Middleware to Axum App

```rust
use api_contracts::middleware::{ApiMiddlewareState, ApiVersioningMiddleware, ContextPropagationMiddleware};
use axum::{Router, middleware};

let versioning_middleware = ApiVersioningMiddleware::new(version_manager);
let context_middleware = ContextPropagationMiddleware::new(context_propagation);

let middleware_state = ApiMiddlewareState {
    versioning_middleware,
    context_middleware,
};

let app = Router::new()
    .route("/api/auth", post(authenticate_handler))
    .layer(middleware::from_fn_with_state(middleware_state, api_middleware));
```

## 📖 Core Components

### API Versioning

```rust
use api_contracts::{ApiVersion, VersionManager, DeprecationPolicy};

// Create version manager
let mut manager = VersionManager::new(
    ApiVersion::new(1, 0, 0),
    DeprecationPolicy::default(),
);

// Add new versions
manager.add_version(ApiVersion::new(1, 1, 0));
manager.add_version(ApiVersion::new(2, 0, 0));

// Deprecate old versions
manager.deprecate_version(ApiVersion::new(1, 0, 0))?;

// Resolve version for request
let version = manager.resolve_version("/api/auth", Some(&requested_version))?;
```

### Service Contracts

```rust
use api_contracts::{
    AuthServiceContract, PolicyServiceContract, 
    AuthenticationRequest, PolicyEvaluationRequest
};

// Auth service contract implementation
impl AuthServiceContract for AuthService {
    async fn authenticate(&self, ctx: &RequestContext, request: AuthenticationRequest) 
        -> Result<AuthenticationResponse, ContractError> {
        // Validate request
        if let Err(e) = request.validate() {
            return Err(ContractError::DataValidation(e.to_string()));
        }
        
        // Process authentication
        match request.method {
            AuthenticationMethod::Password => {
                // Handle password authentication
            },
            AuthenticationMethod::OAuth => {
                // Handle OAuth authentication
            },
            // Other methods...
        }
    }
}

// Policy service contract implementation
impl PolicyServiceContract for PolicyService {
    async fn evaluate_policy(&self, ctx: &RequestContext, request: PolicyEvaluationRequest)
        -> Result<PolicyEvaluationResponse, ContractError> {
        // Policy evaluation logic
    }
}
```

### Context Propagation

```rust
use api_contracts::{RequestContext, TraceContext, UserContext, ContextPropagation};

// Create request context
let mut context = RequestContext::new("auth-service".to_string())
    .with_trace(TraceContext::new())
    .with_user(UserContext {
        user_id: user_id,
        username: "user123".to_string(),
        roles: vec!["admin".to_string()],
        permissions: vec!["read".to_string(), "write".to_string()],
        // ... other fields
    });

// Propagate context to downstream service
let propagation = ContextPropagation::new(config);
let headers = propagation.inject_into_headers(&context);

// Make HTTP request with context
let client = reqwest::Client::new();
let request = client
    .post("http://policy-service:8081/v1/authorize")
    .headers(headers.into())
    .json(&policy_request);
```

## 🔧 Service Ownership

### Auth Service Responsibilities
- ✅ User authentication (password, OAuth, SAML, MFA)
- ✅ Token issuance and validation (JWT, refresh tokens)
- ✅ Session management and lifecycle
- ✅ User profile management (CRUD operations)
- ✅ Multi-factor authentication flows
- ✅ Password policy enforcement
- ✅ Authentication audit logging

### Policy Service Responsibilities
- ✅ Policy evaluation and authorization decisions
- ✅ Policy definition management (CRUD operations)
- ✅ Cedar policy language processing
- ✅ Policy version control and rollback
- ✅ Policy conflict resolution
- ✅ Authorization audit logging
- ✅ Policy compliance reporting

### Shared Responsibilities
- ✅ Request context propagation
- ✅ Distributed tracing and observability
- ✅ Rate limiting and throttling
- ✅ Security monitoring and alerting
- ✅ Error handling and resilience patterns

## 📊 Data Ownership

### Auth Service Data
- 🔐 User credentials (passwords, MFA secrets)
- 👤 User profiles (personal information, preferences)
- 🎫 Authentication sessions and tokens
- 🔑 OAuth authorization codes and refresh tokens
- 📱 Multi-factor authentication tokens

### Policy Service Data
- 📜 Policy definitions (Cedar policies, XACML, OPA)
- ⚖️ Policy evaluation results and decisions
- 💾 Authorization decision cache
- 📊 Policy metadata (version, author, status)

### Shared Data
- 📋 Audit logs (authentication and authorization events)
- 🚦 Rate limiting counters and quotas
- ⚙️ System configuration and feature flags

## 🔍 Advanced Features

### Deprecation Management

```rust
use api_contracts::{DeprecationPolicy, VersionManager};

// Configure deprecation policy
let policy = DeprecationPolicy {
    notice_period_days: 90,      // 3 months notice
    sunset_period_days: 180,     // 6 months to sunset
    migration_guide_required: true,
    notification_channels: vec![
        "email".to_string(),
        "documentation".to_string(),
        "api-headers".to_string(),
    ],
};

// Deprecate version with automatic sunset
manager.deprecate_version(ApiVersion::new(1, 0, 0))?;

// Headers automatically added to deprecated endpoints:
// Sunset: Wed, 11 Nov 2024 07:28:00 GMT
// Deprecation: true
// Link: </docs/migration/v1.0.0>; rel="successor-version"
```

### OpenAPI Documentation

```rust
use api_contracts::documentation::{DocumentationManager, OpenApiConfig};

// Create documentation manager
let config = OpenApiConfig::default();
let mut docs = DocumentationManager::new(config);

// Generate OpenAPI spec
let openapi_spec = docs.generate_openapi_spec(&ApiVersion::new(1, 0, 0));

// Generate markdown documentation
let markdown_docs = docs.generate_markdown_docs(&ApiVersion::new(1, 0, 0));
```

### Validation and Error Handling

```rust
use api_contracts::{ApiError, ValidationError, types::ApiResponse};
use validator::Validate;

// Request validation
#[derive(Deserialize, Validate)]
struct LoginRequest {
    #[validate(email)]
    email: String,
    
    #[validate(length(min = 8, max = 128))]
    password: String,
}

// Automatic error handling
async fn login_handler(Json(request): Json<LoginRequest>) -> Result<Json<ApiResponse<TokenResponse>>, ApiError> {
    // Validation is handled by middleware
    request.validate().map_err(utils::validation_errors_to_api_error)?;
    
    // Business logic
    let token_response = authenticate_user(&request).await?;
    
    Ok(Json(ApiResponse::success(token_response)))
}
```

### Batch Operations

```rust
use api_contracts::types::{BatchRequest, BatchResponse};

// Batch authentication requests
async fn batch_authenticate(
    Json(batch): Json<BatchRequest<AuthenticationRequest>>
) -> Result<Json<ApiResponse<BatchResponse<AuthenticationResponse, AuthenticationError>>>, ApiError> {
    let mut success = Vec::new();
    let mut errors = Vec::new();
    
    for (index, request) in batch.items.into_iter().enumerate() {
        match authenticate_single(request).await {
            Ok(response) => success.push(BatchResult { index, data: response }),
            Err(error) => errors.push(BatchError { index, error }),
        }
    }
    
    let response = BatchResponse {
        success,
        errors,
        summary: BatchSummary {
            total: batch.items.len(),
            success_count: success.len(),
            error_count: errors.len(),
            processing_time_ms: 150,
        },
    };
    
    Ok(Json(ApiResponse::success(response)))
}
```

## 🧪 Testing

### Contract Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use api_contracts::*;

    #[tokio::test]
    async fn test_auth_service_contract() {
        let service = MyAuthService::new();
        let ctx = RequestContext::new("test-service".to_string());
        
        let request = AuthenticationRequest {
            method: AuthenticationMethod::Password,
            credentials: AuthenticationCredentials::Password {
                username: "test@example.com".to_string(),
                password: "secure_password".to_string(),
            },
            client_info: ClientInfo {
                client_id: "test-client".to_string(),
                user_agent: "test-agent".to_string(),
                ip_address: "127.0.0.1".to_string(),
                device_fingerprint: None,
            },
        };
        
        let response = service.authenticate(&ctx, request).await;
        assert!(response.is_ok());
    }
}
```

### Version Compatibility Testing

```rust
#[tokio::test]
async fn test_version_compatibility() {
    let v1_0 = ApiVersion::new(1, 0, 0);
    let v1_1 = ApiVersion::new(1, 1, 0);
    let v2_0 = ApiVersion::new(2, 0, 0);
    
    // Compatible versions (same major)
    assert!(v1_0.is_compatible_with(&v1_1));
    assert!(v1_1.is_compatible_with(&v1_0));
    
    // Incompatible versions (different major)
    assert!(!v1_0.is_compatible_with(&v2_0));
    assert!(!v2_0.is_compatible_with(&v1_0));
}
```

## 📚 Examples

Complete working examples are available in the test files:

- **Basic Usage**: See `tests/integration_tests.rs` for simple API with versioning
- **Service Integration**: Auth and Policy service integration examples in integration tests
- **Context Propagation**: Distributed tracing examples in middleware tests
- **Error Handling**: Comprehensive error management examples in unit tests

> **Note**: Standalone examples directory is planned for future releases

## 🔧 Configuration

### Environment Variables

```bash
# Service configuration
SERVICE_NAME=auth-service
SERVICE_VERSION=1.1.0
INSTANCE_ID=auth-service-1

# API versioning
API_DEFAULT_VERSION=1.1.0
API_SUPPORTED_VERSIONS=1.0.0,1.1.0,2.0.0

# Context propagation
ENABLE_TRACING=true
TRACE_HEADER=traceparent
REQUEST_ID_HEADER=x-request-id
USER_CONTEXT_HEADER=x-user-context
```

### Configuration File

```toml
# api-config.toml
[api]
current_version = "1.1.0"
supported_versions = ["1.0.0", "1.1.0", "2.0.0"]

[api.service_endpoints]
auth-service = "http://auth-service:8080"
policy-service = "http://policy-service:8081"

[api.context_propagation]
enable_tracing = true
trace_header = "traceparent"
request_id_header = "x-request-id"
user_context_header = "x-user-context"
service_name = "rust-security-platform"

[deprecation]
notice_period_days = 90
sunset_period_days = 180
migration_guide_required = true
notification_channels = ["email", "documentation", "api-headers"]
```

## 🏆 Benefits

### 🔒 **Security**
- **Type-safe contracts** prevent API misuse
- **Context validation** ensures proper request handling
- **Security-aware propagation** prevents information leakage
- **Audit trail integration** for compliance

### 📈 **Scalability**
- **Clear service boundaries** enable independent scaling
- **Efficient context propagation** with minimal overhead
- **Version-specific optimizations** for different API generations
- **Batch operation support** for high-throughput scenarios

### 🛠️ **Developer Experience**
- **Auto-generated documentation** with OpenAPI
- **Type-safe contracts** with compile-time guarantees
- **Clear error messages** with helpful guidance
- **Migration tooling** for version upgrades

### 🔄 **Operational Excellence**
- **Distributed tracing** for debugging and monitoring
- **Deprecation management** with automated warnings
- **Health check standards** for reliability
- **Backward compatibility** for smooth deployments

This API contracts framework provides a solid foundation for building maintainable, scalable, and secure microservices with the Rust Security Platform.
