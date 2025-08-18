# Service Contracts

## Overview

This document defines the clear contracts between `auth-service` and `policy-service`, including API boundaries, data models, and ownership responsibilities.

## Service Boundaries

### Auth Service Responsibilities
- **OAuth 2.0/OIDC Provider**: Token issuance, validation, and lifecycle management
- **Authentication**: User login, MFA verification, federated identity
- **Session Management**: Session creation, refresh, invalidation
- **SCIM User/Group Management**: User provisioning and deprovisioning
- **Security Monitoring**: Threat detection, audit logging, rate limiting
- **Token Storage**: Redis-backed token persistence and caching

### Policy Service Responsibilities  
- **Policy Evaluation**: RBAC/ABAC rule processing and decision making
- **Policy Management**: Create, update, delete access policies
- **Policy Caching**: Distributed cache with TTL and invalidation
- **Audit Trail**: Access decision logging and compliance reporting
- **Integration**: External policy engines (OPA, Cedar, etc.)

## API Contracts

### Auth Service → Policy Service

#### 1. Policy Evaluation API

**Endpoint**: `POST /v1/policies/evaluate`

**Request Model**:
```json
{
  "subject": {
    "type": "user",
    "id": "user123",
    "attributes": {
      "roles": ["developer", "team-lead"],
      "groups": ["engineering"],
      "department": "product",
      "clearance_level": "confidential"
    }
  },
  "resource": {
    "type": "api_endpoint",
    "id": "/admin/users",
    "attributes": {
      "method": "POST",
      "sensitive": true,
      "data_classification": "pii"
    }
  },
  "action": {
    "type": "http_request",
    "verb": "CREATE",
    "attributes": {
      "ip_address": "192.168.1.100",
      "user_agent": "PostmanRuntime/7.29.2",
      "timestamp": "2024-01-15T10:30:00Z"
    }
  },
  "environment": {
    "time_of_day": "business_hours",
    "location": "office_network",
    "risk_score": 0.2,
    "mfa_verified": true
  },
  "context": {
    "correlation_id": "req-123e4567-e89b-12d3-a456-426614174000",
    "client_id": "webapp_client",
    "scopes": ["read", "write", "admin"],
    "token_type": "bearer"
  }
}
```

**Response Model**:
```json
{
  "decision": "PERMIT",
  "obligations": [
    {
      "type": "log_access",
      "message": "Administrative action performed",
      "severity": "high"
    },
    {
      "type": "require_mfa",
      "timeout_seconds": 300
    }
  ],
  "advice": [
    {
      "type": "rate_limit",
      "limit": 10,
      "window": "per_minute"
    }
  ],
  "metadata": {
    "policy_version": "v2.1.0",
    "evaluation_time_ms": 15,
    "rules_evaluated": ["admin_access_rule", "pii_protection_rule"],
    "cache_hit": false
  }
}
```

**Error Response**:
```json
{
  "error": "POLICY_EVALUATION_FAILED",
  "message": "Unable to evaluate policy due to missing subject attributes",
  "details": {
    "missing_attributes": ["clearance_level"],
    "correlation_id": "req-123e4567-e89b-12d3-a456-426614174000"
  }
}
```

#### 2. Policy Cache Invalidation API

**Endpoint**: `POST /v1/policies/cache/invalidate`

**Request Model**:
```json
{
  "invalidation_type": "subject",
  "patterns": [
    "user:user123:*",
    "role:admin:*"
  ],
  "reason": "user_role_change",
  "correlation_id": "cache-inv-456"
}
```

#### 3. Bulk Policy Evaluation API

**Endpoint**: `POST /v1/policies/evaluate/batch`

**Request Model**:
```json
{
  "evaluations": [
    {
      "id": "eval_1",
      "subject": { /* subject object */ },
      "resource": { /* resource object */ },
      "action": { /* action object */ }
    }
  ],
  "options": {
    "fail_fast": false,
    "include_metadata": true
  }
}
```

### Policy Service → Auth Service

#### 1. Policy Update Notifications API

**Endpoint**: `POST /v1/notifications/policy-update`

**Request Model**:
```json
{
  "event_type": "POLICY_UPDATED",
  "policy_id": "admin_access_policy_v2",
  "affected_subjects": ["user:admin_*", "role:super_admin"],
  "affected_resources": ["/admin/*"],
  "version": "2.1.0",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Data Models

### Core Entities

#### Subject Model
```json
{
  "type": "user" | "service_account" | "api_key",
  "id": "string",
  "attributes": {
    "roles": ["string"],
    "groups": ["string"],
    "department": "string",
    "clearance_level": "public" | "internal" | "confidential" | "restricted",
    "employment_type": "full_time" | "contractor" | "intern",
    "location": "string",
    "valid_until": "ISO8601"
  }
}
```

#### Resource Model  
```json
{
  "type": "api_endpoint" | "data_object" | "system_resource",
  "id": "string",
  "attributes": {
    "method": "GET" | "POST" | "PUT" | "DELETE",
    "path_pattern": "string",
    "sensitive": boolean,
    "data_classification": "public" | "internal" | "confidential" | "restricted",
    "owner": "string",
    "tags": ["string"]
  }
}
```

#### Action Model
```json
{
  "type": "http_request" | "data_access" | "system_operation", 
  "verb": "CREATE" | "READ" | "UPDATE" | "DELETE" | "EXECUTE",
  "attributes": {
    "ip_address": "string",
    "user_agent": "string",
    "timestamp": "ISO8601",
    "request_size": "number",
    "frequency": "number"
  }
}
```

#### Decision Model
```json
{
  "decision": "PERMIT" | "DENY" | "INDETERMINATE",
  "obligations": [
    {
      "type": "log_access" | "require_mfa" | "rate_limit",
      "parameters": {}
    }
  ],
  "advice": [
    {
      "type": "string",
      "parameters": {}
    }
  ]
}
```

## Error Handling

### Standard Error Codes
- `POLICY_NOT_FOUND`: Requested policy does not exist
- `POLICY_EVALUATION_FAILED`: Error during policy evaluation
- `INSUFFICIENT_CONTEXT`: Missing required evaluation context
- `POLICY_ENGINE_UNAVAILABLE`: Backend policy engine is down
- `INVALID_REQUEST`: Malformed request payload
- `RATE_LIMIT_EXCEEDED`: Too many evaluation requests
- `CACHE_MISS_TIMEOUT`: Cache lookup exceeded timeout

### Error Response Format
```json
{
  "error": "ERROR_CODE",
  "message": "Human readable error message",
  "details": {
    "field": "Additional context",
    "correlation_id": "req-123",
    "retry_after_seconds": 30
  },
  "timestamp": "ISO8601"
}
```

## Performance Requirements

### SLA Targets
- **Policy Evaluation Latency**: 
  - P50: < 10ms
  - P90: < 25ms  
  - P99: < 50ms
- **Availability**: 99.9% uptime
- **Throughput**: 10,000 evaluations/second
- **Cache Hit Rate**: > 95%

### Timeout Configuration
- **Network Timeout**: 5 seconds
- **Circuit Breaker**: 3 failures trigger open state
- **Retry Policy**: Exponential backoff (100ms, 200ms, 400ms)

## Security Requirements

### Authentication
- **Service-to-Service**: mTLS with client certificates
- **Request Signing**: HMAC-SHA256 for critical operations
- **Token Validation**: JWT bearer tokens for API access

### Authorization
- **Auth Service**: Can evaluate policies for any subject/resource
- **Policy Service**: Admin operations require elevated privileges
- **Audit Requirements**: All policy evaluations must be logged

### Data Protection
- **PII Handling**: Subject attributes containing PII must be masked in logs
- **Data Classification**: Respect resource classification levels
- **Encryption**: All inter-service communication over TLS 1.3

## Integration Patterns

### Synchronous Operations
- Policy evaluation (real-time authorization decisions)
- Cache invalidation (immediate consistency)
- Health checks and readiness probes

### Asynchronous Operations  
- Policy update notifications (event-driven)
- Audit log shipping (batch processing)
- Metrics and monitoring data (streaming)

### Circuit Breaker Patterns
- **Policy Service Unavailable**: Auth service falls back to cached policies
- **Degraded Mode**: Allow basic operations, deny complex authorizations
- **Recovery**: Gradual traffic restoration with health checks

## Versioning Strategy

### API Versioning
- **Semantic Versioning**: Major.Minor.Patch (e.g., v2.1.0)
- **Backward Compatibility**: Minor versions are backward compatible
- **Deprecation Policy**: 6-month notice for breaking changes
- **Version Header**: `API-Version: 2.1` in all requests

### Policy Schema Versioning
- **Schema Evolution**: Additive changes only in minor versions
- **Migration Path**: Automated schema upgrade procedures
- **Rollback Support**: Previous version compatibility for 30 days

## Monitoring and Observability

### Key Metrics
- Policy evaluation success/failure rates
- Response time percentiles
- Cache hit/miss ratios
- Circuit breaker state transitions
- Error rates by type

### Distributed Tracing
- **Correlation IDs**: Propagated across all service calls
- **Span Attributes**: Subject/resource/action metadata
- **Error Tracking**: Detailed stack traces and context

### Health Checks
- **Liveness**: Service process health
- **Readiness**: Dependencies (cache, policy engine) availability
- **Dependency Checks**: Downstream service connectivity

## Testing Strategy

### Contract Testing
- **Pact**: Consumer-driven contract tests
- **Schema Validation**: Request/response format verification
- **Backward Compatibility**: Version compatibility testing

### Integration Testing
- **End-to-End Flows**: Full authorization scenarios
- **Failure Scenarios**: Network failures, timeouts, invalid data
- **Performance Testing**: Load testing at SLA targets

### Security Testing
- **Penetration Testing**: Authorization bypass attempts
- **Fuzzing**: Malformed request handling
- **Privilege Escalation**: Unauthorized access attempts