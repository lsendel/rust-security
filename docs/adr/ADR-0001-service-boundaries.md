# ADR-0001: Service Boundaries and Responsibilities

## Status
Accepted

## Context
The Rust Security Platform consists of multiple services that need clear boundaries and responsibilities to ensure maintainability, scalability, and security. The current architecture includes:
- auth-service: Handles authentication, authorization, and token management
- policy-service: Handles policy evaluation and enforcement decisions
- Additional services for compliance, monitoring, and threat hunting

We need to clearly define the boundaries between these services to avoid overlap, ensure proper separation of concerns, and maintain clear ownership.

## Decision

### Auth Service Responsibilities
- **Authentication**: Verify user/client identity via OIDC, OAuth2, SCIM
- **Token Management**: Issue, refresh, revoke, and validate JWT tokens
- **Key Management**: Generate, rotate, and manage cryptographic keys
- **Session Management**: Handle user sessions and cleanup
- **Rate Limiting**: Apply authentication-specific rate limits
- **Audit Logging**: Log all authentication and authorization events
- **MFA**: Multi-factor authentication flows and TOTP/WebAuthn
- **Client Management**: OAuth client registration and validation

### Policy Service Responsibilities  
- **Policy Evaluation**: Execute Cedar policies against requests
- **Policy Storage**: Store and version policy documents
- **Policy Caching**: Cache frequently used policies with TTL
- **Entity Management**: Manage entities (users, resources, roles)
- **Authorization Decisions**: Return allow/deny decisions with context
- **Policy Analytics**: Track policy usage and performance metrics

### Service Communication Boundaries
- **auth-service → policy-service**: Send authorization requests with context
- **policy-service** never initiates calls to auth-service
- Both services expose metrics independently
- Each service manages its own configuration and secrets

### Data Ownership
- **Auth Service**: Tokens, keys, sessions, client secrets, MFA state
- **Policy Service**: Policies, entities, authorization decisions
- **Shared**: User identities (read-only from OIDC providers)

## Consequences

### Positive
- Clear ownership and responsibility boundaries
- Independent scaling and deployment
- Reduced blast radius for security issues
- Easier testing and development
- Clear API contracts between services

### Negative
- Network overhead for service-to-service calls
- Complexity in distributed tracing and debugging
- Need for service discovery and health checks
- Potential consistency challenges with distributed data

## Alternatives Considered

### Monolithic Service
- **Rejected**: Would make independent scaling difficult and increase blast radius
- **Rejected**: Would complicate testing and deployment

### Fine-grained Microservices
- **Rejected**: Would add unnecessary complexity with current scale
- **Rejected**: Would increase operational overhead without clear benefits

## Related ADRs
- [ADR-0002](ADR-0002-token-storage-strategy.md): Token Storage Strategy
- [ADR-0003](ADR-0003-cryptographic-libraries.md): Cryptographic Libraries Selection