# ADR-0002: Token Storage Strategy

## Status
Accepted

## Context
The auth-service needs to store various types of tokens and session data:
- Access tokens and refresh tokens
- Session state and cleanup tracking
- Token revocation lists
- Rate limiting counters
- Temporary authorization codes

We need a storage strategy that provides:
- High availability and low latency
- Atomic operations for token lifecycle
- TTL-based expiration
- Scalability for high token volume
- Durability for critical tokens

## Decision

### Primary Storage: Redis with Fallback
- **Redis**: Primary token store for production deployments
- **In-Memory HashMap**: Fallback for development/testing
- **Connection Pooling**: Use bb8-redis for efficient connection management
- **Clustering**: Support Redis cluster for high availability

### Token Storage Patterns
```rust
// Token storage keys
access_token:{token_id} -> TokenData
refresh_token:{token_id} -> RefreshTokenData  
session:{session_id} -> SessionData
revoked:{token_id} -> RevocationReason
rate_limit:{client_id}:{window} -> Counter
authz_code:{code} -> AuthorizationData
```

### TTL Strategy
- Access tokens: 1 hour default TTL
- Refresh tokens: 30 days default TTL  
- Authorization codes: 10 minutes TTL
- Rate limit counters: Window-based TTL
- Sessions: Configurable TTL (default 24 hours)

### Consistency Guarantees
- Use Redis transactions for atomic token operations
- Implement optimistic locking for token refresh
- Graceful degradation if Redis is unavailable
- Periodic cleanup of expired data

## Consequences

### Positive
- High performance for token operations
- Automatic expiration with Redis TTL
- Atomic operations prevent race conditions
- Scales horizontally with Redis clustering
- Clear separation of concerns

### Negative  
- External dependency on Redis
- Need for Redis monitoring and backups
- Network latency for token operations
- Memory usage for large token volumes
- Complexity in fallback scenarios

## Alternatives Considered

### PostgreSQL/Database Storage
- **Rejected**: Higher latency for simple key-value operations
- **Rejected**: More complex for TTL-based expiration
- **Considered**: May be needed for long-term audit logs

### Pure In-Memory Storage
- **Rejected**: No persistence across restarts
- **Rejected**: Doesn't scale across multiple instances
- **Used**: Only as fallback for development

### Distributed Cache (Hazelcast/etc.)
- **Rejected**: Adds complexity without clear benefits over Redis
- **Rejected**: Less mature ecosystem in Rust

## Implementation Details

### TokenStore Trait
```rust
#[async_trait]
pub trait TokenStore {
    async fn store_token(&self, token_id: &str, data: TokenData, ttl: Duration) -> Result<()>;
    async fn get_token(&self, token_id: &str) -> Result<Option<TokenData>>;
    async fn revoke_token(&self, token_id: &str, reason: RevocationReason) -> Result<()>;
    async fn is_revoked(&self, token_id: &str) -> Result<bool>;
    async fn cleanup_expired(&self) -> Result<u64>;
}
```

### Error Handling
- Graceful fallback to in-memory store if Redis fails
- Retry logic with exponential backoff
- Circuit breaker to prevent cascade failures
- Clear error boundaries and logging

## Related ADRs
- [ADR-0001](ADR-0001-service-boundaries.md): Service Boundaries and Responsibilities
- [ADR-0003](ADR-0003-cryptographic-libraries.md): Cryptographic Libraries Selection