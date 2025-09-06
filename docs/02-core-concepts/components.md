# Component Architecture

Detailed architecture of individual components in the Rust Security Platform.

## Overview

This document provides detailed architecture information for individual components in the Rust Security Platform. The platform consists of several core services, each with its own architecture and design patterns.

## Architecture

The Rust Security Platform implements a microservices architecture with clearly defined boundaries between components. Each service is designed to be independently deployable and scalable while maintaining secure communication between services.

## Auth Service Architecture

The Auth Service is the core authentication component providing OAuth 2.0, OpenID Connect, and user management functionality.

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            AUTH SERVICE                                     │
│                              (Port 8080)                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   API Layer     │  │ Business Logic  │  │   Data Access   │             │
│  │                 │  │                 │  │                 │             │
│  │ • HTTP Handlers │  │ • OAuth Flows   │  │ • Redis Client  │             │
│  │ • Middleware    │  │ • Token Mgmt    │  │ • DB Client     │             │
│  │ • Validation    │  │ • User Mgmt     │  │ • Cache Layer   │             │
│  │ • Rate Limiting │  │ • MFA Handling  │  │ • Repositories  │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   Security      │  │   Monitoring    │  │ Infrastructure  │             │
│  │                 │  │                 │  │                 │             │
│  │ • JWT Signing   │  │ • Metrics       │  │ • Config Mgmt   │             │
│  │ • Crypto        │  │ • Logging       │  │ • Health Checks │             │
│  │ • MFA Crypto    │  │ • Tracing       │  │ • Graceful      │             │
│  │ • TLS           │  │ • Audit Trail   │  │   Shutdown      │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### API Layer

#### HTTP Handlers

```rust
// Main router structure
pub struct AuthRouter {
    oauth_handler: OAuthHandler,
    user_handler: UserHandler,
    mfa_handler: MfaHandler,
    scim_handler: ScimHandler,
    admin_handler: AdminHandler,
}

impl AuthRouter {
    pub fn routes(&self) -> Router {
        Router::new()
            // OAuth 2.0 endpoints
            .route("/oauth/authorize", get(oauth_authorize))
            .route("/oauth/token", post(oauth_token))
            .route("/oauth/introspect", post(oauth_introspect))
            .route("/oauth/revoke", post(oauth_revoke))
            
            // OIDC endpoints
            .route("/oauth/userinfo", get(oidc_userinfo))
            .route("/.well-known/openid-configuration", get(oidc_discovery))
            .route("/.well-known/jwks.json", get(jwks_endpoint))
            
            // User management
            .route("/api/v1/auth/register", post(user_register))
            .route("/api/v1/auth/login", post(user_login))
            .route("/api/v1/auth/logout", post(user_logout))
            .route("/api/v1/auth/me", get(user_profile))
            
            // MFA endpoints
            .route("/mfa/totp/setup", post(totp_setup))
            .route("/mfa/totp/verify", post(totp_verify))
            .route("/mfa/webauthn/register", post(webauthn_register))
            .route("/mfa/webauthn/verify", post(webauthn_verify))
            
            // SCIM 2.0 endpoints
            .route("/scim/v2/Users", get(scim_list_users).post(scim_create_user))
            .route("/scim/v2/Users/:id", get(scim_get_user).put(scim_update_user).delete(scim_delete_user))
            
            // Admin endpoints
            .route("/admin/health", get(admin_health))
            .route("/admin/metrics", get(admin_metrics))
            .route("/admin/status", get(admin_status))
    }
}
```

#### Middleware

```rust
// Security middleware stack
pub struct SecurityMiddleware {
    rate_limiter: RateLimiter,
    security_headers: SecurityHeaders,
    request_validator: RequestValidator,
    auth_middleware: AuthMiddleware,
}

impl SecurityMiddleware {
    pub fn apply(&self, app: Router) -> Router {
        app
            // Rate limiting
            .layer(self.rate_limiter.layer())
            // Security headers
            .layer(self.security_headers.layer())
            // Request validation
            .layer(self.request_validator.layer())
            // Authentication
            .layer(self.auth_middleware.layer())
    }
}
```

### Business Logic Layer

#### OAuth Flow Implementation

```rust
pub struct OAuthService {
    token_manager: TokenManager,
    client_manager: ClientManager,
    user_manager: UserManager,
    policy_client: PolicyClient,
    session_manager: SessionManager,
}

impl OAuthService {
    // Authorization Code Flow
    pub async fn authorization_code_flow(&self, request: AuthorizationRequest) -> Result<AuthorizationResponse, OAuthError> {
        // 1. Validate client
        self.client_manager.validate_client(&request.client_id).await?;
        
        // 2. Validate redirect URI
        self.client_manager.validate_redirect_uri(&request.client_id, &request.redirect_uri).await?;
        
        // 3. Validate PKCE (if required)
        if let Some(challenge) = &request.code_challenge {
            self.validate_pkce(challenge, &request.code_challenge_method)?;
        }
        
        // 4. Create authorization code
        let auth_code = self.token_manager.generate_authorization_code(
            &request.client_id,
            &request.redirect_uri,
            &request.scope,
            request.code_challenge.clone(),
        ).await?;
        
        // 5. Return authorization response
        Ok(AuthorizationResponse {
            code: auth_code,
            state: request.state,
        })
    }
    
    // Token Exchange
    pub async fn token_exchange(&self, request: TokenRequest) -> Result<TokenResponse, OAuthError> {
        match request.grant_type {
            GrantType::AuthorizationCode => {
                self.exchange_authorization_code(request).await
            }
            GrantType::ClientCredentials => {
                self.client_credentials_flow(request).await
            }
            GrantType::RefreshToken => {
                self.refresh_token_flow(request).await
            }
            GrantType::Password => {
                self.password_grant_flow(request).await
            }
        }
    }
}
```

#### Token Management

```rust
pub struct TokenManager {
    redis_client: RedisClient,
    jwt_signer: JwtSigner,
    key_manager: KeyManager,
    token_repository: TokenRepository,
}

impl TokenManager {
    // Generate access token
    pub async fn generate_access_token(&self, claims: TokenClaims) -> Result<String, TokenError> {
        let jwt_claims = JwtClaims {
            iss: self.config.issuer.clone(),
            sub: claims.subject,
            aud: claims.audience,
            exp: Utc::now() + self.config.access_token_ttl,
            iat: Utc::now(),
            scope: claims.scope,
            client_id: claims.client_id,
            // Additional claims for security
            nonce: claims.nonce,
            auth_time: claims.auth_time,
            acr: claims.acr,
            amr: claims.amr,
        };
        
        let token = self.jwt_signer.sign(jwt_claims).await?;
        self.store_token_metadata(&token, &claims).await?;
        Ok(token)
    }
    
    // Generate refresh token
    pub async fn generate_refresh_token(&self, claims: TokenClaims) -> Result<String, TokenError> {
        let refresh_token = generate_secure_random_string(128);
        let metadata = RefreshTokenMetadata {
            token: refresh_token.clone(),
            user_id: claims.subject,
            client_id: claims.client_id,
            scope: claims.scope,
            expires_at: Utc::now() + self.config.refresh_token_ttl,
            issued_at: Utc::now(),
            used: false,
        };
        
        self.token_repository.store_refresh_token(metadata).await?;
        Ok(refresh_token)
    }
    
    // Refresh token rotation
    pub async fn rotate_refresh_token(&self, old_token: &str) -> Result<(String, String), TokenError> {
        // Validate and mark old token as used
        let old_metadata = self.token_repository.get_refresh_token(old_token).await?;
        if old_metadata.used {
            // Token reuse detected - revoke all tokens for user
            self.revoke_all_user_tokens(&old_metadata.user_id).await?;
            return Err(TokenError::TokenReuseDetected);
        }
        
        self.token_repository.mark_token_as_used(old_token).await?;
        
        // Generate new tokens
        let claims = TokenClaims {
            subject: old_metadata.user_id,
            client_id: old_metadata.client_id,
            scope: old_metadata.scope,
            ..Default::default()
        };
        
        let access_token = self.generate_access_token(claims.clone()).await?;
        let refresh_token = self.generate_refresh_token(claims).await?;
        
        Ok((access_token, refresh_token))
    }
}
```

### Data Access Layer

#### Redis Client

```rust
pub struct RedisClient {
    pool: RedisPool,
    config: RedisConfig,
}

impl RedisClient {
    // Store session with expiration
    pub async fn store_session(&self, session: &Session) -> Result<(), RedisError> {
        let mut conn = self.pool.get().await?;
        let key = format!("session:{}", session.id);
        let value = serde_json::to_string(session)?;
        let ttl = session.expires_at.timestamp() - Utc::now().timestamp();
        
        redis::cmd("SETEX")
            .arg(&key)
            .arg(ttl)
            .arg(&value)
            .query_async(&mut conn)
            .await?;
            
        Ok(())
    }
    
    // Get session with atomic update
    pub async fn get_and_update_session(&self, session_id: &str) -> Result<Option<Session>, RedisError> {
        let mut conn = self.pool.get().await?;
        let key = format!("session:{}", session_id);
        
        // Atomic get and update last activity
        let value: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await?;
            
        if let Some(session_str) = value {
            let mut session: Session = serde_json::from_str(&session_str)?;
            session.last_activity = Some(Utc::now());
            
            // Update session with new last activity
            let updated_value = serde_json::to_string(&session)?;
            redis::cmd("SET")
                .arg(&key)
                .arg(updated_value)
                .query_async(&mut conn)
                .await?;
                
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }
}
```

#### Database Client

```rust
pub struct DatabaseClient {
    pool: PgPool,
    config: DatabaseConfig,
}

impl DatabaseClient {
    // User operations with transactions
    pub async fn create_user(&self, user: NewUser) -> Result<User, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        
        // Insert user record
        let user_record = sqlx::query_as!(
            UserRecord,
            r#"
            INSERT INTO users (username, email, password_hash, first_name, last_name, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
            RETURNING id, username, email, first_name, last_name, created_at, updated_at, last_login, status
            "#,
            user.username,
            user.email,
            user.password_hash,
            user.first_name,
            user.last_name
        )
        .fetch_one(&mut tx)
        .await?;
        
        // Insert user profile
        sqlx::query!(
            r#"
            INSERT INTO user_profiles (user_id, phone_number, department, require_mfa, email_verified)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            user_record.id,
            user.phone_number,
            user.department,
            user.require_mfa,
            false
        )
        .execute(&mut tx)
        .await?;
        
        tx.commit().await?;
        
        Ok(User::from_record(user_record))
    }
    
    // Audit logging
    pub async fn log_audit_event(&self, event: AuditEvent) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            INSERT INTO audit_log (event_type, timestamp, user_id, client_id, ip_address, user_agent, session_id, resource, action, outcome, details)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            event.event_type as i32,
            event.timestamp,
            event.user_id,
            event.client_id,
            event.ip_address,
            event.user_agent,
            event.session_id,
            event.resource,
            event.action,
            event.outcome as i32,
            serde_json::to_value(&event.details)?
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
}
```

## Policy Service Architecture

The Policy Service provides authorization policy evaluation using the Cedar policy language.

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          POLICY SERVICE                                     │
│                              (Port 8081)                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   API Layer     │  │ Business Logic  │  │   Data Access   │             │
│  │                 │  │                 │  │                 │             │
│  │ • HTTP Handlers │  │ • Policy Engine │  │ • File Storage  │             │
│  │ • Middleware    │  │ • Evaluation    │  │ • Cache Layer   │             │
│  │ • Validation    │  │ • Entity Mgmt   │  │ • Repositories  │             │
│  │ • Rate Limiting │  │ • Audit Logging │  │                 │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   Security      │  │   Monitoring    │  │ Infrastructure  │             │
│  │                 │  │                 │  │                 │             │
│  │ • TLS           │  │ • Metrics       │  │ • Config Mgmt   │             │
│  │ • Validation    │  │ • Logging       │  │ • Health Checks │             │
│  │                 │  │ • Tracing       │  │ • Graceful      │             │
│  │                 │  │ • Audit Trail   │  │   Shutdown      │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Policy Engine Implementation

```rust
pub struct PolicyEngine {
    cedar_engine: CedarEngine,
    policy_cache: PolicyCache,
    entity_store: EntityStore,
    audit_logger: AuditLogger,
}

impl PolicyEngine {
    // Evaluate authorization request
    pub async fn evaluate(&self, request: AuthorizationRequest) -> Result<AuthorizationResponse, PolicyError> {
        // 1. Load policies from cache or file system
        let policies = self.policy_cache.get_policies().await?;
        
        // 2. Load entities
        let entities = self.entity_store.get_entities_for_principal(&request.principal).await?;
        
        // 3. Create Cedar request
        let cedar_request = CedarRequest {
            principal: request.principal.into(),
            action: request.action.into(),
            resource: request.resource.into(),
            context: request.context.map(|c| c.into()),
        };
        
        // 4. Evaluate policies
        let result = self.cedar_engine.evaluate(&policies, &entities, &cedar_request).await?;
        
        // 5. Log audit event
        self.audit_logger.log_authorization_decision(&request, &result).await?;
        
        // 6. Return response
        Ok(AuthorizationResponse {
            decision: result.decision.into(),
            obligations: result.obligations.into_iter().map(|o| o.into()).collect(),
            advice: result.advice.into_iter().map(|a| a.into()).collect(),
        })
    }
    
    // Batch evaluation
    pub async fn evaluate_batch(&self, requests: Vec<AuthorizationRequest>) -> Result<Vec<AuthorizationResponse>, PolicyError> {
        let mut responses = Vec::new();
        
        // Load policies and entities once for batch
        let policies = self.policy_cache.get_policies().await?;
        let entities = self.entity_store.get_all_entities().await?;
        
        for request in requests {
            let cedar_request = CedarRequest {
                principal: request.principal.into(),
                action: request.action.into(),
                resource: request.resource.into(),
                context: request.context.map(|c| c.into()),
            };
            
            let result = self.cedar_engine.evaluate(&policies, &entities, &cedar_request).await?;
            self.audit_logger.log_authorization_decision(&request, &result).await?;
            
            responses.push(AuthorizationResponse {
                decision: result.decision.into(),
                obligations: result.obligations.into_iter().map(|o| o.into()).collect(),
                advice: result.advice.into_iter().map(|a| a.into()).collect(),
            });
        }
        
        Ok(responses)
    }
}
```

### Policy Cache

```rust
pub struct PolicyCache {
    inner: Arc<RwLock<HashMap<String, CachedPolicy>>>,
    file_watcher: FileWatcher,
    ttl: Duration,
}

impl PolicyCache {
    // Get policies with TTL check
    pub async fn get_policies(&self) -> Result<Vec<Policy>, PolicyError> {
        let cache = self.inner.read().await;
        let now = SystemTime::now();
        
        let mut valid_policies = Vec::new();
        let mut expired_keys = Vec::new();
        
        for (key, cached_policy) in cache.iter() {
            if now.duration_since(cached_policy.cached_at)? < self.ttl {
                valid_policies.push(cached_policy.policy.clone());
            } else {
                expired_keys.push(key.clone());
            }
        }
        
        drop(cache);
        
        // Remove expired policies
        if !expired_keys.is_empty() {
            let mut cache = self.inner.write().await;
            for key in expired_keys {
                cache.remove(&key);
            }
        }
        
        // If no policies in cache, load from file system
        if valid_policies.is_empty() {
            valid_policies = self.load_policies_from_filesystem().await?;
            self.update_cache(&valid_policies).await?;
        }
        
        Ok(valid_policies)
    }
    
    // Update cache with new policies
    pub async fn update_cache(&self, policies: &[Policy]) -> Result<(), PolicyError> {
        let mut cache = self.inner.write().await;
        cache.clear();
        
        for policy in policies {
            let cached_policy = CachedPolicy {
                policy: policy.clone(),
                cached_at: SystemTime::now(),
            };
            cache.insert(policy.id.clone(), cached_policy);
        }
        
        Ok(())
    }
}
```

## Data Layer Architecture

### Redis Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              REDIS CLUSTER                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   Database 0    │  │   Database 1    │  │   Database 2    │             │
│  │                 │  │                 │  │                 │             │
│  │ • Sessions      │  │ • Tokens        │  │ • Rate Limits   │             │
│  │ • Cache         │  │ • Cache         │  │ • Cache         │             │
│  │ • MFA Data      │  │ • User Data     │  │ • Stats         │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   Database 3    │  │   Database 4    │  │   Database 5    │             │
│  │                 │  │                 │  │                 │             │
│  │ • Config        │  │ • Audit Data    │  │ • Temp Data     │             │
│  │ • Settings      │  │ • Logs          │  │ • Queue         │             │
│  │ • Metadata      │  │ • Events        │  │ • Locks         │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### PostgreSQL Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           POSTGRESQL DATABASE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   Users         │  │   Clients       │  │   Sessions      │             │
│  │                 │  │                 │  │                 │             │
│  │ • user_id       │  │ • client_id     │  │ • session_id    │             │
│  │ • username      │  │ • client_secret │  │ • user_id       │             │
│  │ • email         │  │ • redirect_uris │  │ • created_at    │             │
│  │ • password_hash │  │ • grant_types   │  │ • expires_at    │             │
│  │ • first_name    │  │ • scopes        │  │ • last_activity │             │
│  │ • last_name     │  │ • ...           │  │ • ...           │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   Tokens        │  │   Audit Log     │  │   Configuration │             │
│  │                 │  │                 │  │                 │             │
│  │ • token_id      │  │ • event_id      │  │ • config_id     │             │
│  │ • user_id       │  │ • timestamp     │  │ • key           │             │
│  │ • client_id     │  │ • event_type    │  │ • value         │             │
│  │ • token_type    │  │ • user_id       │  │ • description   │             │
│  │ • expires_at    │  │ • client_id     │  │ • updated_at    │             │
│  │ • scope         │  │ • ip_address    │  │                 │             │
│  │ • ...           │  │ • ...           │  │                 │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Security Components

### JWT Signing Architecture

```rust
pub struct JwtSigner {
    key_manager: KeyManager,
    algorithm: SigningAlgorithm,
}

impl JwtSigner {
    pub async fn sign(&self, claims: JwtClaims) -> Result<String, JwtError> {
        // Get current signing key
        let signing_key = self.key_manager.get_current_key().await?;
        
        // Create JWT header
        let header = json!({
            "alg": self.algorithm.as_str(),
            "typ": "JWT",
            "kid": signing_key.key_id
        });
        
        // Encode header and claims
        let header_b64 = base64_url_encode(serde_json::to_string(&header)?.as_bytes());
        let claims_b64 = base64_url_encode(serde_json::to_string(&claims)?.as_bytes());
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        
        // Sign the input
        let signature = signing_key.sign(signing_input.as_bytes()).await?;
        let signature_b64 = base64_url_encode(&signature);
        
        Ok(format!("{}.{}", signing_input, signature_b64))
    }
    
    pub async fn verify(&self, token: &str) -> Result<JwtClaims, JwtError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::InvalidFormat);
        }
        
        let header_b64 = parts[0];
        let claims_b64 = parts[1];
        let signature_b64 = parts[2];
        
        // Decode header
        let header_json = base64_url_decode(header_b64)?;
        let header: JwtHeader = serde_json::from_slice(&header_json)?;
        
        // Get key for verification
        let verifying_key = self.key_manager.get_key_by_id(&header.kid).await?;
        
        // Verify signature
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let signature = base64_url_decode(signature_b64)?;
        verifying_key.verify(signing_input.as_bytes(), &signature).await?;
        
        // Decode claims
        let claims_json = base64_url_decode(claims_b64)?;
        let claims: JwtClaims = serde_json::from_slice(&claims_json)?;
        
        // Validate claims
        self.validate_claims(&claims).await?;
        
        Ok(claims)
    }
}
```

### Key Management Architecture

```rust
pub struct KeyManager {
    storage: KeyStorage,
    rotation_scheduler: RotationScheduler,
    config: KeyConfig,
}

impl KeyManager {
    // Automatic key rotation
    pub async fn rotate_keys(&self) -> Result<(), KeyError> {
        // Generate new key
        let new_key = self.generate_new_key().await?;
        let kid = format!("key-{}", Utc::now().format("%Y-%m-%d"));
        
        // Store new key
        self.storage.store_key(&kid, &new_key).await?;
        
        // Update current key pointer
        self.storage.set_current_key(&kid).await?;
        
        // Archive old key (keep last 3 for verification)
        self.archive_old_keys(3).await?;
        
        // Notify services of key rotation
        self.notify_key_rotation(&kid).await?;
        
        Ok(())
    }
    
    // Get current signing key
    pub async fn get_current_key(&self) -> Result<Arc<SigningKey>, KeyError> {
        let kid = self.storage.get_current_key_id().await?;
        self.storage.get_key(&kid).await
    }
    
    // Get key by ID for verification
    pub async fn get_key_by_id(&self, kid: &str) -> Result<Arc<VerifyingKey>, KeyError> {
        self.storage.get_key(kid).await
    }
}
```

## Monitoring Components

### Metrics Architecture

```rust
pub struct MetricsCollector {
    registry: Registry,
    auth_metrics: AuthMetrics,
    policy_metrics: PolicyMetrics,
    security_metrics: SecurityMetrics,
}

impl MetricsCollector {
    pub fn new() -> Self {
        let registry = Registry::new();
        
        let auth_metrics = AuthMetrics::new(&registry);
        let policy_metrics = PolicyMetrics::new(&registry);
        let security_metrics = SecurityMetrics::new(&registry);
        
        Self {
            registry,
            auth_metrics,
            policy_metrics,
            security_metrics,
        }
    }
    
    // Record authentication metrics
    pub async fn record_auth_attempt(&self, result: &AuthResult) {
        match result {
            AuthResult::Success => {
                self.auth_metrics.success.inc();
            }
            AuthResult::Failure(reason) => {
                self.auth_metrics.failures.inc();
                match reason {
                    AuthFailureReason::InvalidCredentials => {
                        self.auth_metrics.invalid_credentials.inc();
                    }
                    AuthFailureReason::AccountLocked => {
                        self.auth_metrics.account_locked.inc();
                    }
                    AuthFailureReason::RateLimitExceeded => {
                        self.auth_metrics.rate_limit_exceeded.inc();
                    }
                }
            }
        }
    }
    
    // Record policy evaluation metrics
    pub async fn record_policy_evaluation(&self, decision: &PolicyDecision, duration: Duration) {
        match decision {
            PolicyDecision::Allow => {
                self.policy_metrics.allow.inc();
            }
            PolicyDecision::Deny => {
                self.policy_metrics.deny.inc();
            }
        }
        
        self.policy_metrics.evaluation_duration.observe(duration.as_secs_f64());
    }
}
```

## Next Steps

To understand the component interactions:

1. **Data Architecture**: How data flows between components
2. **Security Architecture**: Detailed security implementation
3. **Integration Patterns**: How to integrate with the platform
4. **Performance Architecture**: Optimization strategies

For API details, see the [API Reference](../03-api-reference/README.md).