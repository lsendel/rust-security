# 🔧 Troubleshooting Guide

Comprehensive guide to diagnosing and fixing common issues with auth-core OAuth 2.0 implementation.

## Table of Contents

1. [Quick Diagnostic Checklist](#quick-diagnostic-checklist)
2. [Token Issues](#token-issues)
3. [Authentication Failures](#authentication-failures)
4. [Permission & Scope Problems](#permission--scope-problems)
5. [Network & Connection Issues](#network--connection-issues)
6. [Performance Problems](#performance-problems)
7. [Configuration Issues](#configuration-issues)
8. [Integration Problems](#integration-problems)
9. [Security Concerns](#security-concerns)
10. [Debugging Tools & Techniques](#debugging-tools--techniques)

---

## Quick Diagnostic Checklist

When something isn't working, start here:

### ✅ **1-Minute Health Check**

```bash
# 1. Is the server running?
curl http://localhost:8080/health
# Expected: {"status": "ok", ...}

# 2. Can you get a token?
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=client_credentials&client_id=YOUR_CLIENT&client_secret=YOUR_SECRET"
# Expected: {"access_token": "...", "token_type": "Bearer", ...}

# 3. Can you use the token?
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8080/api/profile
# Expected: 200 OK response

# 4. Check logs for errors
docker logs your-auth-container
# or
tail -f /var/log/auth-service.log
```

### 📋 **Common Issue Patterns**

| Symptom | Most Likely Cause | Quick Fix |
|---------|------------------|-----------|
| `{"error": "invalid_client"}` | Wrong credentials | Check client_id/secret |
| `401 Unauthorized` | Missing/wrong token | Check Authorization header |
| `403 Forbidden` | Missing scope | Check token scopes |
| `500 Internal Server Error` | Server configuration | Check logs & config |
| Connection refused | Server not running | Start the server |
| Slow responses | Performance issue | Check resource usage |

---

## Token Issues

### 🚨 **Problem: "Invalid Client" Error**

**Symptoms:**
```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

**Diagnostic Steps:**

1. **Verify Client Registration**
   ```rust
   // In your server code, check if client is registered
   let server = AuthServer::minimal()
       .with_client("my_client", "my_secret")  // ← These must match exactly
       .build()?;
   ```

2. **Check Request Format**
   ```bash
   # ✅ Correct format
   curl -X POST http://localhost:8080/oauth/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=client_credentials" \
     -d "client_id=my_client" \
     -d "client_secret=my_secret"
   
   # ❌ Common mistakes
   curl -X POST http://localhost:8080/oauth/token \
     -H "Content-Type: application/json" \  # Wrong content type
     -d '{"client_id": "my_client"}'        # Wrong format
   ```

3. **Debug Client Lookup**
   ```rust
   // Add debug logging to see what's happening
   #[derive(Debug)]
   pub struct AuthServer {
       clients: HashMap<String, ClientConfig>,
   }
   
   impl AuthServer {
       pub fn validate_client(&self, client_id: &str, client_secret: &str) -> bool {
           log::debug!("Validating client: {}", client_id);
           log::debug!("Available clients: {:?}", self.clients.keys().collect::<Vec<_>>());
           
           if let Some(client) = self.clients.get(client_id) {
               let is_valid = client.client_secret == client_secret;
               log::debug!("Client {} validation result: {}", client_id, is_valid);
               is_valid
           } else {
               log::warn!("Client {} not found", client_id);
               false
           }
       }
   }
   ```

**Solutions:**

- ✅ **Fix typos in client_id/client_secret**
- ✅ **Ensure client is registered in auth server**
- ✅ **Use correct Content-Type header**
- ✅ **Check for special characters in credentials**

### 🚨 **Problem: Token Expired**

**Symptoms:**
```bash
curl -H "Authorization: Bearer expired_token" http://localhost:8080/api/data
# Returns: 401 Unauthorized
```

**Diagnostic Steps:**

1. **Check Token Expiration**
   ```bash
   # Introspect the token
   curl -X POST http://localhost:8080/oauth/introspect \
     -d "token=YOUR_TOKEN" \
     -d "client_id=YOUR_CLIENT" \
     -d "client_secret=YOUR_SECRET"
   
   # Response will show:
   # {"active": false} ← Token expired
   # or
   # {"active": true, "exp": 1640995200, ...} ← Check exp timestamp
   ```

2. **Compare with Current Time**
   ```bash
   # Current Unix timestamp
   date +%s
   # Compare with token 'exp' field
   ```

3. **Check Server Token TTL Configuration**
   ```rust
   let server = AuthServer::minimal()
       .with_token_ttl(3600)  // ← 1 hour in seconds
       .build()?;
   ```

**Solutions:**

- ✅ **Get a fresh token**
- ✅ **Increase token TTL if appropriate**
- ✅ **Implement token refresh logic**
- ✅ **Handle 401 errors gracefully in client**

### 🚨 **Problem: Malformed Token**

**Symptoms:**
```bash
curl -H "Authorization: Bearer not_a_real_token" http://localhost:8080/api/data
# Returns: 401 Unauthorized
```

**Diagnostic Steps:**

1. **Verify Token Format**
   ```bash
   # Auth-core tokens have this format:
   # auth_core_CLIENT_ID_TIMESTAMP_RANDOM
   
   echo "YOUR_TOKEN" | grep -E "^auth_core_[a-zA-Z0-9_]+_[0-9]+_[a-zA-Z0-9]+$"
   # Should match if it's a valid auth-core token
   ```

2. **Check Authorization Header**
   ```bash
   # ✅ Correct format
   curl -H "Authorization: Bearer auth_core_my_client_1640995200_abc123"
   
   # ❌ Common mistakes
   curl -H "Authorization: auth_core_..."           # Missing "Bearer"
   curl -H "Authorization: Bearer auth_core_ ..."   # Space in token
   curl -H "Authorization: Bearer\nauth_core_..."   # Newline in header
   ```

3. **Debug Token Validation**
   ```rust
   async fn debug_token_validation(token: &str) {
       log::debug!("Validating token: {}", token);
       
       // Check format
       if !token.starts_with("auth_core_") {
           log::error!("Token doesn't start with auth_core_");
           return;
       }
       
       // Parse components
       let parts: Vec<&str> = token.split('_').collect();
       if parts.len() < 4 {
           log::error!("Token has wrong number of parts: {}", parts.len());
           return;
       }
       
       let client_id = parts[2];
       let timestamp = parts[3].parse::<u64>();
       
       log::debug!("Token client_id: {}", client_id);
       log::debug!("Token timestamp: {:?}", timestamp);
   }
   ```

**Solutions:**

- ✅ **Check token is complete and unmodified**
- ✅ **Verify no extra spaces or characters**
- ✅ **Ensure proper Authorization header format**
- ✅ **Regenerate token if corrupted**

---

## Authentication Failures

### 🚨 **Problem: 401 Unauthorized on API Calls**

**Symptoms:**
All API calls return 401 even with seemingly valid tokens.

**Diagnostic Steps:**

1. **Verify Middleware Chain**
   ```rust
   let app = Router::new()
       .route("/api/protected", get(protected_handler))
       .layer(axum::middleware::from_fn(auth_middleware))  // ← Must be here
       .with_state(app_state);
   
   // ❌ Wrong - middleware applied too late
   let app = Router::new()
       .route("/api/protected", get(protected_handler))
       .with_state(app_state)
       .layer(axum::middleware::from_fn(auth_middleware));  // ← Too late!
   ```

2. **Debug Middleware Execution**
   ```rust
   async fn auth_middleware(
       headers: HeaderMap,
       mut request: axum::extract::Request,
       next: axum::middleware::Next,
   ) -> Result<axum::response::Response, StatusCode> {
       log::debug!("Auth middleware called");
       log::debug!("Headers: {:?}", headers);
       
       let auth_header = headers.get("authorization");
       log::debug!("Authorization header: {:?}", auth_header);
       
       // ... rest of validation
   }
   ```

3. **Test Middleware Directly**
   ```bash
   # Test if middleware is running
   curl -v -H "Authorization: Bearer test" http://localhost:8080/api/protected
   # Look for debug logs in server output
   ```

**Solutions:**

- ✅ **Ensure middleware is applied to protected routes**
- ✅ **Check middleware order (auth before route handling)**
- ✅ **Verify auth service is accessible from API service**
- ✅ **Test token validation logic separately**

### 🚨 **Problem: Token Validation Always Fails**

**Symptoms:**
Even known-good tokens are rejected.

**Diagnostic Steps:**

1. **Test Token Store**
   ```rust
   // In your auth server
   impl AuthServer {
       pub fn debug_token_store(&self) {
           log::debug!("Active tokens: {}", self.token_store.len());
           for (token, info) in &self.token_store {
               log::debug!("Token: {}... -> Client: {}", 
                   &token[..20], info.client_id);
           }
       }
   }
   ```

2. **Check Token Storage/Retrieval**
   ```rust
   async fn validate_token(token: &str) -> Result<TokenInfo, AuthError> {
       log::debug!("Looking up token: {}...", &token[..20]);
       
       // Check if token exists
       let token_info = TOKEN_STORE.get(token)
           .ok_or_else(|| {
               log::warn!("Token not found in store");
               AuthError::InvalidToken
           })?;
       
       // Check expiration
       let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
       if token_info.expires_at < now {
           log::warn!("Token expired: {} < {}", token_info.expires_at, now);
           return Err(AuthError::TokenExpired);
       }
       
       Ok(token_info)
   }
   ```

3. **Verify Time Synchronization**
   ```bash
   # Check system time on auth server and API server
   date
   # Both should be in sync (use NTP)
   ```

**Solutions:**

- ✅ **Check token storage implementation**
- ✅ **Verify token cleanup isn't too aggressive**
- ✅ **Ensure time synchronization between services**
- ✅ **Test token validation logic in isolation**

---

## Permission & Scope Problems

### 🚨 **Problem: 403 Forbidden Despite Valid Token**

**Symptoms:**
```bash
curl -H "Authorization: Bearer valid_token" http://localhost:8080/api/admin
# Returns: 403 Forbidden
```

**Diagnostic Steps:**

1. **Check Token Scopes**
   ```bash
   # Introspect token to see what scopes it has
   curl -X POST http://localhost:8080/oauth/introspect \
     -d "token=YOUR_TOKEN" \
     -d "client_id=YOUR_CLIENT" \
     -d "client_secret=YOUR_SECRET"
   
   # Response shows: {"active": true, "scope": "read write", ...}
   ```

2. **Verify Endpoint Requirements**
   ```rust
   async fn admin_endpoint(
       axum::Extension(token_info): axum::Extension<TokenInfo>
   ) -> Result<Json<AdminData>, StatusCode> {
       log::debug!("Admin endpoint called by client: {}", token_info.client_id);
       log::debug!("Token scopes: {:?}", token_info.scopes);
       
       // Check required scope
       if !token_info.has_scope("admin") {
           log::warn!("Missing admin scope. Has: {:?}", token_info.scopes);
           return Err(StatusCode::FORBIDDEN);
       }
       
       // ... rest of handler
   }
   ```

3. **Debug Scope Assignment**
   ```rust
   // Check how scopes are assigned to client
   let server = AuthServer::minimal()
       .with_client_scopes("my_client", "my_secret", &[
           "read", "write"  // ← Missing "admin" scope
       ])
       .build()?;
   ```

**Solutions:**

- ✅ **Add required scopes to client configuration**
- ✅ **Request correct scopes when getting token**
- ✅ **Verify scope matching logic (case-sensitive)**
- ✅ **Check for typos in scope names**

### 🚨 **Problem: Scope Inheritance Not Working**

**Symptoms:**
Expected scope hierarchies not working (e.g., admin should include read/write).

**Diagnostic Steps:**

1. **Check Scope Logic**
   ```rust
   impl TokenInfo {
       pub fn has_scope(&self, required: &str) -> bool {
           log::debug!("Checking scope '{}' against: {:?}", required, self.scopes);
           
           // Simple exact match (no inheritance)
           let result = self.scopes.contains(&required.to_string());
           log::debug!("Scope check result: {}", result);
           result
       }
   }
   ```

2. **Implement Scope Hierarchy**
   ```rust
   impl TokenInfo {
       pub fn has_scope_or_higher(&self, required: &str) -> bool {
           match required {
               "read" => {
                   self.scopes.contains(&"read".to_string()) ||
                   self.scopes.contains(&"write".to_string()) ||
                   self.scopes.contains(&"admin".to_string())
               },
               "write" => {
                   self.scopes.contains(&"write".to_string()) ||
                   self.scopes.contains(&"admin".to_string())
               },
               "admin" => {
                   self.scopes.contains(&"admin".to_string())
               },
               _ => self.scopes.contains(&required.to_string())
           }
       }
   }
   ```

**Solutions:**

- ✅ **Implement explicit scope hierarchy logic**
- ✅ **Document scope relationships clearly**
- ✅ **Use specific scopes rather than relying on inheritance**
- ✅ **Test scope combinations thoroughly**

---

## Network & Connection Issues

### 🚨 **Problem: Connection Refused**

**Symptoms:**
```bash
curl: (7) Failed to connect to localhost port 8080: Connection refused
```

**Diagnostic Steps:**

1. **Check if Server is Running**
   ```bash
   # Check process
   ps aux | grep auth-service
   
   # Check port binding
   netstat -tlnp | grep :8080
   # or
   lsof -i :8080
   ```

2. **Check Server Logs**
   ```bash
   # Look for startup errors
   tail -f /var/log/auth-service.log
   
   # Docker logs
   docker logs auth-service-container
   ```

3. **Verify Binding Address**
   ```rust
   // ❌ Only binds to localhost
   let listener = TcpListener::bind("127.0.0.1:8080").await?;
   
   // ✅ Binds to all interfaces (for Docker)
   let listener = TcpListener::bind("0.0.0.0:8080").await?;
   ```

**Solutions:**

- ✅ **Start the auth service**
- ✅ **Check port conflicts**
- ✅ **Fix binding address for container deployment**
- ✅ **Check firewall rules**

### 🚨 **Problem: Timeout on Token Requests**

**Symptoms:**
Token requests hang or timeout after 30+ seconds.

**Diagnostic Steps:**

1. **Check Server Responsiveness**
   ```bash
   # Test with timeout
   timeout 5s curl -X POST http://localhost:8080/oauth/token \
     -d "grant_type=client_credentials&client_id=test&client_secret=test"
   
   # Check if server responds to health checks
   curl http://localhost:8080/health
   ```

2. **Monitor Resource Usage**
   ```bash
   # Check CPU and memory
   top -p $(pgrep auth-service)
   
   # Check disk space
   df -h
   
   # Check network
   netstat -i
   ```

3. **Check for Blocking Operations**
   ```rust
   // ❌ Blocking database call on main thread
   async fn handle_token(req: TokenRequest) -> Result<TokenResponse> {
       let client = database.get_client(&req.client_id).await?;  // This could block
       // ...
   }
   
   // ✅ Use connection pooling and timeouts
   async fn handle_token(req: TokenRequest) -> Result<TokenResponse> {
       let client = tokio::time::timeout(
           Duration::from_secs(5),
           database.get_client(&req.client_id)
       ).await??;
       // ...
   }
   ```

**Solutions:**

- ✅ **Add timeouts to external calls**
- ✅ **Check database/Redis connectivity**
- ✅ **Monitor resource usage**
- ✅ **Use connection pooling**

---

## Performance Problems

### 🚨 **Problem: Slow Token Generation**

**Symptoms:**
Token generation takes > 1 second consistently.

**Diagnostic Steps:**

1. **Profile Token Generation**
   ```rust
   use std::time::Instant;
   
   async fn generate_token(client_id: &str, scopes: &[String]) -> Result<Token> {
       let start = Instant::now();
       
       // Step 1: Generate random part
       let random_start = Instant::now();
       let random_part = generate_random_string(32);
       log::debug!("Random generation took: {:?}", random_start.elapsed());
       
       // Step 2: Create token structure
       let token_start = Instant::now();
       let token = format!("auth_core_{}_{}_{}",
           client_id,
           SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
           random_part
       );
       log::debug!("Token formatting took: {:?}", token_start.elapsed());
       
       // Step 3: Store token
       let store_start = Instant::now();
       store_token(&token, &token_info).await?;
       log::debug!("Token storage took: {:?}", store_start.elapsed());
       
       log::info!("Total token generation time: {:?}", start.elapsed());
       Ok(token)
   }
   ```

2. **Check Random Number Generation**
   ```rust
   // ❌ Slow: Creating new RNG each time
   fn generate_random_string(len: usize) -> String {
       use rand::Rng;
       let mut rng = rand::thread_rng();  // New RNG each time
       (0..len).map(|_| rng.gen::<char>()).collect()
   }
   
   // ✅ Fast: Reuse RNG
   use once_cell::sync::Lazy;
   use rand::prelude::*;
   
   static RNG: Lazy<std::sync::Mutex<StdRng>> = Lazy::new(|| {
       std::sync::Mutex::new(StdRng::from_entropy())
   });
   
   fn generate_random_string(len: usize) -> String {
       let mut rng = RNG.lock().unwrap();
       (0..len).map(|_| rng.gen_range(0..62))
           .map(|i| match i {
               0..=25 => (b'A' + i) as char,
               26..=51 => (b'a' + (i - 26)) as char,
               _ => (b'0' + (i - 52)) as char,
           })
           .collect()
   }
   ```

3. **Optimize Token Storage**
   ```rust
   // ❌ Slow: Database write for each token
   async fn store_token(token: &str, info: &TokenInfo) -> Result<()> {
       database.insert("tokens", token, info).await
   }
   
   // ✅ Fast: In-memory with periodic persistence
   async fn store_token(token: &str, info: &TokenInfo) -> Result<()> {
       // Store in memory immediately
       TOKEN_CACHE.insert(token.to_string(), info.clone());
       
       // Queue for background persistence
       PERSIST_QUEUE.push((token.to_string(), info.clone())).await;
       
       Ok(())
   }
   ```

**Solutions:**

- ✅ **Optimize random number generation**
- ✅ **Use in-memory token storage with persistence**
- ✅ **Profile and optimize slow operations**
- ✅ **Consider token pre-generation for high load**

### 🚨 **Problem: High Memory Usage**

**Symptoms:**
Auth service memory usage grows continuously or is unexpectedly high.

**Diagnostic Steps:**

1. **Monitor Memory Usage**
   ```bash
   # Check memory usage over time
   while true; do
     ps -p $(pgrep auth-service) -o pid,vsz,rss,pmem,comm
     sleep 30
   done
   ```

2. **Check Token Storage Size**
   ```rust
   // Add metrics to token store
   impl TokenStore {
       pub fn debug_stats(&self) {
           log::info!("Token store stats:");
           log::info!("  Active tokens: {}", self.tokens.len());
           log::info!("  Memory usage estimate: {} MB", 
               self.tokens.len() * std::mem::size_of::<TokenInfo>() / 1024 / 1024);
           
           // Check for old tokens
           let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
           let expired_count = self.tokens.values()
               .filter(|info| info.expires_at < now)
               .count();
           log::warn!("Expired tokens not cleaned up: {}", expired_count);
       }
   }
   ```

3. **Implement Token Cleanup**
   ```rust
   // Background token cleanup task
   async fn token_cleanup_task(store: Arc<TokenStore>) {
       let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
       
       loop {
           interval.tick().await;
           
           let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
           let initial_count = store.len();
           
           store.retain(|_token, info| info.expires_at > now);
           
           let cleaned_count = initial_count - store.len();
           if cleaned_count > 0 {
               log::info!("Cleaned up {} expired tokens", cleaned_count);
           }
       }
   }
   ```

**Solutions:**

- ✅ **Implement automatic token cleanup**
- ✅ **Set reasonable token TTL**
- ✅ **Monitor token store size**
- ✅ **Use efficient data structures**

---

## Configuration Issues

### 🚨 **Problem: Environment Variables Not Loading**

**Symptoms:**
Server starts with default config instead of environment-specific settings.

**Diagnostic Steps:**

1. **Check Environment Variables**
   ```bash
   # List all auth-related env vars
   env | grep AUTH_
   
   # Check specific variables
   echo "AUTH_PORT: $AUTH_PORT"
   echo "AUTH_TOKEN_TTL: $AUTH_TOKEN_TTL"
   ```

2. **Debug Config Loading**
   ```rust
   #[derive(Debug)]
   pub struct Config {
       pub port: u16,
       pub token_ttl: u64,
       pub log_level: String,
   }
   
   impl Config {
       pub fn from_env() -> Self {
           let config = Config {
               port: env::var("AUTH_PORT")
                   .unwrap_or_else(|e| {
                       log::warn!("AUTH_PORT not set: {}, using default 8080", e);
                       "8080".to_string()
                   })
                   .parse()
                   .expect("AUTH_PORT must be a valid number"),
               
               token_ttl: env::var("AUTH_TOKEN_TTL")
                   .unwrap_or_else(|e| {
                       log::warn!("AUTH_TOKEN_TTL not set: {}, using default 3600", e);
                       "3600".to_string()
                   })
                   .parse()
                   .expect("AUTH_TOKEN_TTL must be a valid number"),
               
               log_level: env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
           };
           
           log::info!("Loaded config: {:?}", config);
           config
       }
   }
   ```

3. **Test Config in Docker**
   ```bash
   # Check environment in container
   docker exec auth-container env | grep AUTH_
   
   # Test with explicit environment
   docker run -e AUTH_PORT=8080 -e AUTH_TOKEN_TTL=7200 auth-image
   ```

**Solutions:**

- ✅ **Verify environment variables are set**
- ✅ **Use .env files for development**
- ✅ **Add config validation and logging**
- ✅ **Test configuration loading in containers**

### 🚨 **Problem: Client Configuration Not Found**

**Symptoms:**
Clients configured in code/config file not recognized.

**Diagnostic Steps:**

1. **Debug Client Loading**
   ```rust
   impl AuthServer {
       pub fn new() -> Self {
           let mut server = AuthServer::minimal();
           
           // Load clients from config file
           if let Ok(config_content) = std::fs::read_to_string("clients.toml") {
               let clients: Vec<ClientConfig> = toml::from_str(&config_content)
                   .expect("Invalid clients.toml format");
               
               for client in clients {
                   log::info!("Loading client: {}", client.client_id);
                   server = server.with_client(&client.client_id, &client.client_secret);
               }
           } else {
               log::warn!("clients.toml not found, using default clients");
           }
           
           log::info!("Loaded {} clients total", server.client_count());
           server
       }
   }
   ```

2. **Validate Configuration File Format**
   ```toml
   # clients.toml
   [[clients]]
   client_id = "web_app"
   client_secret = "web_secret_123"
   scopes = ["read", "write"]
   
   [[clients]]
   client_id = "mobile_app"
   client_secret = "mobile_secret_456"
   scopes = ["read"]
   ```

3. **Check File Permissions and Location**
   ```bash
   # Check file exists and is readable
   ls -la clients.toml
   
   # Check working directory
   pwd
   
   # Test file can be read
   cat clients.toml
   ```

**Solutions:**

- ✅ **Verify configuration file exists and is readable**
- ✅ **Check file format and syntax**
- ✅ **Use absolute paths for config files**
- ✅ **Add error handling for config loading**

---

## Integration Problems

### 🚨 **Problem: Framework Middleware Not Working**

**Symptoms:**
Authentication middleware doesn't seem to run or always fails.

**Diagnostic Steps:**

1. **Check Middleware Ordering (Axum)**
   ```rust
   // ✅ Correct: Auth middleware applied to protected routes
   let app = Router::new()
       .route("/public", get(public_handler))  // No auth needed
       .route("/protected", get(protected_handler)
           .layer(axum::middleware::from_fn(auth_middleware))  // Auth required
       )
       .with_state(app_state);
   
   // ❌ Wrong: Middleware applied to entire app
   let app = Router::new()
       .route("/public", get(public_handler))
       .route("/protected", get(protected_handler))
       .layer(axum::middleware::from_fn(auth_middleware))  // Affects ALL routes
       .with_state(app_state);
   ```

2. **Debug Middleware Execution (Actix-Web)**
   ```rust
   // Add logging to see middleware execution
   async fn auth_middleware(
       req: ServiceRequest,
       next: actix_web::dev::Transform<...>,
   ) -> Result<ServiceResponse, actix_web::Error> {
       log::debug!("Auth middleware called for: {}", req.path());
       
       // Check if route should be protected
       let should_protect = req.path().starts_with("/api/");
       log::debug!("Should protect route: {}", should_protect);
       
       if !should_protect {
           return Ok(next.call(req).await?);
       }
       
       // ... auth logic
   }
   ```

3. **Test Middleware Isolation**
   ```rust
   // Create minimal test to verify middleware works
   #[tokio::test]
   async fn test_auth_middleware() {
       let app = Router::new()
           .route("/test", get(|| async { "OK" })
               .layer(axum::middleware::from_fn(test_auth_middleware))
           );
       
       let response = app
           .oneshot(
               Request::builder()
                   .uri("/test")
                   .header("Authorization", "Bearer test_token")
                   .body(Body::empty())
                   .unwrap()
           )
           .await
           .unwrap();
       
       assert_eq!(response.status(), 200);
   }
   ```

**Solutions:**

- ✅ **Verify middleware is applied to correct routes**
- ✅ **Check middleware execution order**
- ✅ **Test middleware in isolation**
- ✅ **Add logging to trace middleware execution**

### 🚨 **Problem: Service-to-Service Authentication Fails**

**Symptoms:**
Microservices can't authenticate with each other.

**Diagnostic Steps:**

1. **Test Service-to-Service Token Flow**
   ```bash
   # 1. Service A gets token from auth service
   TOKEN=$(curl -s -X POST http://auth-service:8001/oauth/token \
     -d "grant_type=client_credentials" \
     -d "client_id=service_a" \
     -d "client_secret=service_a_secret" | jq -r '.access_token')
   
   # 2. Service A calls Service B with token
   curl -H "Authorization: Bearer $TOKEN" http://service-b:8002/api/data
   ```

2. **Check Network Connectivity**
   ```bash
   # From Service A container, test connection to auth service
   docker exec service-a-container nc -zv auth-service 8001
   
   # Test DNS resolution
   docker exec service-a-container nslookup auth-service
   ```

3. **Debug Service Discovery**
   ```rust
   // Add service discovery debugging
   #[derive(Clone)]
   pub struct ServiceConfig {
       pub auth_service_url: String,
   }
   
   impl ServiceConfig {
       pub fn from_env() -> Self {
           let auth_url = env::var("AUTH_SERVICE_URL")
               .unwrap_or_else(|_| "http://localhost:8001".to_string());
           
           log::info!("Using auth service URL: {}", auth_url);
           
           // Test connectivity
           tokio::spawn(async move {
               let client = reqwest::Client::new();
               match client.get(&format!("{}/health", auth_url)).send().await {
                   Ok(resp) => log::info!("Auth service health check: {}", resp.status()),
                   Err(e) => log::error!("Auth service unreachable: {}", e),
               }
           });
           
           ServiceConfig {
               auth_service_url: auth_url,
           }
       }
   }
   ```

**Solutions:**

- ✅ **Check service discovery configuration**
- ✅ **Verify network connectivity between services**
- ✅ **Use proper service URLs (not localhost in containers)**
- ✅ **Add health checks and retry logic**

---

## Security Concerns

### 🚨 **Problem: Token Security Warnings**

**Symptoms:**
Security scanners flag potential token security issues.

**Diagnostic Steps:**

1. **Check Token Entropy**
   ```rust
   // Analyze token randomness
   fn analyze_token_entropy(tokens: &[String]) {
       let mut char_counts = std::collections::HashMap::new();
       let mut total_chars = 0;
       
       for token in tokens {
           for c in token.chars() {
               *char_counts.entry(c).or_insert(0) += 1;
               total_chars += 1;
           }
       }
       
       // Calculate entropy
       let mut entropy = 0.0;
       for &count in char_counts.values() {
           let frequency = count as f64 / total_chars as f64;
           entropy -= frequency * frequency.log2();
       }
       
       log::info!("Token entropy: {:.2} bits", entropy);
       
       // Check for patterns
       for token in tokens {
           if token.contains("000") || token.contains("111") {
               log::warn!("Token contains repeated patterns: {}", &token[..20]);
           }
       }
   }
   ```

2. **Verify Timing Attack Protection**
   ```rust
   use subtle::ConstantTimeEq;
   
   // ❌ Vulnerable to timing attacks
   fn validate_client_secret_bad(stored: &str, provided: &str) -> bool {
       stored == provided  // Short-circuits on first difference
   }
   
   // ✅ Constant-time comparison
   fn validate_client_secret_secure(stored: &str, provided: &str) -> bool {
       stored.as_bytes().ct_eq(provided.as_bytes()).into()
   }
   ```

3. **Check Token Storage Security**
   ```rust
   // ❌ Tokens stored in plain text logs
   log::info!("Generated token: {}", token);  // DON'T DO THIS
   
   // ✅ Log token metadata only
   log::info!("Generated token for client: {}, expires: {}", 
       client_id, expires_at);
   
   // ✅ Hash tokens for storage if needed
   use sha2::{Sha256, Digest};
   
   fn hash_token(token: &str) -> String {
       let mut hasher = Sha256::new();
       hasher.update(token.as_bytes());
       format!("{:x}", hasher.finalize())
   }
   ```

**Solutions:**

- ✅ **Use cryptographically secure random number generation**
- ✅ **Implement constant-time comparisons**
- ✅ **Never log tokens in plain text**
- ✅ **Use secure token storage practices**

### 🚨 **Problem: Rate Limiting Not Working**

**Symptoms:**
Clients can make unlimited requests despite rate limiting configuration.

**Diagnostic Steps:**

1. **Test Rate Limiting**
   ```bash
   # Make rapid requests to test rate limiting
   for i in {1..20}; do
     curl -w "%{http_code} " -s -o /dev/null \
       -X POST http://localhost:8080/oauth/token \
       -d "grant_type=client_credentials&client_id=test&client_secret=wrong"
   done
   echo
   
   # Should see 429 responses after hitting limit
   ```

2. **Debug Rate Limiter State**
   ```rust
   use std::collections::HashMap;
   use std::sync::Arc;
   use tokio::sync::RwLock;
   
   #[derive(Debug)]
   pub struct RateLimiter {
       requests: Arc<RwLock<HashMap<String, RequestCount>>>,
       max_requests: usize,
       window_secs: u64,
   }
   
   impl RateLimiter {
       pub async fn check_rate_limit(&self, client_id: &str) -> bool {
           let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
           let mut requests = self.requests.write().await;
           
           let count = requests
               .entry(client_id.to_string())
               .or_insert_with(|| RequestCount::new(now));
           
           // Clean old requests
           count.requests.retain(|&timestamp| now - timestamp < self.window_secs);
           
           log::debug!("Client {} has {} requests in window", 
               client_id, count.requests.len());
           
           if count.requests.len() >= self.max_requests {
               log::warn!("Rate limit exceeded for client: {}", client_id);
               false
           } else {
               count.requests.push(now);
               true
           }
       }
   }
   ```

3. **Check Rate Limiter Integration**
   ```rust
   async fn token_handler(
       State(rate_limiter): State<Arc<RateLimiter>>,
       Form(request): Form<TokenRequest>,
   ) -> Result<Json<TokenResponse>, StatusCode> {
       
       // Check rate limit FIRST
       if !rate_limiter.check_rate_limit(&request.client_id).await {
           return Err(StatusCode::TOO_MANY_REQUESTS);
       }
       
       // ... rest of token generation
   }
   ```

**Solutions:**

- ✅ **Verify rate limiter is properly integrated**
- ✅ **Test rate limiting with multiple requests**
- ✅ **Check rate limiter cleanup/expiry**
- ✅ **Use persistent storage for distributed rate limiting**

---

## Debugging Tools & Techniques

### 🔧 **Logging Configuration**

**Structured Logging Setup:**
```rust
use tracing::{info, warn, error, debug};
use tracing_subscriber::{fmt, EnvFilter};

fn init_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
        
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();
}

// Usage in auth code
async fn handle_token_request(req: TokenRequest) -> Result<TokenResponse> {
    debug!("Token request received: client_id={}", req.client_id);
    
    match validate_client(&req.client_id, &req.client_secret).await {
        Ok(client) => {
            info!("Client authenticated: {}", req.client_id);
        }
        Err(e) => {
            warn!("Client authentication failed: {} - {}", req.client_id, e);
            return Err(AuthError::InvalidClient);
        }
    }
    
    // ... rest of processing
}
```

**Log Levels by Environment:**
```bash
# Development - verbose logging
export RUST_LOG=debug

# Production - error and warning only
export RUST_LOG=warn

# Debugging specific issues
export RUST_LOG=auth_core=debug,tower_http=debug

# JSON structured logs for production
export RUST_LOG=info
export LOG_FORMAT=json
```

### 🔧 **Health Check Endpoints**

**Comprehensive Health Check:**
```rust
#[derive(Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime: u64,
    pub checks: HashMap<String, CheckResult>,
}

#[derive(Serialize)]
pub struct CheckResult {
    pub status: String,
    pub message: String,
    pub response_time_ms: u64,
}

async fn health_check(
    State(app_state): State<AppState>
) -> Json<HealthStatus> {
    let mut checks = HashMap::new();
    
    // Check database connectivity
    let db_start = Instant::now();
    let db_result = match test_database_connection(&app_state.db).await {
        Ok(_) => CheckResult {
            status: "healthy".to_string(),
            message: "Database connection successful".to_string(),
            response_time_ms: db_start.elapsed().as_millis() as u64,
        },
        Err(e) => CheckResult {
            status: "unhealthy".to_string(),
            message: format!("Database connection failed: {}", e),
            response_time_ms: db_start.elapsed().as_millis() as u64,
        }
    };
    checks.insert("database".to_string(), db_result);
    
    // Check Redis connectivity
    let redis_start = Instant::now();
    let redis_result = match test_redis_connection(&app_state.redis).await {
        Ok(_) => CheckResult {
            status: "healthy".to_string(),
            message: "Redis connection successful".to_string(),
            response_time_ms: redis_start.elapsed().as_millis() as u64,
        },
        Err(e) => CheckResult {
            status: "unhealthy".to_string(),
            message: format!("Redis connection failed: {}", e),
            response_time_ms: redis_start.elapsed().as_millis() as u64,
        }
    };
    checks.insert("redis".to_string(), redis_result);
    
    // Check token store
    let token_count = app_state.token_store.len().await;
    checks.insert("token_store".to_string(), CheckResult {
        status: "healthy".to_string(),
        message: format!("Active tokens: {}", token_count),
        response_time_ms: 0,
    });
    
    let overall_status = if checks.values().all(|check| check.status == "healthy") {
        "healthy"
    } else {
        "unhealthy"
    };
    
    Json(HealthStatus {
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: get_uptime_seconds(),
        checks,
    })
}
```

### 🔧 **Metrics and Monitoring**

**Prometheus Metrics:**
```rust
use prometheus::{Counter, Histogram, Gauge, register_counter, register_histogram, register_gauge};

lazy_static! {
    static ref TOKEN_REQUESTS_TOTAL: Counter = register_counter!(
        "auth_token_requests_total",
        "Total number of token requests"
    ).unwrap();
    
    static ref TOKEN_REQUEST_DURATION: Histogram = register_histogram!(
        "auth_token_request_duration_seconds",
        "Token request processing time"
    ).unwrap();
    
    static ref ACTIVE_TOKENS: Gauge = register_gauge!(
        "auth_active_tokens",
        "Number of active tokens"
    ).unwrap();
}

async fn handle_token_request(req: TokenRequest) -> Result<TokenResponse> {
    let _timer = TOKEN_REQUEST_DURATION.start_timer();
    TOKEN_REQUESTS_TOTAL.inc();
    
    // ... process request
    
    ACTIVE_TOKENS.set(get_active_token_count() as f64);
    
    // Return response
}

// Metrics endpoint
async fn metrics() -> String {
    use prometheus::{Encoder, TextEncoder};
    
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    encoder.encode_to_string(&metric_families).unwrap()
}
```

### 🔧 **Testing Utilities**

**Integration Test Helpers:**
```rust
pub struct TestAuthServer {
    pub server: AuthServer,
    pub base_url: String,
    pub client: reqwest::Client,
}

impl TestAuthServer {
    pub async fn new() -> Self {
        let server = AuthServer::minimal()
            .with_client("test_client", "test_secret")
            .with_client("limited_client", "limited_secret")
            .with_token_ttl(300)  // Short TTL for tests
            .build()
            .expect("Failed to create test server");
        
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://127.0.0.1:{}", addr.port());
        
        tokio::spawn(async move {
            axum::serve(listener, server.into_router()).await.unwrap();
        });
        
        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        TestAuthServer {
            server,
            base_url,
            client: reqwest::Client::new(),
        }
    }
    
    pub async fn get_token(&self, client_id: &str, client_secret: &str, scopes: &str) -> Result<String> {
        let response = self.client
            .post(&format!("{}/oauth/token", self.base_url))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("scope", scopes),
            ])
            .send()
            .await?;
            
        let token_data: serde_json::Value = response.json().await?;
        Ok(token_data["access_token"].as_str().unwrap().to_string())
    }
    
    pub async fn test_endpoint(&self, token: &str, method: &str, path: &str) -> reqwest::Response {
        let url = format!("{}{}", self.base_url, path);
        
        let request = match method {
            "GET" => self.client.get(&url),
            "POST" => self.client.post(&url),
            "PUT" => self.client.put(&url),
            "DELETE" => self.client.delete(&url),
            _ => panic!("Unsupported method: {}", method),
        };
        
        request
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
    }
}

// Usage in tests
#[tokio::test]
async fn test_complete_flow() {
    let test_server = TestAuthServer::new().await;
    
    // Get token
    let token = test_server
        .get_token("test_client", "test_secret", "read write")
        .await
        .unwrap();
        
    // Test API endpoints
    let response = test_server
        .test_endpoint(&token, "GET", "/api/profile")
        .await;
        
    assert_eq!(response.status(), 200);
}
```

This troubleshooting guide provides systematic approaches to diagnosing and fixing the most common issues when implementing OAuth 2.0 with auth-core, helping developers quickly resolve problems and maintain secure, reliable authentication systems.