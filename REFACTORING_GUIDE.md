# 🔧 Practical Refactoring Guide

## 📋 **Overview**

This guide provides specific refactoring examples based on the current Rust Security Platform codebase. Each example shows the "before" and "after" code with explanations of the improvements.

## 🎯 **Refactoring Priorities**

### **Priority 1: Large Functions (>100 lines)**
### **Priority 2: Complex Error Handling**
### **Priority 3: Magic Numbers and Constants**
### **Priority 4: Deep Nesting**
### **Priority 5: Unused Dependencies**

## 🔨 **Specific Refactoring Examples**

### **1. Function Decomposition**

#### **Before: Large Authentication Handler**
```rust
// ❌ BEFORE: 150+ line function with multiple responsibilities
pub async fn handle_authentication(
    request: AuthRequest,
    state: &AppState,
) -> Result<AuthResponse, AuthError> {
    // Input validation (20 lines)
    if request.username.is_empty() {
        return Err(AuthError::InvalidInput("Username cannot be empty".to_string()));
    }
    if request.password.len() < 8 {
        return Err(AuthError::InvalidInput("Password too short".to_string()));
    }
    // ... more validation
    
    // Rate limiting (30 lines)
    let rate_limit_key = format!("auth_attempts:{}", request.username);
    let attempts = state.redis.get::<_, u32>(&rate_limit_key).await.unwrap_or(0);
    if attempts >= 5 {
        let ttl = state.redis.ttl(&rate_limit_key).await.unwrap_or(0);
        return Err(AuthError::RateLimitExceeded { retry_after: ttl });
    }
    // ... more rate limiting logic
    
    // Database operations (40 lines)
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE username = $1",
        request.username
    )
    .fetch_optional(&state.database)
    .await
    .map_err(AuthError::Database)?;
    
    let user = match user {
        Some(u) => u,
        None => {
            // Increment failed attempts
            let _: () = state.redis.incr(&rate_limit_key, 1).await.unwrap_or(());
            let _: () = state.redis.expire(&rate_limit_key, 300).await.unwrap_or(());
            return Err(AuthError::InvalidCredentials);
        }
    };
    // ... more database logic
    
    // Password verification (20 lines)
    let password_hash = user.password_hash.as_bytes();
    let is_valid = argon2::verify_encoded(&user.password_hash, request.password.as_bytes())
        .map_err(|_| AuthError::InternalError)?;
    
    if !is_valid {
        // Increment failed attempts
        let _: () = state.redis.incr(&rate_limit_key, 1).await.unwrap_or(());
        let _: () = state.redis.expire(&rate_limit_key, 300).await.unwrap_or(());
        return Err(AuthError::InvalidCredentials);
    }
    // ... more password logic
    
    // Token generation (30 lines)
    let claims = Claims {
        sub: user.id.to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp(),
        iat: Utc::now().timestamp(),
        iss: "auth-service".to_string(),
    };
    
    let token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_ref()),
    )
    .map_err(|_| AuthError::TokenGeneration)?;
    // ... more token logic
    
    // Logging and cleanup (10 lines)
    tracing::info!("User {} authenticated successfully", user.username);
    let _: () = state.redis.del(&rate_limit_key).await.unwrap_or(());
    
    Ok(AuthResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        user_id: user.id,
    })
}
```

#### **After: Decomposed Functions**
```rust
// ✅ AFTER: Single responsibility functions
pub async fn handle_authentication(
    request: AuthRequest,
    state: &AppState,
) -> Result<AuthResponse, AuthError> {
    let validated_request = validate_auth_request(&request)?;
    
    check_rate_limits(&validated_request.username, &state.rate_limiter).await?;
    
    let user = authenticate_user(&validated_request, &state.user_service).await?;
    
    let tokens = generate_tokens(&user, &state.token_service).await?;
    
    clear_rate_limits(&validated_request.username, &state.rate_limiter).await?;
    
    log_successful_authentication(&user);
    
    Ok(AuthResponse::from_tokens(tokens, user.id))
}

// Validation function (single responsibility)
fn validate_auth_request(request: &AuthRequest) -> Result<ValidatedAuthRequest, AuthError> {
    if request.username.trim().is_empty() {
        return Err(AuthError::InvalidInput {
            field: "username".to_string(),
            message: "Username cannot be empty".to_string(),
        });
    }
    
    if request.password.len() < MIN_PASSWORD_LENGTH {
        return Err(AuthError::InvalidInput {
            field: "password".to_string(),
            message: format!("Password must be at least {} characters", MIN_PASSWORD_LENGTH),
        });
    }
    
    Ok(ValidatedAuthRequest {
        username: request.username.trim().to_lowercase(),
        password: request.password.clone(),
    })
}

// Rate limiting function (single responsibility)
async fn check_rate_limits(
    username: &str,
    rate_limiter: &RateLimiter,
) -> Result<(), AuthError> {
    match rate_limiter.check_auth_attempts(username).await? {
        RateLimitStatus::Allowed => Ok(()),
        RateLimitStatus::Exceeded { retry_after } => {
            Err(AuthError::RateLimitExceeded { retry_after })
        }
    }
}

// Authentication function (single responsibility)
async fn authenticate_user(
    request: &ValidatedAuthRequest,
    user_service: &UserService,
) -> Result<User, AuthError> {
    let user = user_service
        .find_by_username(&request.username)
        .await?
        .ok_or(AuthError::InvalidCredentials)?;
    
    if !user_service
        .verify_password(&user, &request.password)
        .await?
    {
        return Err(AuthError::InvalidCredentials);
    }
    
    Ok(user)
}

// Token generation function (single responsibility)
async fn generate_tokens(
    user: &User,
    token_service: &TokenService,
) -> Result<TokenPair, AuthError> {
    token_service.generate_tokens(user).await
}
```

### **2. Error Handling Improvement**

#### **Before: Inconsistent Error Handling**
```rust
// ❌ BEFORE: Inconsistent error handling
pub async fn get_user_profile(user_id: &str, state: &AppState) -> Result<UserProfile, String> {
    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
        .fetch_optional(&state.database)
        .await
        .unwrap(); // ❌ Panic on database error
    
    match user {
        Some(u) => {
            if u.active {
                Ok(UserProfile {
                    id: u.id,
                    username: u.username,
                    email: u.email,
                    created_at: u.created_at,
                })
            } else {
                Err("User is not active".to_string()) // ❌ String error
            }
        }
        None => Err("User not found".to_string()), // ❌ String error
    }
}
```

#### **After: Structured Error Handling**
```rust
// ✅ AFTER: Structured error handling with proper types
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserError {
    #[error("User not found: {user_id}")]
    NotFound { user_id: String },
    
    #[error("User account is inactive: {user_id}")]
    Inactive { user_id: String },
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Invalid user ID format: {user_id}")]
    InvalidId { user_id: String },
}

pub type UserResult<T> = Result<T, UserError>;

pub async fn get_user_profile(
    user_id: &str,
    state: &AppState,
) -> UserResult<UserProfile> {
    // Validate input
    let parsed_id = uuid::Uuid::parse_str(user_id)
        .map_err(|_| UserError::InvalidId {
            user_id: user_id.to_string(),
        })?;
    
    // Database query with proper error handling
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE id = $1",
        parsed_id
    )
    .fetch_optional(&state.database)
    .await?; // Automatic conversion via #[from]
    
    // Business logic validation
    let user = user.ok_or_else(|| UserError::NotFound {
        user_id: user_id.to_string(),
    })?;
    
    if !user.active {
        return Err(UserError::Inactive {
            user_id: user_id.to_string(),
        });
    }
    
    // Success case
    Ok(UserProfile::from(user))
}
```

### **3. Constants and Magic Numbers**

#### **Before: Magic Numbers**
```rust
// ❌ BEFORE: Magic numbers scattered throughout code
pub async fn validate_token(token: &str) -> Result<Claims, TokenError> {
    if token.len() < 20 {  // ❌ Magic number
        return Err(TokenError::TooShort);
    }
    
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {  // ❌ Magic number
        return Err(TokenError::InvalidFormat);
    }
    
    // Token expires in 3600 seconds  // ❌ Magic number
    let exp_time = Utc::now().timestamp() + 3600;
    
    // Rate limit: 100 requests per minute  // ❌ Magic numbers
    if request_count > 100 {
        return Err(TokenError::RateLimited);
    }
    
    Ok(claims)
}
```

#### **After: Named Constants**
```rust
// ✅ AFTER: Named constants with documentation
/// Token validation constants
pub mod token_constants {
    use std::time::Duration;
    
    /// Minimum token length to prevent trivial tokens
    pub const MIN_TOKEN_LENGTH: usize = 20;
    
    /// JWT tokens always have exactly 3 parts (header.payload.signature)
    pub const JWT_PARTS_COUNT: usize = 3;
    
    /// Default token expiration time (1 hour)
    pub const DEFAULT_TOKEN_EXPIRY: Duration = Duration::from_secs(3600);
    
    /// Rate limiting: maximum requests per minute for token validation
    pub const MAX_VALIDATION_REQUESTS_PER_MINUTE: u32 = 100;
    
    /// Rate limiting window duration
    pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
}

use token_constants::*;

pub async fn validate_token(token: &str) -> Result<Claims, TokenError> {
    if token.len() < MIN_TOKEN_LENGTH {
        return Err(TokenError::TooShort {
            actual: token.len(),
            minimum: MIN_TOKEN_LENGTH,
        });
    }
    
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != JWT_PARTS_COUNT {
        return Err(TokenError::InvalidFormat {
            expected_parts: JWT_PARTS_COUNT,
            actual_parts: parts.len(),
        });
    }
    
    let exp_time = Utc::now() + DEFAULT_TOKEN_EXPIRY;
    
    if request_count > MAX_VALIDATION_REQUESTS_PER_MINUTE {
        return Err(TokenError::RateLimited {
            limit: MAX_VALIDATION_REQUESTS_PER_MINUTE,
            window: RATE_LIMIT_WINDOW,
        });
    }
    
    Ok(claims)
}
```

### **4. Reducing Deep Nesting**

#### **Before: Deep Nesting**
```rust
// ❌ BEFORE: Deep nesting makes code hard to follow
pub async fn process_oauth_callback(
    code: &str,
    state: &str,
    app_state: &AppState,
) -> Result<TokenResponse, OAuthError> {
    if !code.is_empty() {
        if !state.is_empty() {
            if let Some(stored_state) = app_state.oauth_states.get(state) {
                if stored_state.is_valid() {
                    if let Ok(token_response) = exchange_code_for_token(code).await {
                        if let Ok(user_info) = get_user_info(&token_response.access_token).await {
                            if let Some(user) = find_or_create_user(&user_info, app_state).await? {
                                if user.is_active() {
                                    let tokens = generate_internal_tokens(&user, app_state).await?;
                                    cleanup_oauth_state(state, app_state).await;
                                    return Ok(tokens);
                                } else {
                                    return Err(OAuthError::UserInactive);
                                }
                            } else {
                                return Err(OAuthError::UserCreationFailed);
                            }
                        } else {
                            return Err(OAuthError::UserInfoFailed);
                        }
                    } else {
                        return Err(OAuthError::TokenExchangeFailed);
                    }
                } else {
                    return Err(OAuthError::InvalidState);
                }
            } else {
                return Err(OAuthError::StateNotFound);
            }
        } else {
            return Err(OAuthError::MissingState);
        }
    } else {
        return Err(OAuthError::MissingCode);
    }
}
```

#### **After: Early Returns and Guard Clauses**
```rust
// ✅ AFTER: Early returns eliminate deep nesting
pub async fn process_oauth_callback(
    code: &str,
    state: &str,
    app_state: &AppState,
) -> Result<TokenResponse, OAuthError> {
    // Guard clauses for input validation
    if code.is_empty() {
        return Err(OAuthError::MissingCode);
    }
    
    if state.is_empty() {
        return Err(OAuthError::MissingState);
    }
    
    // Validate OAuth state
    let stored_state = app_state
        .oauth_states
        .get(state)
        .ok_or(OAuthError::StateNotFound)?;
    
    if !stored_state.is_valid() {
        return Err(OAuthError::InvalidState);
    }
    
    // Exchange code for token
    let token_response = exchange_code_for_token(code)
        .await
        .map_err(|_| OAuthError::TokenExchangeFailed)?;
    
    // Get user information
    let user_info = get_user_info(&token_response.access_token)
        .await
        .map_err(|_| OAuthError::UserInfoFailed)?;
    
    // Find or create user
    let user = find_or_create_user(&user_info, app_state)
        .await?
        .ok_or(OAuthError::UserCreationFailed)?;
    
    // Check user status
    if !user.is_active() {
        return Err(OAuthError::UserInactive);
    }
    
    // Generate tokens and cleanup
    let tokens = generate_internal_tokens(&user, app_state).await?;
    cleanup_oauth_state(state, app_state).await;
    
    Ok(tokens)
}
```

### **5. Type Safety Improvements**

#### **Before: Primitive Obsession**
```rust
// ❌ BEFORE: Using primitive types for domain concepts
pub struct User {
    pub id: String,           // Could be any string
    pub email: String,        // Could be invalid email
    pub username: String,     // Could be empty or invalid
    pub role: String,         // Could be any string
    pub created_at: i64,      // Unix timestamp, could be negative
}

pub fn create_user(
    id: String,
    email: String,
    username: String,
    role: String,
) -> Result<User, String> {
    // Manual validation scattered throughout
    if email.is_empty() || !email.contains('@') {
        return Err("Invalid email".to_string());
    }
    
    if username.len() < 3 {
        return Err("Username too short".to_string());
    }
    
    // ... more validation
    
    Ok(User {
        id,
        email,
        username,
        role,
        created_at: Utc::now().timestamp(),
    })
}
```

#### **After: Strong Types with Validation**
```rust
// ✅ AFTER: Strong types with built-in validation
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(uuid::Uuid);

impl UserId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
    
    pub fn from_str(s: &str) -> Result<Self, UserError> {
        uuid::Uuid::parse_str(s)
            .map(Self)
            .map_err(|_| UserError::InvalidId { id: s.to_string() })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Email(String);

impl Email {
    pub fn new(email: String) -> Result<Self, UserError> {
        if validator::validate_email(&email) {
            Ok(Self(email))
        } else {
            Err(UserError::InvalidEmail { email })
        }
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Username(String);

impl Username {
    pub fn new(username: String) -> Result<Self, UserError> {
        let trimmed = username.trim();
        
        if trimmed.len() < 3 {
            return Err(UserError::UsernameTooShort { 
                length: trimmed.len() 
            });
        }
        
        if trimmed.len() > 50 {
            return Err(UserError::UsernameTooLong { 
                length: trimmed.len() 
            });
        }
        
        if !trimmed.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(UserError::InvalidUsernameCharacters);
        }
        
        Ok(Self(trimmed.to_string()))
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    User,
    Guest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub email: Email,
    pub username: Username,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn new(
        email: String,
        username: String,
        role: UserRole,
    ) -> Result<Self, UserError> {
        Ok(Self {
            id: UserId::new(),
            email: Email::new(email)?,
            username: Username::new(username)?,
            role,
            created_at: Utc::now(),
        })
    }
}
```

## 🔄 **Refactoring Process**

### **Step 1: Identify Refactoring Candidates**
```bash
# Run the clean code enforcement script
./scripts/enforce-clean-code.sh

# Look for specific patterns
grep -r "unwrap()" src/ --include="*.rs"
grep -r "expect(" src/ --include="*.rs"
grep -r "panic!" src/ --include="*.rs"
```

### **Step 2: Create Tests Before Refactoring**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_authentication_success() {
        // Test the current behavior before refactoring
        let request = AuthRequest {
            username: "testuser".to_string(),
            password: "validpassword".to_string(),
        };
        
        let result = handle_authentication(request, &test_state()).await;
        assert!(result.is_ok());
    }
    
    // Add more tests to cover edge cases
}
```

### **Step 3: Refactor Incrementally**
1. **Extract functions** one at a time
2. **Run tests** after each extraction
3. **Commit changes** frequently
4. **Update documentation** as you go

### **Step 4: Validate Improvements**
```bash
# Check that refactoring improved metrics
cargo clippy --workspace --all-features
cargo test --workspace --all-features
./scripts/enforce-clean-code.sh
```

## 📊 **Measuring Success**

### **Before Refactoring Metrics**
- Function length: 150+ lines
- Cyclomatic complexity: 15+
- Test coverage: 70%
- Clippy warnings: 50+

### **After Refactoring Targets**
- Function length: <100 lines
- Cyclomatic complexity: <10
- Test coverage: >90%
- Clippy warnings: 0

## 🎯 **Next Steps**

1. **Run the enforcement script** to identify current issues
2. **Prioritize refactoring** based on complexity and risk
3. **Create comprehensive tests** before making changes
4. **Refactor incrementally** with frequent testing
5. **Document improvements** and update team guidelines

This refactoring guide provides concrete examples and a systematic approach to improving code quality while maintaining the security and performance characteristics of your platform.
