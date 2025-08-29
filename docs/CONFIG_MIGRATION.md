# Configuration System Migration

This document explains the migration from environment variable-based configuration to a static Rust configuration system.

## Overview

The new configuration system eliminates the need for `.env` files by embedding configuration directly in the Rust code. This approach provides:

- **Compile-time validation**: Configuration errors are caught at build time
- **Environment-specific defaults**: Different settings for development, testing, staging, and production
- **Reduced runtime dependencies**: No need to manage `.env` files in deployments
- **Better security**: Sensitive defaults are hardcoded per environment
- **Type safety**: All configuration is strongly typed

## Architecture

### Static Configuration (`config_static.rs`)

Contains environment-specific configuration that is determined at compile time:

- Server settings (bind address, CORS, timeouts)
- Security policies (rate limits, token expiry, session timeouts)
- Client credentials (with bcrypt-hashed secrets)
- Feature flags (OAuth providers, MFA, SCIM, etc.)
- OAuth configuration (PKCE, redirect schemes, etc.)

### Runtime Secrets (`RuntimeSecrets`)

Contains sensitive data that must still be provided via environment variables:

- `JWT_SIGNING_KEY`: JWT signing key (required in production)
- `DATABASE_URL`: Database connection string
- `REDIS_URL`: Redis connection string  
- `OIDC_*_CLIENT_SECRET`: OAuth provider client secrets
- `WEBHOOK_SIGNING_SECRET`: Webhook signature validation

### Environment Detection

The system automatically detects the environment from the `ENVIRONMENT` variable:

- `development` (default): Developer-friendly settings
- `testing`: Optimized for automated tests
- `staging`: Production-like with testing accommodations
- `production`: Secure, hardened configuration

## Migration Process

### 1. Run Migration Analysis

```bash
# Run the migration analysis tool
cargo run --bin auth-service -- --migrate-config

# Or use the convenience script
./scripts/migrate-config.sh
```

This will:
- Compare current `.env` configuration with static configuration
- Show differences and potential impacts
- Generate recommendations for your environment
- Validate that the migration is safe

### 2. Update Environment Variables

**Before Migration (.env file):**
```env
BIND_ADDR=127.0.0.1:8080
JWT_SECRET=CHANGE_ME_STRONG_SECRET_REQUIRED_FOR_PRODUCTION
JWT_ISSUER=auth-service
JWT_AUDIENCE=api-clients
TOKEN_EXPIRY_SECONDS=3600
CLIENT_CREDENTIALS=your_client_id:CHANGE_ME_STRONG_SECRET_REQUIRED
ALLOWED_SCOPES=read,write,admin
RATE_LIMIT_REQUESTS_PER_MINUTE=60
CORS_ALLOWED_ORIGINS=http://localhost:3000
```

**After Migration (environment variables):**
```bash
# Required
export ENVIRONMENT=production
export JWT_SIGNING_KEY="your-32-plus-character-cryptographically-strong-key"

# Optional (only if needed)
export DATABASE_URL="postgresql://user:pass@localhost/db"
export REDIS_URL="redis://localhost:6379"
export OIDC_GOOGLE_CLIENT_SECRET="your-google-oauth-secret"
```

### 3. Remove .env Files

After migration, remove `.env` files to ensure static configuration is used:

```bash
rm .env .env.local .env.production
```

### 4. Update Deployment Scripts

Update your deployment configuration to set only the required environment variables.

## Environment-Specific Configuration

### Development Environment

```rust
// Automatically applied when ENVIRONMENT=development
ServerConfig {
    bind_addr: "127.0.0.1:8080",
    cors_allowed_origins: ["http://localhost:3000", "http://localhost:3001"],
    // ...
}
```

Features:
- Permissive CORS for local development
- Long token expiry (2 hours) for convenience
- All OAuth providers enabled
- High rate limits
- Auto-generated JWT key if not provided

### Production Environment

```rust
// Automatically applied when ENVIRONMENT=production
ServerConfig {
    bind_addr: "0.0.0.0:8080",
    cors_allowed_origins: ["https://api.company.com", "https://app.company.com"],
    // ...
}
```

Features:
- Strict CORS policies
- Short token expiry (1 hour)
- GitHub OAuth disabled by default
- Conservative rate limits
- Strong secret validation required

### Testing Environment

```rust
// Automatically applied when ENVIRONMENT=testing
ServerConfig {
    bind_addr: "127.0.0.1:0", // Random port
    cors_allowed_origins: ["*"],
    // ...
}
```

Features:
- Permissive settings for automated tests
- High rate limits for test performance
- Simplified authentication requirements
- Short token expiry for fast test cycles

## Client Credentials

Client credentials are now defined statically per environment with bcrypt-hashed secrets:

```rust
// Development clients
clients.insert("dev-client", ClientInfo {
    name: "Development Client",
    secret_hash: "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW", // "dev-secret"
    scopes: ["read", "write", "admin", "dev"],
    redirect_uris: ["http://localhost:3000/auth/callback"],
    grant_types: ["authorization_code", "client_credentials"],
});
```

For production, you must update the placeholder hashes with real bcrypt hashes of your client secrets.

## Security Improvements

### Before (Environment Variables)
- Secrets stored in plain text in `.env` files
- Configuration errors discovered at runtime
- Inconsistent settings across environments
- Manual validation of configuration values

### After (Static Configuration)
- Client secrets stored as bcrypt hashes
- Configuration validated at compile time
- Consistent, environment-specific defaults
- Automatic validation of security policies

## Validation

The system includes comprehensive validation:

### Compile-Time Validation
- Type checking for all configuration fields
- Range validation for numeric values (token expiry, rate limits)
- URL validation for endpoints and redirect URIs

### Runtime Validation
- JWT key strength validation in production
- Client secret verification using bcrypt
- Environment-specific policy enforcement

### Migration Validation
- Comparison between old and new configuration
- Warning for missing or changed settings
- Validation that migration is safe to perform

## Usage Examples

### Basic Usage

```rust
use auth_service::config_static::ConfigManager;

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration automatically based on ENVIRONMENT
    let config = ConfigManager::new()?;
    
    // Use static configuration
    let bind_addr = &config.static_config.server.bind_addr;
    
    // Use runtime secrets
    let jwt_key = config.jwt_signing_key();
    
    // Check feature flags
    if config.is_feature_enabled("oidc_google") {
        // Enable Google OAuth
    }
    
    Ok(())
}
```

### Client Validation

```rust
// Validate client credentials
let is_valid = config.validate_client_credentials("dev-client", "dev-secret");

// Get client information
if let Some(client_info) = config.get_client_info("dev-client") {
    println!("Client: {}", client_info.name);
    println!("Scopes: {:?}", client_info.scopes);
}
```

## Troubleshooting

### Common Issues

1. **"JWT_SIGNING_KEY is required in production"**
   - Set the `JWT_SIGNING_KEY` environment variable with a strong key (32+ characters)

2. **"Client has placeholder hash"**
   - Update the client secret hash in the static configuration with a real bcrypt hash

3. **"Configuration differs from legacy"**
   - Review the migration report and update settings as needed

### Migration Validation

Run the migration tool to identify issues:

```bash
cargo run --bin auth-service -- --migrate-config
```

Look for:
- ❌ Validation errors that must be fixed
- ⚠️  Warnings that should be reviewed
- 💡 Recommendations for your environment

## Benefits

### For Developers
- No more managing `.env` files
- Configuration errors caught at compile time
- Environment-specific defaults work out of the box
- Clear documentation of all available settings

### For Operations
- Reduced deployment complexity
- Fewer environment variables to manage
- Built-in validation and security policies
- Consistent configuration across environments

### For Security
- Secrets are hashed, not stored in plain text
- Strong validation of security parameters
- Environment-specific security policies
- Reduced risk of configuration errors

## Rollback Plan

If you need to rollback to the old system:

1. Keep the old `config.rs` file (don't delete it)
2. Update `main.rs` to use `AppConfig::from_env()` instead of `ConfigManager::new()`
3. Restore your `.env` files
4. Remove references to `config_static` and `config_migration` modules

The old system will continue to work alongside the new system during the transition period.