# 🔧 Enable SCIM Endpoints Guide

## How to Enable SCIM 2.0 Group Management

The SCIM implementation is complete but not currently exposed. Here's how to enable it:

### Option 1: Modify main.rs (Recommended)

```rust
// In auth-service/src/main.rs
// Add SCIM import
mod scim;

// Add to the router creation
let app = axum::Router::new()
    // ... existing routes ...
    // Add SCIM routes
    .merge(scim::router())
    // ... rest of configuration ...
```

### Option 2: Feature Flag Approach

```rust
// Add conditional compilation
#[cfg(feature = "scim")]
let app = app.merge(scim::router());
```

### Option 3: Environment Variable Control

```rust
// Enable based on environment
if std::env::var("ENABLE_SCIM").is_ok() {
    let app = app.merge(scim::router());
}
```

## Required Dependencies

The SCIM implementation depends on:
- `AppState` with `store` field implementing the `Store` trait
- Common SCIM types (`ScimUser`, `ScimGroup`) 
- Error handling (`AuthError`)

## Testing When Enabled

Once enabled, test with:

```bash
./test-scim-endpoints.sh
```