# 🚀 Quick Start Guide - OAuth in 5 Minutes

Welcome! This guide will get you running with a secure OAuth 2.0 server in just 5 minutes.

## 🎯 What You'll Build

A minimal, production-ready OAuth 2.0 server with:
- ✅ Client credentials flow
- ✅ JWT tokens
- ✅ Rate limiting
- ✅ Health checks

## 📋 Prerequisites

Just Docker installed on your machine. That's it!

## 🏃 Option 1: Instant Start with Docker (Recommended)

```bash
# Pull and run the pre-configured image
docker run -p 8080:8080 ghcr.io/rust-security/auth-core:latest

# That's it! Your OAuth server is running at http://localhost:8080
```

### Test Your Server

```bash
# Health check
curl http://localhost:8080/health

# Get an access token
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=demo&client_secret=demo-secret"
```

## 🛠️ Option 2: Minimal Rust Setup (10 lines of code)

```rust
// main.rs
use auth_core::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a minimal OAuth server with defaults
    let server = AuthServer::minimal()
        .with_client("demo", "demo-secret")
        .build()?;
    
    // Start serving on port 8080
    server.serve("0.0.0.0:8080").await
}
```

```toml
# Cargo.toml
[package]
name = "my-auth-server"
version = "0.1.0"
edition = "2021"

[dependencies]
auth-core = "1.0"
tokio = { version = "1", features = ["full"] }
```

```bash
# Run it
cargo run

# Your OAuth server is ready!
```

## 🎓 Learning Path

### Level 1: Basic OAuth (You are here! ✅)
- Simple client credentials flow
- JWT tokens
- In-memory storage

### Level 2: Add Features (When you're ready)
- [Add authorization code flow](docs/guides/authorization-code.md)
- [Enable refresh tokens](docs/guides/refresh-tokens.md)
- [Add PostgreSQL storage](docs/guides/postgresql.md)

### Level 3: Production Features
- [Set up monitoring](docs/guides/monitoring.md)
- [Configure rate limiting](docs/guides/rate-limiting.md)
- [Add multi-factor authentication](docs/guides/mfa.md)

### Level 4: Enterprise Features
- [SAML integration](docs/guides/saml.md)
- [Advanced threat detection](docs/guides/threat-detection.md)
- [High availability setup](docs/guides/high-availability.md)

## 🔍 Common Use Cases

### Use Case 1: Microservices Authentication

```rust
// Service-to-service authentication
let server = AuthServer::minimal()
    .with_client("service-a", env::var("SERVICE_A_SECRET")?)
    .with_client("service-b", env::var("SERVICE_B_SECRET")?)
    .with_scope("api:read", "api:write")
    .build()?;
```

### Use Case 2: Mobile App Backend

```rust
// Mobile app with refresh tokens
let server = AuthServer::standard()
    .with_refresh_tokens(Duration::days(30))
    .with_pkce_required(true)
    .build()?;
```

### Use Case 3: Web Application

```rust
// Web app with session management
let server = AuthServer::standard()
    .with_session_store(RedisStore::new("redis://localhost")?)
    .with_cookie_settings(CookieSettings {
        secure: true,
        http_only: true,
        ..Default::default()
    })
    .build()?;
```

## ❓ Troubleshooting

### Port 8080 is already in use
```bash
# Use a different port
docker run -p 3000:8080 ghcr.io/rust-security/auth-core:latest
```

### Need to see more logs
```bash
# Enable debug logging
docker run -e RUST_LOG=debug -p 8080:8080 ghcr.io/rust-security/auth-core:latest
```

### Want to use a configuration file
```bash
# Mount your config file
docker run -v ./my-config.yaml:/config.yaml \
  -p 8080:8080 \
  ghcr.io/rust-security/auth-core:latest
```

## 📖 Next Steps

1. **Explore the API**: Check out our [interactive API documentation](http://localhost:8080/swagger-ui)
2. **Join the community**: Get help in our [Discord server](https://discord.gg/rust-security)
3. **Read the concepts**: Understand [OAuth 2.0 basics](docs/concepts/oauth2-basics.md)
4. **Deploy to production**: Follow our [production guide](docs/deployment/production.md)

## 🆘 Need Help?

- 💬 [Discord Community](https://discord.gg/rust-security) - Get real-time help
- 📝 [GitHub Discussions](https://github.com/rust-security/auth-service/discussions) - Ask questions
- 🐛 [Report Issues](https://github.com/rust-security/auth-service/issues) - Found a bug?
- 📧 [Email Support](mailto:support@rust-security.dev) - For sensitive questions

## 🎉 Congratulations!

You now have a working OAuth 2.0 server! 🎊

Start with the basics and add features as you need them. The modular design means you only pay for what you use.

---

**Ready for more?** Check out our [standard setup guide](GETTING_STARTED_STANDARD.md) for additional features like MFA and monitoring.