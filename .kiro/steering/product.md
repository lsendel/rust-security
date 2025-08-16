# Product Overview

This is a Rust-based security workspace providing OAuth2-compatible authentication and Cedar-based authorization services.

## Services

- **auth-service** (port 8080): OAuth2-compatible authentication service handling token issuance, introspection, and revocation. Uses Redis for token persistence with in-memory fallback.
- **policy-service** (port 8081): Authorization service using AWS Cedar policy engine for fine-grained access control decisions.

## Key Features

- OAuth2 token flows (client_credentials, refresh_token)
- Token introspection and revocation
- Cedar policy-based authorization
- OpenAPI documentation generation
- Request tracing and audit logging
- Redis-backed token storage with fallback
- Security-focused middleware and headers