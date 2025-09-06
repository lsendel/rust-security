# Documentation Index

Complete index of all documentation in the Rust Security Platform.

## Table of Contents

### 1. Introduction
- [Overview](01-introduction/README.md)
- [Quick Start Guide](01-introduction/quick-start.md)
- [Developer Setup Guide](01-introduction/developer-setup.md)
- [Installation Guide](01-introduction/installation.md)
- [Configuration Guide](01-introduction/configuration.md)
- [Deployment Guide](01-introduction/deployment.md)
- [Integration Guide](01-introduction/integration.md)

### 2. Core Concepts
- [Overview](02-core-concepts/README.md)
- [System Architecture Overview](02-core-concepts/overview.md)
- [Component Architecture](02-core-concepts/components.md)

### 3. API Reference
- [Overview](03-api-reference/README.md)
- [API Overview](03-api-reference/overview.md)
- [Authentication API](03-api-reference/authentication.md)
- [Authorization API](03-api-reference/authorization.md)
- [User Management API](03-api-reference/user-management.md)
- [Token Management API](03-api-reference/token-management.md)
- [API Examples](03-api-reference/examples.md)

### 4. Security
- [Overview](04-security/README.md)
- [Security Overview](04-security/security-overview.md)
- [Threat Model](04-security/threat-model.md)
- [Authentication Security](04-security/authentication-security.md)

### 5. Service Documentation
- [Auth Service](../auth-service/README.md)
- [Policy Service](../enterprise/policy-service/README.md)
- [Common Crate](../common/README.md)

### 6. Development
- [Documentation Quality Checklist](07-development/documentation-quality-checklist.md)

## By User Role

### For New Developers
1. [Quick Start Guide](01-introduction/quick-start.md)
2. [Developer Setup Guide](01-introduction/developer-setup.md)
3. [System Architecture Overview](02-core-concepts/overview.md)
4. [API Overview](03-api-reference/overview.md)

### For System Administrators
1. [Installation Guide](01-introduction/installation.md)
2. [Configuration Guide](01-introduction/configuration.md)
3. [Deployment Guide](01-introduction/deployment.md)
4. [Security Overview](04-security/security-overview.md)

### For Application Integrators
1. [Integration Guide](01-introduction/integration.md)
2. [API Examples](03-api-reference/examples.md)
3. [Authentication API](03-api-reference/authentication.md)
4. [Authorization API](03-api-reference/authorization.md)

### For Security Teams
1. [Threat Model](04-security/threat-model.md)
2. [Authentication Security](04-security/authentication-security.md)
3. [Security Overview](04-security/security-overview.md)

## By Topic

### Architecture
- [System Architecture Overview](02-core-concepts/overview.md)
- [Component Architecture](02-core-concepts/components.md)

### Authentication
- [Authentication API](03-api-reference/authentication.md)
- [Authentication Security](04-security/authentication-security.md)

### Authorization
- [Authorization API](03-api-reference/authorization.md)

### User Management
- [User Management API](03-api-reference/user-management.md)

### Token Management
- [Token Management API](03-api-reference/token-management.md)

### Security
- [Security Overview](04-security/security-overview.md)
- [Threat Model](04-security/threat-model.md)
- [Authentication Security](04-security/authentication-security.md)

### Development
- [Developer Setup Guide](01-introduction/developer-setup.md)
- [Documentation Quality Checklist](07-development/documentation-quality-checklist.md)

### Operations
- [Installation Guide](01-introduction/installation.md)
- [Configuration Guide](01-introduction/configuration.md)
- [Deployment Guide](01-introduction/deployment.md)

## Service-Specific Documentation

### Auth Service
- [Auth Service README](../auth-service/README.md)
- [Authentication API](03-api-reference/authentication.md)
- [User Management API](03-api-reference/user-management.md)
- [Token Management API](03-api-reference/token-management.md)

### Policy Service
- [Policy Service README](../enterprise/policy-service/README.md)
- [Authorization API](03-api-reference/authorization.md)

### Common Crate
- [Common Crate README](../common/README.md)

## Quick Reference

### Common Tasks

#### Getting Started
```bash
# Quick start (30 seconds)
git clone https://github.com/company/rust-security.git
cd rust-security
./start-services-dev.sh --demo
```

#### API Authentication
```bash
# Get access token
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "client_id:client_secret" \
  -d "grant_type=client_credentials&scope=read write"
```

#### Policy Evaluation
```bash
# Check authorization
curl -X POST http://localhost:8081/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "principal": {"type": "User", "id": "alice"},
    "action": {"type": "Action", "id": "read"},
    "resource": {"type": "Document", "id": "doc1"}
  }'
```

### Environment Variables

#### Auth Service
```bash
PORT=8080
DATABASE_URL=postgresql://user:pass@localhost:5432/auth_service
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-super-secure-jwt-secret-key-32-chars-min
```

#### Policy Service
```bash
PORT=8081
POLICY_DIRECTORY=./policies
ENTITY_DIRECTORY=./entities
REDIS_URL=redis://localhost:6379
```

## Contributing

To contribute to the documentation:

1. Follow the [Documentation Quality Checklist](07-development/documentation-quality-checklist.md)
2. Use consistent formatting and structure
3. Include practical examples and best practices
4. Keep documentation up-to-date with code changes
5. Review documentation as part of code reviews

## License

This documentation is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.