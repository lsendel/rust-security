# Deployment Guide

## Overview
This guide provides step-by-step instructions for deploying the rust-security project components.

## Prerequisites
- Rust 1.70+
- Docker and Docker Compose
- PostgreSQL 13+
- Redis 6+

## Core Components Deployment

### 1. Policy Service
```bash
# Build and run policy service
cargo build --release -p policy-service
./target/release/policy-service
```

### 2. Authentication Service  
```bash
# Build with essential features only
cargo build --release -p auth-service --features security-essential
./target/release/auth-service
```

### 3. Common Components
```bash
# Build shared libraries
cargo build --release -p common
```

## Environment Configuration
Set the following environment variables:

```bash
export DATABASE_URL="postgresql://user:pass@localhost/rustauth"
export REDIS_URL="redis://localhost:6379"
export JWT_SECRET="your-secret-key"
export ALLOWED_ORIGINS="http://localhost:3000"
```

## Docker Deployment
```bash
# Build and start services
docker-compose up --build

# Check service health
curl http://localhost:8080/health
curl http://localhost:8081/health
```

## Security Considerations
- Use TLS/SSL in production
- Rotate JWT secrets regularly  
- Configure proper CORS origins
- Enable audit logging
- Use secrets management system

## Monitoring
- Health endpoints available at `/health`
- Metrics endpoints at `/metrics` 
- Logs structured in JSON format
- Use monitoring tools like Prometheus/Grafana

## Troubleshooting
Common issues and solutions:
- **Database connection**: Check DATABASE_URL and PostgreSQL status
- **Redis connection**: Verify REDIS_URL and Redis availability
- **JWT errors**: Ensure JWT_SECRET is set properly
- **CORS errors**: Configure ALLOWED_ORIGINS correctly