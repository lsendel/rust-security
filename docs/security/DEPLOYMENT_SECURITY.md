# Security Deployment Guide

## Overview

This guide provides comprehensive security deployment instructions for the Rust authentication service in production environments. It covers security hardening, monitoring, and operational best practices.

## Table of Contents

1. [Pre-Deployment Security Checklist](#pre-deployment-security-checklist)
2. [Environment Configuration](#environment-configuration)
3. [Network Security](#network-security)
4. [Cryptographic Configuration](#cryptographic-configuration)
5. [Rate Limiting and DDoS Protection](#rate-limiting-and-ddos-protection)
6. [Security Monitoring](#security-monitoring)
7. [Backup and Recovery](#backup-and-recovery)
8. [Incident Response](#incident-response)

## Pre-Deployment Security Checklist

### Configuration Validation

Before deploying to production, run the security configuration validator:

```bash
# Validate production configuration
cargo run --bin validate_config -- --production --strict

# Generate security report
cargo run --bin validate_config -- --production --output security-report.md --format markdown
```

### Security Requirements

- [ ] **Configuration Validation**: All critical security issues resolved
- [ ] **Secrets Management**: No hardcoded secrets or keys
- [ ] **TLS Configuration**: HTTPS only with strong cipher suites
- [ ] **Database Security**: Encrypted connections and proper access controls
- [ ] **Logging**: Security event logging configured
- [ ] **Monitoring**: Security metrics and alerting enabled
- [ ] **Rate Limiting**: Production rate limits configured
- [ ] **Network Security**: Firewall rules and network segmentation

## Environment Configuration

### Required Environment Variables

```bash
# === CORE SECURITY ===
# JWT Configuration
JWT_SECRET="$(openssl rand -base64 64)"  # 512-bit secret minimum
JWT_ALGORITHM="RS256"  # Use RS256 for production
JWT_ACCESS_TOKEN_EXPIRY_MINUTES="15"  # Short-lived access tokens
JWT_REFRESH_TOKEN_EXPIRY_DAYS="7"  # Reasonable refresh token lifetime

# Encryption Configuration
ENCRYPTION_KEY="$(openssl rand -base64 32)"  # AES-256 key
ARGON2_MEMORY_SIZE="65536"  # 64MB minimum for Argon2
ARGON2_ITERATIONS="3"  # Minimum 3 iterations
ARGON2_PARALLELISM="4"  # CPU cores available

# === RATE LIMITING ===
# Global Limits
RATE_LIMIT_GLOBAL_PER_MINUTE="10000"
RATE_LIMIT_GLOBAL_PER_HOUR="100000"

# Per-IP Limits (strict for production)
RATE_LIMIT_PER_IP_PER_MINUTE="60"
RATE_LIMIT_PER_IP_PER_HOUR="600"
RATE_LIMIT_PER_IP_PER_DAY="5000"

# Security Features
RATE_LIMIT_BAN_THRESHOLD="5"  # Ban after 5 violations
RATE_LIMIT_BAN_DURATION_MINUTES="60"  # 1 hour ban
RATE_LIMIT_ENABLE_ADAPTIVE="true"  # Enable adaptive limits

# IP Filtering
RATE_LIMIT_ALLOWLIST_IPS="10.0.0.0/8,172.16.0.0/12"  # Internal networks
RATE_LIMIT_BANLIST_IPS=""  # External threat feeds

# === DATABASE ===
DATABASE_URL="postgresql://user:pass@localhost:5432/authdb?sslmode=require"
DATABASE_MAX_CONNECTIONS="20"
DATABASE_CONNECTION_TIMEOUT_SECONDS="30"

# === REDIS (if using distributed features) ===
REDIS_URL="rediss://user:pass@localhost:6379/0"  # Use TLS
REDIS_MAX_CONNECTIONS="50"
REDIS_CONNECTION_TIMEOUT_SECONDS="5"

# === SECURITY HEADERS ===
SECURITY_HEADERS_ENABLE_HSTS="true"
SECURITY_HEADERS_HSTS_MAX_AGE="31536000"  # 1 year
SECURITY_HEADERS_ENABLE_CSP="true"
SECURITY_HEADERS_FRAME_OPTIONS="DENY"
SECURITY_HEADERS_REFERRER_POLICY="strict-origin-when-cross-origin"

# === MONITORING ===
AUDIT_LOGGING_ENABLE="true"
AUDIT_LOGGING_LEVEL="LOW"  # Log from LOW severity up
AUDIT_LOGGING_FORMAT="json"  # JSON for SIEM integration
AUDIT_LOGGING_RETENTION_DAYS="365"  # 1 year retention

# === ENVIRONMENT ===
RUST_ENV="production"
RUST_LOG="auth_service=info,warn,error"  # No debug logs in production
DEVELOPMENT_MODE="false"
```

### Secrets Management

**DO NOT** store secrets directly in environment variables in production. Use a proper secrets management solution:

#### HashiCorp Vault
```bash
# Store secrets in Vault
vault kv put secret/auth-service \
    jwt_secret="$(openssl rand -base64 64)" \
    encryption_key="$(openssl rand -base64 32)"

# Enable Vault integration
VAULT_ADDR="https://vault.company.com"
VAULT_AUTH_METHOD="kubernetes"  # or other auth method
VAULT_ROLE="auth-service"
VAULT_MOUNT_PATH="secret"
```

#### AWS Secrets Manager
```bash
# Store secrets in AWS Secrets Manager
aws secretsmanager create-secret \
    --name "auth-service/production" \
    --secret-string '{"jwt_secret":"...","encryption_key":"..."}'

# Enable AWS integration
AWS_REGION="us-west-2"
AWS_SECRETS_MANAGER_SECRET_NAME="auth-service/production"
```

## Network Security

### TLS Configuration

```nginx
# Nginx configuration for TLS termination
server {
    listen 443 ssl http2;
    server_name auth.company.com;
    
    # TLS Configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private-key.pem;
    
    # Modern TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305';
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Firewall Rules

```bash
# UFW firewall configuration
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (restrict source IPs)
sudo ufw allow from 10.0.0.0/8 to any port 22

# Allow HTTPS
sudo ufw allow 443

# Allow application port (internal only)
sudo ufw allow from 10.0.0.0/8 to any port 8080

# Enable firewall
sudo ufw enable
```

### Network Segmentation

- Place authentication service in a DMZ or dedicated security zone
- Restrict database access to application servers only
- Use VPC/network security groups to control traffic flow
- Implement network intrusion detection systems (NIDS)

## Cryptographic Configuration

### Key Management

```bash
# Generate RSA key pair for JWT signing (recommended for production)
openssl genrsa -out private_key.pem 4096
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Store keys securely (not in filesystem)
# Use Vault, AWS KMS, or Azure Key Vault
```

### Post-Quantum Cryptography (Future-Proofing)

Enable post-quantum cryptography for future security:

```bash
# Enable post-quantum features
ENABLE_POST_QUANTUM="true"
PQ_ALGORITHM="ml_dsa_65"  # ML-DSA (NIST standard)
PQ_HYBRID_MODE="true"  # Run alongside classical crypto

# Migration settings
PQ_MIGRATION_MODE="hybrid"  # gradual, hybrid, or full
PQ_MIGRATION_TIMELINE_MONTHS="12"  # 12-month migration
```

## Rate Limiting and DDoS Protection

### Production Rate Limiting

```bash
# Strict production limits
RATE_LIMIT_PER_IP_PER_MINUTE="60"      # 1 request per second average
RATE_LIMIT_PER_IP_PER_HOUR="600"       # Allow some burst
RATE_LIMIT_PER_IP_PER_DAY="5000"       # Daily cap

# OAuth endpoint limits (more restrictive)
RATE_LIMIT_OAUTH_TOKEN_PER_MINUTE="10"
RATE_LIMIT_OAUTH_AUTHORIZE_PER_MINUTE="20"

# Adaptive rate limiting
RATE_LIMIT_ENABLE_ADAPTIVE="true"
RATE_LIMIT_CPU_THRESHOLD="75"          # Reduce limits when CPU > 75%
RATE_LIMIT_MEMORY_THRESHOLD="80"       # Reduce limits when memory > 80%

# Security features
RATE_LIMIT_BAN_THRESHOLD="3"           # Aggressive banning
RATE_LIMIT_BAN_DURATION_MINUTES="120"  # 2-hour bans
RATE_LIMIT_PROGRESSIVE_DELAYS="true"   # Increasing delays
```

### DDoS Protection

1. **Application Layer**: Rate limiting with Redis distributed backend
2. **Network Layer**: Use Cloudflare, AWS Shield, or similar
3. **Geographic Filtering**: Block traffic from suspicious regions
4. **Behavioral Analysis**: Implement threat detection patterns

## Security Monitoring

### Audit Logging

```bash
# Enable comprehensive audit logging
AUDIT_LOGGING_ENABLE="true"
AUDIT_LOGGING_LEVEL="LOW"  # Log low severity and above
AUDIT_LOGGING_FORMAT="json"
AUDIT_LOGGING_SIEM_INTEGRATION="true"

# Log all authentication events
AUDIT_AUTHENTICATION_EVENTS="true"
AUDIT_AUTHORIZATION_EVENTS="true"
AUDIT_RATE_LIMIT_VIOLATIONS="true"
AUDIT_CRYPTO_OPERATIONS="false"  # May be too verbose

# Retention and rotation
AUDIT_LOGGING_RETENTION_DAYS="365"
AUDIT_LOGGING_MAX_FILE_SIZE_MB="100"
AUDIT_LOGGING_MAX_FILES="50"
```

### Real-Time Monitoring

```bash
# Start security event monitoring
cargo run --bin audit_monitor -- --severity high --realtime

# Export security events for analysis
cargo run --bin audit_monitor -- --export security-events.json --duration 24h
```

### SIEM Integration

Configure your SIEM (Splunk, ELK Stack, etc.) to ingest audit logs:

```json
{
  "event_id": "uuid",
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "HIGH",
  "event_type": "AUTHENTICATION",
  "message": "Failed login attempt",
  "source_ip": "192.168.1.100",
  "user_id": "user123",
  "outcome": "FAILURE",
  "compliance_tags": ["authentication", "access_control"]
}
```

### Key Metrics to Monitor

1. **Authentication Metrics**:
   - Failed login rates
   - Account lockout events
   - Successful authentications by geography/time

2. **Rate Limiting Metrics**:
   - Rate limit violations per IP
   - Banned IPs and duration
   - Global rate limit hits

3. **Security Metrics**:
   - Certificate expiry dates
   - Cryptographic operation failures
   - Configuration validation results

4. **System Metrics**:
   - Response times for authentication requests
   - Memory and CPU usage during crypto operations
   - Database connection pool status

## Backup and Recovery

### Database Backups

```bash
# Automated daily backups with encryption
pg_dump -h localhost -U auth_user -d auth_db | \
  gpg --symmetric --cipher-algo AES256 --output backup-$(date +%Y%m%d).sql.gpg

# Retention: 30 daily, 12 monthly, 7 yearly
```

### Configuration Backups

- Version control all configuration files
- Backup secrets separately with encryption
- Test recovery procedures monthly

### Disaster Recovery

1. **Recovery Time Objective (RTO)**: 4 hours maximum
2. **Recovery Point Objective (RPO)**: 1 hour maximum data loss
3. **Backup Testing**: Monthly restore tests
4. **Geographic Distribution**: Store backups in multiple regions

## Incident Response

### Security Incident Playbook

#### 1. Detection and Analysis
- Monitor security alerts and audit logs
- Analyze suspicious patterns or anomalies
- Classify incident severity (Low/Medium/High/Critical)

#### 2. Containment
- **Immediate**: Block malicious IPs, disable compromised accounts
- **Short-term**: Isolate affected systems, preserve evidence
- **Long-term**: Apply patches, update security controls

#### 3. Eradication and Recovery
- Remove malware or unauthorized access
- Patch vulnerabilities
- Restore systems from clean backups if needed
- Verify system integrity

#### 4. Post-Incident Activity
- Document lessons learned
- Update security controls and procedures
- Conduct security awareness training

### Emergency Response Commands

```bash
# Emergency rate limiting (block all traffic temporarily)
curl -X POST https://auth.company.com/admin/emergency-lockdown \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Ban specific IP immediately
curl -X POST https://auth.company.com/admin/ban-ip \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"ip": "192.168.1.100", "duration_hours": 24}'

# Force password reset for user
curl -X POST https://auth.company.com/admin/force-password-reset \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"user_id": "compromised_user"}'

# Export security events for forensic analysis
cargo run --bin audit_monitor -- --export incident-$(date +%Y%m%d).json --duration 7d
```

## Security Testing

### Pre-Deployment Testing

```bash
# 1. Configuration validation
cargo run --bin validate_config -- --production --strict

# 2. Cryptographic performance under load
cargo run --bin crypto_benchmark --release -- --concurrent 100 --duration 300

# 3. Rate limiting stress test
cargo run --bin rate_limit_test -- --concurrent 1000 --duration 60

# 4. Security headers validation
curl -I https://auth.company.com/ | grep -E "(Strict-Transport|X-Frame|X-Content)"
```

### Ongoing Security Testing

1. **Penetration Testing**: Quarterly external penetration tests
2. **Vulnerability Scanning**: Weekly automated scans
3. **Code Security Review**: Security review for all code changes
4. **Dependency Scanning**: Daily checks for vulnerable dependencies

## Compliance Considerations

### SOC 2 Type II
- Implement access controls and monitoring
- Maintain audit logs for 1+ years
- Regular security awareness training
- Incident response procedures

### GDPR
- Data encryption at rest and in transit
- Right to erasure (user deletion)
- Data breach notification within 72 hours
- Privacy by design principles

### PCI DSS (if handling payment data)
- Network segmentation
- Strong access controls
- Regular security testing
- Secure development practices

## Maintenance and Updates

### Security Update Procedures

1. **Dependency Updates**: 
   - Weekly scan for security updates
   - Test in staging environment
   - Deploy during maintenance window

2. **Configuration Reviews**:
   - Monthly security configuration review
   - Annual security assessment
   - Update security policies as needed

3. **Key Rotation**:
   - JWT signing keys: Every 90 days
   - Encryption keys: Every 365 days
   - TLS certificates: Before expiry (auto-renewal recommended)

### Monitoring Security Posture

```bash
# Daily security status check
cargo run --bin validate_config -- --production --output daily-security-check.md

# Weekly comprehensive security report
cargo run --bin security_report -- --comprehensive --output weekly-security-report.pdf
```

## Support and Escalation

### Security Team Contacts
- **Security Incident**: security-incident@company.com
- **Security Questions**: security-team@company.com
- **Emergency Hotline**: +1-xxx-xxx-xxxx (24/7)

### Vendor Support
- **Critical Security Issues**: Create high-priority support ticket
- **Security Updates**: Subscribe to security mailing list
- **Professional Services**: Engage for security assessment

---

*This deployment security guide should be reviewed and updated quarterly or after significant security incidents.*