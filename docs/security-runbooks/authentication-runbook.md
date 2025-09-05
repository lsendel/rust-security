# Authentication System Security Runbook

## Overview

This runbook provides comprehensive operational procedures for managing the authentication system security, monitoring, troubleshooting, and incident response for the Rust Security Platform's authentication service.

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Monitoring and Alerting](#monitoring-and-alerting)
3. [Common Issues and Troubleshooting](#common-issues-and-troubleshooting)
4. [Emergency Procedures](#emergency-procedures)
5. [Maintenance Procedures](#maintenance-procedures)
6. [Security Hardening](#security-hardening)

## System Architecture

### Core Components

#### Authentication Service
- **Location**: `/auth-service/src/main.rs`
- **Function**: Primary authentication and authorization service
- **Dependencies**: Redis, PostgreSQL, JWT/JWKS system
- **Ports**: 3000 (HTTP), health check on `/health`

#### Multi-Factor Authentication (MFA)
- **Location**: `/auth-service/src/mfa/`
- **Function**: TOTP, SMS, Email, WebAuthn, and backup codes
- **Dependencies**: External SMS/Email services, TOTP libraries
- **Configuration**: Environment variables for each MFA method

#### Threat Intelligence
- **Location**: `/auth-service/src/threat_intelligence/`
- **Function**: AI-based behavioral analysis and anomaly detection
- **Dependencies**: Machine learning models, user behavior profiles
- **Configuration**: Risk thresholds and learning parameters

### Key Configuration Files
```
/auth-service/src/config_production.rs    # Production configuration
/.env.example                            # Environment template
/auth-service/Cargo.toml                 # Dependencies and features
```

## Monitoring and Alerting

### Health Checks

#### Primary Health Check
```bash
# Check service health
curl -s http://localhost:3000/health | jq

# Expected response
{
  "status": "healthy",
  "service": "rust-security-auth-service",
  "version": "2.0.0",
  "timestamp": "2025-01-15T10:30:00Z",
  "features": {
    "user_registration": true,
    "oauth2_flows": true,
    "jwt_authentication": true,
    "multi_factor_auth": true,
    "session_management": true
  }
}
```

#### Detailed Status Check
```bash
# Check comprehensive status
curl -s http://localhost:3000/api/v1/status | jq
```

### Key Metrics to Monitor

#### Authentication Metrics
- **Login Success Rate**: Should be > 95%
- **MFA Challenge Success Rate**: Should be > 90%
- **JWT Token Generation Rate**: Monitor for spikes
- **Session Creation Rate**: Normal business patterns
- **Password Reset Requests**: Monitor for unusual spikes

#### Security Metrics
- **Failed Login Attempts**: Alert if > 100/minute from single IP
- **Account Lockouts**: Monitor patterns and frequency
- **Suspicious Behavior Alerts**: From AI threat detection
- **Rate Limit Triggers**: Monitor API endpoint abuse
- **Compliance Violations**: Any critical violations require immediate attention

#### System Performance
- **Response Time**: < 200ms for authentication requests
- **Memory Usage**: Monitor for leaks in long-running processes
- **CPU Usage**: Should remain < 70% under normal load
- **Database Connections**: Monitor pool utilization
- **Redis Connection Health**: Session storage availability

### Alert Thresholds

#### Critical Alerts (P0)
```yaml
Failed Logins: >1000 in 5 minutes
System Downtime: >30 seconds
Database Connection Failure: Any occurrence
Memory Usage: >90% for 5+ minutes
Critical Security Violation: Any occurrence
```

#### Warning Alerts (P1)
```yaml
Failed Logins: >100 in 5 minutes from single IP
Response Time: >500ms for 2+ minutes
Memory Usage: >80% for 10+ minutes
MFA Failures: >50 in 5 minutes
Compliance Violations: High severity
```

### Monitoring Commands

#### Service Status
```bash
# Check if service is running
systemctl status auth-service

# View recent logs
journalctl -u auth-service -f --lines=100

# Check process information
ps aux | grep auth-service
```

#### Resource Usage
```bash
# Memory usage
free -h
cat /proc/meminfo | grep -E "(MemTotal|MemAvailable|MemFree)"

# CPU usage
top -p $(pgrep auth-service)

# Disk usage
df -h
du -sh /path/to/auth-service/logs/
```

#### Network Connectivity
```bash
# Check port binding
netstat -tlnp | grep :3000

# Test database connectivity
redis-cli ping
psql -U username -h localhost -d dbname -c "SELECT version();"

# Check external dependencies
curl -s https://api.twilio.com/health  # SMS service
curl -s https://api.sendgrid.com/v3/health  # Email service
```

## Common Issues and Troubleshooting

### Authentication Failures

#### Issue: High Volume of Failed Logins
**Symptoms:**
- Spike in failed authentication attempts
- Users reporting login difficulties
- Rate limiting being triggered frequently

**Diagnosis:**
```bash
# Check recent auth logs
grep "authentication_failure" /var/log/auth-service/security.log | tail -50

# Analyze IP addresses
grep "authentication_failure" /var/log/auth-service/security.log | \
  grep -o '"source_ip":"[^"]*"' | sort | uniq -c | sort -nr

# Check rate limiting status
curl -s http://localhost:3000/security/threats/metrics | jq '.rate_limiting'
```

**Resolution:**
1. **Identify attack source**:
   ```bash
   # Block suspicious IPs (if confirmed malicious)
   iptables -A INPUT -s <malicious_ip> -j DROP
   ```

2. **Temporary measures**:
   ```bash
   # Increase rate limiting (emergency)
   export RATE_LIMIT_PER_IP_PER_MINUTE=50
   systemctl restart auth-service
   ```

3. **Long-term fixes**:
   - Review and update threat detection rules
   - Consider implementing CAPTCHA for repeated failures
   - Update IP reputation lists

#### Issue: JWT Token Validation Failures
**Symptoms:**
- Users reporting "invalid token" errors
- API requests returning 401 Unauthorized
- Token validation errors in logs

**Diagnosis:**
```bash
# Check JWT key status
curl -s http://localhost:3000/.well-known/jwks.json | jq

# Verify key rotation status
grep "key_rotation" /var/log/auth-service/application.log | tail -10

# Check token generation
grep "jwt_generation" /var/log/auth-service/application.log | tail -10
```

**Resolution:**
1. **Check key configuration**:
   ```bash
   # Verify RSA keys are properly configured
   echo $RSA_PRIVATE_KEY | base64 -d | openssl rsa -check
   
   # Check JWT secret
   echo "JWT_SECRET length: ${#JWT_SECRET}"
   ```

2. **Force key rotation**:
   ```bash
   # Trigger manual key rotation
   curl -X POST http://localhost:3000/admin/keys/rotate \
     -H "Authorization: Bearer $ADMIN_TOKEN"
   ```

3. **Verify JWKS endpoint**:
   ```bash
   # Test JWKS endpoint accessibility
   curl -v http://localhost:3000/.well-known/jwks.json
   ```

### MFA Issues

#### Issue: TOTP Codes Not Working
**Symptoms:**
- Users reporting TOTP codes are invalid
- MFA verification failures in logs

**Diagnosis:**
```bash
# Check system time synchronization
timedatectl status

# Check MFA service logs
grep "mfa_verification" /var/log/auth-service/security.log | tail -20

# Verify TOTP window configuration
grep "totp_window" /var/log/auth-service/application.log
```

**Resolution:**
1. **Fix time synchronization**:
   ```bash
   # Sync system time
   sudo chrony sources -v
   sudo systemctl restart chronyd
   ```

2. **Adjust TOTP window**:
   ```bash
   # Temporarily increase tolerance window
   export MFA_TOTP_WINDOW=2
   systemctl restart auth-service
   ```

#### Issue: SMS/Email MFA Not Delivering
**Symptoms:**
- Users not receiving MFA codes via SMS/Email
- External service integration failures

**Diagnosis:**
```bash
# Check external service credentials
curl -s https://api.twilio.com/2010-04-01/Accounts/$TWILIO_SID.json \
  -u $TWILIO_SID:$TWILIO_TOKEN

# Check email service status
curl -s https://api.sendgrid.com/v3/user/profile \
  -H "Authorization: Bearer $SENDGRID_API_KEY"

# Review MFA logs
grep "mfa_delivery" /var/log/auth-service/application.log | tail -20
```

**Resolution:**
1. **Verify service credentials**:
   ```bash
   # Test Twilio integration
   curl -X POST https://api.twilio.com/2010-04-01/Accounts/$TWILIO_SID/Messages.json \
     -u $TWILIO_SID:$TWILIO_TOKEN \
     -d "To=+1234567890" \
     -d "From=+1987654321" \
     -d "Body=Test message"
   ```

2. **Check rate limits**:
   - Review external service usage quotas
   - Verify account standing with providers

### Performance Issues

#### Issue: High Response Times
**Symptoms:**
- API responses taking >500ms
- User complaints about slow authentication
- Timeout errors

**Diagnosis:**
```bash
# Check current response times
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:3000/health

# Monitor active connections
ss -tuln | grep :3000

# Check database performance
redis-cli --latency -h localhost -p 6379
```

**Resolution:**
1. **Database optimization**:
   ```bash
   # Check Redis memory usage
   redis-cli info memory
   
   # Optimize database connections
   redis-cli config set maxclients 1000
   ```

2. **Resource scaling**:
   ```bash
   # Increase service instances (if using containers)
   docker-compose up --scale auth-service=3
   
   # Monitor resource usage
   top -p $(pgrep auth-service)
   ```

## Emergency Procedures

### Service Recovery

#### Complete Service Failure
1. **Immediate Assessment**:
   ```bash
   # Check if service is running
   systemctl status auth-service
   
   # Check port availability
   netstat -tlnp | grep :3000
   
   # Review recent logs
   journalctl -u auth-service --since "10 minutes ago"
   ```

2. **Quick Recovery Steps**:
   ```bash
   # Restart service
   systemctl restart auth-service
   
   # Verify health
   sleep 10
   curl http://localhost:3000/health
   
   # Check dependencies
   redis-cli ping
   ```

3. **If restart fails**:
   ```bash
   # Check configuration
   /path/to/auth-service --check-config
   
   # Start with verbose logging
   RUST_LOG=debug systemctl restart auth-service
   
   # Monitor startup
   journalctl -u auth-service -f
   ```

#### Database Connection Issues
1. **Redis Connectivity**:
   ```bash
   # Test connection
   redis-cli ping
   
   # Check Redis status
   systemctl status redis
   
   # Restart Redis if needed
   systemctl restart redis
   ```

2. **Session Recovery**:
   ```bash
   # Clear potentially corrupted sessions
   redis-cli FLUSHDB
   
   # Restart auth service
   systemctl restart auth-service
   ```

#### Security Breach Response
1. **Immediate Containment**:
   ```bash
   # Isolate service (if compromised)
   iptables -A INPUT -p tcp --dport 3000 -j DROP
   
   # Invalidate all sessions
   redis-cli FLUSHALL
   
   # Force JWT key rotation
   curl -X POST http://localhost:3000/admin/keys/rotate
   ```

2. **Evidence Preservation**:
   ```bash
   # Backup current logs
   tar -czf /tmp/auth-logs-$(date +%Y%m%d-%H%M%S).tar.gz \
     /var/log/auth-service/
   
   # Create system snapshot
   systemctl stop auth-service
   tar -czf /tmp/auth-service-snapshot-$(date +%Y%m%d-%H%M%S).tar.gz \
     /path/to/auth-service/
   ```

## Maintenance Procedures

### Routine Maintenance

#### Daily Tasks
```bash
#!/bin/bash
# Daily maintenance script

# Check service health
curl -s http://localhost:3000/health | jq '.status'

# Review error logs
grep -i error /var/log/auth-service/application.log | tail -10

# Check disk usage
df -h /var/log/auth-service/

# Verify backup completion
ls -la /backup/auth-service/$(date +%Y%m%d)*
```

#### Weekly Tasks
```bash
#!/bin/bash
# Weekly maintenance script

# Rotate logs
logrotate -f /etc/logrotate.d/auth-service

# Update threat intelligence feeds
curl -X POST http://localhost:3000/admin/threat-intel/update

# Run security compliance checks
./scripts/security-test.sh

# Generate security metrics report
curl -s http://localhost:3000/security/threats/metrics > \
  /reports/security-metrics-$(date +%Y%m%d).json
```

#### Monthly Tasks
```bash
#!/bin/bash
# Monthly maintenance script

# Update dependencies
cargo audit
cargo outdated

# Review user accounts
curl -s http://localhost:3000/admin/users/inactive | \
  jq '.users[] | select(.last_login < (now - 86400*30))'

# Compliance framework checks
curl -s http://localhost:3000/compliance/summary | \
  jq '.frameworks'

# Performance optimization review
./scripts/performance-analysis.sh
```

### Security Updates

#### Applying Security Patches
1. **Pre-update checks**:
   ```bash
   # Backup current version
   systemctl stop auth-service
   cp -r /path/to/auth-service /backup/auth-service-$(date +%Y%m%d)
   
   # Run security tests
   ./scripts/security-test.sh
   ```

2. **Update process**:
   ```bash
   # Update dependencies
   cargo update
   
   # Run security audit
   cargo audit
   
   # Rebuild service
   cargo build --release
   
   # Update configuration if needed
   cp config/production.toml.new config/production.toml
   ```

3. **Post-update verification**:
   ```bash
   # Start service
   systemctl start auth-service
   
   # Verify functionality
   ./scripts/integration-tests.sh
   
   # Run security tests
   ./scripts/security-test.sh
   ```

## Security Hardening

### Configuration Hardening

#### Environment Variables
```bash
# Required security configurations
export JWT_SECRET="$(openssl rand -hex 32)"
export RSA_PRIVATE_KEY="$(cat /secure/path/to/private-key.pem | base64 -w 0)"
export APP_ENV="production"
export RUST_LOG="info"

# Security headers
export SECURITY_HEADERS_ENABLED="true"
export HSTS_MAX_AGE="31536000"
export CSP_POLICY="default-src 'self'"

# Rate limiting
export RATE_LIMIT_PER_IP_PER_MINUTE="100"
export RATE_LIMIT_BURST="10"

# MFA settings
export MFA_REQUIRED_FOR_ADMIN="true"
export MFA_BACKUP_CODES_COUNT="10"
```

#### File Permissions
```bash
# Set secure file permissions
chmod 600 /etc/auth-service/config.toml
chmod 700 /var/log/auth-service/
chmod 644 /etc/systemd/system/auth-service.service

# Set ownership
chown auth-service:auth-service /var/log/auth-service/
chown root:root /etc/auth-service/config.toml
```

#### Network Security
```bash
# Firewall configuration
ufw allow from trusted_network to any port 3000
ufw deny 3000

# TLS configuration
# Ensure HTTPS is enforced in production
export FORCE_HTTPS="true"
export TLS_CERT_PATH="/etc/ssl/certs/auth-service.crt"
export TLS_KEY_PATH="/etc/ssl/private/auth-service.key"
```

### Monitoring Security

#### Log Analysis
```bash
# Security event monitoring
tail -f /var/log/auth-service/security.log | \
  grep -E "(authentication_failure|suspicious_activity|security_violation)"

# Automated log analysis
./scripts/security-log-analyzer.sh | \
  grep -E "(CRITICAL|HIGH)" | \
  mail -s "Security Alert" security-team@company.com
```

#### Automated Security Checks
```bash
#!/bin/bash
# Automated security validation

# Check for weak passwords
curl -s http://localhost:3000/admin/security/weak-passwords | \
  jq '.weak_passwords[] | select(.strength < 60)'

# Verify encryption status
curl -s http://localhost:3000/admin/security/encryption-status | \
  jq '.encryption_enabled'

# Check compliance status
curl -s http://localhost:3000/compliance/violations | \
  jq '.critical_violations[]'
```

## Escalation Procedures

### Contact Information
- **Primary On-call**: [Phone/Email]
- **Security Team Lead**: [Phone/Email]  
- **DevOps Manager**: [Phone/Email]
- **CISO**: [Phone/Email]

### Escalation Triggers
- **P0**: Service down >5 minutes, security breach, data exposure
- **P1**: Performance degradation >30%, multiple failed authentications
- **P2**: Configuration issues, compliance violations

---

**Document Version**: 1.0  
**Last Updated**: [Current Date]  
**Next Review**: [Date + 6 months]  
**Owner**: Security Operations Team