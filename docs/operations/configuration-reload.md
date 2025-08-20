# Configuration Reload Guide

This guide explains how to use the configuration reload functionality in the Auth Service for zero-downtime configuration updates.

## Overview

The Auth Service supports dynamic configuration reloading, allowing you to update most configuration settings without restarting the service. This capability is essential for production environments where uptime is critical.

## Configuration Sources

The service supports loading configuration from:

1. **Environment Variables** (default)
2. **Configuration Files** (TOML, JSON, YAML)

### Environment Variables

By default, the service loads configuration from environment variables:

```bash
export BIND_ADDR="0.0.0.0:8080"
export REDIS_URL="redis://localhost:6379"
export JWT_ACCESS_TOKEN_TTL_SECONDS="3600"
export RATE_LIMIT_REQUESTS_PER_MINUTE="120"
# ... other configuration variables
```

### Configuration Files

To use file-based configuration, set the `CONFIG_FILE` environment variable:

```bash
export CONFIG_FILE="/etc/auth-service/config.toml"
```

#### TOML Configuration Example

```toml
# /etc/auth-service/config.toml
bind_addr = "0.0.0.0:8080"
redis_url = "redis://localhost:6379"

[security]
jwt_access_token_ttl_seconds = 3600
jwt_refresh_token_ttl_seconds = 86400
rsa_key_size = 2048
enforce_pkce = true

[rate_limiting]
requests_per_minute = 120
burst_size = 20
per_ip_limit = 200

[features]
mfa_enabled = true
scim_enabled = true
oidc_enabled = true
```

#### JSON Configuration Example

```json
{
  "bind_addr": "0.0.0.0:8080",
  "redis_url": "redis://localhost:6379",
  "security": {
    "jwt_access_token_ttl_seconds": 3600,
    "jwt_refresh_token_ttl_seconds": 86400,
    "enforce_pkce": true
  },
  "rate_limiting": {
    "requests_per_minute": 120,
    "burst_size": 20
  },
  "features": {
    "mfa_enabled": true,
    "scim_enabled": true
  }
}
```

#### YAML Configuration Example

```yaml
bind_addr: "0.0.0.0:8080"
redis_url: "redis://localhost:6379"

security:
  jwt_access_token_ttl_seconds: 3600
  jwt_refresh_token_ttl_seconds: 86400
  enforce_pkce: true

rate_limiting:
  requests_per_minute: 120
  burst_size: 20

features:
  mfa_enabled: true
  scim_enabled: true
```

## Reload Methods

### 1. Signal-Based Reload (Unix/Linux)

Send a `SIGHUP` signal to the process:

```bash
# Find the process ID
ps aux | grep auth-service

# Send SIGHUP signal
kill -HUP <PID>

# Or if running with systemd
systemctl reload auth-service
```

### 2. HTTP API Reload

Use the admin API endpoints for programmatic reloading:

#### Trigger Reload

```bash
curl -X POST http://localhost:8080/admin/config/reload \
  -H "Content-Type: application/json" \
  -H "X-Signature: <HMAC_SIGNATURE>" \
  -H "X-Timestamp: $(date +%s)" \
  -d '{"force": false}'
```

#### Check Configuration Status

```bash
curl http://localhost:8080/admin/config/status \
  -H "X-Signature: <HMAC_SIGNATURE>" \
  -H "X-Timestamp: $(date +%s)"
```

Response:
```json
{
  "version": 5,
  "last_reload": "2024-01-15T10:30:00Z",
  "source": "file",
  "validation_status": "valid",
  "requires_restart": false
}
```

### 3. Kubernetes ConfigMap Reload

For Kubernetes deployments using ConfigMaps:

```bash
# Update the ConfigMap
kubectl create configmap auth-config --from-file=config.toml --dry-run=client -o yaml | kubectl apply -f -

# Trigger reload
kubectl exec deployment/auth-service -- kill -HUP 1
```

## Configuration Validation

Before applying changes, the service validates the new configuration:

### Validation Rules

1. **Required Fields**: All mandatory configuration fields must be present
2. **Type Validation**: Values must be of the correct type
3. **Range Validation**: Numeric values must be within acceptable ranges
4. **Format Validation**: URLs, addresses, and other formatted fields are checked
5. **Dependency Validation**: Related configuration options are validated together

### Validation API

Validate configuration without applying:

```bash
curl -X POST http://localhost:8080/admin/config/validate \
  -H "Content-Type: application/json" \
  -H "X-Signature: <HMAC_SIGNATURE>" \
  -H "X-Timestamp: $(date +%s)" \
  -d @new-config.json
```

Response:
```json
{
  "valid": true,
  "errors": [],
  "warnings": [
    "JWT token TTL is longer than recommended"
  ]
}
```

## Reloadable vs. Non-Reloadable Settings

### ✅ Reloadable Settings

These can be changed without restarting:

- **Rate Limiting**: Requests per minute, burst size, per-IP limits
- **Security Settings**: JWT TTL, PKCE enforcement, CORS origins
- **Feature Flags**: MFA, SCIM, OIDC, logging levels
- **Monitoring**: Metrics configuration, health check intervals
- **OAuth Settings**: Code TTL, refresh token rotation
- **SCIM Settings**: Max results, case sensitivity
- **External URLs**: Redis connections (reconnects automatically)

### ❌ Non-Reloadable Settings (Require Restart)

These require a service restart:

- **Server Bind Address**: `bind_addr`
- **Store Backend Type**: Switching between SQL/Redis/Hybrid
- **Database Connection String**: Core database URL
- **TLS Configuration**: Certificate and key changes

## Change Detection

The system automatically detects configuration changes and categorizes them:

### Example Change Log

```
[INFO] Configuration change: rate_limiting.requests_per_minute: 60 -> 120
[INFO] Configuration change: features.mfa_enabled: false -> true
[WARN] Configuration change: bind_addr: 127.0.0.1:8080 -> 0.0.0.0:8080 (requires restart)
```

## Rollback Capability

If a configuration change causes issues, you can rollback:

### Automatic Rollback

The service keeps a backup of the previous working configuration:

```bash
curl -X POST http://localhost:8080/admin/config/rollback \
  -H "X-Signature: <HMAC_SIGNATURE>" \
  -H "X-Timestamp: $(date +%s)"
```

### Manual Rollback

Restore from a previous configuration file:

```bash
# Copy previous config
cp /etc/auth-service/config.toml.backup /etc/auth-service/config.toml

# Trigger reload
kill -HUP <PID>
```

## Error Handling

### Validation Failures

If validation fails, the service:
1. Logs validation errors
2. Keeps the current configuration
3. Returns error details via API
4. Maintains service availability

### Reload Failures

If reload fails after validation:
1. Automatically rolls back to previous configuration
2. Logs the failure reason
3. Continues operating with previous config
4. Sends alerts if monitoring is configured

## Monitoring and Metrics

### Configuration Metrics

The service exposes Prometheus metrics:

```
# Configuration reload metrics
config_reload_attempts_total{result="success|failure"}
config_reload_duration_seconds
config_validation_failures_total
config_version_current

# Current configuration status
config_requires_restart{value="true|false"}
config_last_reload_timestamp
```

### Health Checks

Configuration health is included in health endpoints:

```bash
curl http://localhost:8080/health/detailed
```

Response includes:
```json
{
  "configuration": {
    "status": "healthy",
    "version": 5,
    "last_reload": "2024-01-15T10:30:00Z",
    "requires_restart": false
  }
}
```

## Security Considerations

### Admin Endpoint Protection

Configuration endpoints are protected by:

1. **Request Signing**: HMAC-SHA256 signatures required
2. **Timestamp Validation**: Prevents replay attacks
3. **IP Allowlisting**: Restrict access to admin networks
4. **TLS Encryption**: All communication encrypted

### Configuration Security

- Sensitive values (secrets, passwords) are not included in status responses
- Configuration files should have restrictive permissions (600)
- Use external secret management for production
- Audit all configuration changes

## Best Practices

### Development

1. **Test Configuration**: Always validate in development first
2. **Version Control**: Track configuration changes in Git
3. **Documentation**: Document configuration changes
4. **Gradual Rollout**: Test changes in staging before production

### Production

1. **Blue-Green Deployments**: Use for major configuration changes
2. **Monitoring**: Set up alerts for configuration failures
3. **Backup Strategy**: Maintain configuration backups
4. **Change Management**: Follow formal change processes

### Automation

1. **CI/CD Integration**: Automate configuration validation
2. **Configuration Drift**: Monitor for unplanned changes
3. **Compliance**: Ensure configurations meet security standards
4. **Documentation**: Auto-generate config documentation

## Troubleshooting

### Common Issues

#### Configuration Not Reloading

```bash
# Check if config file exists and is readable
ls -la /etc/auth-service/config.toml

# Check service logs
journalctl -u auth-service -f

# Verify configuration syntax
auth-service --validate-config /etc/auth-service/config.toml
```

#### Validation Errors

```bash
# Get detailed validation errors
curl -X POST http://localhost:8080/admin/config/validate \
  -H "Content-Type: application/json" \
  -d @config.json
```

#### Signal Handling Issues

```bash
# Check if process is receiving signals
strace -p <PID> -e signal

# Verify signal handler registration
cat /proc/<PID>/status | grep Sig
```

### Debug Mode

Enable debug logging for configuration reload:

```bash
export RUST_LOG="auth_service::config_reload=debug"
```

### Configuration Schema

Get the complete configuration schema:

```bash
curl http://localhost:8080/admin/config/schema
```

## Examples

### Updating Rate Limits

1. Edit configuration file:
```toml
[rate_limiting]
requests_per_minute = 200  # Increased from 120
burst_size = 30           # Increased from 20
```

2. Reload configuration:
```bash
kill -HUP $(pgrep auth-service)
```

3. Verify changes:
```bash
curl http://localhost:8080/admin/config/status
```

### Enabling New Features

1. Update feature flags:
```json
{
  "features": {
    "mfa_enabled": true,
    "scim_enabled": true,
    "threat_hunting": true
  }
}
```

2. Validate and apply:
```bash
curl -X POST http://localhost:8080/admin/config/validate -d @config.json
curl -X POST http://localhost:8080/admin/config/reload
```

### Emergency Rollback

```bash
# Quick rollback to previous configuration
curl -X POST http://localhost:8080/admin/config/rollback

# Verify service is working
curl http://localhost:8080/health
```