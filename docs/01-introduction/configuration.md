# Configuration Guide

Comprehensive guide to configuring the Rust Security Platform for different environments and use cases.

## Configuration Methods

The platform can be configured using multiple methods, which are applied in the following order of precedence:

1. **Command-line arguments** - Highest precedence
2. **Environment variables** - Medium precedence
3. **Configuration files** - Lowest precedence
4. **Default values** - Used when no other configuration is provided

## Configuration Files

### File Locations

Configuration files are loaded from the following locations (in order):

1. **Current working directory**: `./config.yaml`, `./config.json`, `./config.toml`
2. **Configuration directory**: `./config/`, `/etc/rust-security/`
3. **Home directory**: `~/.config/rust-security/`
4. **System directory**: `/usr/local/etc/rust-security/`

### File Formats

The platform supports multiple configuration file formats:

- **YAML** (recommended): `config.yaml`
- **JSON**: `config.json`
- **TOML**: `config.toml`

## Auth Service Configuration

### Core Settings

```yaml
# config.yaml
server:
  # Server binding
  host: "0.0.0.0"
  port: 8080
  
  # TLS configuration (optional)
  tls:
    enabled: false
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"
  
  # CORS settings
  cors:
    enabled: true
    origins:
      - "https://app.example.com"
      - "https://admin.example.com"
    methods:
      - "GET"
      - "POST"
      - "PUT"
      - "DELETE"
    headers:
      - "Content-Type"
      - "Authorization"

# Database configuration
database:
  url: "postgresql://user:pass@localhost:5432/auth_service"
  pool_size: 10
  connect_timeout: 30
  idle_timeout: 600

# Redis configuration
redis:
  url: "redis://localhost:6379"
  pool_size: 10
  connect_timeout: 10
  idle_timeout: 300

# JWT settings
jwt:
  secret: "your-super-secure-jwt-secret-key-32-chars-min"
  algorithm: "RS256"
  expiration: 3600  # 1 hour
  issuer: "https://auth.example.com"
  audience: "https://api.example.com"

# OAuth 2.0 settings
oauth:
  authorization_code_ttl: 600  # 10 minutes
  refresh_token_ttl: 2592000  # 30 days
  access_token_ttl: 3600  # 1 hour
  pkce_required: true

# Security settings
security:
  # Rate limiting
  rate_limit:
    enabled: true
    requests_per_minute: 100
    burst_size: 10
  
  # Password policy
  password:
    min_length: 8
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_special_chars: true
    max_age_days: 90
  
  # Multi-Factor Authentication
  mfa:
    required: false
    totp_issuer: "Rust Security Platform"
    backup_codes_count: 10

# Logging
logging:
  level: "info"
  format: "json"  # json or text
  file: "/var/log/auth-service.log"
  max_size: "100MB"
  max_files: 10

# Metrics and monitoring
metrics:
  enabled: true
  endpoint: "/metrics"
  collect_defaults: true

# Tracing
tracing:
  enabled: true
  endpoint: "http://jaeger:14268/api/traces"
  service_name: "auth-service"
```

### Environment Variables

All configuration options can be set using environment variables by converting the YAML structure to uppercase snake case:

```bash
# Server configuration
AUTH_SERVICE_HOST=0.0.0.0
AUTH_SERVICE_PORT=8080

# Database configuration
DATABASE_URL=postgresql://user:pass@localhost:5432/auth_service
DATABASE_POOL_SIZE=10

# Redis configuration
REDIS_URL=redis://localhost:6379
REDIS_POOL_SIZE=10

# JWT settings
JWT_SECRET=your-super-secure-jwt-secret-key-32-chars-min
JWT_EXPIRATION=3600

# OAuth 2.0 settings
OAUTH_AUTHORIZATION_CODE_TTL=600
OAUTH_REFRESH_TOKEN_TTL=2592000

# Security settings
SECURITY_RATE_LIMIT_ENABLED=true
SECURITY_RATE_LIMIT_REQUESTS_PER_MINUTE=100
```

## Policy Service Configuration

### Core Settings

```yaml
# policy-service/config.yaml
server:
  # Server binding
  host: "0.0.0.0"
  port: 8081
  
  # TLS configuration (optional)
  tls:
    enabled: false
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"

# Database configuration
database:
  url: "postgresql://user:pass@localhost:5432/policy_service"
  pool_size: 5
  connect_timeout: 30

# Redis configuration
redis:
  url: "redis://localhost:6379"
  pool_size: 5

# Policy settings
policies:
  # Directory containing policy files
  directory: "./policies"
  
  # Watch for file changes
  watch_for_changes: true
  
  # Cache TTL in seconds
  cache_ttl: 300
  
  # Maximum policy size (in KB)
  max_size_kb: 1024

# Entities settings
entities:
  # Directory containing entity files
  directory: "./entities"
  
  # Auto-reload entities when files change
  auto_reload: true

# Logging
logging:
  level: "info"
  format: "json"
  file: "/var/log/policy-service.log"

# Metrics and monitoring
metrics:
  enabled: true
  endpoint: "/metrics"
```

### Environment Variables

```bash
# Server configuration
POLICY_SERVICE_HOST=0.0.0.0
POLICY_SERVICE_PORT=8081

# Database configuration
POLICY_DATABASE_URL=postgresql://user:pass@localhost:5432/policy_service

# Redis configuration
POLICY_REDIS_URL=redis://localhost:6379

# Policy settings
POLICY_DIRECTORY=./policies
POLICY_CACHE_TTL=300
```

## Database Configuration

### PostgreSQL Setup

#### Create Database and User

```sql
-- Create databases
CREATE DATABASE auth_service;
CREATE DATABASE policy_service;

-- Create users
CREATE USER auth_user WITH PASSWORD 'secure_password_123';
CREATE USER policy_user WITH PASSWORD 'secure_password_456';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE auth_service TO auth_user;
GRANT ALL PRIVILEGES ON DATABASE policy_service TO policy_user;
```

#### Connection Strings

```bash
# Auth Service
DATABASE_URL=postgresql://auth_user:secure_password_123@localhost:5432/auth_service

# Policy Service
POLICY_DATABASE_URL=postgresql://policy_user:secure_password_456@localhost:5432/policy_service
```

### Redis Configuration

#### Basic Setup

```bash
# Redis connection string
REDIS_URL=redis://localhost:6379

# With authentication
REDIS_URL=redis://:password@localhost:6379

# With database selection
REDIS_URL=redis://localhost:6379/1
```

#### Redis Security

```bash
# Enable Redis authentication
echo "requirepass your_redis_password" >> /etc/redis/redis.conf

# Restart Redis
sudo systemctl restart redis
```

## TLS Configuration

### Generating Certificates

#### Self-Signed Certificates

```bash
# Generate private key
openssl genrsa -out key.pem 2048

# Generate certificate
openssl req -new -x509 -key key.pem -out cert.pem -days 365
```

#### Let's Encrypt Certificates

```bash
# Install certbot
sudo apt install certbot

# Obtain certificate
sudo certbot certonly --standalone -d auth.example.com -d policy.example.com

# Certificates will be in:
# /etc/letsencrypt/live/auth.example.com/fullchain.pem
# /etc/letsencrypt/live/auth.example.com/privkey.pem
```

### Configuring TLS

```yaml
# Auth Service TLS configuration
server:
  tls:
    enabled: true
    cert_file: "/etc/letsencrypt/live/auth.example.com/fullchain.pem"
    key_file: "/etc/letsencrypt/live/auth.example.com/privkey.pem"
```

## Security Configuration

### JWT Secret Management

#### Generating Strong Secrets

```bash
# Generate a 32-character secret
openssl rand -base64 32

# Generate a hex-encoded 32-byte secret
openssl rand -hex 32
```

#### Environment-based Secrets

```bash
# Store secrets in environment variables
export JWT_SECRET=$(openssl rand -base64 32)
export DATABASE_PASSWORD=$(openssl rand -base64 16)
```

### Rate Limiting

```yaml
security:
  rate_limit:
    enabled: true
    # Global rate limit
    global:
      requests_per_minute: 1000
      burst_size: 100
    
    # Per-client rate limit
    per_client:
      requests_per_minute: 100
      burst_size: 10
    
    # Per-user rate limit
    per_user:
      requests_per_minute: 50
      burst_size: 5
    
    # IP-based rate limit
    per_ip:
      requests_per_minute: 20
      burst_size: 2
```

### Password Policy

```yaml
security:
  password:
    min_length: 12
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_special_chars: true
    max_age_days: 90
    history_count: 5
    lockout_attempts: 5
    lockout_duration: 900  # 15 minutes
```

## Monitoring Configuration

### Prometheus Metrics

```yaml
metrics:
  enabled: true
  endpoint: "/metrics"
  collect_defaults: true
  # Custom metrics
  custom:
    - name: "auth_requests_total"
      type: "counter"
      help: "Total number of authentication requests"
    - name: "auth_latency_seconds"
      type: "histogram"
      help: "Authentication request latency"
```

### Tracing

```yaml
tracing:
  enabled: true
  endpoint: "http://jaeger:14268/api/traces"
  service_name: "auth-service"
  sampling_rate: 0.1  # 10% of requests
```

## Advanced Configuration

### High Availability

```yaml
# Load balancing configuration
load_balancing:
  enabled: true
  strategy: "round_robin"
  health_check:
    interval: 30
    timeout: 5
    path: "/health"

# Clustering
clustering:
  enabled: true
  discovery:
    type: "consul"
    address: "consul:8500"
  replication:
    mode: "active_active"
```

### Caching

```yaml
cache:
  # Token cache
  tokens:
    enabled: true
    ttl: 3600  # 1 hour
    max_size: 10000
  
  # Policy cache
  policies:
    enabled: true
    ttl: 300  # 5 minutes
    max_size: 1000
  
  # User cache
  users:
    enabled: true
    ttl: 1800  # 30 minutes
    max_size: 5000
```

### Logging

```yaml
logging:
  level: "info"
  format: "json"
  outputs:
    - type: "file"
      path: "/var/log/auth-service.log"
      max_size: "100MB"
      max_files: 10
    - type: "stdout"
      level: "warn"
    - type: "syslog"
      host: "syslog-server:514"
```

## Environment-Specific Configuration

### Development

```yaml
# Development configuration
server:
  host: "127.0.0.1"
  port: 8080

logging:
  level: "debug"
  format: "text"

security:
  rate_limit:
    enabled: false

metrics:
  enabled: true
```

### Production

```yaml
# Production configuration
server:
  host: "0.0.0.0"
  port: 443
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/auth-service.crt"
    key_file: "/etc/ssl/private/auth-service.key"

logging:
  level: "info"
  format: "json"
  file: "/var/log/auth-service.log"

security:
  rate_limit:
    enabled: true
    requests_per_minute: 100

metrics:
  enabled: true
```

### Testing

```yaml
# Testing configuration
database:
  url: "postgresql://test_user:test_pass@localhost:5432/auth_service_test"

redis:
  url: "redis://localhost:6379/15"  # Use database 15 for tests

logging:
  level: "warn"
  format: "text"

security:
  rate_limit:
    enabled: false
```

## Configuration Validation

### Validate Configuration

```bash
# Validate configuration without starting the service
auth-service --validate-config

# Check configuration values
auth-service --show-config

# Test database connection
auth-service --test-db-connection

# Test Redis connection
auth-service --test-redis-connection
```

### Configuration Templates

```bash
# Generate configuration template
auth-service --generate-config-template > config.yaml

# Generate environment file
auth-service --generate-env-template > .env
```

## Troubleshooting

### Common Configuration Issues

#### Invalid Configuration Values

```bash
# Check for configuration errors
auth-service --validate-config

# View loaded configuration
auth-service --show-config
```

#### Database Connection Issues

```bash
# Test database connection
psql $DATABASE_URL

# Check connection string format
echo $DATABASE_URL
```

#### Redis Connection Issues

```bash
# Test Redis connection
redis-cli -u $REDIS_URL ping

# Check Redis is running
systemctl status redis
```

#### TLS Configuration Issues

```bash
# Test TLS connection
openssl s_client -connect localhost:443

# Check certificate validity
openssl x509 -in cert.pem -text -noout
```

## Next Steps

After configuring the platform:

1. **Test Configuration**: Run validation commands to ensure configuration is correct
2. **Start Services**: Launch the services with the new configuration
3. **Monitor Logs**: Check logs for any configuration-related errors
4. **Verify Functionality**: Test core features to ensure proper configuration

For deployment-specific configuration, see the [Deployment Guide](../05-operations/deployment.md).