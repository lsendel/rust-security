# Installation Guide

Step-by-step instructions for installing the Rust Security Platform in different environments.

## System Requirements

### Minimum Requirements
- **CPU**: 2 cores
- **Memory**: 4 GB RAM
- **Storage**: 10 GB available disk space
- **Operating System**: Linux (Ubuntu 20.04+), macOS 12+, or Windows 10+
- **Container Runtime**: Docker 20.0+ or Podman 3.0+

### Recommended Requirements
- **CPU**: 4 cores
- **Memory**: 8 GB RAM
- **Storage**: 50 GB available disk space
- **Operating System**: Latest stable Linux distribution
- **Container Runtime**: Docker 24.0+ or Podman 4.0+

## Installation Methods

### 1. Docker Installation (Recommended)

The easiest way to install the platform is using Docker Compose:

```bash
# Download the docker-compose file
curl -O https://raw.githubusercontent.com/company/rust-security/main/docker-compose.yml

# Start the platform
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

### 2. Binary Installation

Download pre-built binaries for your platform:

```bash
# Download the latest release
wget https://github.com/company/rust-security/releases/latest/download/rust-security-linux-amd64.tar.gz

# Extract the archive
tar -xzf rust-security-linux-amd64.tar.gz

# Make binaries executable
chmod +x auth-service policy-service

# Run services
./auth-service &
./policy-service &
```

### 3. Source Installation

Build from source code:

```bash
# Clone the repository
git clone https://github.com/company/rust-security.git
cd rust-security

# Build the services
cargo build --release

# Find binaries in target/release/
ls target/release/auth-service
ls target/release/policy-service
```

## Platform Components

The Rust Security Platform consists of several components that can be installed together or separately:

### Core Services
1. **Auth Service** - Authentication and OAuth 2.0 provider
2. **Policy Service** - Authorization policy engine
3. **Security Dashboard** - Monitoring and administration interface

### Dependencies
1. **Redis** - Cache and session storage
2. **PostgreSQL** - Primary database
3. **Prometheus** - Metrics collection (optional)
4. **Grafana** - Metrics visualization (optional)

### Optional Components
1. **Load Balancer** - For high availability
2. **Certificate Manager** - For TLS certificate management
3. **Backup Service** - For data backup and recovery

## Installation Steps

### Step 1: Prepare the Environment

```bash
# Create installation directory
sudo mkdir -p /opt/rust-security
sudo chown $USER:$USER /opt/rust-security
cd /opt/rust-security

# Create data directories
mkdir -p data/redis data/postgres data/prometheus data/grafana

# Set proper permissions
chmod 755 data/
chmod 700 data/redis data/postgres
```

### Step 2: Install Dependencies

#### Using Package Manager (Ubuntu/Debian)

```bash
# Update package list
sudo apt update

# Install system dependencies
sudo apt install -y \
  docker.io \
  docker-compose \
  postgresql-client \
  redis-tools \
  curl \
  wget \
  jq

# Start Docker service
sudo systemctl enable docker
sudo systemctl start docker

# Add user to docker group
sudo usermod -aG docker $USER
```

#### Using Package Manager (CentOS/RHEL)

```bash
# Install Docker
sudo yum install -y docker
sudo systemctl enable docker
sudo systemctl start docker

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install other dependencies
sudo yum install -y postgresql redis curl wget jq
```

### Step 3: Deploy Platform

#### Docker Deployment

```bash
# Download deployment files
curl -O https://raw.githubusercontent.com/company/rust-security/main/deploy/docker-compose.yml
curl -O https://raw.githubusercontent.com/company/rust-security/main/deploy/.env

# Customize configuration
nano .env

# Start services
docker-compose up -d

# Wait for services to start
sleep 30

# Verify installation
docker-compose ps
```

#### Binary Deployment

```bash
# Download binaries
wget https://github.com/company/rust-security/releases/latest/download/rust-security-linux-amd64.tar.gz

# Extract
tar -xzf rust-security-linux-amd64.tar.gz -C /opt/rust-security

# Create systemd services
sudo tee /etc/systemd/system/auth-service.service > /dev/null <<EOF
[Unit]
Description=Rust Security Auth Service
After=network.target

[Service]
Type=simple
User=rust-security
WorkingDirectory=/opt/rust-security
ExecStart=/opt/rust-security/auth-service
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/policy-service.service > /dev/null <<EOF
[Unit]
Description=Rust Security Policy Service
After=network.target

[Service]
Type=simple
User=rust-security
WorkingDirectory=/opt/rust-security
ExecStart=/opt/rust-security/policy-service
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create service user
sudo useradd -r -s /bin/false rust-security

# Set permissions
sudo chown -R rust-security:rust-security /opt/rust-security

# Enable and start services
sudo systemctl daemon-reload
sudo systemctl enable auth-service policy-service
sudo systemctl start auth-service policy-service
```

### Step 4: Configure Services

#### Environment Variables

Create a configuration file for environment variables:

```bash
# Create .env file
cat > /opt/rust-security/.env <<EOF
# Auth Service Configuration
AUTH_SERVICE_HOST=0.0.0.0
AUTH_SERVICE_PORT=8080
DATABASE_URL=postgresql://auth_user:auth_pass@localhost:5432/auth_service
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-super-secure-jwt-secret-key-32-chars-min
CORS_ORIGINS=*

# Policy Service Configuration
POLICY_SERVICE_HOST=0.0.0.0
POLICY_SERVICE_PORT=8081
POLICY_DATABASE_URL=postgresql://policy_user:policy_pass@localhost:5432/policy_service
POLICY_REDIS_URL=redis://localhost:6379
POLICY_CACHE_TTL=300

# Security Settings
LOG_LEVEL=info
ENABLE_METRICS=true
ENABLE_TRACING=true
EOF
```

#### Database Setup

```bash
# Create databases
sudo -u postgres createdb auth_service
sudo -u postgres createdb policy_service

# Create users
sudo -u postgres createuser auth_user
sudo -u postgres createuser policy_user

# Set passwords
sudo -u postgres psql -c "ALTER USER auth_user PASSWORD 'auth_pass';"
sudo -u postgres psql -c "ALTER USER policy_user PASSWORD 'policy_pass';"

# Grant privileges
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE auth_service TO auth_user;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE policy_service TO policy_user;"
```

### Step 5: Initialize Services

#### Run Migrations

```bash
# For Auth Service
cd /opt/rust-security
DATABASE_URL=postgresql://auth_user:auth_pass@localhost:5432/auth_service \
  ./auth-service migrate

# For Policy Service
POLICY_DATABASE_URL=postgresql://policy_user:policy_pass@localhost:5432/policy_service \
  ./policy-service migrate
```

#### Create Initial Data

```bash
# Create admin user
curl -X POST http://localhost:8080/admin/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat /opt/rust-security/admin-token)" \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "password": "SecureAdminPass123!",
    "roles": ["admin", "user"]
  }'
```

## Verification

### Check Service Health

```bash
# Check Auth Service
curl -f http://localhost:8080/health || echo "Auth Service is not healthy"

# Check Policy Service
curl -f http://localhost:8081/health || echo "Policy Service is not healthy"

# Check metrics
curl -f http://localhost:8080/metrics >/dev/null && echo "Metrics endpoint accessible"
curl -f http://localhost:8081/metrics >/dev/null && echo "Policy metrics endpoint accessible"
```

### Test Authentication

```bash
# Test OAuth 2.0 client credentials flow
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "test_client:test_secret" \
  -d "grant_type=client_credentials&scope=read"
```

### Monitor Logs

```bash
# Docker logs
docker-compose logs -f

# Systemd logs
sudo journalctl -u auth-service -f
sudo journalctl -u policy-service -f
```

## Post-Installation Steps

### 1. Configure TLS (Recommended)

```bash
# Obtain certificate using Let's Encrypt
sudo certbot certonly --standalone -d auth.example.com -d policy.example.com

# Configure reverse proxy with TLS termination
# See examples/nginx-tls.conf
```

### 2. Set Up Monitoring

```bash
# Configure Prometheus scraping
# See examples/prometheus.yml

# Import Grafana dashboards
# See examples/grafana-dashboards.json
```

### 3. Configure Backup

```bash
# Set up automated database backups
# See examples/backup-script.sh

# Configure backup retention policies
# See examples/backup-retention.conf
```

## Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check logs for errors
docker-compose logs auth-service
journalctl -u auth-service

# Verify dependencies
ping postgres-host
redis-cli ping

# Check configuration
cat /opt/rust-security/.env
```

#### Database Connection Issues
```bash
# Test database connectivity
psql -h localhost -U auth_user -d auth_service

# Check database permissions
sudo -u postgres psql -c "\du"
sudo -u postgres psql -c "\l"

# Verify connection strings
echo $DATABASE_URL
```

#### Authentication Failures
```bash
# Check JWT configuration
curl http://localhost:8080/.well-known/jwks.json

# Test token generation
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "test_client:test_secret" \
  -d "grant_type=client_credentials"
```

## Next Steps

After successful installation:

1. **Configure Security**: Follow the [Security Hardening Guide](../04-security/hardening-guide.md)
2. **Set Up Monitoring**: Implement the [Monitoring Guide](../05-operations/monitoring.md)
3. **Deploy to Production**: Use the [Production Deployment Guide](../05-operations/deployment.md)
4. **Integrate Applications**: Follow the [Integration Guide](integration.md)

For detailed configuration options, see the [Configuration Guide](configuration.md).