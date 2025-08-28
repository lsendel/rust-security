#!/bin/bash
# Production secrets generation script
# This script generates secure secrets for production deployment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Directories
SECRETS_DIR="./secrets"
CONFIG_DIR="./config"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

generate_password() {
    local length=${1:-32}
    openssl rand -base64 $length | tr -d "=+/" | cut -c1-$length
}

generate_jwt_secret() {
    # Generate a secure 256-bit secret for JWT signing
    openssl rand -hex 32
}

create_directories() {
    log_info "Creating directories..."
    mkdir -p "$SECRETS_DIR"
    mkdir -p "$CONFIG_DIR/nginx"
    mkdir -p "$CONFIG_DIR/redis"
    chmod 700 "$SECRETS_DIR"
}

generate_secrets() {
    log_info "Generating production secrets..."

    # PostgreSQL password
    if [[ ! -f "$SECRETS_DIR/postgres_password.txt" ]]; then
        generate_password 24 > "$SECRETS_DIR/postgres_password.txt"
        log_info "Generated PostgreSQL password"
    else
        log_warn "PostgreSQL password already exists, skipping"
    fi

    # JWT secret
    if [[ ! -f "$SECRETS_DIR/jwt_secret.txt" ]]; then
        generate_jwt_secret > "$SECRETS_DIR/jwt_secret.txt"
        log_info "Generated JWT secret"
    else
        log_warn "JWT secret already exists, skipping"
    fi

    # Grafana admin password
    if [[ ! -f "$SECRETS_DIR/grafana_password.txt" ]]; then
        generate_password 16 > "$SECRETS_DIR/grafana_password.txt"
        log_info "Generated Grafana admin password"
    else
        log_warn "Grafana password already exists, skipping"
    fi

    # Redis authentication (optional)
    if [[ ! -f "$SECRETS_DIR/redis_password.txt" ]]; then
        generate_password 20 > "$SECRETS_DIR/redis_password.txt"
        log_info "Generated Redis password"
    else
        log_warn "Redis password already exists, skipping"
    fi

    # Set secure permissions
    chmod 600 "$SECRETS_DIR"/*
    log_info "Set secure permissions on secret files"
}

create_env_template() {
    log_info "Creating environment template..."
    
    cat > "$CONFIG_DIR/production.env.template" << EOF
# Production Environment Variables Template
# Copy this file to production.env and fill in the values

# Database Configuration
DATABASE_URL=postgres://auth_service:\$(cat $SECRETS_DIR/postgres_password.txt)@postgres:5432/auth_service
POSTGRES_DB=auth_service
POSTGRES_USER=auth_service

# Redis Configuration  
REDIS_URL=redis://:\$(cat $SECRETS_DIR/redis_password.txt)@redis:6379

# JWT Configuration
JWT_SECRET_FILE=/run/secrets/jwt_secret

# Service Configuration
AUTH_SERVICE_PORT=8080
POLICY_SERVICE_PORT=8081
DASHBOARD_PORT=3000

# Logging Configuration
RUST_LOG=info
LOG_LEVEL=info
LOG_FORMAT=json

# Security Configuration
ENVIRONMENT=production
CORS_ALLOWED_ORIGINS=https://yourdomain.com
TRUSTED_PROXIES=172.20.0.0/16

# Session Configuration
SESSION_TIMEOUT_MINUTES=60
REMEMBER_ME_DAYS=30

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
BURST_SIZE=10

# Health Check Configuration
HEALTH_CHECK_INTERVAL=30
HEALTH_CHECK_TIMEOUT=10
EOF

    log_info "Created environment template at $CONFIG_DIR/production.env.template"
}

create_redis_config() {
    log_info "Creating Redis configuration..."
    
    cat > "$CONFIG_DIR/redis/redis.conf" << EOF
# Redis production configuration

# Network and Security
bind 0.0.0.0
protected-mode yes
requirepass $(cat "$SECRETS_DIR/redis_password.txt" 2>/dev/null || echo "CHANGEME")

# Persistence
save 900 1
save 300 10
save 60 10000

# Memory and Performance
maxmemory 256mb
maxmemory-policy allkeys-lru

# Security
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command CONFIG ""
rename-command DEBUG ""

# Logging
loglevel notice
logfile "/var/log/redis/redis-server.log"

# Timeouts
timeout 300
tcp-keepalive 300
EOF

    log_info "Created Redis configuration"
}

create_nginx_config() {
    log_info "Creating Nginx configuration..."
    
    cat > "$CONFIG_DIR/nginx/nginx.conf" << EOF
# Production nginx reverse proxy configuration
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logging
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    
    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone \$binary_remote_addr zone=login:10m rate=5r/m;
    
    # Upstream services
    upstream auth-service {
        server auth-service:8080;
        keepalive 32;
    }
    
    upstream policy-service {
        server policy-service:8081;
        keepalive 32;
    }
    
    upstream dashboard {
        server dashboard:3000;
        keepalive 32;
    }
    
    # Main server block
    server {
        listen 80;
        server_name _;
        
        # Redirect HTTP to HTTPS in production
        return 301 https://\$server_name\$request_uri;
    }
    
    # HTTPS server block (configure SSL certificates)
    server {
        listen 443 ssl http2;
        server_name your-domain.com;
        
        # SSL configuration (replace with your certificates)
        # ssl_certificate /etc/nginx/ssl/cert.pem;
        # ssl_certificate_key /etc/nginx/ssl/key.pem;
        
        # Dashboard
        location / {
            proxy_pass http://dashboard;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
        
        # Auth API
        location /api/auth/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://auth-service/api/;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
        
        # Login endpoint with stricter rate limiting
        location /api/auth/login {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://auth-service/api/auth/login;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
        
        # Policy API
        location /api/policy/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://policy-service/;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
        
        # Health checks
        location /health {
            access_log off;
            return 200 "healthy";
            add_header Content-Type text/plain;
        }
    }
}
EOF

    log_info "Created Nginx configuration"
}

create_deployment_scripts() {
    log_info "Creating deployment scripts..."
    
    # Production deployment script
    cat > "./deploy-production.sh" << 'EOF'
#!/bin/bash
# Production deployment script

set -euo pipefail

log_info() {
    echo -e "\033[0;32m[INFO]\033[0m $1"
}

log_error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1"
}

# Check requirements
check_requirements() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is required but not installed"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is required but not installed"
        exit 1
    fi
}

# Deploy services
deploy() {
    log_info "Starting production deployment..."
    
    # Generate secrets if they don't exist
    if [[ ! -d "./secrets" ]]; then
        log_info "Generating production secrets..."
        ./scripts/generate-production-secrets.sh
    fi
    
    # Build and deploy services
    log_info "Building and starting services..."
    docker-compose -f docker-compose.production.yml up -d --build
    
    # Wait for services to be healthy
    log_info "Waiting for services to be healthy..."
    sleep 30
    
    # Check health
    log_info "Checking service health..."
    docker-compose -f docker-compose.production.yml ps
    
    log_info "Production deployment completed successfully!"
    log_info "Services available at:"
    log_info "  - Dashboard: http://localhost:3000"
    log_info "  - Auth API: http://localhost:8080"
    log_info "  - Policy API: http://localhost:8081"
    log_info "  - Monitoring: http://localhost:9090 (if enabled)"
}

main() {
    check_requirements
    deploy
}

main "$@"
EOF
    
    chmod +x "./deploy-production.sh"
    log_info "Created production deployment script"
}

print_summary() {
    log_info "Production secrets and configuration generated successfully!"
    echo
    echo "Generated files:"
    echo "  - $SECRETS_DIR/postgres_password.txt"
    echo "  - $SECRETS_DIR/jwt_secret.txt" 
    echo "  - $SECRETS_DIR/grafana_password.txt"
    echo "  - $SECRETS_DIR/redis_password.txt"
    echo "  - $CONFIG_DIR/production.env.template"
    echo "  - $CONFIG_DIR/redis/redis.conf"
    echo "  - $CONFIG_DIR/nginx/nginx.conf"
    echo "  - ./deploy-production.sh"
    echo
    log_warn "IMPORTANT SECURITY NOTES:"
    echo "1. Keep the secrets/ directory secure and never commit to version control"
    echo "2. Use proper SSL certificates in production"
    echo "3. Update nginx configuration with your actual domain name"
    echo "4. Consider using external secret management (AWS Secrets Manager, HashiCorp Vault)"
    echo "5. Review and customize all configuration files for your environment"
    echo
    log_info "To deploy to production, run: ./deploy-production.sh"
}

main() {
    log_info "Setting up production secrets and configuration..."
    
    create_directories
    generate_secrets
    create_env_template
    create_redis_config
    create_nginx_config
    create_deployment_scripts
    print_summary
}

# Check if running as source or script
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi