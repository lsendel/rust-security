#!/bin/bash
# Generate secure secrets for the authentication service
# This script creates cryptographically secure secrets for production use

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to generate secure random hex string
generate_hex_secret() {
    local length=$1
    openssl rand -hex "$length" 2>/dev/null || {
        echo "Error: OpenSSL not available. Please install OpenSSL." >&2
        exit 1
    }
}

# Function to generate secure random base64 string
generate_base64_secret() {
    local length=$1
    openssl rand -base64 "$length" 2>/dev/null | tr -d '\n' || {
        echo "Error: OpenSSL not available. Please install OpenSSL." >&2
        exit 1
    }
}

# Function to validate secret strength
validate_secret_strength() {
    local secret=$1
    local min_length=$2
    
    if [ ${#secret} -lt "$min_length" ]; then
        echo "Error: Secret too short (${#secret} < $min_length)" >&2
        return 1
    fi
    
    # Check for sufficient entropy (basic check)
    local unique_chars=$(echo "$secret" | fold -w1 | sort -u | wc -l)
    if [ "$unique_chars" -lt 10 ]; then
        echo "Warning: Secret may have low entropy ($unique_chars unique characters)" >&2
    fi
    
    return 0
}

echo -e "${BLUE}🔐 Secure Secret Generator for Rust Security Platform${NC}"
echo -e "${BLUE}=====================================================${NC}"
echo

# Check if .env already exists
if [ -f ".env" ]; then
    echo -e "${YELLOW}⚠️  .env file already exists!${NC}"
    read -p "Do you want to overwrite it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}❌ Aborted. Existing .env file preserved.${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}🔑 Generating cryptographically secure secrets...${NC}"
echo

# Generate secrets
JWT_SECRET=$(generate_hex_secret 32)
ENCRYPTION_KEY=$(generate_hex_secret 32)
TOKEN_BINDING_SALT=$(generate_hex_secret 32)
REQUEST_SIGNING_SECRET=$(generate_hex_secret 32)
CSRF_SECRET=$(generate_hex_secret 16)
SESSION_SECRET=$(generate_hex_secret 32)

# Validate all secrets
echo -e "${BLUE}🔍 Validating secret strength...${NC}"
validate_secret_strength "$JWT_SECRET" 64 || exit 1
validate_secret_strength "$ENCRYPTION_KEY" 64 || exit 1
validate_secret_strength "$TOKEN_BINDING_SALT" 64 || exit 1
validate_secret_strength "$REQUEST_SIGNING_SECRET" 64 || exit 1
validate_secret_strength "$CSRF_SECRET" 32 || exit 1
validate_secret_strength "$SESSION_SECRET" 64 || exit 1

echo -e "${GREEN}✅ All secrets validated successfully${NC}"
echo

# Create .env file
cat > .env << EOF
# Rust Security Platform Environment Configuration
# Generated on $(date)
# 
# ⚠️  SECURITY WARNING: Keep this file secure and never commit to version control!
# Add .env to your .gitignore file immediately.

# JWT Configuration
JWT_SECRET=$JWT_SECRET
JWT_EXPIRY_SECONDS=3600
JWT_REFRESH_EXPIRY_SECONDS=86400

# Encryption Keys
MASTER_ENCRYPTION_KEY=$ENCRYPTION_KEY
ENCRYPTION_KEY=$ENCRYPTION_KEY
TOKEN_BINDING_SALT=$TOKEN_BINDING_SALT

# Database Configuration (UPDATE THESE VALUES)
DATABASE_URL=postgresql://auth_user:CHANGE_THIS_PASSWORD@localhost:5432/auth_db
REDIS_URL=redis://localhost:6379

# Server Configuration
SERVER_HOST=127.0.0.1
SERVER_PORT=8080
ENABLE_TLS=false
# TLS_CERT_PATH=/path/to/cert.pem
# TLS_KEY_PATH=/path/to/key.pem

# Rate Limiting
RATE_LIMIT_PER_MINUTE=100
DISABLE_RATE_LIMIT=false

# Security Settings
REQUEST_SIGNING_SECRET=$REQUEST_SIGNING_SECRET
CSRF_SECRET=$CSRF_SECRET
SESSION_SECRET=$SESSION_SECRET

# External Services (UPDATE THESE VALUES)
# VAULT_URL=https://vault.example.com
# VAULT_TOKEN=hvs.XXXXXXXXXXXXXXXXXXXXXXXX
# AWS_REGION=us-east-1
# AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
# AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# Monitoring and Logging
LOG_LEVEL=info
ENABLE_METRICS=true
METRICS_PORT=9090
# JAEGER_ENDPOINT=http://localhost:14268/api/traces

# Feature Flags
ENABLE_MFA=true
ENABLE_AUDIT_LOGGING=true
ENABLE_THREAT_DETECTION=false
STRICT_SECURITY_MODE=true

# Development/Testing (SET TO false IN PRODUCTION)
TEST_MODE=false
DEBUG_MODE=false
BYPASS_SECURITY_CHECKS=false
EOF

# Set secure permissions
chmod 600 .env

echo -e "${GREEN}✅ .env file created successfully with secure permissions (600)${NC}"
echo

# Security recommendations
echo -e "${YELLOW}🛡️  Security Recommendations:${NC}"
echo -e "${YELLOW}================================${NC}"
echo "1. Add '.env' to your .gitignore file immediately"
echo "2. Update DATABASE_URL with your actual database credentials"
echo "3. Configure TLS certificates for production (set ENABLE_TLS=true)"
echo "4. Update external service credentials (AWS, Vault, etc.)"
echo "5. Set TEST_MODE=false and DEBUG_MODE=false in production"
echo "6. Consider using a secrets management system for production"
echo "7. Rotate these secrets regularly (recommended: every 90 days)"
echo

# Check if .gitignore exists and contains .env
if [ -f ".gitignore" ]; then
    if ! grep -q "^\.env$" .gitignore; then
        echo -e "${YELLOW}⚠️  Adding .env to .gitignore...${NC}"
        echo ".env" >> .gitignore
        echo -e "${GREEN}✅ .env added to .gitignore${NC}"
    else
        echo -e "${GREEN}✅ .env already in .gitignore${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Creating .gitignore with .env entry...${NC}"
    echo ".env" > .gitignore
    echo -e "${GREEN}✅ .gitignore created with .env entry${NC}"
fi

echo
echo -e "${GREEN}🎉 Secret generation complete!${NC}"
echo -e "${BLUE}Your secrets are ready for use. Keep them secure!${NC}"

# Optional: Show secret strength analysis
echo
read -p "Show secret strength analysis? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}📊 Secret Strength Analysis:${NC}"
    echo "JWT_SECRET: ${#JWT_SECRET} characters"
    echo "ENCRYPTION_KEY: ${#ENCRYPTION_KEY} characters"
    echo "TOKEN_BINDING_SALT: ${#TOKEN_BINDING_SALT} characters"
    echo "REQUEST_SIGNING_SECRET: ${#REQUEST_SIGNING_SECRET} characters"
    echo "CSRF_SECRET: ${#CSRF_SECRET} characters"
    echo "SESSION_SECRET: ${#SESSION_SECRET} characters"
    echo
    echo "All secrets use cryptographically secure random generation."
    echo "Entropy source: OpenSSL RAND_bytes()"
fi