-- Production Database Migration: Initial Schema
-- Version: 001
-- Date: 2025-08-28
-- Description: Complete initial schema for auth-service production deployment

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Users table with enhanced security fields
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_name VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(320) UNIQUE, -- RFC 5321 max email length
    password_hash VARCHAR(255), -- for local auth
    active BOOLEAN NOT NULL DEFAULT true,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ,
    
    -- Security constraints
    CONSTRAINT valid_email_format CHECK (email IS NULL OR email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT reasonable_failed_attempts CHECK (failed_login_attempts >= 0 AND failed_login_attempts <= 1000)
);

-- Groups table for role-based access control
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    display_name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

-- Group membership with audit trail
CREATE TABLE IF NOT EXISTS group_members (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    added_by UUID REFERENCES users(id),
    role VARCHAR(50) DEFAULT 'member',
    
    PRIMARY KEY (group_id, user_id),
    CONSTRAINT valid_member_role CHECK (role IN ('member', 'admin', 'owner'))
);

-- OAuth authorization codes with PKCE support
CREATE TABLE IF NOT EXISTS auth_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    nonce VARCHAR(255),
    scope TEXT NOT NULL,
    pkce_challenge VARCHAR(128),
    pkce_method VARCHAR(10) CHECK (pkce_method IN ('S256', 'plain')),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    
    -- Security constraints
    CONSTRAINT valid_code_format CHECK (length(code) >= 32),
    CONSTRAINT future_expiration CHECK (expires_at > created_at),
    CONSTRAINT valid_redirect_uri CHECK (redirect_uri ~* '^https?://')
);

-- Access tokens with enhanced metadata
CREATE TABLE IF NOT EXISTS tokens (
    token_hash VARCHAR(64) PRIMARY KEY, -- SHA-256 hash
    token_display VARCHAR(16) NOT NULL, -- First few chars for display
    active BOOLEAN NOT NULL DEFAULT true,
    scope TEXT,
    client_id VARCHAR(255),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    token_binding TEXT, -- for token binding
    mfa_verified BOOLEAN NOT NULL DEFAULT false,
    device_info JSONB, -- client device information
    
    -- Security constraints
    CONSTRAINT valid_token_hash CHECK (length(token_hash) = 64),
    CONSTRAINT valid_token_display CHECK (length(token_display) <= 16)
);

-- Refresh tokens with rotation support
CREATE TABLE IF NOT EXISTS refresh_tokens (
    refresh_token_hash VARCHAR(64) PRIMARY KEY,
    access_token_hash VARCHAR(64) NOT NULL REFERENCES tokens(token_hash) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    
    CONSTRAINT valid_refresh_hash CHECK (length(refresh_token_hash) = 64)
);

-- Refresh token reuse detection
CREATE TABLE IF NOT EXISTS refresh_token_reuse (
    refresh_token_hash VARCHAR(64) PRIMARY KEY,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    client_id VARCHAR(255),
    user_id UUID REFERENCES users(id),
    source_ip INET
);

-- API Keys with enhanced security
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hashed_key VARCHAR(255) UNIQUE NOT NULL,
    key_prefix VARCHAR(16) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL, -- human-readable name
    permissions JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    
    CONSTRAINT valid_api_key_status CHECK (status IN ('active', 'revoked', 'expired')),
    CONSTRAINT reasonable_key_prefix CHECK (length(key_prefix) >= 4)
);

-- OAuth Clients (Dynamic Client Registration)
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id VARCHAR(255) PRIMARY KEY,
    client_secret_hash VARCHAR(255) NOT NULL,
    client_secret_expires_at TIMESTAMPTZ NOT NULL,
    registration_access_token_hash VARCHAR(255) NOT NULL,
    
    -- OAuth client metadata
    redirect_uris JSONB NOT NULL,
    response_types JSONB DEFAULT '["code"]',
    grant_types JSONB DEFAULT '["authorization_code"]',
    application_type VARCHAR(50) DEFAULT 'web',
    contacts JSONB,
    client_name VARCHAR(255),
    logo_uri TEXT,
    client_uri TEXT,
    policy_uri TEXT,
    tos_uri TEXT,
    jwks_uri TEXT,
    jwks JSONB,
    default_acr_values JSONB,
    default_max_age INTEGER,
    require_auth_time BOOLEAN DEFAULT false,
    token_endpoint_auth_method VARCHAR(100) DEFAULT 'client_secret_basic',
    id_token_signed_response_alg VARCHAR(100) DEFAULT 'RS256',
    scope TEXT DEFAULT 'openid profile',
    software_id VARCHAR(255),
    software_version VARCHAR(100),
    
    -- Audit fields
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by_ip INET,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    
    -- Constraints
    CONSTRAINT valid_client_status CHECK (status IN ('active', 'suspended', 'revoked')),
    CONSTRAINT valid_application_type CHECK (application_type IN ('web', 'native', 'service')),
    CONSTRAINT non_empty_redirect_uris CHECK (jsonb_array_length(redirect_uris) > 0)
);

-- Session management for web authentication
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    
    CONSTRAINT valid_session_id CHECK (length(session_id) >= 32)
);

-- Audit log for security events
CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    user_id UUID REFERENCES users(id),
    client_id VARCHAR(255),
    session_id VARCHAR(128),
    ip_address INET,
    user_agent TEXT,
    details JSONB,
    risk_score INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT valid_risk_score CHECK (risk_score >= 0 AND risk_score <= 100)
);

-- Rate limiting buckets
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket_key VARCHAR(255) PRIMARY KEY,
    tokens_remaining INTEGER NOT NULL DEFAULT 0,
    last_refill TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT non_negative_tokens CHECK (tokens_remaining >= 0)
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_users_user_name ON users USING btree(user_name);
CREATE INDEX IF NOT EXISTS idx_users_email ON users USING btree(email);
CREATE INDEX IF NOT EXISTS idx_users_active ON users USING btree(active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_users_locked ON users USING btree(locked_until) WHERE locked_until IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_groups_display_name ON groups USING btree(display_name);

CREATE INDEX IF NOT EXISTS idx_group_members_user_id ON group_members USING btree(user_id);
CREATE INDEX IF NOT EXISTS idx_group_members_group_id ON group_members USING btree(group_id);

CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at ON auth_codes USING btree(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_codes_client_id ON auth_codes USING btree(client_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_user_id ON auth_codes USING btree(user_id);

CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens USING btree(user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_client_id ON tokens USING btree(client_id);
CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens USING btree(expires_at);
CREATE INDEX IF NOT EXISTS idx_tokens_active ON tokens USING btree(active) WHERE active = true;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens USING btree(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens USING btree(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_used_at ON refresh_tokens USING btree(used_at) WHERE used_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_refresh_token_reuse_detected_at ON refresh_token_reuse USING btree(detected_at);
CREATE INDEX IF NOT EXISTS idx_refresh_token_reuse_user_id ON refresh_token_reuse USING btree(user_id);

CREATE INDEX IF NOT EXISTS idx_api_keys_client_id ON api_keys USING btree(client_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys USING btree(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys USING btree(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys USING btree(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON api_keys USING btree(expires_at) WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_oauth_clients_status ON oauth_clients USING btree(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_oauth_clients_created_at ON oauth_clients USING btree(created_at);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_expires_at ON oauth_clients USING btree(client_secret_expires_at);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions USING btree(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions USING btree(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_sessions_last_activity ON user_sessions USING btree(last_activity_at);

CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events USING btree(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events USING btree(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events USING btree(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_risk_score ON security_events USING btree(risk_score) WHERE risk_score > 50;

CREATE INDEX IF NOT EXISTS idx_rate_limits_last_refill ON rate_limits USING btree(last_refill);

-- Full-text search indexes
CREATE INDEX IF NOT EXISTS idx_users_search ON users USING gin(to_tsvector('english', user_name || ' ' || COALESCE(email, '')));
CREATE INDEX IF NOT EXISTS idx_groups_search ON groups USING gin(to_tsvector('english', display_name || ' ' || COALESCE(description, '')));

-- Database functions and triggers
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Add update triggers
CREATE TRIGGER users_updated_at_trigger
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER groups_updated_at_trigger
    BEFORE UPDATE ON groups
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER oauth_clients_updated_at_trigger
    BEFORE UPDATE ON oauth_clients
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Cleanup function for expired tokens
CREATE OR REPLACE FUNCTION cleanup_expired_data()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER := 0;
    temp_count INTEGER;
BEGIN
    -- Cleanup expired auth codes (older than 1 hour)
    DELETE FROM auth_codes WHERE expires_at < NOW() - INTERVAL '1 hour';
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Cleanup expired tokens
    DELETE FROM tokens WHERE expires_at < NOW() AND expires_at IS NOT NULL;
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Cleanup expired refresh tokens
    DELETE FROM refresh_tokens WHERE expires_at < NOW();
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Cleanup old refresh token reuse records (older than 30 days)
    DELETE FROM refresh_token_reuse WHERE detected_at < NOW() - INTERVAL '30 days';
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Cleanup expired sessions
    DELETE FROM user_sessions WHERE expires_at < NOW();
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Cleanup old security events (older than 1 year)
    DELETE FROM security_events WHERE created_at < NOW() - INTERVAL '1 year';
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Row Level Security (RLS) policies
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;

-- Basic RLS policy (can be customized per deployment)
CREATE POLICY users_own_data ON users
    FOR ALL TO authenticated_user
    USING (id = current_setting('app.current_user_id')::UUID);

CREATE POLICY sessions_own_data ON user_sessions
    FOR ALL TO authenticated_user
    USING (user_id = current_setting('app.current_user_id')::UUID);

-- Views for common queries
CREATE OR REPLACE VIEW active_tokens AS
SELECT 
    token_hash,
    token_display,
    scope,
    client_id,
    user_id,
    created_at,
    expires_at,
    last_used_at,
    mfa_verified
FROM tokens 
WHERE active = true 
AND (expires_at IS NULL OR expires_at > NOW());

CREATE OR REPLACE VIEW user_summary AS
SELECT 
    u.id,
    u.user_name,
    u.email,
    u.active,
    u.email_verified,
    u.failed_login_attempts > 0 as has_failed_attempts,
    u.locked_until > NOW() as is_locked,
    u.created_at,
    u.last_login_at,
    COUNT(DISTINCT gm.group_id) as group_count,
    COUNT(DISTINCT ak.id) as api_key_count,
    COUNT(DISTINCT at.token_hash) as active_token_count
FROM users u
LEFT JOIN group_members gm ON u.id = gm.user_id
LEFT JOIN api_keys ak ON u.id = ak.user_id AND ak.status = 'active'
LEFT JOIN active_tokens at ON u.id = at.user_id
GROUP BY u.id, u.user_name, u.email, u.active, u.email_verified, u.failed_login_attempts, u.locked_until, u.created_at, u.last_login_at;

-- Comments for documentation
COMMENT ON DATABASE postgres IS 'Auth Service Production Database';
COMMENT ON SCHEMA public IS 'Main schema for auth service tables';

COMMENT ON TABLE users IS 'User accounts with enhanced security features';
COMMENT ON TABLE groups IS 'User groups for role-based access control';
COMMENT ON TABLE group_members IS 'Group membership with audit trail';
COMMENT ON TABLE auth_codes IS 'OAuth 2.0 authorization codes with PKCE';
COMMENT ON TABLE tokens IS 'OAuth 2.0 access tokens with metadata';
COMMENT ON TABLE refresh_tokens IS 'OAuth 2.0 refresh tokens with rotation';
COMMENT ON TABLE api_keys IS 'API keys for service authentication';
COMMENT ON TABLE oauth_clients IS 'Dynamically registered OAuth 2.0 clients';
COMMENT ON TABLE user_sessions IS 'Web application user sessions';
COMMENT ON TABLE security_events IS 'Security audit log and monitoring';
COMMENT ON TABLE rate_limits IS 'Rate limiting token buckets';

-- Grant permissions to auth service user
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_service') THEN
        GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO auth_service;
        GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO auth_service;
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO auth_service;
    END IF;
END $$;