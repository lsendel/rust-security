-- OAuth 2.0 Dynamic Client Registration Tables
-- Migration for storing dynamically registered OAuth clients and related data

-- Table for storing registered OAuth clients
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id VARCHAR(255) PRIMARY KEY NOT NULL,
    client_secret_hash VARCHAR(255) NOT NULL,
    client_secret_expires_at TIMESTAMPTZ NOT NULL,
    registration_access_token_hash VARCHAR(255) NOT NULL,
    
    -- OAuth client metadata
    redirect_uris JSONB NOT NULL,
    response_types JSONB,
    grant_types JSONB,
    application_type VARCHAR(50),
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
    require_auth_time BOOLEAN,
    token_endpoint_auth_method VARCHAR(100),
    id_token_signed_response_alg VARCHAR(100),
    scope TEXT,
    software_id VARCHAR(255),
    software_version VARCHAR(100),
    
    -- Audit fields
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by_ip INET,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    
    -- Constraints
    CONSTRAINT valid_status CHECK (status IN ('active', 'suspended', 'revoked')),
    CONSTRAINT valid_application_type CHECK (application_type IN ('web', 'native', 'service') OR application_type IS NULL),
    CONSTRAINT non_empty_redirect_uris CHECK (jsonb_array_length(redirect_uris) > 0)
);

-- Table for tracking client registration events (audit log)
CREATE TABLE IF NOT EXISTS oauth_client_registrations (
    id BIGSERIAL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    created_by_ip INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(50) NOT NULL,
    metadata JSONB,
    
    -- Foreign key
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    
    -- Constraints
    CONSTRAINT valid_event_type CHECK (event_type IN ('registered', 'updated', 'deleted', 'secret_rotated', 'suspended', 'revoked'))
);

-- Table for client secret rotation history
CREATE TABLE IF NOT EXISTS oauth_client_secrets (
    id BIGSERIAL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    rotation_reason VARCHAR(100),
    
    -- Foreign key
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    
    -- Constraints
    CONSTRAINT valid_rotation_reason CHECK (rotation_reason IN ('scheduled', 'compromised', 'manual', 'policy') OR rotation_reason IS NULL)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_oauth_clients_status ON oauth_clients(status);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_created_at ON oauth_clients(created_at);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_created_by_ip ON oauth_clients(created_by_ip);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_expires_at ON oauth_clients(client_secret_expires_at);

CREATE INDEX IF NOT EXISTS idx_oauth_client_registrations_client_id ON oauth_client_registrations(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_client_registrations_created_at ON oauth_client_registrations(created_at);
CREATE INDEX IF NOT EXISTS idx_oauth_client_registrations_ip ON oauth_client_registrations(created_by_ip);
CREATE INDEX IF NOT EXISTS idx_oauth_client_registrations_event_type ON oauth_client_registrations(event_type);

CREATE INDEX IF NOT EXISTS idx_oauth_client_secrets_client_id ON oauth_client_secrets(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_client_secrets_active ON oauth_client_secrets(client_id, is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_oauth_client_secrets_expires_at ON oauth_client_secrets(expires_at);

-- Partial index for performance on active clients
CREATE INDEX IF NOT EXISTS idx_oauth_clients_active ON oauth_clients(client_id) WHERE status = 'active';

-- Composite index for rate limiting queries
CREATE INDEX IF NOT EXISTS idx_oauth_client_registrations_ip_date ON oauth_client_registrations(created_by_ip, DATE(created_at));

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_oauth_clients_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at
CREATE TRIGGER oauth_clients_updated_at_trigger
    BEFORE UPDATE ON oauth_clients
    FOR EACH ROW
    EXECUTE FUNCTION update_oauth_clients_updated_at();

-- Function to cleanup expired client secrets
CREATE OR REPLACE FUNCTION cleanup_expired_client_secrets()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Mark expired secrets as inactive
    UPDATE oauth_client_secrets 
    SET is_active = FALSE, revoked_at = NOW()
    WHERE expires_at < NOW() AND is_active = TRUE;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Delete very old inactive secrets (older than 1 year)
    DELETE FROM oauth_client_secrets 
    WHERE revoked_at < NOW() - INTERVAL '1 year' AND is_active = FALSE;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Comments for documentation
COMMENT ON TABLE oauth_clients IS 'OAuth 2.0 dynamically registered clients following RFC 7591';
COMMENT ON TABLE oauth_client_registrations IS 'Audit log for OAuth client registration events';
COMMENT ON TABLE oauth_client_secrets IS 'History of client secret rotations for security auditing';

COMMENT ON COLUMN oauth_clients.client_id IS 'Unique OAuth 2.0 client identifier';
COMMENT ON COLUMN oauth_clients.client_secret_hash IS 'SHA-256 hash of the client secret';
COMMENT ON COLUMN oauth_clients.registration_access_token_hash IS 'SHA-256 hash of the registration access token';
COMMENT ON COLUMN oauth_clients.redirect_uris IS 'JSON array of allowed redirect URIs';
COMMENT ON COLUMN oauth_clients.status IS 'Client status: active, suspended, or revoked';

COMMENT ON COLUMN oauth_client_secrets.is_active IS 'Whether this secret is currently active for authentication';
COMMENT ON COLUMN oauth_client_secrets.rotation_reason IS 'Reason for secret rotation: scheduled, compromised, manual, or policy';