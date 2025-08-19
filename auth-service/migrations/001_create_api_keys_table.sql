-- Migration to create the api_keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hashed_key VARCHAR(255) UNIQUE NOT NULL,
    prefix VARCHAR(16) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    permissions TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired'))
);

-- Create index on client_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_api_keys_client_id ON api_keys(client_id);

-- Create index on prefix
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix);
