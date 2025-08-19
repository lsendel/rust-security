-- migrations/20250818213800_initial_schema.sql

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    user_name TEXT NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY NOT NULL,
    display_name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code TEXT PRIMARY KEY NOT NULL,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    nonce TEXT,
    scope TEXT NOT NULL,
    pkce_challenge TEXT,
    pkce_method TEXT,
    user_id TEXT,
    exp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY NOT NULL,
    token_display TEXT NOT NULL, -- For logging/display purposes
    active BOOLEAN NOT NULL,
    scope TEXT,
    client_id TEXT,
    exp BIGINT,
    iat BIGINT,
    sub TEXT,
    token_binding TEXT,
    mfa_verified BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    refresh_token_hash TEXT PRIMARY KEY NOT NULL,
    access_token_hash TEXT NOT NULL,
    exp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_token_reuse (
    refresh_token_hash TEXT PRIMARY KEY NOT NULL,
    exp BIGINT NOT NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_user_name ON users(user_name);
CREATE INDEX IF NOT EXISTS idx_tokens_sub ON tokens(sub);
CREATE INDEX IF NOT EXISTS idx_tokens_client_id ON tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_exp ON refresh_tokens(exp);
CREATE INDEX IF NOT EXISTS idx_refresh_token_reuse_exp ON refresh_token_reuse(exp);
CREATE INDEX IF NOT EXISTS idx_auth_codes_exp ON auth_codes(exp);
CREATE INDEX IF NOT EXISTS idx_tokens_exp ON tokens(exp);
