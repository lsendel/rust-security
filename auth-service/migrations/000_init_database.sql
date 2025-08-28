-- Database Initialization Script for Production
-- This script sets up the database, users, and permissions for production deployment

-- Create the auth_service database (if it doesn't exist)
-- Note: This should be run by a superuser (postgres)

-- Create dedicated user for auth service
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_service') THEN
        CREATE ROLE auth_service WITH LOGIN PASSWORD 'CHANGE_ME_IN_PRODUCTION';
    END IF;
END $$;

-- Create the database with proper encoding and collation
SELECT 'CREATE DATABASE auth_service 
    WITH OWNER = auth_service
    ENCODING = ''UTF8''
    LC_COLLATE = ''en_US.utf8''
    LC_CTYPE = ''en_US.utf8''
    TABLESPACE = pg_default
    CONNECTION LIMIT = -1
    TEMPLATE template0'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'auth_service')\gexec

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON DATABASE auth_service TO auth_service;

-- Connect to the auth_service database
\c auth_service;

-- Set up extensions (requires superuser privileges)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Grant usage on extensions
GRANT ALL ON ALL TABLES IN SCHEMA public TO auth_service;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO auth_service;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO auth_service;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public 
GRANT ALL ON TABLES TO auth_service;

ALTER DEFAULT PRIVILEGES IN SCHEMA public 
GRANT ALL ON SEQUENCES TO auth_service;

ALTER DEFAULT PRIVILEGES IN SCHEMA public 
GRANT EXECUTE ON FUNCTIONS TO auth_service;

-- Create application role for RLS policies
CREATE ROLE authenticated_user;
GRANT authenticated_user TO auth_service;

-- Create a schema for application-specific functions
CREATE SCHEMA IF NOT EXISTS auth_service_functions AUTHORIZATION auth_service;

-- Grant schema permissions
GRANT ALL ON SCHEMA auth_service_functions TO auth_service;

-- Set search path
ALTER ROLE auth_service SET search_path = public, auth_service_functions;

-- Create migration tracking table
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(255) PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    checksum VARCHAR(255),
    description TEXT
);

-- Grant permissions on migration table
GRANT ALL ON TABLE schema_migrations TO auth_service;

-- Insert initial migration record
INSERT INTO schema_migrations (version, description, checksum)
VALUES ('000_init_database', 'Database initialization and setup', '000')
ON CONFLICT (version) DO NOTHING;

-- Performance tuning settings for auth service workload
-- These can be adjusted based on actual server specifications
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;

-- Security settings
ALTER SYSTEM SET log_statement = 'mod';
ALTER SYSTEM SET log_min_duration_statement = 1000;
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
ALTER SYSTEM SET log_failed_authentication_connections = on;

-- Reload configuration
SELECT pg_reload_conf();