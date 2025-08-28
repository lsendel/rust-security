# Database Migration System

This directory contains SQL migration files for the auth-service production database.

## Migration Files

- `000_init_database.sql` - Database initialization and user setup (requires superuser)
- `001_initial_production_schema.sql` - Complete production schema with all tables and indexes

## Running Migrations

### Production Deployment

Migrations are automatically run during Docker production deployment:

```bash
# Deploy with migrations
./deploy-docker-production.sh
```

### Manual Migration

Use the migration runner script:

```bash
# Run all pending migrations
./scripts/run-migrations.sh

# Dry run (show what would be migrated)
./scripts/run-migrations.sh --dry-run

# Database initialization only
./scripts/run-migrations.sh --init-only

# Connect to remote database
./scripts/run-migrations.sh --host prod-db.example.com --database auth_service
```

### Migration Validation

Test migrations before deploying to production:

```bash
# Validate all migrations in temporary container
./scripts/validate-migrations.sh
```

## Migration Structure

### Core Tables

- `users` - User accounts with security features
- `groups` - Role-based access control groups
- `group_members` - Group membership tracking
- `auth_codes` - OAuth 2.0 authorization codes with PKCE
- `tokens` - OAuth 2.0 access tokens
- `refresh_tokens` - OAuth 2.0 refresh tokens with rotation
- `api_keys` - API key authentication
- `oauth_clients` - Dynamic client registration
- `user_sessions` - Web session management
- `security_events` - Security audit logging
- `rate_limits` - Rate limiting buckets

### Security Features

- Row Level Security (RLS) policies
- Comprehensive indexing for performance
- Automatic cleanup functions for expired data
- Audit trails for sensitive operations
- Password policy enforcement
- Account lockout protection

### Performance Optimizations

- Strategic indexing on frequently queried columns
- Partial indexes for active records
- Full-text search capabilities
- Composite indexes for complex queries
- Automatic statistics maintenance

## Migration Best Practices

1. **Backward Compatibility**: Migrations should not break existing applications
2. **Data Preservation**: Never delete data without explicit backup
3. **Performance Impact**: Test migrations on production-sized datasets
4. **Rollback Strategy**: Consider rollback implications for schema changes
5. **Security**: Review migrations for security implications

## Schema Management

The `schema_migrations` table tracks applied migrations:

```sql
-- Check migration status
SELECT version, applied_at, description 
FROM schema_migrations 
ORDER BY version;

-- Manual migration record (if needed)
INSERT INTO schema_migrations (version, description, checksum)
VALUES ('002_new_feature', 'Add new feature tables', 'checksum_here');
```

## Maintenance Functions

The database includes automatic maintenance functions:

```sql
-- Clean up expired data (run periodically)
SELECT cleanup_expired_data();

-- Update statistics (PostgreSQL auto-vacuum handles this)
ANALYZE;
```

## Monitoring

Monitor migration performance and database health:

- Watch PostgreSQL logs during migration
- Monitor connection counts and lock contention
- Check disk space before large migrations
- Verify index usage after schema changes

## Troubleshooting

### Common Issues

1. **Connection Failures**
   - Check database credentials and network connectivity
   - Verify PostgreSQL is running and accepting connections

2. **Permission Denied**
   - Ensure auth_service user has necessary privileges
   - Check if database initialization was completed

3. **Migration Conflicts**
   - Verify migration files are not corrupted
   - Check for concurrent migration attempts
   - Review schema_migrations table for duplicate entries

4. **Performance Issues**
   - Large migrations may require maintenance windows
   - Monitor connection pools during schema changes
   - Consider running migrations during low-traffic periods

### Recovery

If a migration fails:

1. Check PostgreSQL logs for detailed error messages
2. Verify data integrity with consistency checks
3. Restore from backup if necessary
4. Re-run migrations after fixing issues

## Environment Variables

The migration scripts support these environment variables:

- `DB_HOST` - Database hostname (default: localhost)
- `DB_PORT` - Database port (default: 5432)
- `DB_NAME` - Database name (default: auth_service)
- `DB_USER` - Database username (default: auth_service)
- `DB_PASSWORD` - Database password (prompted if not set)
- `DRY_RUN` - Set to 'true' for dry run mode

## Development

When creating new migrations:

1. Use sequential numbering: `002_feature_name.sql`
2. Include descriptive comments in the migration file
3. Test with the validation script before committing
4. Document any manual steps required
5. Consider rollback procedures

Example migration template:

```sql
-- Migration: 002_add_feature
-- Description: Add new feature tables and indexes
-- Author: Your Name
-- Date: YYYY-MM-DD

-- Create new table
CREATE TABLE IF NOT EXISTS new_feature_table (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add indexes
CREATE INDEX IF NOT EXISTS idx_new_feature_name ON new_feature_table(name);

-- Update migration record
-- (This is handled automatically by the migration runner)
```