# Migration and Versioning Guide

## Overview

This guide covers the comprehensive migration and versioning system for the Rust Security Platform. It provides detailed instructions for managing database migrations, configuration updates, policy changes, and version management across all platform components.

## Migration Framework Architecture

### Components

The migration framework consists of several key components:

1. **Migration Framework Script** (`scripts/migrations/migration-framework.sh`)
   - Core migration engine with rollback capabilities
   - Pre and post-migration validation
   - Backup and restore functionality
   - Comprehensive logging and error handling

2. **Version Management System** (`scripts/version-management.sh`)
   - Semantic versioning for all components
   - Release creation and validation
   - Component version tracking
   - Changelog generation

3. **Migration Scripts** (`scripts/migrations/migrations/`)
   - Component-specific migration scripts
   - Rollback scripts for safe reversions
   - Structured by component type (redis, config, policies, database)

4. **State Management** (`scripts/migrations/state/`)
   - Version tracking per component
   - Migration history and audit logs
   - Backup references and metadata

## Migration Types

### 1. Redis Migrations

Redis migrations handle data structure changes, configuration updates, and performance optimizations.

#### Current Migrations:
- **v1**: Initial Redis configuration with basic settings
- **v2**: Advanced monitoring, performance optimization, and index creation

#### Example Redis Migration:
```bash
# Run Redis migration to latest version
./scripts/migrations/migration-framework.sh migrate redis

# Run specific version
./scripts/migrations/migration-framework.sh migrate redis 2

# Rollback to previous version
./scripts/migrations/migration-framework.sh rollback redis 1
```

### 2. Configuration Migrations

Configuration migrations update Kubernetes ConfigMaps, Secrets, and service configurations.

#### Current Migrations:
- **v1**: Base configuration setup for all services
- **v2**: Enhanced security, external secrets integration, comprehensive monitoring

#### Example Configuration Migration:
```bash
# Migrate configurations to latest
./scripts/migrations/migration-framework.sh migrate config

# Force migration (even if version is current)
./scripts/migrations/migration-framework.sh migrate config latest true
```

### 3. Policy Migrations

Policy migrations update Cedar authorization policies, schemas, and RBAC structures.

#### Current Migrations:
- **v1**: Initial Cedar RBAC framework with foundational policies

#### Example Policy Migration:
```bash
# Migrate policies to latest version
./scripts/migrations/migration-framework.sh migrate policies

# Validate all policies
./scripts/migrations/migration-framework.sh validate
```

### 4. Database Migrations (Future)

Database migrations are prepared for future SQL database implementation.

#### Current Status:
- **v1**: Placeholder migration with schema documentation

## Migration Workflow

### Pre-Migration Checklist

1. **Backup Current State**
   ```bash
   # Create manual backup
   ./scripts/migrations/migration-framework.sh backup redis
   ./scripts/migrations/migration-framework.sh backup config
   ./scripts/migrations/migration-framework.sh backup policies
   ```

2. **Verify System Health**
   ```bash
   # Check cluster connectivity
   kubectl cluster-info
   
   # Verify service status
   kubectl get pods -n rust-security
   
   # Check resource availability
   kubectl describe nodes
   ```

3. **Review Migration Plan**
   ```bash
   # Check current versions
   ./scripts/migrations/migration-framework.sh status
   
   # Validate migration scripts
   ./scripts/migrations/migration-framework.sh validate
   ```

### Migration Execution

#### Single Component Migration
```bash
# Migrate specific component
./scripts/migrations/migration-framework.sh migrate <component> [version]

# Example: Migrate Redis to version 2
./scripts/migrations/migration-framework.sh migrate redis 2
```

#### Multi-Component Migration
```bash
#!/bin/bash
# migrate-all.sh - Migrate all components to latest versions

set -euo pipefail

COMPONENTS=("redis" "config" "policies")

echo "Starting multi-component migration..."

for component in "${COMPONENTS[@]}"; do
    echo "Migrating $component..."
    if ./scripts/migrations/migration-framework.sh migrate "$component"; then
        echo "✓ $component migration completed"
    else
        echo "✗ $component migration failed"
        exit 1
    fi
done

echo "All migrations completed successfully"
```

### Post-Migration Validation

1. **Verify Service Health**
   ```bash
   # Check pod status
   kubectl get pods -n rust-security
   
   # Verify service endpoints
   kubectl get endpoints -n rust-security
   
   # Test service connectivity
   curl -f https://auth.example.com/health
   ```

2. **Validate Migration Status**
   ```bash
   # Check migration status
   ./scripts/migrations/migration-framework.sh status
   
   # Review migration logs
   cat scripts/migrations/logs/migration.log
   ```

3. **Run Smoke Tests**
   ```bash
   # Test authentication
   curl -X POST https://auth.example.com/login \
     -H "Content-Type: application/json" \
     -d '{"email":"test@example.com","password":"test"}'
   
   # Test authorization
   curl -X POST https://policy.example.com/authorize \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"user":"test","action":"read","resource":"data"}'
   ```

## Rollback Procedures

### Automatic Rollback

The migration framework automatically creates backups and can rollback on failure:

```bash
# The framework automatically attempts rollback on migration failure
# Manual rollback to specific version
./scripts/migrations/migration-framework.sh rollback redis 1
```

### Manual Rollback

For complex rollback scenarios, use the dedicated rollback scripts:

```bash
# Use specific rollback script (if available)
./scripts/migrations/migrations/redis/rollback_2_to_1.sh

# Or use backup restoration
./scripts/migrations/migration-framework.sh restore redis /path/to/backup
```

### Emergency Rollback

In case of critical issues:

1. **Immediate Service Restoration**
   ```bash
   # Scale down affected services
   kubectl scale deployment auth-service --replicas=0 -n rust-security
   
   # Restore from backup
   ./scripts/migrations/migration-framework.sh restore redis /backups/latest
   
   # Scale services back up
   kubectl scale deployment auth-service --replicas=3 -n rust-security
   ```

2. **Full System Rollback**
   ```bash
   # Rollback all components to known good state
   ./scripts/migrations/migration-framework.sh rollback redis 1
   ./scripts/migrations/migration-framework.sh rollback config 1
   ./scripts/migrations/migration-framework.sh rollback policies 1
   ```

## Version Management

### Semantic Versioning

The platform uses semantic versioning (MAJOR.MINOR.PATCH) for all components:

- **MAJOR**: Breaking changes requiring manual intervention
- **MINOR**: New features with backward compatibility
- **PATCH**: Bug fixes and small improvements

### Component Versioning

```bash
# Get current versions
./scripts/version-management.sh list-versions

# Set component version
./scripts/version-management.sh set-version auth-service 1.2.3

# Increment version
./scripts/version-management.sh increment platform minor
```

### Release Management

#### Creating a Release

```bash
# Create new release
./scripts/version-management.sh create-release 1.0.0 "Initial production release"

# Validate release readiness
./scripts/version-management.sh validate-release 1.0.0

# Show release information
./scripts/version-management.sh show-release 1.0.0
```

#### Release Artifacts

Each release creates:
- **Release manifest** with component versions and compatibility info
- **Migration scripts** for the specific release
- **Checksums** for integrity verification
- **Release package** (tar.gz) for deployment

### Changelog Management

```bash
# Generate changelog
./scripts/version-management.sh generate-changelog

# Generate changelog between versions
./scripts/version-management.sh generate-changelog v0.9.0 v1.0.0
```

## Migration Script Development

### Script Structure

All migration scripts follow a standard structure:

```bash
#!/bin/bash
# Component Migration vX: Description
# Purpose: Detailed purpose description

set -euo pipefail

# Migration metadata
MIGRATION_NAME="Migration Name"
MIGRATION_DESCRIPTION="Detailed description"

echo "=== Component Migration vX: $MIGRATION_NAME ==="
echo "Description: $MIGRATION_DESCRIPTION"
echo "Timestamp: $(date)"

# Prerequisites validation
# Migration logic
# Post-migration validation
# Cleanup

echo "✓ Migration vX completed successfully"
exit 0
```

### Best Practices

1. **Idempotency**: Migrations should be safe to run multiple times
2. **Validation**: Include pre and post-migration checks
3. **Error Handling**: Use `set -euo pipefail` for strict error handling
4. **Logging**: Provide detailed progress information
5. **Rollback**: Create corresponding rollback scripts when possible

### Testing Migrations

```bash
# Test migration in development environment
kubectl config use-context development
./scripts/migrations/migration-framework.sh migrate redis 2

# Validate results
./scripts/migrations/migration-framework.sh status

# Test rollback
./scripts/migrations/migration-framework.sh rollback redis 1
```

## Troubleshooting

### Common Issues

#### Migration Timeout
```bash
# Increase timeout in migration-framework.sh
timeout 600 bash "$migration_file"  # 10 minutes instead of 5
```

#### Permission Errors
```bash
# Check service account permissions
kubectl auth can-i --list --as=system:serviceaccount:rust-security:default

# Verify pod security context
kubectl describe pod auth-service-xxx | grep -A 10 "Security Context"
```

#### Rollback Failures
```bash
# Check backup availability
ls -la scripts/migrations/backups/

# Manual backup restoration
kubectl cp backup-file.rdb rust-security/redis-master-0:/data/dump.rdb
kubectl exec redis-master-0 -n rust-security -- redis-cli DEBUG RESTART
```

### Debugging Commands

```bash
# Check migration logs
tail -f scripts/migrations/logs/migration.log

# Check migration state
cat scripts/migrations/state/*_version
cat scripts/migrations/state/migration_history.csv

# Verify component connectivity
kubectl exec -it auth-service-xxx -- curl http://localhost:8080/health
kubectl exec -it policy-service-xxx -- curl http://localhost:8080/health
kubectl exec -it redis-master-0 -- redis-cli ping
```

## Monitoring and Alerting

### Migration Metrics

Monitor these metrics during migrations:

- Migration execution time
- Backup creation time
- Service downtime duration
- Error rates during migration
- Rollback frequency

### Alerts

Set up alerts for:
- Migration failures
- Long-running migrations (>10 minutes)
- Backup failures
- Service health during migrations

### Dashboard

Create Grafana dashboard with:
- Migration status by component
- Migration history timeline
- Service health during migrations
- Backup status and retention

## Security Considerations

### Secret Management

- Never include secrets in migration scripts
- Use External Secrets for sensitive configuration
- Rotate secrets after major migrations
- Audit secret access during migrations

### Access Control

- Limit migration execution to authorized personnel
- Use service accounts with minimal required permissions
- Log all migration activities for audit
- Require approval for production migrations

### Data Protection

- Encrypt backups at rest and in transit
- Retain backups according to compliance requirements
- Test backup restoration regularly
- Implement data classification enforcement

## Compliance and Audit

### Audit Trail

The migration framework maintains comprehensive audit logs:
- Migration execution history
- User attribution for all changes
- Backup and restoration activities
- Rollback operations

### Compliance Requirements

- **SOC 2**: Change management and data protection
- **GDPR**: Data processing and retention policies
- **CCPA**: Data handling and user rights
- **Industry Standards**: Security and operational best practices

### Documentation Requirements

Maintain documentation for:
- Migration procedures and runbooks
- Risk assessments for major changes
- Business impact analysis
- Recovery procedures and validation

This comprehensive migration and versioning system ensures safe, reliable, and auditable changes to the Rust Security Platform while maintaining high availability and data integrity.