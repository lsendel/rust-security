# Documentation Migration Guide

Guide for migrating from the old documentation structure to the new organized documentation.

## Overview

This guide helps users and contributors migrate from the old scattered documentation structure to the new organized documentation structure. The new structure provides better organization, consistency, and usability.

## Migration Map

### Old → New Documentation Paths

#### Getting Started Documentation
- `docs/getting-started.md` → `docs/01-introduction/quick-start.md`
- `docs/QUICK_START_GUIDE.md` → `docs/01-introduction/quick-start.md`
- `docs/DEVELOPER_ONBOARDING.md` → `docs/01-introduction/developer-setup.md`
- `docs/PROGRESSIVE_SETUP.md` → `docs/01-introduction/installation.md`

#### Architecture Documentation
- `docs/architecture/README.md` → `docs/02-core-concepts/overview.md`
- `docs/architecture/PLATFORM_OVERVIEW.md` → `docs/02-core-concepts/overview.md`
- `docs/architecture/SYSTEM_ARCHITECTURE.md` → `docs/02-core-concepts/components.md`

#### API Documentation
- `API_DOCUMENTATION.md` → `docs/03-api-reference/overview.md`
- `docs/API_REFERENCE.md` → `docs/03-api-reference/README.md`
- `docs/API_EXAMPLES_GUIDE.md` → `docs/03-api-reference/examples.md`

#### Security Documentation
- `docs/security/README.md` → `docs/04-security/security-overview.md`
- `docs/security/SECURITY_AUDIT.md` → `docs/04-security/threat-model.md`
- `docs/SECURITY_BEST_PRACTICES.md` → `docs/04-security/security-overview.md`

#### Operations Documentation
- `docs/deployment/README.md` → `docs/01-introduction/deployment.md`
- `docs/operations/operations-guide.md` → `docs/01-introduction/deployment.md`
- `DEPLOYMENT_GUIDE.md` → `docs/01-introduction/deployment.md`

## Key Changes

### 1. Organized Structure
**Old Structure:**
```
docs/
├── getting-started.md
├── architecture/
│   └── README.md
├── security/
│   └── README.md
└── api/
    └── README.md
```

**New Structure:**
```
docs/
├── 01-introduction/
│   ├── README.md
│   ├── quick-start.md
│   ├── developer-setup.md
│   ├── installation.md
│   ├── configuration.md
│   └── deployment.md
├── 02-core-concepts/
│   ├── README.md
│   ├── overview.md
│   └── components.md
├── 03-api-reference/
│   ├── README.md
│   ├── overview.md
│   ├── authentication.md
│   ├── authorization.md
│   ├── user-management.md
│   ├── token-management.md
│   └── examples.md
└── 04-security/
    ├── README.md
    ├── security-overview.md
    ├── threat-model.md
    └── authentication-security.md
```

### 2. Numbered Directories
- Directories are now numbered for consistent ordering
- Makes navigation more predictable in file browsers
- Ensures proper documentation flow

### 3. Consistent Naming
- All files use kebab-case naming convention
- Consistent file extensions (.md)
- Descriptive, consistent file names

### 4. Comprehensive Coverage
- Added missing documentation sections
- Enhanced existing documentation with more details
- Created new documentation for key components

## Migration Steps

### For Users
1. **Update Bookmarks**: Update bookmarks to new documentation locations
2. **Review New Structure**: Familiarize yourself with the new organization
3. **Use Index**: Refer to `docs/INDEX.md` for complete documentation navigation
4. **Check Quick Links**: Use the quick links in the main README

### For Contributors
1. **Follow New Structure**: Place new documentation in appropriate directories
2. **Use Documentation Standards**: Follow the documentation standards in `docs/DOCUMENTATION_STANDARDS.md`
3. **Update References**: Update any internal links to new documentation paths
4. **Review Quality Checklist**: Use `docs/07-development/documentation-quality-checklist.md` for quality assurance

### For Automated Tools
1. **Update Documentation Paths**: Update any tools that reference documentation paths
2. **Check Link Validity**: Verify all internal links work with new structure
3. **Update Search Indexes**: Reindex documentation for search tools
4. **Update Documentation Generators**: Update any documentation generation tools

## Backward Compatibility

### Kept Files
Some files have been kept for backward compatibility but are deprecated:
- `docs/getting-started.md` (deprecated - use `docs/01-introduction/quick-start.md`)
- `docs/architecture/README.md` (deprecated - use `docs/02-core-concepts/overview.md`)
- `docs/security/README.md` (deprecated - use `docs/04-security/README.md`)

### Deprecated Files
These files are deprecated and will be removed in future versions:
- `docs/QUICK_START_GUIDE.md` (replaced by `docs/01-introduction/quick-start.md`)
- `docs/API_REFERENCE.md` (replaced by `docs/03-api-reference/README.md`)
- `docs/API_DOCUMENTATION.md` (replaced by `docs/03-api-reference/overview.md`)

## Benefits of New Structure

### 1. Improved Navigation
- Clear, organized structure by topic and user role
- Numbered directories for consistent ordering
- Comprehensive index and navigation aids

### 2. Better Maintainability
- Consistent documentation standards
- Modular structure for easy updates
- Quality assurance through checklist

### 3. Enhanced Usability
- Targeted documentation for different user types
- Comprehensive coverage of all features
- Practical examples and best practices

### 4. Future-Proof Design
- Scalable structure for new documentation
- Consistent patterns for ongoing additions
- Clear guidelines for contributors

## Support

For help with the documentation migration:
1. **Check the Index**: Refer to `docs/INDEX.md` for complete navigation
2. **Review Migration Map**: Use this guide for path mappings
3. **Contact Team**: Reach out to documentation maintainers for assistance
4. **Report Issues**: File issues for any broken links or missing documentation

The new documentation structure provides a much better experience for all users while maintaining the comprehensive coverage of the platform's features and capabilities.