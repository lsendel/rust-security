#!/bin/bash
set -euo pipefail

# Regenerate API documentation from OpenAPI specs
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_SPECS_DIR="$PROJECT_ROOT/api-specs"
DOCS_DIR="$PROJECT_ROOT/docs"

echo "🔄 Regenerating API documentation from OpenAPI specs..."

# Function to convert OpenAPI YAML to Markdown
generate_api_docs() {
    local spec_file="$1"
    local output_file="$2"
    local service_name="$3"
    
    echo "📝 Generating documentation for $service_name..."
    
    cat > "$output_file" << EOF
# $service_name API Documentation

> **Auto-generated from OpenAPI specification**  
> Source: \`$(basename "$spec_file")\`  
> Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

## Overview

This document provides comprehensive API documentation for the $service_name, automatically generated from the OpenAPI specification.

## Base URLs

EOF

    # Extract server URLs from the spec
    if command -v yq >/dev/null 2>&1; then
        echo "### Available Servers" >> "$output_file"
        echo "" >> "$output_file"
        yq eval '.servers[] | "- **" + .description + "**: " + .url' "$spec_file" >> "$output_file" 2>/dev/null || true
        echo "" >> "$output_file"
    fi

    # Add authentication section
    cat >> "$output_file" << EOF

## Authentication

This API uses the following authentication methods:

- **Bearer Token**: Include \`Authorization: Bearer <token>\` header
- **API Key**: Include \`X-API-Key: <key>\` header

## API Reference

For detailed endpoint documentation, please refer to:

1. **Interactive Documentation**: Available at \`/swagger-ui\` when running the service
2. **OpenAPI Specification**: [\`$(basename "$spec_file")\`](../api-specs/$(basename "$spec_file"))
3. **Postman Collection**: Auto-generated from OpenAPI spec

## Quick Start

\`\`\`bash
# Health check
curl -X GET "http://localhost:8080/health"

# Get API version
curl -X GET "http://localhost:8080/version"
\`\`\`

## Error Handling

All API endpoints return standardized error responses:

\`\`\`json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": {}
  }
}
\`\`\`

## Rate Limiting

- **Default**: 1000 requests per minute per IP
- **Authenticated**: 5000 requests per minute per user
- **Headers**: \`X-RateLimit-Limit\`, \`X-RateLimit-Remaining\`, \`X-RateLimit-Reset\`

---

*This documentation is automatically generated from the OpenAPI specification. For the most up-to-date information, please refer to the interactive Swagger UI available when running the service.*
EOF
}

# Generate documentation for each service
if [[ -f "$API_SPECS_DIR/auth-service.openapi.yaml" ]]; then
    generate_api_docs "$API_SPECS_DIR/auth-service.openapi.yaml" "$DOCS_DIR/api/auth-service.md" "Auth Service"
fi

if [[ -f "$API_SPECS_DIR/policy-service.openapi.yaml" ]]; then
    generate_api_docs "$API_SPECS_DIR/policy-service.openapi.yaml" "$DOCS_DIR/api/policy-service.md" "Policy Service"
fi

if [[ -f "$API_SPECS_DIR/complete-platform.openapi.yaml" ]]; then
    generate_api_docs "$API_SPECS_DIR/complete-platform.openapi.yaml" "$DOCS_DIR/API_DOCUMENTATION.md" "Complete Platform"
fi

# Update the main API documentation index
cat > "$DOCS_DIR/api/README.md" << EOF
# API Documentation

> **Auto-generated from OpenAPI specifications**  
> Last updated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

## Available APIs

- [**Auth Service API**](./auth-service.md) - Authentication and authorization endpoints
- [**Policy Service API**](./policy-service.md) - Policy management and evaluation
- [**Complete Platform API**](../API_DOCUMENTATION.md) - Unified platform documentation

## Interactive Documentation

When running the services locally, interactive Swagger UI documentation is available at:

- Auth Service: http://localhost:8080/swagger-ui
- Policy Service: http://localhost:8081/swagger-ui

## OpenAPI Specifications

Raw OpenAPI specifications are available in the [\`api-specs/\`](../../api-specs/) directory:

- [\`auth-service.openapi.yaml\`](../../api-specs/auth-service.openapi.yaml)
- [\`policy-service.openapi.yaml\`](../../api-specs/policy-service.openapi.yaml)
- [\`complete-platform.openapi.yaml\`](../../api-specs/complete-platform.openapi.yaml)

## Development

To regenerate this documentation after updating OpenAPI specs:

\`\`\`bash
./scripts/regenerate-api-docs.sh
\`\`\`
EOF

echo "✅ API documentation regenerated successfully!"
echo "📍 Updated files:"
echo "   - docs/api/README.md"
echo "   - docs/api/auth-service.md"
echo "   - docs/api/policy-service.md" 
echo "   - docs/API_DOCUMENTATION.md"
