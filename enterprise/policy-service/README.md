# Policy Service

The Policy Service is the authorization component of the Rust Security Platform, providing fine-grained access control using the Cedar policy language.

## Overview

The Policy Service implements a comprehensive authorization engine using AWS Cedar, a policy language designed for defining and enforcing access control policies. It provides real-time policy evaluation with high performance and scalability.

## Features

### Authorization Engine
- **Cedar Policy Language**: AWS Cedar for fine-grained authorization
- **RBAC Implementation**: Role-based access control
- **ABAC Implementation**: Attribute-based access control
- **Policy Caching**: Intelligent caching with TTL and invalidation

### Performance
- **Sub-5ms policy evaluation latency**
- **50,000+ policy evaluations per second**
- **Horizontal scaling support**
- **Efficient caching strategies**

### Security
- **Policy Validation**: Static policy validation
- **Audit Logging**: Comprehensive authorization logging
- **Secure Communication**: TLS 1.3 support
- **Input Validation**: Comprehensive sanitization

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   POLICY SERVICE                            │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   API       │  │  Business   │  │   Data      │         │
│  │  Layer      │  │   Logic     │  │  Access     │         │
│  │             │  │             │  │             │         │
│  │ • HTTP      │  │ • Policy    │  │ • File      │         │
│  │ • Middleware│  │ • Entity    │  │ • Cache     │         │
│  │ • Validation│  │ • Eval      │  │ • Storage   │         │
│  └─────────────┘  │             │  └─────────────┘         │
│                   └─────────────┘                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Security   │  │ Monitoring  │  │   Infra     │         │
│  │             │  │             │  │             │         │
│  │ • TLS       │  │ • Metrics   │  │ • Config    │         │
│  │ • Validation│  │ • Logging   │  │ • Health    │         │
│  │             │  │ • Tracing   │  │ • Shutdown  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## Key Components

### Policy Engine
- Cedar policy language evaluation
- Policy caching and invalidation
- Batch policy evaluation
- Policy validation

### Entity Management
- User and resource entity management
- Entity relationship handling
- Entity caching
- Entity validation

### Authorization Evaluation
- Real-time policy evaluation
- Context-aware decisions
- Obligation and advice handling
- Decision logging

### Audit Logging
- Comprehensive authorization logging
- Decision metadata capture
- Performance metrics
- Security event logging

## API Endpoints

### Policy Evaluation
- `POST /v1/authorize` - Evaluate authorization request
- `POST /v1/authorize/bulk` - Batch policy evaluation

### Policy Management
- `GET /api/v1/policies` - List policies
- `POST /api/v1/policies` - Create policy
- `GET /api/v1/policies/{id}` - Get policy
- `PUT /api/v1/policies/{id}` - Update policy
- `DELETE /api/v1/policies/{id}` - Delete policy

### Entity Management
- `GET /api/v1/entities` - List entities
- `POST /api/v1/entities` - Create entity
- `GET /api/v1/entities/{id}` - Get entity
- `PUT /api/v1/entities/{id}` - Update entity
- `DELETE /api/v1/entities/{id}` - Delete entity

### Administration
- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics
- `GET /openapi.json` - OpenAPI specification

## Policy Language

### Cedar Policy Example

```cedar
// Allow users in the "Admin" group to perform any action on any resource
permit (
    principal in Group::"Admin",
    action,
    resource
);

// Allow users to read documents they own
permit (
    principal,
    action == Action::"Read",
    resource in Document::"UserDocuments"
) when {
    resource.owner == principal
};

// Allow users in the "Engineering" group to write to engineering documents
permit (
    principal in Group::"Engineering",
    action in [Action::"Write", Action::"Read"],
    resource in Document::"Engineering"
);
```

### Entity Example

```json
[
  {
    "uid": {"type": "User", "id": "alice"},
    "attrs": {
      "department": "Engineering",
      "roles": ["user", "developer"]
    },
    "parents": [
      {"type": "Group", "id": "Users"},
      {"type": "Group", "id": "Engineering"}
    ]
  },
  {
    "uid": {"type": "Resource", "id": "document1"},
    "attrs": {
      "owner": "alice",
      "classification": "Internal"
    }
  }
]
```

## Configuration

### Environment Variables

```bash
# Server Configuration
PORT=8081
BIND_ADDRESS=0.0.0.0
ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com

# Policy Configuration
POLICY_DIRECTORY=./policies
POLICY_WATCH_FOR_CHANGES=true
POLICY_CACHE_TTL=300

# Entity Configuration
ENTITY_DIRECTORY=./entities
ENTITY_AUTO_RELOAD=true

# Redis Configuration (for caching)
REDIS_URL=redis://localhost:6379
REDIS_POOL_SIZE=5
```

### Configuration File

```yaml
# config.yaml
server:
  host: "0.0.0.0"
  port: 8081
  allowed_origins:
    - "https://app.example.com"
    - "https://admin.example.com"

policies:
  directory: "./policies"
  watch_for_changes: true
  cache_ttl: 300

entities:
  directory: "./entities"
  auto_reload: true

redis:
  url: "redis://localhost:6379"
  pool_size: 5
```

## Running the Service

### Development

```bash
# Run with default configuration
cargo run -p policy-service

# Run with custom environment
PORT=8081 cargo run -p policy-service

# Run with configuration file
CONFIG_FILE=config.yaml cargo run -p policy-service
```

### Production

```bash
# Build optimized binary
cargo build --release -p policy-service

# Run optimized binary
./target/release/policy-service
```

### Docker

```bash
# Build Docker image
docker build -t policy-service -f Dockerfile.prod .

# Run Docker container
docker run -p 8081:8081 policy-service
```

## Testing

### Unit Tests

```bash
# Run unit tests
cargo test -p policy-service --lib

# Run specific test
cargo test -p policy-service test_policy_evaluation
```

### Integration Tests

```bash
# Run integration tests
cargo test -p policy-service --test '*'
```

### Policy Tests

```bash
# Run policy-specific tests
cargo test -p policy-service --features policy-tests
```

## Monitoring

### Metrics

The service exposes Prometheus metrics at `/metrics`:

- `policy_evaluations_total` - Total policy evaluations
- `policy_evaluation_duration_seconds` - Evaluation duration
- `policy_cache_hits_total` - Cache hits
- `policy_cache_misses_total` - Cache misses
- `policy_updates_total` - Policy updates

### Health Checks

- `GET /health` - Basic health check

### Distributed Tracing

OpenTelemetry tracing is available for request tracking and performance monitoring.

## Performance

### Benchmarks

- **Policy Evaluation**: <5ms P95 latency
- **Throughput**: >50,000 evaluations/second
- **Concurrency**: Horizontal scaling support
- **Caching**: Multi-level caching strategy

### Optimization Strategies

- **Policy Caching**: Intelligent caching with TTL
- **Entity Caching**: Efficient entity loading
- **Batch Processing**: Bulk policy evaluation
- **Memory Management**: Efficient memory usage

## Security

### Policy Security

- **Policy Validation**: Static policy validation
- **Input Sanitization**: Comprehensive input validation
- **Secure Communication**: TLS 1.3 support
- **Audit Logging**: Complete authorization logging

### Threat Protection

- **Rate Limiting**: API rate limiting
- **Input Validation**: Comprehensive sanitization
- **Policy Isolation**: Secure policy execution
- **Access Controls**: Strict API access controls

## Contributing

### Development Setup

```bash
# Install dependencies
cargo build -p policy-service

# Run tests
cargo test -p policy-service

# Run linter
cargo clippy -p policy-service

# Format code
cargo fmt -p policy-service
```

### Code Standards

- Follow Rust naming conventions
- Write comprehensive documentation
- Include tests for new functionality
- Maintain 80%+ test coverage
- Use error handling appropriately
- Follow security best practices

## Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check port availability
netstat -tlnp | grep :8081

# Verify policy files
ls ./policies/*.cedar
ls ./entities/*.json

# Check configuration
cargo run --bin policy-service -- --validate-config
```

#### Policy Evaluation Failures
```bash
# Check policy syntax
cedar validate --policies ./policies/*.cedar

# Check entity format
cat ./entities/*.json | jq .

# Validate policy evaluation
curl -X POST http://localhost:8081/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{"principal": {"type": "User", "id": "alice"}, "action": {"type": "Action", "id": "Read"}, "resource": {"type": "Document", "id": "doc1"}}'
```

#### Performance Issues
```bash
# Check metrics
curl http://localhost:8081/metrics | grep -E "(policy_evaluation|cache)"

# Monitor resource usage
docker stats
```

## Documentation

For comprehensive documentation, see:
- [API Reference](../../docs/03-api-reference/authorization.md)
- [Security Documentation](../../docs/04-security/authorization-security.md)
- [Architecture Documentation](../../docs/02-core-concepts/components.md)

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.