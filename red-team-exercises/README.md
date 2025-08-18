# Comprehensive Cloud Security Infrastructure for Rust Authentication Service

This repository provides a complete cloud security hardening implementation for a Rust-based authentication service, featuring enterprise-grade security controls, monitoring, and compliance frameworks across multiple cloud providers.

## 🏗️ Architecture Overview

The security infrastructure implements a **Zero-Trust Architecture** with defense-in-depth principles:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Internet / External Users                   │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│  WAF + DDoS Protection + Rate Limiting                          │
│  ├── AWS WAF / CloudFlare / Azure Front Door                    │
│  └── Geographic IP filtering & Bot protection                   │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│                 Load Balancer (mTLS)                            │
│  ├── SSL/TLS Termination (TLS 1.3)                             │
│  ├── Health Checks & Circuit Breakers                          │
│  └── Request routing & Sticky sessions                         │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│              Kubernetes Ingress Controller                      │
│  ├── Nginx/Istio Gateway with security headers                 │
│  ├── Certificate management (cert-manager)                     │
│  └── Rate limiting & authentication                            │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│                 Service Mesh (Istio)                           │
│  ├── mTLS between all services                                 │
│  ├── Authorization policies (RBAC)                             │
│  ├── Traffic encryption & observability                       │
│  └── Circuit breakers & fault injection                       │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│             Auth Service Pods (Hardened)                       │
│  ├── Pod Security Standards (Restricted)                       │
│  ├── Read-only root filesystem                                 │
│  ├── Non-root user (UID 10001)                                │
│  ├── Dropped capabilities (ALL)                               │
│  ├── Seccomp & AppArmor profiles                              │
│  └── Resource limits & network policies                       │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│                  Data Layer                                     │
│  ├── PostgreSQL (encrypted at rest & in transit)              │
│  ├── Redis (auth tokens, encrypted)                           │
│  ├── KMS for key management                                   │
│  └── Secrets management (External Secrets Operator)          │
└─────────────────────────────────────────────────────────────────┘
```

## 🛡️ Security Features

### 1. **Kubernetes Security Hardening**
- **Pod Security Standards**: Restricted profile enforcement
- **Network Policies**: Micro-segmentation with deny-all default
- **RBAC**: Least privilege access controls
- **Admission Controllers**: OPA Gatekeeper policy enforcement
- **Runtime Security**: Falco behavioral monitoring
- **Container Security**: gVisor/Kata Containers support

### 2. **Service Mesh Security (Istio)**
- **mTLS**: Automatic mutual TLS between all services
- **Authorization Policies**: Fine-grained access controls
- **Traffic Encryption**: End-to-end encryption
- **Security Headers**: Comprehensive HTTP security headers
- **Rate Limiting**: Per-service and global rate limits

### 3. **Zero-Trust Architecture**
- **Identity Verification**: Continuous authentication
- **Least Privilege**: Minimal required permissions
- **Micro-segmentation**: Network isolation between services
- **Encrypted Communication**: All traffic encrypted in transit
- **Audit Logging**: Complete audit trail

### 4. **Cloud Security (Multi-Cloud)**
- **AWS**: GuardDuty, Config, CloudTrail, WAF, KMS
- **GCP**: Security Command Center, Cloud KMS, VPC Security
- **Azure**: Security Center, Key Vault, Network Security Groups
- **Infrastructure as Code**: Terraform with security best practices

### 5. **Compliance & Governance**
- **CIS Kubernetes Benchmark**: Automated compliance checking
- **SOC 2 Type II**: Control framework implementation
- **PCI DSS**: Payment data protection
- **GDPR/CCPA**: Data privacy compliance
- **HIPAA**: Healthcare data protection

## 📁 Repository Structure

```
red-team-exercises/
├── README.md                          # This file
├── k8s/                              # Kubernetes manifests
│   └── security/
│       ├── pod-security-standards.yaml    # Pod security policies
│       ├── network-policies.yaml          # Network segmentation
│       ├── admission-controllers.yaml     # OPA Gatekeeper policies
│       └── service-mesh.yaml             # Istio security configuration
├── terraform/                        # Infrastructure as Code
│   ├── aws/
│   │   ├── main.tf                       # AWS infrastructure
│   │   ├── iam.tf                        # IAM roles and policies
│   │   └── variables.tf                  # Configuration variables
│   ├── gcp/                             # Google Cloud Platform
│   └── azure/                           # Microsoft Azure
├── helm/                             # Helm charts
│   └── auth-service/
│       ├── Chart.yaml                    # Helm chart metadata
│       ├── values.yaml                   # Default configuration
│       └── templates/                    # Kubernetes templates
├── monitoring/                       # Observability stack
│   ├── prometheus/
│   │   └── rules.yaml                    # Security monitoring rules
│   └── grafana/
│       └── auth-service-dashboard.json   # Security dashboard
├── gitops/                          # GitOps configuration
│   └── argocd/
│       └── auth-service-app.yaml         # ArgoCD application
├── compliance/                      # Compliance frameworks
│   └── cis-benchmark.yaml               # CIS Kubernetes Benchmark
├── disaster-recovery/               # Backup and DR
│   └── backup-strategy.yaml             # Comprehensive backup strategy
└── scripts/                        # Automation scripts
    └── deploy-security-infrastructure.sh # Main deployment script
```

## 🚀 Quick Start

### Prerequisites

Ensure you have the following tools installed:

```bash
# Required tools
kubectl >= 1.24
helm >= 3.8
terraform >= 1.0
aws-cli >= 2.0  # or gcloud/az cli
jq >= 1.6
yq >= 4.0

# Optional but recommended
istioctl >= 1.18
velero >= 1.11
argocd >= 2.7
```

### 1. Clone and Configure

```bash
git clone <repository-url>
cd red-team-exercises

# Create configuration file
cat > deployment.config << EOF
ENVIRONMENT=production
CLOUD_PROVIDER=aws
REGION=us-west-2
CLUSTER_NAME=auth-service-production
DOMAIN_NAME=auth.yourcompany.com
ENABLE_ISTIO=true
ENABLE_GATEKEEPER=true
ENABLE_FALCO=true
ENABLE_MONITORING=true
ENABLE_BACKUP=true
ENABLE_GITOPS=true
EOF
```

### 2. Deploy Infrastructure

```bash
# Deploy complete security infrastructure
./scripts/deploy-security-infrastructure.sh

# Or deploy with specific options
./scripts/deploy-security-infrastructure.sh \
  --environment production \
  --cloud-provider aws \
  --region us-west-2 \
  --domain auth.yourcompany.com
```

### 3. Verify Deployment

```bash
# Check cluster status
kubectl get nodes
kubectl get pods -A

# Verify security policies
kubectl get constraints -A
kubectl get networkpolicies -A

# Check service mesh
istioctl proxy-status
istioctl analyze -A

# Test application
kubectl run test-curl --rm -i --restart=Never \
  --image=curlimages/curl:latest \
  -- curl -f http://auth-service.auth-service.svc.cluster.local/health
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ENVIRONMENT` | Deployment environment | `production` |
| `CLOUD_PROVIDER` | Cloud provider (aws/gcp/azure) | `aws` |
| `REGION` | Cloud region | `us-west-2` |
| `CLUSTER_NAME` | Kubernetes cluster name | `auth-service-${ENVIRONMENT}` |
| `DOMAIN_NAME` | Service domain name | `auth.example.com` |
| `ENABLE_ISTIO` | Install Istio service mesh | `true` |
| `ENABLE_GATEKEEPER` | Install OPA Gatekeeper | `true` |
| `ENABLE_FALCO` | Install Falco runtime security | `true` |
| `ENABLE_MONITORING` | Install monitoring stack | `true` |
| `ENABLE_BACKUP` | Setup backup system | `true` |
| `ENABLE_GITOPS` | Install ArgoCD | `true` |

### Security Configuration

#### Pod Security Standards
```yaml
# Restricted profile enforcement
apiVersion: v1
kind: Namespace
metadata:
  name: auth-service
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

#### Network Policies
```yaml
# Default deny all traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

#### OPA Gatekeeper Constraints
```yaml
# Require non-root containers
apiVersion: config.gatekeeper.sh/v1alpha1
kind: K8sRequiredNonRoot
metadata:
  name: must-run-as-non-root
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

## 📊 Monitoring & Observability

### Prometheus Metrics

The system exposes comprehensive security metrics:

```promql
# Authentication metrics
auth_login_attempts_total{status="failed"}
auth_mfa_attempts_total{status="success"}
auth_rate_limit_triggered_total
auth_idor_attempts_total
auth_token_replay_attempts_total

# Infrastructure metrics
container_memory_working_set_bytes
container_cpu_usage_seconds_total
kube_pod_security_policy_violations_total
```

### Grafana Dashboards

Pre-configured dashboards include:
- **Security Overview**: Authentication metrics, security events
- **Infrastructure Health**: Resource usage, pod status
- **Compliance Status**: Policy violations, audit events
- **Threat Detection**: Anomaly detection, attack patterns

### Alerting Rules

Critical security alerts:
- Failed login rate > 10%
- IDOR attempts detected
- Token replay attacks
- Policy violations
- Service downtime
- Certificate expiration

## 🔐 Security Controls

### Authentication & Authorization
- **Multi-Factor Authentication**: TOTP, SMS, hardware tokens
- **OAuth 2.0 / OpenID Connect**: Standards-compliant flows
- **JWT**: Secure token handling with rotation
- **Session Management**: Secure session handling
- **RBAC**: Role-based access control

### Data Protection
- **Encryption at Rest**: AES-256 encryption for all data
- **Encryption in Transit**: TLS 1.3 for all communications
- **Key Management**: Hardware Security Modules (HSM)
- **Secrets Management**: External secrets with rotation
- **Data Classification**: Automated PII detection

### Network Security
- **Zero Trust**: No implicit trust, verify everything
- **Micro-segmentation**: Isolated network zones
- **DDoS Protection**: Multi-layer DDoS mitigation
- **WAF**: Web Application Firewall with custom rules
- **VPN**: Secure remote access

### Runtime Security
- **Behavioral Analysis**: Falco runtime monitoring
- **Anomaly Detection**: ML-based threat detection
- **Container Scanning**: Vulnerability assessment
- **SIEM Integration**: Security information and event management
- **Incident Response**: Automated response playbooks

## 🌍 Multi-Cloud Support

### AWS Security Services
- **GuardDuty**: Threat detection
- **Config**: Compliance monitoring
- **CloudTrail**: Audit logging
- **WAF**: Web application firewall
- **KMS**: Key management
- **Secrets Manager**: Secrets storage

### Google Cloud Security
- **Security Command Center**: Centralized security
- **Cloud KMS**: Key management
- **Cloud Armor**: DDoS protection
- **VPC Security**: Network security
- **Cloud IAM**: Identity management

### Azure Security Services
- **Security Center**: Security posture management
- **Key Vault**: Secrets and key management
- **Application Gateway**: WAF and load balancing
- **Network Security Groups**: Network filtering
- **Azure AD**: Identity management

## 📋 Compliance Frameworks

### CIS Kubernetes Benchmark
Automated compliance checking for:
- Control plane security
- Worker node security
- Pod security policies
- Network policies
- Logging and monitoring

### SOC 2 Type II
Implementation of controls for:
- Security
- Availability
- Processing integrity
- Confidentiality
- Privacy

### Industry-Specific Compliance
- **PCI DSS**: Payment card industry
- **HIPAA**: Healthcare data
- **GDPR**: European data protection
- **CCPA**: California privacy rights
- **ISO 27001**: Information security management

## 🔄 Disaster Recovery

### Backup Strategy
- **Daily Backups**: Application data and configurations
- **Weekly Backups**: Full system snapshots
- **Monthly Backups**: Long-term retention
- **Cross-Region Replication**: Geographic redundancy
- **Automated Testing**: DR procedure validation

### Recovery Procedures
- **RTO**: Recovery Time Objective < 4 hours
- **RPO**: Recovery Point Objective < 1 hour
- **Automated Failover**: Multi-region deployment
- **Data Consistency**: ACID compliance
- **Business Continuity**: Minimal service disruption

## 🔧 Troubleshooting

### Common Issues

#### Pod Security Policy Violations
```bash
# Check pod security constraints
kubectl get constraints
kubectl describe constraint <constraint-name>

# View violation details
kubectl get events --field-selector reason=FailedCreate
```

#### Network Policy Issues
```bash
# Test network connectivity
kubectl run debug --image=nicolaka/netshoot -it --rm
nslookup auth-service.auth-service.svc.cluster.local

# Check network policies
kubectl get networkpolicies -A
kubectl describe networkpolicy <policy-name>
```

#### Istio Configuration Problems
```bash
# Check Istio proxy status
istioctl proxy-status

# Analyze configuration
istioctl analyze -A

# Check mTLS status
istioctl authn tls-check auth-service.auth-service.svc.cluster.local
```

### Debug Commands

```bash
# Security policy debugging
kubectl get constraintviolations -A
kubectl get falcoalerts -A

# Application debugging
kubectl logs -f deployment/auth-service -n auth-service
kubectl describe pod <pod-name> -n auth-service

# Network debugging
kubectl exec -it <pod-name> -n auth-service -- netstat -tlnp
kubectl exec -it <pod-name> -n auth-service -- nslookup kubernetes.default
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/security-enhancement`)
3. Commit your changes (`git commit -am 'Add new security control'`)
4. Push to the branch (`git push origin feature/security-enhancement`)
5. Create a Pull Request

### Security Guidelines
- All security controls must be tested
- Follow principle of least privilege
- Document security implications
- Include threat model updates
- Add monitoring and alerting

## 📞 Support

### Security Team
- **Email**: security@company.com
- **Slack**: #security-team
- **On-call**: security-oncall@company.com

### Platform Team
- **Email**: platform@company.com
- **Slack**: #platform-team
- **Documentation**: https://wiki.company.com/platform

### Emergency Contacts
- **Security Incident**: +1-555-SECURITY
- **Platform Issues**: +1-555-PLATFORM
- **After Hours**: +1-555-ONCALL

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Notice

This infrastructure implements enterprise-grade security controls. Ensure proper:
- Access controls and authentication
- Network segmentation and monitoring
- Regular security assessments
- Incident response procedures
- Compliance validation

For security vulnerabilities, please email security@company.com instead of creating public issues.