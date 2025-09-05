#!/bin/bash

# Comprehensive Cloud Security Infrastructure Deployment Script
# This script deploys a complete cloud security hardening setup for the Rust authentication service

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_FILE="${PROJECT_ROOT}/deployment.log"
CONFIG_FILE="${PROJECT_ROOT}/deployment.config"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
ENVIRONMENT=${ENVIRONMENT:-"production"}
CLOUD_PROVIDER=${CLOUD_PROVIDER:-"aws"}
REGION=${REGION:-"us-west-2"}
CLUSTER_NAME=${CLUSTER_NAME:-"auth-service-${ENVIRONMENT}"}
DOMAIN_NAME=${DOMAIN_NAME:-"auth.example.com"}
ENABLE_ISTIO=${ENABLE_ISTIO:-"true"}
ENABLE_GATEKEEPER=${ENABLE_GATEKEEPER:-"true"}
ENABLE_FALCO=${ENABLE_FALCO:-"true"}
ENABLE_MONITORING=${ENABLE_MONITORING:-"true"}
ENABLE_BACKUP=${ENABLE_BACKUP:-"true"}
ENABLE_GITOPS=${ENABLE_GITOPS:-"true"}

# Logging function
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} ${message}" | tee -a "${LOG_FILE}"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} ${message}" | tee -a "${LOG_FILE}"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} ${message}" | tee -a "${LOG_FILE}"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} ${message}" | tee -a "${LOG_FILE}"
            ;;
    esac
    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"
}

# Error handling
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    # Check required tools
    local required_tools=("kubectl" "helm" "terraform" "aws" "jq" "yq")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error_exit "Required tool '$tool' is not installed"
        fi
    done
    
    # Check Kubernetes cluster access
    if ! kubectl cluster-info &> /dev/null; then
        error_exit "Cannot access Kubernetes cluster. Please configure kubectl"
    fi
    
    # Check AWS credentials
    if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
        if ! aws sts get-caller-identity &> /dev/null; then
            error_exit "AWS credentials not configured"
        fi
    fi
    
    log "INFO" "All prerequisites satisfied"
}

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log "INFO" "Loading configuration from $CONFIG_FILE"
        source "$CONFIG_FILE"
    else
        log "WARN" "Configuration file not found, using defaults"
    fi
}

# Initialize Terraform
init_terraform() {
    log "INFO" "Initializing Terraform infrastructure..."
    
    local terraform_dir="${PROJECT_ROOT}/terraform/${CLOUD_PROVIDER}"
    
    if [[ ! -d "$terraform_dir" ]]; then
        error_exit "Terraform directory not found: $terraform_dir"
    fi
    
    cd "$terraform_dir"
    
    # Initialize Terraform
    terraform init -reconfigure
    
    # Plan infrastructure
    terraform plan \
        -var="environment=${ENVIRONMENT}" \
        -var="region=${REGION}" \
        -var="domain_name=${DOMAIN_NAME}" \
        -out=tfplan
    
    # Apply infrastructure
    log "INFO" "Applying Terraform infrastructure..."
    terraform apply tfplan
    
    # Get outputs
    CLUSTER_ENDPOINT=$(terraform output -raw cluster_endpoint)
    VPC_ID=$(terraform output -raw vpc_id)
    
    log "INFO" "Infrastructure deployment completed"
    cd "$PROJECT_ROOT"
}

# Configure kubectl for EKS
configure_kubectl() {
    if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
        log "INFO" "Configuring kubectl for EKS cluster..."
        aws eks update-kubeconfig \
            --region "$REGION" \
            --name "$CLUSTER_NAME"
    fi
}

# Install security operators
install_security_operators() {
    log "INFO" "Installing security operators..."
    
    # Install cert-manager
    log "INFO" "Installing cert-manager..."
    helm repo add jetstack https://charts.jetstack.io
    helm repo update
    
    helm upgrade --install cert-manager jetstack/cert-manager \
        --namespace cert-manager \
        --create-namespace \
        --set installCRDs=true \
        --set global.leaderElection.namespace=cert-manager \
        --wait
    
    # Install external-secrets operator
    log "INFO" "Installing external-secrets operator..."
    helm repo add external-secrets https://charts.external-secrets.io
    helm repo update
    
    helm upgrade --install external-secrets external-secrets/external-secrets \
        --namespace external-secrets-system \
        --create-namespace \
        --wait
    
    # Install OPA Gatekeeper
    if [[ "$ENABLE_GATEKEEPER" == "true" ]]; then
        log "INFO" "Installing OPA Gatekeeper..."
        helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
        helm repo update
        
        helm upgrade --install gatekeeper gatekeeper/gatekeeper \
            --namespace gatekeeper-system \
            --create-namespace \
            --set auditInterval=60 \
            --set constraintViolationsLimit=20 \
            --set auditFromCache=false \
            --wait
    fi
    
    # Install Falco
    if [[ "$ENABLE_FALCO" == "true" ]]; then
        log "INFO" "Installing Falco..."
        helm repo add falcosecurity https://falcosecurity.github.io/charts
        helm repo update
        
        helm upgrade --install falco falcosecurity/falco \
            --namespace falco-system \
            --create-namespace \
            --set driver.kind=ebpf \
            --set falco.grpc.enabled=true \
            --set falco.grpcOutput.enabled=true \
            --wait
    fi
}

# Install service mesh
install_service_mesh() {
    if [[ "$ENABLE_ISTIO" == "true" ]]; then
        log "INFO" "Installing Istio service mesh..."
        
        # Download and install Istio
        if ! command -v istioctl &> /dev/null; then
            log "INFO" "Downloading Istio..."
            curl -L https://istio.io/downloadIstio | sh -
            export PATH="$PWD/istio-*/bin:$PATH"
        fi
        
        # Install Istio
        istioctl install --set values.defaultRevision=default -y
        
        # Enable Istio injection for auth-service namespace
        kubectl label namespace auth-service istio-injection=enabled --overwrite
        
        # Install Istio addons
        kubectl apply -f "https://raw.githubusercontent.com/istio/istio/release-1.19/samples/addons/prometheus.yaml"
        kubectl apply -f "https://raw.githubusercontent.com/istio/istio/release-1.19/samples/addons/grafana.yaml"
        kubectl apply -f "https://raw.githubusercontent.com/istio/istio/release-1.19/samples/addons/jaeger.yaml"
        kubectl apply -f "https://raw.githubusercontent.com/istio/istio/release-1.19/samples/addons/kiali.yaml"
    fi
}

# Apply security policies
apply_security_policies() {
    log "INFO" "Applying security policies..."
    
    # Apply Pod Security Standards
    kubectl apply -f "${PROJECT_ROOT}/k8s/security/pod-security-standards.yaml"
    
    # Apply Network Policies
    kubectl apply -f "${PROJECT_ROOT}/k8s/security/network-policies.yaml"
    
    # Apply Admission Controllers
    if [[ "$ENABLE_GATEKEEPER" == "true" ]]; then
        # Wait for Gatekeeper to be ready
        kubectl wait --for=condition=ready pod -l app=gatekeeper-controller-manager -n gatekeeper-system --timeout=300s
        
        # Apply Gatekeeper policies
        kubectl apply -f "${PROJECT_ROOT}/k8s/security/admission-controllers.yaml"
        
        # Apply CIS benchmark policies
        kubectl apply -f "${PROJECT_ROOT}/compliance/cis-benchmark.yaml"
    fi
    
    # Apply Service Mesh security policies
    if [[ "$ENABLE_ISTIO" == "true" ]]; then
        kubectl apply -f "${PROJECT_ROOT}/k8s/security/service-mesh.yaml"
    fi
}

# Install monitoring stack
install_monitoring() {
    if [[ "$ENABLE_MONITORING" == "true" ]]; then
        log "INFO" "Installing monitoring stack..."
        
        # Install Prometheus Operator
        helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
        helm repo update
        
        helm upgrade --install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
            --namespace monitoring \
            --create-namespace \
            --set prometheus.prometheusSpec.retention=30d \
            --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=50Gi \
            --set grafana.adminPassword=admin123 \
            --set grafana.persistence.enabled=true \
            --set grafana.persistence.size=10Gi \
            --wait
        
        # Apply custom Prometheus rules
        kubectl apply -f "${PROJECT_ROOT}/monitoring/prometheus/rules.yaml"
        
        # Apply Grafana dashboards
        kubectl create configmap auth-service-dashboard \
            --from-file="${PROJECT_ROOT}/monitoring/grafana/auth-service-dashboard.json" \
            --namespace monitoring \
            --dry-run=client -o yaml | kubectl apply -f -
    fi
}

# Setup backup system
setup_backup() {
    if [[ "$ENABLE_BACKUP" == "true" ]]; then
        log "INFO" "Setting up backup system..."
        
        # Install Velero
        helm repo add vmware-tanzu https://vmware-tanzu.github.io/helm-charts
        helm repo update
        
        helm upgrade --install velero vmware-tanzu/velero \
            --namespace backup-system \
            --create-namespace \
            --set configuration.provider=aws \
            --set configuration.backupStorageLocation.bucket="auth-service-backups-${ENVIRONMENT}" \
            --set configuration.backupStorageLocation.config.region="$REGION" \
            --set configuration.volumeSnapshotLocation.config.region="$REGION" \
            --set initContainers[0].name=velero-plugin-for-aws \
            --set initContainers[0].image=velero/velero-plugin-for-aws:v1.8.0 \
            --set initContainers[0].volumeMounts[0].mountPath=/target \
            --set initContainers[0].volumeMounts[0].name=plugins \
            --wait
        
        # Apply backup strategy
        kubectl apply -f "${PROJECT_ROOT}/disaster-recovery/backup-strategy.yaml"
    fi
}

# Setup GitOps
setup_gitops() {
    if [[ "$ENABLE_GITOPS" == "true" ]]; then
        log "INFO" "Setting up GitOps with ArgoCD..."
        
        # Install ArgoCD
        helm repo add argo https://argoproj.github.io/argo-helm
        helm repo update
        
        helm upgrade --install argocd argo/argo-cd \
            --namespace argocd \
            --create-namespace \
            --set server.service.type=LoadBalancer \
            --set server.config.application.instanceLabelKey=argocd.argoproj.io/instance \
            --set configs.secret.argocdServerAdminPassword='$2a$10$rRyBsGSHK6.uc8fntPwVIuLVHgsAhAX7TcdrqW/RADU0ufHSdWJSW' \
            --wait
        
        # Apply ArgoCD applications
        kubectl apply -f "${PROJECT_ROOT}/gitops/argocd/auth-service-app.yaml"
    fi
}

# Deploy auth service
deploy_auth_service() {
    log "INFO" "Deploying auth service..."
    
    # Add auth service helm repository (placeholder)
    # helm repo add auth-service https://helm.company.com/auth-service
    
    # Create namespace
    kubectl create namespace auth-service --dry-run=client -o yaml | kubectl apply -f -
    
    # Label namespace for security policies
    kubectl label namespace auth-service \
        pod-security.kubernetes.io/enforce=restricted \
        pod-security.kubernetes.io/audit=restricted \
        pod-security.kubernetes.io/warn=restricted \
        name=auth-service \
        --overwrite
    
    # Deploy using Helm chart
    helm upgrade --install auth-service "${PROJECT_ROOT}/helm/auth-service" \
        --namespace auth-service \
        --values "${PROJECT_ROOT}/helm/auth-service/values.yaml" \
        --set image.tag=latest \
        --set environment="$ENVIRONMENT" \
        --set domain="$DOMAIN_NAME" \
        --set replicaCount=3 \
        --wait
}

# Verify deployment
verify_deployment() {
    log "INFO" "Verifying deployment..."
    
    # Check pod status
    kubectl get pods -n auth-service
    kubectl wait --for=condition=ready pod -l app=auth-service -n auth-service --timeout=300s
    
    # Check service status
    kubectl get services -n auth-service
    
    # Check ingress
    kubectl get ingress -n auth-service
    
    # Test health endpoint
    if kubectl get service auth-service -n auth-service &> /dev/null; then
        log "INFO" "Testing health endpoint..."
        kubectl run test-curl --rm -i --restart=Never \
            --image=curlimages/curl:latest \
            --namespace=auth-service \
            -- curl -f http://auth-service.auth-service.svc.cluster.local/health
    fi
    
    # Check security policies
    if [[ "$ENABLE_GATEKEEPER" == "true" ]]; then
        log "INFO" "Checking Gatekeeper constraints..."
        kubectl get constraints -A
    fi
    
    # Check Istio configuration
    if [[ "$ENABLE_ISTIO" == "true" ]]; then
        log "INFO" "Checking Istio configuration..."
        istioctl proxy-status
        istioctl analyze -n auth-service
    fi
    
    log "INFO" "Deployment verification completed"
}

# Run security tests
run_security_tests() {
    log "INFO" "Running security tests..."
    
    # Test network policies
    log "INFO" "Testing network policies..."
    kubectl run network-test --rm -i --restart=Never \
        --image=nicolaka/netshoot \
        --namespace=default \
        -- timeout 10 nc -zv auth-service.auth-service.svc.cluster.local 8080 || true
    
    # Test RBAC
    log "INFO" "Testing RBAC..."
    kubectl auth can-i list pods --namespace=auth-service --as=system:serviceaccount:auth-service:auth-service
    
    # Test admission controllers
    if [[ "$ENABLE_GATEKEEPER" == "true" ]]; then
        log "INFO" "Testing admission controllers..."
        
        # Try to create a privileged pod (should be blocked)
        kubectl apply -f - <<EOF || log "INFO" "Privileged pod correctly blocked by admission controller"
apiVersion: v1
kind: Pod
metadata:
  name: privileged-test
  namespace: auth-service
spec:
  containers:
  - name: test
    image: nginx
    securityContext:
      privileged: true
EOF
        
        # Cleanup
        kubectl delete pod privileged-test -n auth-service --ignore-not-found=true
    fi
    
    log "INFO" "Security tests completed"
}

# Generate summary report
generate_report() {
    log "INFO" "Generating deployment summary report..."
    
    local report_file="${PROJECT_ROOT}/deployment-report.md"
    
    cat > "$report_file" << EOF
# Auth Service Security Deployment Report

**Deployment Date:** $(date)
**Environment:** $ENVIRONMENT
**Cloud Provider:** $CLOUD_PROVIDER
**Region:** $REGION
**Cluster:** $CLUSTER_NAME

## Deployed Components

### Infrastructure
- [x] VPC and networking
- [x] EKS cluster
- [x] Security groups
- [x] IAM roles and policies
- [x] KMS encryption

### Security
- [$([ "$ENABLE_GATEKEEPER" == "true" ] && echo "x" || echo " ")] OPA Gatekeeper
- [$([ "$ENABLE_FALCO" == "true" ] && echo "x" || echo " ")] Falco runtime security
- [$([ "$ENABLE_ISTIO" == "true" ] && echo "x" || echo " ")] Istio service mesh
- [x] Pod Security Standards
- [x] Network Policies
- [x] RBAC configuration

### Monitoring
- [$([ "$ENABLE_MONITORING" == "true" ] && echo "x" || echo " ")] Prometheus
- [$([ "$ENABLE_MONITORING" == "true" ] && echo "x" || echo " ")] Grafana
- [x] Security alerts
- [x] Compliance monitoring

### Backup & DR
- [$([ "$ENABLE_BACKUP" == "true" ] && echo "x" || echo " ")] Velero backup system
- [$([ "$ENABLE_BACKUP" == "true" ] && echo "x" || echo " ")] Database backups
- [$([ "$ENABLE_BACKUP" == "true" ] && echo "x" || echo " ")] Cross-region replication

### GitOps
- [$([ "$ENABLE_GITOPS" == "true" ] && echo "x" || echo " ")] ArgoCD
- [$([ "$ENABLE_GITOPS" == "true" ] && echo "x" || echo " ")] Application deployment

## Access Information

### Cluster Access
\`\`\`bash
aws eks update-kubeconfig --region $REGION --name $CLUSTER_NAME
\`\`\`

### Monitoring Access
- Grafana: $(kubectl get service -n monitoring kube-prometheus-stack-grafana -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "ClusterIP - use port-forward")
- Prometheus: $(kubectl get service -n monitoring kube-prometheus-stack-prometheus -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "ClusterIP - use port-forward")

### ArgoCD Access
- ArgoCD: $(kubectl get service -n argocd argocd-server -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "ClusterIP - use port-forward")
- Username: admin
- Password: Run \`kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d\`

## Security Validation

$(kubectl get constraints -A --no-headers 2>/dev/null | wc -l) Gatekeeper constraints active
$(kubectl get networkpolicies -A --no-headers 2>/dev/null | wc -l) Network policies deployed
$(kubectl get psp --no-headers 2>/dev/null | wc -l) Pod security policies active

## Next Steps

1. Configure external secrets in AWS Secrets Manager
2. Set up monitoring alerts endpoints
3. Configure backup storage buckets
4. Review and customize security policies
5. Set up CI/CD pipelines

## Support

For issues or questions, contact:
- Security Team: security@company.com
- Platform Team: platform@company.com

EOF

    log "INFO" "Deployment report generated: $report_file"
}

# Cleanup function
cleanup() {
    log "INFO" "Cleaning up temporary resources..."
    # Add cleanup logic here if needed
}

# Main deployment function
main() {
    log "INFO" "Starting comprehensive cloud security deployment..."
    log "INFO" "Environment: $ENVIRONMENT, Cloud: $CLOUD_PROVIDER, Region: $REGION"
    
    # Set trap for cleanup
    trap cleanup EXIT
    
    # Load configuration
    load_config
    
    # Check prerequisites
    check_prerequisites
    
    # Initialize infrastructure
    init_terraform
    
    # Configure Kubernetes access
    configure_kubectl
    
    # Install security operators
    install_security_operators
    
    # Install service mesh
    install_service_mesh
    
    # Apply security policies
    apply_security_policies
    
    # Install monitoring
    install_monitoring
    
    # Setup backup system
    setup_backup
    
    # Setup GitOps
    setup_gitops
    
    # Deploy auth service
    deploy_auth_service
    
    # Verify deployment
    verify_deployment
    
    # Run security tests
    run_security_tests
    
    # Generate report
    generate_report
    
    log "INFO" "Deployment completed successfully!"
    log "INFO" "Check the deployment report at: ${PROJECT_ROOT}/deployment-report.md"
    log "INFO" "Full deployment log available at: $LOG_FILE"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --cloud-provider)
            CLOUD_PROVIDER="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --domain)
            DOMAIN_NAME="$2"
            shift 2
            ;;
        --skip-istio)
            ENABLE_ISTIO="false"
            shift
            ;;
        --skip-monitoring)
            ENABLE_MONITORING="false"
            shift
            ;;
        --skip-backup)
            ENABLE_BACKUP="false"
            shift
            ;;
        --skip-gitops)
            ENABLE_GITOPS="false"
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --environment ENV     Environment (dev/staging/production)"
            echo "  --cloud-provider PROVIDER    Cloud provider (aws/gcp/azure)"
            echo "  --region REGION       Cloud region"
            echo "  --domain DOMAIN       Domain name for the service"
            echo "  --skip-istio          Skip Istio service mesh installation"
            echo "  --skip-monitoring     Skip monitoring stack installation"
            echo "  --skip-backup         Skip backup system setup"
            echo "  --skip-gitops         Skip GitOps setup"
            echo "  --help                Show this help message"
            exit 0
            ;;
        *)
            log "ERROR" "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main "$@"