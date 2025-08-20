# External Secrets Setup Guide

This guide explains how to configure External Secrets Operator for secure secret management in the Rust Security Platform.

## Overview

The External Secrets Operator (ESO) enables the platform to retrieve secrets from external secret stores like HashiCorp Vault, AWS Secrets Manager, or Google Secret Manager, instead of storing them as static Kubernetes secrets.

## Prerequisites

1. Kubernetes cluster with External Secrets Operator installed
2. Access to one of the supported secret stores:
   - HashiCorp Vault
   - AWS Secrets Manager  
   - Google Secret Manager
   - Azure Key Vault

## Installation

### 1. Install External Secrets Operator

```bash
# Using Helm (recommended)
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  -n external-secrets-system \
  --create-namespace

# Or using kubectl
kubectl apply -f k8s/external-secrets-operator.yaml
```

### 2. Choose Your Secret Backend

Select one of the following backends based on your infrastructure:

#### Option A: HashiCorp Vault

1. **Set up Vault authentication:**
   ```bash
   # Create Vault token secret
   kubectl create secret generic vault-token \
     --from-literal=token="YOUR_VAULT_TOKEN" \
     -n rust-security
   ```

2. **Configure Vault CA certificate (if using TLS):**
   ```bash
   kubectl create configmap vault-ca-cert \
     --from-file=ca.crt=vault-ca.crt \
     -n rust-security
   ```

3. **Deploy Vault External Secrets:**
   ```bash
   kubectl apply -f k8s/vault-external-secrets.yaml
   ```

4. **Store secrets in Vault:**
   ```bash
   # JWT signing secret
   vault kv put secret/auth-service/jwt secret="$(openssl rand -base64 32)"
   
   # Client credentials
   vault kv put secret/auth-service/clients credentials="client1:$(openssl rand -base64 16);client2:$(openssl rand -base64 16)"
   
   # Request signing secret
   vault kv put secret/auth-service/signing secret="$(openssl rand -base64 32)"
   
   # Google OAuth secret
   vault kv put secret/auth-service/oauth/google client_secret="YOUR_GOOGLE_CLIENT_SECRET"
   
   # Redis password
   vault kv put secret/auth-service/redis password="$(openssl rand -base64 16)"
   ```

#### Option B: AWS Secrets Manager

1. **Set up IAM Role (recommended):**
   ```bash
   # Create IAM role with necessary permissions
   aws iam create-role --role-name rust-security-secrets-role \
     --assume-role-policy-document file://aws-trust-policy.json
   
   # Attach policy for Secrets Manager access
   aws iam attach-role-policy \
     --role-name rust-security-secrets-role \
     --policy-arn arn:aws:iam::aws:policy/SecretsManagerReadWrite
   ```

2. **Configure IRSA (IAM Roles for Service Accounts):**
   ```bash
   # Associate IAM role with Kubernetes service account
   kubectl annotate serviceaccount auth-service-aws-sa \
     eks.amazonaws.com/role-arn=arn:aws:iam::ACCOUNT_ID:role/rust-security-secrets-role \
     -n rust-security
   ```

3. **Deploy AWS External Secrets:**
   ```bash
   kubectl apply -f k8s/aws-external-secrets.yaml
   ```

4. **Store secrets in AWS Secrets Manager:**
   ```bash
   # JWT signing secret
   aws secretsmanager create-secret \
     --name "rust-security/auth-service/jwt-secret" \
     --secret-string '{"secret":"'$(openssl rand -base64 32)'"}'
   
   # Client credentials
   aws secretsmanager create-secret \
     --name "rust-security/auth-service/client-credentials" \
     --secret-string '{"credentials":"client1:'$(openssl rand -base64 16)';client2:'$(openssl rand -base64 16)'"}'
   
   # Request signing secret
   aws secretsmanager create-secret \
     --name "rust-security/auth-service/request-signing-secret" \
     --secret-string '{"secret":"'$(openssl rand -base64 32)'"}'
   
   # Google OAuth secret
   aws secretsmanager create-secret \
     --name "rust-security/auth-service/google-oauth" \
     --secret-string '{"client_secret":"YOUR_GOOGLE_CLIENT_SECRET"}'
   
   # Redis password
   aws secretsmanager create-secret \
     --name "rust-security/redis/password" \
     --secret-string '{"password":"'$(openssl rand -base64 16)'"}'
   ```

#### Option C: Google Secret Manager

1. **Set up Workload Identity:**
   ```bash
   # Create Google Service Account
   gcloud iam service-accounts create rust-security-secrets \
     --description="Service account for accessing secrets" \
     --display-name="Rust Security Secrets"
   
   # Grant Secret Manager access
   gcloud projects add-iam-policy-binding PROJECT_ID \
     --member="serviceAccount:rust-security-secrets@PROJECT_ID.iam.gserviceaccount.com" \
     --role="roles/secretmanager.secretAccessor"
   
   # Enable Workload Identity
   gcloud iam service-accounts add-iam-policy-binding \
     rust-security-secrets@PROJECT_ID.iam.gserviceaccount.com \
     --role roles/iam.workloadIdentityUser \
     --member "serviceAccount:PROJECT_ID.svc.id.goog[rust-security/auth-service-gcp-sa]"
   ```

2. **Deploy GCP External Secrets:**
   ```bash
   kubectl apply -f k8s/gcp-external-secrets.yaml
   ```

3. **Store secrets in Google Secret Manager:**
   ```bash
   # JWT signing secret
   echo -n "$(openssl rand -base64 32)" | gcloud secrets create rust-security-auth-service-jwt-secret --data-file=-
   
   # Client credentials
   echo -n "client1:$(openssl rand -base64 16);client2:$(openssl rand -base64 16)" | \
     gcloud secrets create rust-security-auth-service-client-credentials --data-file=-
   
   # Request signing secret
   echo -n "$(openssl rand -base64 32)" | gcloud secrets create rust-security-auth-service-request-signing-secret --data-file=-
   
   # Google OAuth secret
   echo -n "YOUR_GOOGLE_CLIENT_SECRET" | gcloud secrets create rust-security-auth-service-google-client-secret --data-file=-
   
   # Redis password
   echo -n "$(openssl rand -base64 16)" | gcloud secrets create rust-security-redis-password --data-file=-
   ```

## Helm Configuration

### Enable External Secrets in Helm Values

Update your `values.yaml` or provide override values:

```yaml
# Enable External Secrets
externalSecrets:
  enabled: true
  refreshInterval: "15m"
  
  # For Vault
  provider:
    type: vault
    vault:
      server: "https://vault.example.com"
      path: "secret"
      auth:
        tokenSecretRef:
          name: "vault-token"
          key: "token"

# Disable static secrets in production
secrets:
  jwtSecret: ""  # Will be ignored when externalSecrets.enabled = true
```

### Deploy with External Secrets

```bash
# Deploy with External Secrets enabled
helm upgrade --install auth-service ./helm/auth-service \
  --namespace rust-security \
  --create-namespace \
  --set externalSecrets.enabled=true \
  --set externalSecrets.provider.type=vault \
  --set externalSecrets.provider.vault.server=https://vault.example.com
```

## Verification

### Check External Secret Status

```bash
# Check ExternalSecret resource
kubectl get externalsecret -n rust-security

# Check secret creation
kubectl get secret auth-service-secret -n rust-security

# View secret data (base64 encoded)
kubectl get secret auth-service-secret -n rust-security -o yaml
```

### Verify Secret Refresh

```bash
# Check refresh status
kubectl describe externalsecret auth-service-external-secret -n rust-security

# Force refresh (if needed)
kubectl annotate externalsecret auth-service-external-secret \
  force-sync=$(date +%s) -n rust-security
```

## Security Best Practices

### 1. Least Privilege Access

- Grant minimal necessary permissions to service accounts
- Use scoped access policies in your secret store
- Regularly audit access permissions

### 2. Secret Rotation

- Implement regular secret rotation policies
- Use External Secrets refresh intervals appropriately
- Monitor secret access and refresh events

### 3. Network Security

- Use TLS for all secret store communications
- Implement network policies to restrict access
- Consider using private endpoints for cloud secret stores

### 4. Monitoring and Alerting

- Monitor External Secret synchronization status
- Alert on failed secret retrievals
- Log secret access events for audit trails

## Troubleshooting

### Common Issues

1. **Secret not found in external store:**
   ```bash
   # Check secret path and permissions
   kubectl logs deployment/external-secrets -n external-secrets-system
   ```

2. **Authentication failures:**
   ```bash
   # Verify service account annotations and permissions
   kubectl describe externalsecret auth-service-external-secret -n rust-security
   ```

3. **TLS certificate issues:**
   ```bash
   # Check CA certificate configuration
   kubectl get configmap vault-ca-cert -n rust-security -o yaml
   ```

### Debug Commands

```bash
# Check External Secrets Operator logs
kubectl logs -l app.kubernetes.io/name=external-secrets -n external-secrets-system

# Check ExternalSecret events
kubectl get events --field-selector involvedObject.name=auth-service-external-secret -n rust-security

# Test secret access manually
kubectl run debug --image=busybox -i --tty --rm -- /bin/sh
# Then inside the pod:
# cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## Migration from Static Secrets

### Step-by-Step Migration

1. **Prepare external secret store with current secret values**
2. **Deploy External Secrets configuration with `enabled: false`**
3. **Test External Secrets in a development environment**
4. **Enable External Secrets in production:**
   ```bash
   helm upgrade auth-service ./helm/auth-service \
     --set externalSecrets.enabled=true \
     --reuse-values
   ```
5. **Verify application continues to function correctly**
6. **Remove static secret references from values.yaml**

### Rollback Plan

If issues occur, quickly rollback:

```bash
# Disable External Secrets and use static secrets
helm upgrade auth-service ./helm/auth-service \
  --set externalSecrets.enabled=false \
  --reuse-values
```

## Advanced Configuration

### Using ClusterSecretStore

For cluster-wide secret management:

```yaml
externalSecrets:
  secretStore:
    name: "cluster-secret-store"
    kind: "ClusterSecretStore"
  createSecretStore: false  # ClusterSecretStore is managed separately
```

### Custom Secret Templates

Add custom metadata or transform secret data:

```yaml
externalSecrets:
  annotations:
    custom.io/source: "vault"
    custom.io/owner: "security-team"
```

### Multiple Secret Sources

Configure different secrets from different sources by creating multiple ExternalSecret resources.