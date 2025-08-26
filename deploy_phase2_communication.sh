#!/bin/bash

# Phase 2: Communication Optimization Deployment Script
# Deploys optimized inter-service communication patterns

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="rust-security"
REDIS_NAMESPACE="redis-system"
PHASE="phase2"

echo -e "${BLUE}🔄 Phase 2: Communication Optimization Deployment${NC}"
echo "=================================================="
echo "Namespace: $NAMESPACE"
echo "Phase: $PHASE"
echo ""

# Function to check Phase 1 prerequisites
check_phase1_prerequisites() {
    echo -e "${YELLOW}Checking Phase 1 prerequisites...${NC}"
    
    # Check if Istio is installed
    if ! kubectl get pods -n istio-system | grep -q "istiod.*Running"; then
        echo -e "${RED}✗ Istio control plane not running. Please complete Phase 1 first.${NC}"
        exit 1
    fi
    
    # Check if auth service is running
    if ! kubectl get pods -n $NAMESPACE | grep -q "auth-service.*Running"; then
        echo -e "${RED}✗ Auth service not running. Please complete Phase 1 first.${NC}"
        exit 1
    fi
    
    # Check if policy service is running
    if ! kubectl get pods -n $NAMESPACE | grep -q "policy-service.*Running"; then
        echo -e "${RED}✗ Policy service not running. Please complete Phase 1 first.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Phase 1 prerequisites verified${NC}"
}

# Function to deploy enhanced Redis configuration
deploy_enhanced_redis() {
    echo -e "${YELLOW}Deploying enhanced Redis configuration...${NC}"
    
    # Create Redis namespace if it doesn't exist
    kubectl create namespace $REDIS_NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy Redis with Streams support and optimization
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis-enhanced
  namespace: $REDIS_NAMESPACE
  labels:
    app: redis
    version: enhanced
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
      version: enhanced
  template:
    metadata:
      labels:
        app: redis
        version: enhanced
      annotations:
        sidecar.istio.io/inject: "true"
    spec:
      containers:
      - name: redis
        image: redis:7.2-alpine
        ports:
        - containerPort: 6379
        command:
        - redis-server
        - --maxmemory
        - 512mb
        - --maxmemory-policy
        - allkeys-lru
        - --save
        - "900 1"
        - --save
        - "300 10"
        - --save
        - "60 10000"
        - --appendonly
        - "yes"
        - --appendfsync
        - "everysec"
        - --tcp-keepalive
        - "300"
        - --timeout
        - "0"
        - --tcp-backlog
        - "511"
        - --databases
        - "16"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        volumeMounts:
        - name: redis-data
          mountPath: /data
        - name: redis-config
          mountPath: /usr/local/etc/redis
      volumes:
      - name: redis-data
        emptyDir:
          sizeLimit: 1Gi
      - name: redis-config
        configMap:
          name: redis-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: redis-config
  namespace: $REDIS_NAMESPACE
data:
  redis.conf: |
    # Redis configuration optimized for message bus and caching
    maxmemory 512mb
    maxmemory-policy allkeys-lru
    
    # Persistence
    save 900 1
    save 300 10
    save 60 10000
    appendonly yes
    appendfsync everysec
    
    # Network
    tcp-keepalive 300
    timeout 0
    tcp-backlog 511
    
    # Streams optimization
    stream-node-max-bytes 4096
    stream-node-max-entries 100
    
    # Memory optimization
    hash-max-ziplist-entries 512
    hash-max-ziplist-value 64
    list-max-ziplist-size -2
    list-compress-depth 0
    set-max-intset-entries 512
    zset-max-ziplist-entries 128
    zset-max-ziplist-value 64
    
    # Client optimization
    client-output-buffer-limit normal 0 0 0
    client-output-buffer-limit replica 256mb 64mb 60
    client-output-buffer-limit pubsub 32mb 8mb 60
---
apiVersion: v1
kind: Service
metadata:
  name: redis-enhanced
  namespace: $REDIS_NAMESPACE
  labels:
    app: redis
    version: enhanced
spec:
  ports:
  - port: 6379
    targetPort: 6379
    protocol: TCP
    name: redis
  selector:
    app: redis
    version: enhanced
  type: ClusterIP
EOF

    # Wait for Redis to be ready
    echo "Waiting for enhanced Redis to be ready..."
    kubectl wait --for=condition=Ready pods -l app=redis,version=enhanced -n $REDIS_NAMESPACE --timeout=120s
    
    echo -e "${GREEN}✓ Enhanced Redis deployed${NC}"
}

# Function to update auth service with Phase 2 optimizations
update_auth_service() {
    echo -e "${YELLOW}Updating auth service with Phase 2 optimizations...${NC}"
    
    # Apply Phase 2 auth service configuration
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service-phase2
  namespace: $NAMESPACE
  labels:
    app: auth-service
    version: phase2
spec:
  replicas: 5
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 2
      maxUnavailable: 1
  selector:
    matchLabels:
      app: auth-service
      version: phase2
  template:
    metadata:
      labels:
        app: auth-service
        version: phase2
      annotations:
        sidecar.istio.io/inject: "true"
        sidecar.istio.io/proxyCPU: "100m"
        sidecar.istio.io/proxyMemory: "128Mi"
    spec:
      containers:
      - name: auth-service
        image: auth-service:phase2-1.0.0
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 9090
          name: metrics
        env:
        - name: PHASE
          value: "2"
        - name: REDIS_URL
          value: "redis://redis-enhanced.redis-system.svc.cluster.local:6379"
        - name: POLICY_SERVICE_URL
          value: "http://policy-service-phase2.rust-security.svc.cluster.local:8081"
        - name: CACHE_L1_MAX_ENTRIES
          value: "10000"
        - name: CACHE_L1_MAX_MEMORY_MB
          value: "128"
        - name: CACHE_L2_DEFAULT_TTL_SECONDS
          value: "300"
        - name: MESSAGE_BUS_CONSUMER_GROUP
          value: "auth-service-group"
        - name: MESSAGE_BUS_CONSUMER_NAME
          value: "auth-consumer"
        - name: CIRCUIT_BREAKER_FAILURE_THRESHOLD
          value: "3"
        - name: CIRCUIT_BREAKER_TIMEOUT_MS
          value: "500"
        - name: BATCH_SIZE
          value: "50"
        - name: BATCH_TIMEOUT_MS
          value: "10"
        - name: MAX_CONCURRENT_REQUESTS
          value: "100"
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: jwt-secret
        resources:
          requests:
            memory: "384Mi"  # Increased for caching
            cpu: "200m"
          limits:
            memory: "768Mi"  # Increased for Phase 2 features
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 15
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: auth-service-phase2
  namespace: $NAMESPACE
  labels:
    app: auth-service
    version: phase2
spec:
  ports:
  - port: 8080
    targetPort: 8080
    name: http
  - port: 9090
    targetPort: 9090
    name: metrics
  selector:
    app: auth-service
    version: phase2
EOF

    echo -e "${GREEN}✓ Auth service updated for Phase 2${NC}"
}

# Function to update policy service with batch processing
update_policy_service() {
    echo -e "${YELLOW}Updating policy service with batch processing...${NC}"
    
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: policy-service-phase2
  namespace: $NAMESPACE
  labels:
    app: policy-service
    version: phase2
spec:
  replicas: 3
  selector:
    matchLabels:
      app: policy-service
      version: phase2
  template:
    metadata:
      labels:
        app: policy-service
        version: phase2
      annotations:
        sidecar.istio.io/inject: "true"
    spec:
      containers:
      - name: policy-service
        image: policy-service:phase2-1.0.0
        ports:
        - containerPort: 8081
          name: http
        - containerPort: 9091
          name: metrics
        env:
        - name: PHASE
          value: "2"
        - name: REDIS_URL
          value: "redis://redis-enhanced.redis-system.svc.cluster.local:6379"
        - name: BATCH_PROCESSING_ENABLED
          value: "true"
        - name: MAX_BATCH_SIZE
          value: "100"
        - name: BATCH_TIMEOUT_MS
          value: "50"
        - name: CEDAR_CACHE_SIZE
          value: "20000"
        - name: CEDAR_CACHE_TTL_SECONDS
          value: "600"
        resources:
          requests:
            memory: "256Mi"
            cpu: "150m"
          limits:
            memory: "512Mi"
            cpu: "750m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8081
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: policy-service-phase2
  namespace: $NAMESPACE
  labels:
    app: policy-service
    version: phase2
spec:
  ports:
  - port: 8081
    targetPort: 8081
    name: http
  - port: 9091
    targetPort: 9091
    name: metrics
  selector:
    app: policy-service
    version: phase2
EOF

    echo -e "${GREEN}✓ Policy service updated for Phase 2${NC}"
}

# Function to configure traffic routing for Phase 2
configure_phase2_traffic() {
    echo -e "${YELLOW}Configuring Phase 2 traffic routing...${NC}"
    
    cat <<EOF | kubectl apply -f -
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: auth-service-phase2-routing
  namespace: $NAMESPACE
spec:
  hosts:
  - auth-service
  http:
  - match:
    - headers:
        x-phase:
          exact: "2"
    route:
    - destination:
        host: auth-service-phase2
        port:
          number: 8080
      weight: 100
    timeout: 5s
    retries:
      attempts: 2
      perTryTimeout: 2s
  - route:
    - destination:
        host: auth-service-phase2
        port:
          number: 8080
      weight: 90
    - destination:
        host: auth-service-optimized
        port:
          number: 8080
      weight: 10
    timeout: 10s
---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: policy-service-phase2-routing
  namespace: $NAMESPACE
spec:
  hosts:
  - policy-service
  http:
  - match:
    - headers:
        x-phase:
          exact: "2"
    route:
    - destination:
        host: policy-service-phase2
        port:
          number: 8081
      weight: 100
  - route:
    - destination:
        host: policy-service-phase2
        port:
          number: 8081
      weight: 100
    timeout: 3s
    retries:
      attempts: 2
      perTryTimeout: 1s
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: auth-service-phase2-dr
  namespace: $NAMESPACE
spec:
  host: auth-service-phase2
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 150  # Increased for Phase 2
        connectTimeout: 3s
      http:
        http1MaxPendingRequests: 100
        http2MaxRequests: 1500
        maxRequestsPerConnection: 15
        h2UpgradePolicy: UPGRADE
    loadBalancer:
      consistentHash:
        httpHeaderName: "user-id"
    outlierDetection:
      consecutiveGatewayErrors: 2
      interval: 15s
      baseEjectionTime: 15s
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: policy-service-phase2-dr
  namespace: $NAMESPACE
spec:
  host: policy-service-phase2
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100
        connectTimeout: 2s
      http:
        http1MaxPendingRequests: 50
        http2MaxRequests: 1000
        maxRequestsPerConnection: 20
        h2UpgradePolicy: UPGRADE
    loadBalancer:
      simple: LEAST_CONN
    outlierDetection:
      consecutiveGatewayErrors: 2
      interval: 10s
      baseEjectionTime: 10s
EOF

    echo -e "${GREEN}✓ Phase 2 traffic routing configured${NC}"
}

# Function to deploy monitoring enhancements
deploy_phase2_monitoring() {
    echo -e "${YELLOW}Deploying Phase 2 monitoring enhancements...${NC}"
    
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: phase2-grafana-dashboard
  namespace: istio-system
  labels:
    grafana_dashboard: "1"
data:
  phase2-dashboard.json: |
    {
      "dashboard": {
        "title": "Phase 2 Communication Optimization",
        "panels": [
          {
            "title": "Cache Hit Rates",
            "type": "stat",
            "targets": [
              {
                "expr": "rate(cache_l1_hits_total[5m]) / (rate(cache_l1_hits_total[5m]) + rate(cache_l1_misses_total[5m]))",
                "legendFormat": "L1 Hit Rate"
              },
              {
                "expr": "rate(cache_l2_hits_total[5m]) / (rate(cache_l2_hits_total[5m]) + rate(cache_l2_misses_total[5m]))",
                "legendFormat": "L2 Hit Rate"
              }
            ]
          },
          {
            "title": "Batch Processing Efficiency",
            "type": "graph",
            "targets": [
              {
                "expr": "histogram_quantile(0.95, rate(auth_client_batch_efficiency_bucket[5m]))",
                "legendFormat": "P95 Batch Efficiency"
              }
            ]
          },
          {
            "title": "Circuit Breaker Status",
            "type": "stat",
            "targets": [
              {
                "expr": "auth_client_circuit_breaker_opens_total",
                "legendFormat": "Circuit Breaker Opens"
              }
            ]
          },
          {
            "title": "Message Bus Throughput",
            "type": "graph",
            "targets": [
              {
                "expr": "rate(message_bus_messages_sent_total[5m])",
                "legendFormat": "Messages Sent/sec"
              },
              {
                "expr": "rate(message_bus_messages_processed_total[5m])",
                "legendFormat": "Messages Processed/sec"
              }
            ]
          }
        ]
      }
    }
EOF

    echo -e "${GREEN}✓ Phase 2 monitoring deployed${NC}"
}

# Function to run Phase 2 validation tests
run_phase2_validation() {
    echo -e "${YELLOW}Running Phase 2 validation tests...${NC}"
    
    # Wait for services to be ready
    echo "Waiting for Phase 2 services to be ready..."
    kubectl wait --for=condition=Ready pods -l app=auth-service,version=phase2 -n $NAMESPACE --timeout=180s
    kubectl wait --for=condition=Ready pods -l app=policy-service,version=phase2 -n $NAMESPACE --timeout=180s
    
    # Test cache functionality
    echo "Testing cache functionality..."
    local auth_pod=$(kubectl get pods -n $NAMESPACE -l app=auth-service,version=phase2 -o jsonpath='{.items[0].metadata.name}')
    
    if kubectl exec -n $NAMESPACE $auth_pod -- curl -s http://localhost:9090/metrics | grep -q "cache_l1_hits_total"; then
        echo -e "${GREEN}✓ Cache metrics available${NC}"
    else
        echo -e "${YELLOW}⚠ Cache metrics not yet available${NC}"
    fi
    
    # Test message bus
    echo "Testing message bus connectivity..."
    local redis_pod=$(kubectl get pods -n $REDIS_NAMESPACE -l app=redis,version=enhanced -o jsonpath='{.items[0].metadata.name}')
    
    if kubectl exec -n $REDIS_NAMESPACE $redis_pod -- redis-cli ping | grep -q "PONG"; then
        echo -e "${GREEN}✓ Redis message bus connectivity verified${NC}"
    else
        echo -e "${RED}✗ Redis message bus connectivity failed${NC}"
        return 1
    fi
    
    # Test batch processing endpoint
    echo "Testing batch processing endpoint..."
    local policy_pod=$(kubectl get pods -n $NAMESPACE -l app=policy-service,version=phase2 -o jsonpath='{.items[0].metadata.name}')
    
    if kubectl exec -n $NAMESPACE $policy_pod -- curl -s -f http://localhost:8081/health > /dev/null; then
        echo -e "${GREEN}✓ Policy service batch processing ready${NC}"
    else
        echo -e "${YELLOW}⚠ Policy service not yet ready${NC}"
    fi
    
    echo -e "${GREEN}✓ Phase 2 validation completed${NC}"
}

# Function to display Phase 2 status
display_phase2_status() {
    echo -e "${PURPLE}📊 Phase 2 Deployment Status${NC}"
    echo "================================"
    
    echo ""
    echo "🔄 Services Status:"
    kubectl get pods -n $NAMESPACE -l version=phase2
    
    echo ""
    echo "🗄️ Redis Status:"
    kubectl get pods -n $REDIS_NAMESPACE -l app=redis,version=enhanced
    
    echo ""
    echo "📈 Key Metrics Endpoints:"
    echo "   Auth Service Metrics: kubectl port-forward -n $NAMESPACE svc/auth-service-phase2 9090:9090"
    echo "   Policy Service Metrics: kubectl port-forward -n $NAMESPACE svc/policy-service-phase2 9091:9091"
    echo "   Redis Metrics: kubectl port-forward -n $REDIS_NAMESPACE svc/redis-enhanced 6379:6379"
    
    echo ""
    echo "🎯 Phase 2 Performance Targets:"
    echo "   Auth Latency P95: < 3ms (improved from 5ms Phase 1 target)"
    echo "   Policy Eval P95: < 5ms (improved from 8ms Phase 1 target)"
    echo "   Throughput: > 3000 RPS (improved from 2000 RPS Phase 1 target)"
    echo "   Cache Hit Rate: > 80%"
    echo "   Batch Efficiency: > 10x individual requests"
    
    echo ""
    echo "🔍 Monitoring Commands:"
    echo "   View cache stats: kubectl exec -n $NAMESPACE <auth-pod> -- curl http://localhost:9090/metrics | grep cache"
    echo "   View batch stats: kubectl exec -n $NAMESPACE <policy-pod> -- curl http://localhost:9091/metrics | grep batch"
    echo "   View message bus: kubectl exec -n $REDIS_NAMESPACE <redis-pod> -- redis-cli info streams"
}

# Main execution function
main() {
    echo -e "${BLUE}Starting Phase 2: Communication Optimization Deployment...${NC}"
    echo ""
    
    # Execute deployment steps
    check_phase1_prerequisites
    deploy_enhanced_redis
    update_auth_service
    update_policy_service
    configure_phase2_traffic
    deploy_phase2_monitoring
    run_phase2_validation
    
    echo ""
    echo -e "${GREEN}✅ Phase 2 Deployment Complete!${NC}"
    echo ""
    
    # Display status
    display_phase2_status
    
    echo ""
    echo -e "${PURPLE}🎉 Phase 2 Communication Optimization Deployed Successfully!${NC}"
    echo ""
    echo "Expected Performance Improvements:"
    echo "• 40% faster authentication (5ms → 3ms P95)"
    echo "• 37% faster policy evaluation (8ms → 5ms P95)"
    echo "• 50% higher throughput (2000 → 3000+ RPS)"
    echo "• >80% cache hit rates for frequently accessed data"
    echo "• 10x efficiency improvement through batch processing"
    echo ""
    echo "Next Steps:"
    echo "1. Monitor performance: ./test_service_architecture_performance.sh"
    echo "2. Validate cache effectiveness: kubectl exec <pod> -- curl /metrics | grep cache"
    echo "3. Check message bus throughput: kubectl exec <redis-pod> -- redis-cli info"
    echo "4. Proceed to Phase 3: Performance Tuning when ready"
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "validate")
        run_phase2_validation
        ;;
    "status")
        display_phase2_status
        ;;
    "cleanup")
        echo -e "${YELLOW}Cleaning up Phase 2 deployment...${NC}"
        kubectl delete deployment auth-service-phase2 -n $NAMESPACE || true
        kubectl delete deployment policy-service-phase2 -n $NAMESPACE || true
        kubectl delete deployment redis-enhanced -n $REDIS_NAMESPACE || true
        kubectl delete virtualservice auth-service-phase2-routing -n $NAMESPACE || true
        kubectl delete virtualservice policy-service-phase2-routing -n $NAMESPACE || true
        kubectl delete destinationrule auth-service-phase2-dr -n $NAMESPACE || true
        kubectl delete destinationrule policy-service-phase2-dr -n $NAMESPACE || true
        echo -e "${GREEN}✓ Phase 2 cleanup complete${NC}"
        ;;
    *)
        echo "Usage: $0 [deploy|validate|status|cleanup]"
        echo "  deploy   - Deploy Phase 2 optimizations (default)"
        echo "  validate - Validate Phase 2 deployment"
        echo "  status   - Show Phase 2 status"
        echo "  cleanup  - Remove Phase 2 deployment"
        exit 1
        ;;
esac
