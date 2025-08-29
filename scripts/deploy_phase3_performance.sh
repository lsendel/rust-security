#!/bin/bash

# Phase 3: Performance Tuning Deployment Script
# Deploys memory optimization, CPU profiling, and database optimization

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
PHASE="phase3"

echo -e "${BLUE}⚡ Phase 3: Performance Tuning Deployment${NC}"
echo "============================================"
echo "Namespace: $NAMESPACE"
echo "Phase: $PHASE"
echo ""

# Function to check Phase 2 prerequisites
check_phase2_prerequisites() {
    echo -e "${YELLOW}Checking Phase 2 prerequisites...${NC}"
    
    # Check if Phase 2 services are running
    if ! kubectl get pods -n $NAMESPACE | grep -q "auth-service-phase2.*Running"; then
        echo -e "${RED}✗ Phase 2 auth service not running. Please complete Phase 2 first.${NC}"
        exit 1
    fi
    
    if ! kubectl get pods -n $NAMESPACE | grep -q "policy-service-phase2.*Running"; then
        echo -e "${RED}✗ Phase 2 policy service not running. Please complete Phase 2 first.${NC}"
        exit 1
    fi
    
    # Check if Redis enhanced is running
    if ! kubectl get pods -n redis-system | grep -q "redis-enhanced.*Running"; then
        echo -e "${RED}✗ Enhanced Redis not running. Please complete Phase 2 first.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Phase 2 prerequisites verified${NC}"
}

# Function to deploy performance monitoring tools
deploy_performance_monitoring() {
    echo -e "${YELLOW}Deploying performance monitoring tools...${NC}"
    
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: performance-profiler
  namespace: $NAMESPACE
  labels:
    app: performance-profiler
    version: phase3
spec:
  replicas: 1
  selector:
    matchLabels:
      app: performance-profiler
      version: phase3
  template:
    metadata:
      labels:
        app: performance-profiler
        version: phase3
      annotations:
        sidecar.istio.io/inject: "true"
    spec:
      containers:
      - name: profiler
        image: prom/node-exporter:latest
        ports:
        - containerPort: 9100
          name: metrics
        args:
        - --path.procfs=/host/proc
        - --path.sysfs=/host/sys
        - --collector.filesystem.ignored-mount-points
        - "^/(sys|proc|dev|host|etc|rootfs/var/lib/docker/containers|rootfs/var/lib/docker/overlay2|rootfs/run/docker/netns|rootfs/var/lib/docker/aufs)($$|/)"
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
        - name: rootfs
          mountPath: /rootfs
          readOnly: true
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "200m"
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
      - name: rootfs
        hostPath:
          path: /
      hostNetwork: true
      hostPID: true
---
apiVersion: v1
kind: Service
metadata:
  name: performance-profiler
  namespace: $NAMESPACE
  labels:
    app: performance-profiler
spec:
  ports:
  - port: 9100
    targetPort: 9100
    name: metrics
  selector:
    app: performance-profiler
EOF

    echo -e "${GREEN}✓ Performance monitoring tools deployed${NC}"
}

# Function to update services with Phase 3 optimizations
update_services_phase3() {
    echo -e "${YELLOW}Updating services with Phase 3 optimizations...${NC}"
    
    # Update auth service with memory and CPU optimizations
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service-phase3
  namespace: $NAMESPACE
  labels:
    app: auth-service
    version: phase3
spec:
  replicas: 6  # Increased for Phase 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 2
      maxUnavailable: 1
  selector:
    matchLabels:
      app: auth-service
      version: phase3
  template:
    metadata:
      labels:
        app: auth-service
        version: phase3
      annotations:
        sidecar.istio.io/inject: "true"
        sidecar.istio.io/proxyCPU: "50m"
        sidecar.istio.io/proxyMemory: "64Mi"
    spec:
      containers:
      - name: auth-service
        image: auth-service:phase3-1.0.0
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 9090
          name: metrics
        env:
        - name: PHASE
          value: "3"
        - name: RUST_LOG
          value: "info,auth_service=debug"
        - name: MEMORY_PROFILING_ENABLED
          value: "true"
        - name: CPU_PROFILING_ENABLED
          value: "true"
        - name: CUSTOM_ALLOCATOR
          value: "optimized"
        - name: THREAD_POOL_SIZE
          value: "8"
        - name: MEMORY_POOL_ENABLED
          value: "true"
        - name: SIMD_OPTIMIZATION
          value: "true"
        - name: ZERO_COPY_BUFFERS
          value: "true"
        - name: LOCK_FREE_CACHE_SIZE
          value: "20000"
        - name: DATABASE_CONNECTION_POOL_SIZE
          value: "75"  # Increased for Phase 3
        - name: DATABASE_PREPARED_STATEMENTS
          value: "true"
        - name: DATABASE_QUERY_CACHE_SIZE
          value: "5000"
        - name: REDIS_URL
          value: "redis://redis-enhanced.redis-system.svc.cluster.local:6379"
        - name: POLICY_SERVICE_URL
          value: "http://policy-service-phase3.rust-security.svc.cluster.local:8081"
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: jwt-secret
        resources:
          requests:
            memory: "256Mi"  # Optimized with custom allocator
            cpu: "300m"      # Increased for CPU optimization
          limits:
            memory: "512Mi"
            cpu: "1500m"     # Higher limit for burst performance
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10  # Faster startup with optimizations
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 3   # Very fast readiness
          periodSeconds: 5
        startupProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 2
          periodSeconds: 1
          failureThreshold: 30
---
apiVersion: v1
kind: Service
metadata:
  name: auth-service-phase3
  namespace: $NAMESPACE
  labels:
    app: auth-service
    version: phase3
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
    version: phase3
EOF

    # Update policy service with database optimizations
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: policy-service-phase3
  namespace: $NAMESPACE
  labels:
    app: policy-service
    version: phase3
spec:
  replicas: 4  # Increased for Phase 3
  selector:
    matchLabels:
      app: policy-service
      version: phase3
  template:
    metadata:
      labels:
        app: policy-service
        version: phase3
      annotations:
        sidecar.istio.io/inject: "true"
    spec:
      containers:
      - name: policy-service
        image: policy-service:phase3-1.0.0
        ports:
        - containerPort: 8081
          name: http
        - containerPort: 9091
          name: metrics
        env:
        - name: PHASE
          value: "3"
        - name: RUST_LOG
          value: "info,policy_service=debug"
        - name: DATABASE_OPTIMIZATION_ENABLED
          value: "true"
        - name: QUERY_OPTIMIZER_ENABLED
          value: "true"
        - name: BATCH_QUERY_PROCESSING
          value: "true"
        - name: READ_REPLICA_ENABLED
          value: "true"
        - name: CONNECTION_POOL_SIZE
          value: "50"
        - name: PREPARED_STATEMENTS_CACHE_SIZE
          value: "1000"
        - name: QUERY_CACHE_SIZE
          value: "10000"
        - name: BATCH_SIZE
          value: "200"  # Larger batches for Phase 3
        - name: CEDAR_CACHE_SIZE
          value: "50000"  # Increased cache
        - name: REDIS_URL
          value: "redis://redis-enhanced.redis-system.svc.cluster.local:6379"
        resources:
          requests:
            memory: "384Mi"  # Increased for database optimizations
            cpu: "200m"
          limits:
            memory: "768Mi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 8
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8081
          initialDelaySeconds: 3
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: policy-service-phase3
  namespace: $NAMESPACE
  labels:
    app: policy-service
    version: phase3
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
    version: phase3
EOF

    echo -e "${GREEN}✓ Services updated with Phase 3 optimizations${NC}"
}

# Function to configure Phase 3 traffic routing
configure_phase3_traffic() {
    echo -e "${YELLOW}Configuring Phase 3 traffic routing...${NC}"
    
    cat <<EOF | kubectl apply -f -
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: auth-service-phase3-routing
  namespace: $NAMESPACE
spec:
  hosts:
  - auth-service
  http:
  - match:
    - headers:
        x-phase:
          exact: "3"
    route:
    - destination:
        host: auth-service-phase3
        port:
          number: 8080
      weight: 100
    timeout: 2s  # Aggressive timeout for Phase 3
    retries:
      attempts: 2
      perTryTimeout: 1s
  - route:
    - destination:
        host: auth-service-phase3
        port:
          number: 8080
      weight: 80  # Gradual rollout to Phase 3
    - destination:
        host: auth-service-phase2
        port:
          number: 8080
      weight: 20
    timeout: 5s
---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: policy-service-phase3-routing
  namespace: $NAMESPACE
spec:
  hosts:
  - policy-service
  http:
  - match:
    - headers:
        x-phase:
          exact: "3"
    route:
    - destination:
        host: policy-service-phase3
        port:
          number: 8081
      weight: 100
  - route:
    - destination:
        host: policy-service-phase3
        port:
          number: 8081
      weight: 100
    timeout: 2s  # Very aggressive for Phase 3
    retries:
      attempts: 1
      perTryTimeout: 1s
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: auth-service-phase3-dr
  namespace: $NAMESPACE
spec:
  host: auth-service-phase3
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 200  # Increased for Phase 3
        connectTimeout: 1s   # Very aggressive
      http:
        http1MaxPendingRequests: 200
        http2MaxRequests: 2000
        maxRequestsPerConnection: 20
        h2UpgradePolicy: UPGRADE
        idleTimeout: 30s
        keepAliveTimeout: 60s
    loadBalancer:
      consistentHash:
        httpHeaderName: "user-id"
    outlierDetection:
      consecutiveGatewayErrors: 1  # Very sensitive
      interval: 5s
      baseEjectionTime: 10s
      maxEjectionPercent: 30
EOF

    echo -e "${GREEN}✓ Phase 3 traffic routing configured${NC}"
}

# Function to deploy advanced monitoring
deploy_advanced_monitoring() {
    echo -e "${YELLOW}Deploying advanced Phase 3 monitoring...${NC}"
    
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: phase3-grafana-dashboard
  namespace: istio-system
  labels:
    grafana_dashboard: "1"
data:
  phase3-dashboard.json: |
    {
      "dashboard": {
        "title": "Phase 3 Performance Tuning",
        "panels": [
          {
            "title": "Memory Optimization",
            "type": "graph",
            "targets": [
              {
                "expr": "memory_usage_bytes",
                "legendFormat": "Memory Usage"
              },
              {
                "expr": "memory_pool_hit_rate",
                "legendFormat": "Pool Hit Rate"
              }
            ]
          },
          {
            "title": "CPU Optimization",
            "type": "graph",
            "targets": [
              {
                "expr": "cpu_function_duration_seconds",
                "legendFormat": "Function Duration"
              },
              {
                "expr": "cpu_hotspot_score",
                "legendFormat": "Hotspot Score"
              }
            ]
          },
          {
            "title": "Database Performance",
            "type": "graph",
            "targets": [
              {
                "expr": "db_query_duration_seconds",
                "legendFormat": "Query Duration"
              },
              {
                "expr": "db_query_cache_hits_total / (db_query_cache_hits_total + db_query_cache_misses_total)",
                "legendFormat": "Cache Hit Rate"
              }
            ]
          },
          {
            "title": "SIMD Efficiency",
            "type": "stat",
            "targets": [
              {
                "expr": "simd_efficiency_ratio",
                "legendFormat": "SIMD Efficiency"
              }
            ]
          }
        ]
      }
    }
EOF

    echo -e "${GREEN}✓ Advanced monitoring deployed${NC}"
}

# Function to run Phase 3 validation
run_phase3_validation() {
    echo -e "${YELLOW}Running Phase 3 validation...${NC}"
    
    # Wait for services to be ready
    echo "Waiting for Phase 3 services to be ready..."
    kubectl wait --for=condition=Ready pods -l app=auth-service,version=phase3 -n $NAMESPACE --timeout=300s
    kubectl wait --for=condition=Ready pods -l app=policy-service,version=phase3 -n $NAMESPACE --timeout=300s
    
    # Test memory optimization
    echo "Testing memory optimization..."
    local auth_pod=$(kubectl get pods -n $NAMESPACE -l app=auth-service,version=phase3 -o jsonpath='{.items[0].metadata.name}')
    
    if kubectl exec -n $NAMESPACE $auth_pod -- curl -s http://localhost:9090/metrics | grep -q "memory_usage_bytes"; then
        echo -e "${GREEN}✓ Memory optimization metrics available${NC}"
    else
        echo -e "${YELLOW}⚠ Memory optimization metrics not yet available${NC}"
    fi
    
    # Test CPU profiling
    echo "Testing CPU profiling..."
    if kubectl exec -n $NAMESPACE $auth_pod -- curl -s http://localhost:9090/metrics | grep -q "cpu_function_calls_total"; then
        echo -e "${GREEN}✓ CPU profiling metrics available${NC}"
    else
        echo -e "${YELLOW}⚠ CPU profiling metrics not yet available${NC}"
    fi
    
    # Test database optimization
    echo "Testing database optimization..."
    local policy_pod=$(kubectl get pods -n $NAMESPACE -l app=policy-service,version=phase3 -o jsonpath='{.items[0].metadata.name}')
    
    if kubectl exec -n $NAMESPACE $policy_pod -- curl -s http://localhost:9091/metrics | grep -q "db_queries_total"; then
        echo -e "${GREEN}✓ Database optimization metrics available${NC}"
    else
        echo -e "${YELLOW}⚠ Database optimization metrics not yet available${NC}"
    fi
    
    echo -e "${GREEN}✓ Phase 3 validation completed${NC}"
}

# Function to display Phase 3 status
display_phase3_status() {
    echo -e "${PURPLE}⚡ Phase 3 Performance Tuning Status${NC}"
    echo "===================================="
    
    echo ""
    echo "🚀 Services Status:"
    kubectl get pods -n $NAMESPACE -l version=phase3
    
    echo ""
    echo "📊 Performance Monitoring:"
    kubectl get pods -n $NAMESPACE -l app=performance-profiler
    
    echo ""
    echo "🎯 Phase 3 Performance Targets:"
    echo "   Auth Latency P95: < 2ms (improved from 3ms Phase 2 target)"
    echo "   Policy Eval P95: < 3ms (improved from 5ms Phase 2 target)"
    echo "   Throughput: > 5000 RPS (improved from 3000 RPS Phase 2 target)"
    echo "   Memory Efficiency: 256MB/pod (33% reduction from Phase 2)"
    echo "   CPU Efficiency: 150m baseline (25% reduction from Phase 2)"
    echo "   Cache Intelligence: >90% hit rate (improved from 80%)"
    
    echo ""
    echo "📈 Key Optimizations:"
    echo "   • Custom memory allocators with pooling"
    echo "   • CPU profiling and hotspot elimination"
    echo "   • Database query optimization and caching"
    echo "   • SIMD operations for data processing"
    echo "   • Lock-free data structures"
    echo "   • Zero-copy buffer operations"
    
    echo ""
    echo "🔍 Monitoring Commands:"
    echo "   Memory stats: kubectl exec -n $NAMESPACE <auth-pod> -- curl http://localhost:9090/metrics | grep memory"
    echo "   CPU stats: kubectl exec -n $NAMESPACE <auth-pod> -- curl http://localhost:9090/metrics | grep cpu"
    echo "   DB stats: kubectl exec -n $NAMESPACE <policy-pod> -- curl http://localhost:9091/metrics | grep db"
    echo "   SIMD stats: kubectl exec -n $NAMESPACE <auth-pod> -- curl http://localhost:9090/metrics | grep simd"
}

# Main execution function
main() {
    echo -e "${BLUE}Starting Phase 3: Performance Tuning Deployment...${NC}"
    echo ""
    
    # Execute deployment steps
    check_phase2_prerequisites
    deploy_performance_monitoring
    update_services_phase3
    configure_phase3_traffic
    deploy_advanced_monitoring
    run_phase3_validation
    
    echo ""
    echo -e "${GREEN}✅ Phase 3 Deployment Complete!${NC}"
    echo ""
    
    # Display status
    display_phase3_status
    
    echo ""
    echo -e "${PURPLE}🎉 Phase 3 Performance Tuning Deployed Successfully!${NC}"
    echo ""
    echo "Expected Performance Improvements:"
    echo "• 33% faster authentication (3ms → 2ms P95)"
    echo "• 40% faster policy evaluation (5ms → 3ms P95)"
    echo "• 67% higher throughput (3000 → 5000+ RPS)"
    echo "• 33% memory reduction through custom allocators"
    echo "• 25% CPU efficiency improvement"
    echo "• >90% cache hit rates with intelligent optimization"
    echo ""
    echo "Next Steps:"
    echo "1. Monitor performance: ./test_phase3_performance.sh"
    echo "2. Analyze memory usage: kubectl exec <pod> -- curl /metrics | grep memory"
    echo "3. Review CPU hotspots: kubectl exec <pod> -- curl /metrics | grep cpu"
    echo "4. Validate database optimization: kubectl exec <pod> -- curl /metrics | grep db"
    echo "5. Proceed to Phase 4: Production Validation when ready"
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "validate")
        run_phase3_validation
        ;;
    "status")
        display_phase3_status
        ;;
    "cleanup")
        echo -e "${YELLOW}Cleaning up Phase 3 deployment...${NC}"
        kubectl delete deployment auth-service-phase3 -n $NAMESPACE || true
        kubectl delete deployment policy-service-phase3 -n $NAMESPACE || true
        kubectl delete deployment performance-profiler -n $NAMESPACE || true
        kubectl delete virtualservice auth-service-phase3-routing -n $NAMESPACE || true
        kubectl delete virtualservice policy-service-phase3-routing -n $NAMESPACE || true
        kubectl delete destinationrule auth-service-phase3-dr -n $NAMESPACE || true
        echo -e "${GREEN}✓ Phase 3 cleanup complete${NC}"
        ;;
    *)
        echo "Usage: $0 [deploy|validate|status|cleanup]"
        echo "  deploy   - Deploy Phase 3 optimizations (default)"
        echo "  validate - Validate Phase 3 deployment"
        echo "  status   - Show Phase 3 status"
        echo "  cleanup  - Remove Phase 3 deployment"
        exit 1
        ;;
esac
