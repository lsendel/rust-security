#!/bin/bash
# Start the monitoring stack for Rust Security Platform
# This script starts Prometheus, Grafana, Alertmanager, and other monitoring services

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
MONITORING_DIR="${PROJECT_ROOT}/monitoring"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Starting Rust Security Platform Monitoring Stack${NC}"
echo "Monitoring directory: ${MONITORING_DIR}"

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running. Please start Docker first.${NC}"
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose >/dev/null 2>&1; then
    echo -e "${RED}❌ docker-compose is not installed.${NC}"
    exit 1
fi

# Navigate to monitoring directory
cd "${MONITORING_DIR}"

# Create necessary directories
echo -e "${YELLOW}📁 Creating monitoring directories...${NC}"
mkdir -p prometheus grafana/provisioning/datasources grafana/provisioning/dashboards

# Copy configuration files if they don't exist
if [ ! -f prometheus/prometheus.yml ]; then
    echo -e "${YELLOW}📋 Copying Prometheus configuration...${NC}"
    cp prometheus/prometheus.yml prometheus/ 2>/dev/null || true
fi

if [ ! -f grafana/provisioning/datasources/prometheus.yml ]; then
    echo -e "${YELLOW}📋 Copying Grafana datasource configuration...${NC}"
    cp grafana/provisioning/datasources/prometheus.yml grafana/provisioning/datasources/ 2>/dev/null || true
fi

if [ ! -f grafana/provisioning/dashboards/dashboard.yml ]; then
    echo -e "${YELLOW}📋 Copying Grafana dashboard provisioning...${NC}"
    cp grafana/provisioning/dashboards/dashboard.yml grafana/provisioning/dashboards/ 2>/dev/null || true
fi

# Start the monitoring stack
echo -e "${GREEN}🐳 Starting monitoring services with Docker Compose...${NC}"
docker-compose -f docker-compose.monitoring.yml up -d

# Wait for services to start
echo -e "${YELLOW}⏳ Waiting for services to start...${NC}"
sleep 10

# Check service health
echo -e "${BLUE}🔍 Checking service health...${NC}"

# Check Prometheus
if curl -s http://localhost:9090/-/healthy >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Prometheus is healthy${NC}"
else
    echo -e "${RED}❌ Prometheus is not responding${NC}"
fi

# Check Grafana
if curl -s http://localhost:3000/api/health >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Grafana is healthy${NC}"
else
    echo -e "${RED}❌ Grafana is not responding${NC}"
fi

# Check Alertmanager
if curl -s http://localhost:9093/-/healthy >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Alertmanager is healthy${NC}"
else
    echo -e "${RED}❌ Alertmanager is not responding${NC}"
fi

echo -e "${GREEN}🎉 Monitoring stack started successfully!${NC}"
echo ""
echo -e "${BLUE}📊 Access your monitoring services:${NC}"
echo -e "  • ${GREEN}Grafana:${NC} http://localhost:3000 (admin/admin)"
echo -e "  • ${GREEN}Prometheus:${NC} http://localhost:9090"
echo -e "  • ${GREEN}Alertmanager:${NC} http://localhost:9093"
echo ""
echo -e "${YELLOW}📈 Available dashboards:${NC}"
echo -e "  • Rust Security Platform - Production Monitoring"
echo ""
echo -e "${BLUE}🔧 To stop the monitoring stack:${NC}"
echo -e "  cd ${MONITORING_DIR} && docker-compose -f docker-compose.monitoring.yml down"
echo ""
echo -e "${BLUE}📋 To view logs:${NC}"
echo -e "  cd ${MONITORING_DIR} && docker-compose -f docker-compose.monitoring.yml logs -f [service-name]"
echo ""
echo -e "${GREEN}✅ Monitoring setup complete!${NC}"
