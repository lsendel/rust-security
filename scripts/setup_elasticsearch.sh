#!/bin/bash

# Script to set up Elasticsearch for the Rust Security Workspace
# This script configures index templates, ILM policies, and initial indices

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MONITORING_DIR="$PROJECT_ROOT/monitoring"
ELASTICSEARCH_DIR="$MONITORING_DIR/elasticsearch"
FLUENTD_DIR="$MONITORING_DIR/fluentd"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ELASTICSEARCH_HOST="${ELASTICSEARCH_HOST:-localhost}"
ELASTICSEARCH_PORT="${ELASTICSEARCH_PORT:-9200}"
ELASTICSEARCH_SCHEME="${ELASTICSEARCH_SCHEME:-http}"
ELASTICSEARCH_USER="${ELASTICSEARCH_USER:-}"
ELASTICSEARCH_PASSWORD="${ELASTICSEARCH_PASSWORD:-}"

# Construct base URL
if [ -n "$ELASTICSEARCH_USER" ] && [ -n "$ELASTICSEARCH_PASSWORD" ]; then
    ES_URL="${ELASTICSEARCH_SCHEME}://${ELASTICSEARCH_USER}:${ELASTICSEARCH_PASSWORD}@${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}"
else
    ES_URL="${ELASTICSEARCH_SCHEME}://${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}"
fi

echo -e "${BLUE}🔍 Setting up Elasticsearch for Rust Security Workspace${NC}"
echo "=========================================================="
echo -e "📍 Elasticsearch URL: ${ES_URL%:*}:***@${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}"

# Function to check if Elasticsearch is available
check_elasticsearch() {
    echo -e "\n${YELLOW}🔍 Checking Elasticsearch connectivity${NC}"
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -f "${ES_URL}/_cluster/health" >/dev/null 2>&1; then
            echo -e "${GREEN}✅ Elasticsearch is available${NC}"
            return 0
        else
            echo -e "${YELLOW}⏳ Waiting for Elasticsearch... (attempt $attempt/$max_attempts)${NC}"
            sleep 10
            ((attempt++))
        fi
    done
    
    echo -e "${RED}❌ Failed to connect to Elasticsearch after $max_attempts attempts${NC}"
    return 1
}

# Function to get Elasticsearch version
get_elasticsearch_version() {
    local version=$(curl -s "${ES_URL}/" | jq -r '.version.number' 2>/dev/null || echo "unknown")
    echo -e "${BLUE}📋 Elasticsearch version: $version${NC}"
}

# Function to create ILM policies
create_ilm_policies() {
    echo -e "\n${YELLOW}📜 Creating Index Lifecycle Management policies${NC}"
    
    if [ ! -f "$ELASTICSEARCH_DIR/ilm-policies.json" ]; then
        echo -e "${RED}❌ ILM policies file not found: $ELASTICSEARCH_DIR/ilm-policies.json${NC}"
        return 1
    fi
    
    # Parse and create each policy
    local policies=(
        "security-audit-policy"
        "application-logs-policy"
        "system-logs-policy"
    )
    
    for policy_name in "${policies[@]}"; do
        echo -e "  Creating ILM policy: $policy_name"
        
        local policy_json=$(jq -r ".\"$policy_name\"" "$ELASTICSEARCH_DIR/ilm-policies.json")
        
        if curl -s -X PUT "${ES_URL}/_ilm/policy/${policy_name}" \
           -H "Content-Type: application/json" \
           -d "$policy_json" | jq -r '.acknowledged' | grep -q "true"; then
            echo -e "  ${GREEN}✅ Created ILM policy: $policy_name${NC}"
        else
            echo -e "  ${RED}❌ Failed to create ILM policy: $policy_name${NC}"
            return 1
        fi
    done
}

# Function to create index templates
create_index_templates() {
    echo -e "\n${YELLOW}📝 Creating index templates${NC}"
    
    # Security audit template
    if [ -f "$FLUENTD_DIR/templates/security_audit_template.json" ]; then
        echo -e "  Creating security audit template"
        if curl -s -X PUT "${ES_URL}/_index_template/security-audit-template" \
           -H "Content-Type: application/json" \
           -d @"$FLUENTD_DIR/templates/security_audit_template.json" | jq -r '.acknowledged' | grep -q "true"; then
            echo -e "  ${GREEN}✅ Created security audit template${NC}"
        else
            echo -e "  ${RED}❌ Failed to create security audit template${NC}"
            return 1
        fi
    fi
    
    # Application logs template
    cat > /tmp/application_logs_template.json << 'EOF'
{
  "index_patterns": ["application-logs-*"],
  "settings": {
    "index": {
      "number_of_shards": 2,
      "number_of_replicas": 1,
      "refresh_interval": "30s",
      "lifecycle": {
        "name": "application-logs-policy"
      }
    }
  },
  "mappings": {
    "properties": {
      "timestamp": {
        "type": "date",
        "format": "strict_date_optional_time||epoch_millis"
      },
      "level": {
        "type": "keyword"
      },
      "message": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "service_name": {
        "type": "keyword"
      },
      "log_type": {
        "type": "keyword"
      },
      "environment": {
        "type": "keyword"
      },
      "cluster": {
        "type": "keyword"
      },
      "namespace": {
        "type": "keyword"
      }
    }
  }
}
EOF
    
    echo -e "  Creating application logs template"
    if curl -s -X PUT "${ES_URL}/_index_template/application-logs-template" \
       -H "Content-Type: application/json" \
       -d @/tmp/application_logs_template.json | jq -r '.acknowledged' | grep -q "true"; then
        echo -e "  ${GREEN}✅ Created application logs template${NC}"
    else
        echo -e "  ${RED}❌ Failed to create application logs template${NC}"
        return 1
    fi
    
    # System logs template
    cat > /tmp/system_logs_template.json << 'EOF'
{
  "index_patterns": ["system-logs-*"],
  "settings": {
    "index": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "refresh_interval": "60s",
      "lifecycle": {
        "name": "system-logs-policy"
      }
    }
  },
  "mappings": {
    "properties": {
      "timestamp": {
        "type": "date",
        "format": "strict_date_optional_time||epoch_millis"
      },
      "hostname": {
        "type": "keyword"
      },
      "unit": {
        "type": "keyword"
      },
      "message": {
        "type": "text"
      },
      "environment": {
        "type": "keyword"
      }
    }
  }
}
EOF
    
    echo -e "  Creating system logs template"
    if curl -s -X PUT "${ES_URL}/_index_template/system-logs-template" \
       -H "Content-Type: application/json" \
       -d @/tmp/system_logs_template.json | jq -r '.acknowledged' | grep -q "true"; then
        echo -e "  ${GREEN}✅ Created system logs template${NC}"
    else
        echo -e "  ${RED}❌ Failed to create system logs template${NC}"
        return 1
    fi
    
    # Clean up temporary files
    rm -f /tmp/application_logs_template.json /tmp/system_logs_template.json
}

# Function to create initial indices
create_initial_indices() {
    echo -e "\n${YELLOW}🏗️  Creating initial indices${NC}"
    
    local today=$(date +%Y.%m.%d)
    local indices=(
        "security-audit-${today}"
        "application-logs-${today}"
        "system-logs-${today}"
    )
    
    for index in "${indices[@]}"; do
        echo -e "  Creating index: $index"
        if curl -s -X PUT "${ES_URL}/${index}" \
           -H "Content-Type: application/json" \
           -d '{}' | jq -r '.acknowledged' | grep -q "true"; then
            echo -e "  ${GREEN}✅ Created index: $index${NC}"
        else
            echo -e "  ${YELLOW}⚠️  Index may already exist: $index${NC}"
        fi
    done
}

# Function to create index aliases
create_index_aliases() {
    echo -e "\n${YELLOW}🔗 Creating index aliases${NC}"
    
    local today=$(date +%Y.%m.%d)
    
    # Security audit alias
    if curl -s -X POST "${ES_URL}/_aliases" \
       -H "Content-Type: application/json" \
       -d "{
         \"actions\": [
           {
             \"add\": {
               \"index\": \"security-audit-${today}\",
               \"alias\": \"security-audit\"
             }
           }
         ]
       }" | jq -r '.acknowledged' | grep -q "true"; then
        echo -e "  ${GREEN}✅ Created security-audit alias${NC}"
    else
        echo -e "  ${RED}❌ Failed to create security-audit alias${NC}"
    fi
    
    # Application logs alias
    if curl -s -X POST "${ES_URL}/_aliases" \
       -H "Content-Type: application/json" \
       -d "{
         \"actions\": [
           {
             \"add\": {
               \"index\": \"application-logs-${today}\",
               \"alias\": \"application-logs\"
             }
           }
         ]
       }" | jq -r '.acknowledged' | grep -q "true"; then
        echo -e "  ${GREEN}✅ Created application-logs alias${NC}"
    else
        echo -e "  ${RED}❌ Failed to create application-logs alias${NC}"
    fi
}

# Function to configure cluster settings
configure_cluster_settings() {
    echo -e "\n${YELLOW}⚙️  Configuring cluster settings${NC}"
    
    local settings='{
      "persistent": {
        "cluster.routing.allocation.disk.watermark.low": "85%",
        "cluster.routing.allocation.disk.watermark.high": "90%",
        "cluster.routing.allocation.disk.watermark.flood_stage": "95%",
        "indices.lifecycle.poll_interval": "10m"
      }
    }'
    
    if curl -s -X PUT "${ES_URL}/_cluster/settings" \
       -H "Content-Type: application/json" \
       -d "$settings" | jq -r '.acknowledged' | grep -q "true"; then
        echo -e "  ${GREEN}✅ Updated cluster settings${NC}"
    else
        echo -e "  ${RED}❌ Failed to update cluster settings${NC}"
    fi
}

# Function to validate setup
validate_setup() {
    echo -e "\n${YELLOW}🔍 Validating Elasticsearch setup${NC}"
    
    # Check cluster health
    local health=$(curl -s "${ES_URL}/_cluster/health" | jq -r '.status')
    echo -e "  Cluster health: $health"
    
    if [ "$health" = "green" ] || [ "$health" = "yellow" ]; then
        echo -e "  ${GREEN}✅ Cluster health is acceptable${NC}"
    else
        echo -e "  ${RED}❌ Cluster health is poor: $health${NC}"
    fi
    
    # Check ILM policies
    local policies=$(curl -s "${ES_URL}/_ilm/policy" | jq -r 'keys[]' | wc -l)
    echo -e "  ILM policies configured: $policies"
    
    # Check index templates
    local templates=$(curl -s "${ES_URL}/_index_template" | jq -r '.index_templates | length')
    echo -e "  Index templates configured: $templates"
    
    # Check indices
    local indices=$(curl -s "${ES_URL}/_cat/indices?format=json" | jq -r '. | length')
    echo -e "  Indices created: $indices"
}

# Function to create monitoring dashboards configuration
create_monitoring_config() {
    echo -e "\n${YELLOW}📊 Creating monitoring configuration${NC}"
    
    cat > "$ELASTICSEARCH_DIR/monitoring-config.json" << 'EOF'
{
  "monitoring": {
    "cluster_stats_interval": "10s",
    "index_stats_interval": "10s",
    "collection_enabled": true,
    "exporters": {
      "prometheus": {
        "type": "http",
        "host": ["http://prometheus:9090"],
        "bulk.timeout": "10s"
      }
    }
  }
}
EOF
    
    echo -e "  ${GREEN}✅ Created monitoring configuration${NC}"
}

# Function to provide usage instructions
provide_usage_instructions() {
    echo -e "\n${BLUE}💡 Usage Instructions${NC}"
    echo "============================="
    
    echo -e "\n${YELLOW}1. Search Security Events:${NC}"
    echo "   curl '${ES_URL}/security-audit/_search?q=severity:critical'"
    
    echo -e "\n${YELLOW}2. View Application Logs:${NC}"
    echo "   curl '${ES_URL}/application-logs/_search?q=service_name:auth-service'"
    
    echo -e "\n${YELLOW}3. Check Index Health:${NC}"
    echo "   curl '${ES_URL}/_cat/indices?v'"
    
    echo -e "\n${YELLOW}4. Monitor ILM Policies:${NC}"
    echo "   curl '${ES_URL}/_ilm/explain/security-audit-*'"
    
    echo -e "\n${YELLOW}5. View Cluster Stats:${NC}"
    echo "   curl '${ES_URL}/_cluster/stats?pretty'"
    
    echo -e "\n${YELLOW}6. Configure Kibana (if available):${NC}"
    echo "   - Index Patterns: security-audit-*, application-logs-*, system-logs-*"
    echo "   - Time field: timestamp"
}

# Main function
main() {
    local exit_code=0
    
    echo -e "📍 Project root: $PROJECT_ROOT"
    echo -e "📍 Monitoring directory: $MONITORING_DIR"
    
    # Check dependencies
    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}❌ curl is required but not installed${NC}"
        exit 1
    fi
    
    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${RED}❌ jq is required but not installed${NC}"
        exit 1
    fi
    
    # Create directories if they don't exist
    mkdir -p "$ELASTICSEARCH_DIR"
    mkdir -p "$FLUENTD_DIR/templates"
    
    # Run setup steps
    check_elasticsearch || exit_code=1
    if [ $exit_code -eq 0 ]; then
        get_elasticsearch_version
        create_ilm_policies || exit_code=1
        create_index_templates || exit_code=1
        create_initial_indices
        create_index_aliases
        configure_cluster_settings
        create_monitoring_config
        validate_setup
        provide_usage_instructions
    fi
    
    echo -e "\n=========================================================="
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}🎉 Elasticsearch setup completed successfully!${NC}"
        echo -e "${GREEN}✅ Security workspace logging infrastructure is ready${NC}"
    else
        echo -e "${RED}❌ Elasticsearch setup failed${NC}"
        echo -e "${YELLOW}📝 Please check the errors above and retry${NC}"
    fi
    
    return $exit_code
}

# Handle command line arguments
case "${1:-setup}" in
    "setup")
        main
        ;;
    "validate")
        check_elasticsearch && validate_setup
        ;;
    "help")
        echo "Usage: $0 [setup|validate|help]"
        echo "  setup    - Run full Elasticsearch setup (default)"
        echo "  validate - Only validate existing setup"
        echo "  help     - Show this help message"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac