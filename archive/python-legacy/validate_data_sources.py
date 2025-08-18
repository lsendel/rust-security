#!/usr/bin/env python3
"""
Data Source Connection Validator for Compliance Reporting
Validates connectivity and data availability from various sources
"""

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
import yaml
import requests
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_config(config_path):
    """Load configuration file"""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return None

def validate_prometheus_connection(config):
    """Validate Prometheus connection and data availability"""
    logger.info("🔍 Validating Prometheus connection...")
    
    prometheus_config = config.get('prometheus', {})
    base_url = prometheus_config.get('url', 'http://localhost:9090')
    
    results = {
        'service': 'Prometheus',
        'url': base_url,
        'status': 'unknown',
        'details': [],
        'metrics_available': 0
    }
    
    try:
        # Test basic connectivity
        health_url = f"{base_url}/api/v1/query"
        params = {'query': 'up'}
        
        response = requests.get(health_url, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                results['status'] = 'connected'
                results['details'].append("✅ Successfully connected to Prometheus")
                
                # Count available metrics
                result_data = data.get('data', {}).get('result', [])
                results['metrics_available'] = len(result_data)
                results['details'].append(f"📊 {results['metrics_available']} metrics available")
                
                # Test specific security-related queries
                security_queries = [
                    'prometheus_build_info',
                    'http_requests_total',
                    'up{job="auth-service"}',
                ]
                
                available_queries = 0
                for query in security_queries:
                    try:
                        test_response = requests.get(health_url, params={'query': query}, timeout=5)
                        if test_response.status_code == 200:
                            test_data = test_response.json()
                            if test_data.get('status') == 'success' and test_data.get('data', {}).get('result'):
                                available_queries += 1
                    except:
                        pass
                
                results['details'].append(f"🎯 {available_queries}/{len(security_queries)} security queries responsive")
                
            else:
                results['status'] = 'error'
                results['details'].append(f"❌ Prometheus query failed: {data}")
        else:
            results['status'] = 'error'
            results['details'].append(f"❌ HTTP {response.status_code}: {response.text}")
            
    except requests.ConnectionError:
        results['status'] = 'disconnected'
        results['details'].append("❌ Connection refused - Prometheus not running or not accessible")
    except requests.Timeout:
        results['status'] = 'timeout'
        results['details'].append("❌ Connection timeout - Prometheus not responding")
    except Exception as e:
        results['status'] = 'error'
        results['details'].append(f"❌ Unexpected error: {e}")
    
    return results

def validate_elasticsearch_connection(config):
    """Validate Elasticsearch connection and indices"""
    logger.info("🔍 Validating Elasticsearch connection...")
    
    es_config = config.get('elasticsearch', {})
    base_url = es_config.get('url', 'http://localhost:9200')
    username = es_config.get('username')
    password = es_config.get('password')
    
    results = {
        'service': 'Elasticsearch',
        'url': base_url,
        'status': 'unknown',
        'details': [],
        'indices_available': 0
    }
    
    auth = (username, password) if username and password else None
    
    try:
        # Test cluster health
        health_response = requests.get(f"{base_url}/_cluster/health", auth=auth, timeout=10)
        
        if health_response.status_code == 200:
            health_data = health_response.json()
            cluster_status = health_data.get('status', 'unknown')
            
            if cluster_status in ['green', 'yellow']:
                results['status'] = 'connected'
                results['details'].append(f"✅ Cluster health: {cluster_status}")
                
                # Check indices
                indices_response = requests.get(f"{base_url}/_cat/indices?format=json", auth=auth, timeout=10)
                if indices_response.status_code == 200:
                    indices = indices_response.json()
                    results['indices_available'] = len(indices)
                    results['details'].append(f"📊 {results['indices_available']} indices available")
                    
                    # Look for security-related indices
                    security_indices = [idx for idx in indices if any(pattern in idx.get('index', '') 
                                      for pattern in ['security', 'audit', 'auth', 'log'])]
                    results['details'].append(f"🔒 {len(security_indices)} security-related indices found")
                    
                    # Check specific indices from config
                    expected_indices = es_config.get('indices', {})
                    for index_type, pattern in expected_indices.items():
                        matching_indices = [idx for idx in indices if pattern.replace('*', '') in idx.get('index', '')]
                        if matching_indices:
                            results['details'].append(f"✅ {index_type} indices found: {len(matching_indices)}")
                        else:
                            results['details'].append(f"⚠️  No {index_type} indices found (pattern: {pattern})")
                
            else:
                results['status'] = 'unhealthy'
                results['details'].append(f"⚠️  Cluster status: {cluster_status}")
        else:
            results['status'] = 'error'
            results['details'].append(f"❌ HTTP {health_response.status_code}: {health_response.text}")
            
    except requests.ConnectionError:
        results['status'] = 'disconnected'
        results['details'].append("❌ Connection refused - Elasticsearch not running or not accessible")
    except requests.Timeout:
        results['status'] = 'timeout'
        results['details'].append("❌ Connection timeout - Elasticsearch not responding")
    except Exception as e:
        results['status'] = 'error'
        results['details'].append(f"❌ Unexpected error: {e}")
    
    return results

def validate_file_sources(config):
    """Validate file system data sources"""
    logger.info("🔍 Validating file system data sources...")
    
    results = {
        'service': 'File System',
        'status': 'unknown',
        'details': [],
        'sources_available': 0
    }
    
    # Check configuration directories
    directories_to_check = [
        'config',
        'reports/compliance',
        'evidence/compliance', 
        'monitoring/prometheus',
        'monitoring/alertmanager',
        'monitoring/fluentd',
        'monitoring/elasticsearch',
        'auth-service/src',
        'scripts'
    ]
    
    available_dirs = 0
    for directory in directories_to_check:
        if Path(directory).exists():
            available_dirs += 1
            file_count = len(list(Path(directory).rglob('*'))) if Path(directory).is_dir() else 0
            results['details'].append(f"✅ {directory}: {file_count} files")
        else:
            results['details'].append(f"❌ {directory}: not found")
    
    results['sources_available'] = available_dirs
    
    # Check specific configuration files
    config_files = [
        'config/compliance_config.yaml',
        'monitoring/prometheus/security-alerts.yml',
        'monitoring/alertmanager/alertmanager.yml',
        'monitoring/fluentd/fluent.conf',
        'monitoring/elasticsearch/ilm-policies.json'
    ]
    
    available_configs = 0
    for config_file in config_files:
        if Path(config_file).exists():
            available_configs += 1
            file_size = Path(config_file).stat().st_size
            results['details'].append(f"✅ {config_file}: {file_size} bytes")
        else:
            results['details'].append(f"❌ {config_file}: not found")
    
    # Determine overall status
    total_expected = len(directories_to_check) + len(config_files)
    total_available = available_dirs + available_configs
    
    if total_available >= total_expected * 0.8:  # 80% threshold
        results['status'] = 'available'
    elif total_available >= total_expected * 0.5:  # 50% threshold
        results['status'] = 'partial'
    else:
        results['status'] = 'insufficient'
    
    results['details'].append(f"📁 {total_available}/{total_expected} expected files/directories available")
    
    return results

def validate_security_data_sources(config):
    """Validate security-specific data sources"""
    logger.info("🔍 Validating security data sources...")
    
    results = {
        'service': 'Security Data',
        'status': 'unknown',
        'details': [],
        'sources_available': 0
    }
    
    # Check security modules
    security_modules = [
        'auth-service/src/security_logging.rs',
        'auth-service/src/security.rs',
        'auth-service/src/keys.rs',
        'auth-service/src/mfa.rs',
        'auth-service/src/circuit_breaker.rs',
        'auth-service/src/scim.rs'
    ]
    
    available_modules = 0
    for module in security_modules:
        if Path(module).exists():
            available_modules += 1
            results['details'].append(f"✅ {module}")
        else:
            results['details'].append(f"❌ {module}: not found")
    
    # Check security tests
    security_tests = list(Path('.').glob('**/tests/*security*.rs'))
    results['details'].append(f"🧪 {len(security_tests)} security test files found")
    
    # Check monitoring configurations
    monitoring_configs = [
        'monitoring/prometheus/security-alerts.yml',
        'monitoring/alertmanager/alertmanager.yml'
    ]
    
    available_monitoring = 0
    for config_file in monitoring_configs:
        if Path(config_file).exists():
            available_monitoring += 1
            # Check if file has content
            content_size = Path(config_file).stat().st_size
            if content_size > 100:  # Minimum reasonable size
                results['details'].append(f"✅ {config_file}: {content_size} bytes")
            else:
                results['details'].append(f"⚠️  {config_file}: too small ({content_size} bytes)")
        else:
            results['details'].append(f"❌ {config_file}: not found")
    
    total_sources = len(security_modules) + len(monitoring_configs)
    total_available = available_modules + available_monitoring
    results['sources_available'] = total_available
    
    if total_available >= total_sources * 0.8:
        results['status'] = 'comprehensive'
    elif total_available >= total_sources * 0.6:
        results['status'] = 'adequate'
    else:
        results['status'] = 'insufficient'
    
    results['details'].append(f"🔒 {total_available}/{total_sources} security data sources available")
    
    return results

def generate_validation_report(validation_results, output_dir):
    """Generate validation report"""
    
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    report = {
        'metadata': {
            'validation_timestamp': datetime.now().isoformat(),
            'validator_version': '1.0.0'
        },
        'summary': {
            'total_sources': len(validation_results),
            'connected_sources': len([r for r in validation_results if r['status'] in ['connected', 'available', 'comprehensive']]),
            'failed_sources': len([r for r in validation_results if r['status'] in ['disconnected', 'error', 'insufficient']]),
            'overall_status': 'unknown'
        },
        'detailed_results': validation_results
    }
    
    # Determine overall status
    connected = report['summary']['connected_sources'] 
    total = report['summary']['total_sources']
    
    if connected == total:
        report['summary']['overall_status'] = 'all_connected'
    elif connected >= total * 0.75:
        report['summary']['overall_status'] = 'mostly_connected'
    elif connected >= total * 0.5:
        report['summary']['overall_status'] = 'partially_connected'
    else:
        report['summary']['overall_status'] = 'poorly_connected'
    
    # Save report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = Path(output_dir) / f"data_source_validation_{timestamp}.json"
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report_file, report

def main():
    """Main validation function"""
    config_path = "config/compliance_config.yaml"
    output_dir = "reports/compliance"
    
    print("🔗 Data Source Connection Validator")
    print("===================================")
    
    # Load configuration
    config = load_config(config_path)
    if not config:
        print("❌ Failed to load configuration")
        return 1
    
    print("✅ Configuration loaded successfully\n")
    
    # Run validations
    validation_results = []
    
    # Validate each data source
    validators = [
        validate_prometheus_connection,
        validate_elasticsearch_connection,
        validate_file_sources,
        validate_security_data_sources
    ]
    
    for validator in validators:
        try:
            result = validator(config)
            validation_results.append(result)
            
            # Print results
            status_emoji = {
                'connected': '✅',
                'available': '✅', 
                'comprehensive': '✅',
                'adequate': '⚠️',
                'partial': '⚠️',
                'disconnected': '❌',
                'error': '❌',
                'insufficient': '❌',
                'unknown': '❓'
            }.get(result['status'], '❓')
            
            print(f"{status_emoji} {result['service']}: {result['status'].upper()}")
            for detail in result['details']:
                print(f"   {detail}")
            print()
            
        except Exception as e:
            logger.error(f"Error validating {validator.__name__}: {e}")
    
    # Generate report
    report_file, report = generate_validation_report(validation_results, output_dir)
    
    # Print summary
    print("📊 VALIDATION SUMMARY")
    print("=" * 21)
    print(f"Total Sources: {report['summary']['total_sources']}")
    print(f"Connected: {report['summary']['connected_sources']}")
    print(f"Failed: {report['summary']['failed_sources']}")
    print(f"Overall Status: {report['summary']['overall_status'].replace('_', ' ').title()}")
    print(f"Report saved: {report_file}")
    
    # Return appropriate exit code
    if report['summary']['overall_status'] in ['all_connected', 'mostly_connected']:
        print("\n🎉 Data source validation successful!")
        return 0
    else:
        print("\n⚠️  Some data sources need attention")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)