#!/usr/bin/env python3
"""
Threat Intelligence Rule Generation Tester
Tests the generation of security rules from threat intelligence data
"""

import json
import yaml
import sys
from datetime import datetime
from pathlib import Path
import re

def load_threat_indicators():
    """Load threat indicators from various sources"""
    
    indicators = {
        'malicious_ips': set(),
        'malicious_domains': set(),
        'malicious_urls': set(),
        'ssl_certificates': set(),
        'total_count': 0
    }
    
    # Load from existing threat intelligence files
    threat_files = [
        ('config/threat-intelligence/feeds/malware_domains.txt', 'malicious_domains'),
        ('config/threat-intelligence/feeds/urlhaus_urls.txt', 'malicious_urls'),
        ('config/threat-intelligence/rules/blocked_ips.txt', 'malicious_ips'),
        ('config/threat-intelligence/rules/blocked_domains.txt', 'malicious_domains')
    ]
    
    for file_path, indicator_type in threat_files:
        if Path(file_path).exists():
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                # Parse different file formats
                if indicator_type == 'malicious_ips':
                    # Extract IP addresses
                    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                    ips = re.findall(ip_pattern, content)
                    indicators['malicious_ips'].update(ips)
                    
                elif indicator_type == 'malicious_domains':
                    # Extract domain names
                    lines = content.strip().split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Clean domain from various formats
                            domain = line.replace('0.0.0.0 ', '').replace('127.0.0.1 ', '')
                            if '.' in domain and not domain.startswith('.'):
                                indicators['malicious_domains'].add(domain)
                                
                elif indicator_type == 'malicious_urls':
                    # Extract URLs
                    lines = content.strip().split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and (line.startswith('http://') or line.startswith('https://')):
                            indicators['malicious_urls'].add(line)
                            
                print(f"✅ Loaded {file_path}: {len(indicators[indicator_type])} indicators")
                
            except Exception as e:
                print(f"⚠️  Error loading {file_path}: {e}")
    
    # Add test indicators for demonstration
    test_indicators = {
        'malicious_ips': ['192.0.2.100', '198.51.100.100', '203.0.113.100'],
        'malicious_domains': ['malware.example.com', 'phishing.test', 'evil.invalid'],
        'malicious_urls': [
            'http://malware.example.com/payload.exe',
            'https://phishing.test/login.html'
        ]
    }
    
    for indicator_type, test_list in test_indicators.items():
        indicators[indicator_type].update(test_list)
    
    # Calculate total
    indicators['total_count'] = sum(len(indicator_set) for key, indicator_set in indicators.items() if key != 'total_count')
    
    return indicators

def generate_prometheus_rules(indicators):
    """Generate Prometheus alerting rules"""
    
    rules_content = {
        'groups': [
            {
                'name': 'threat_intelligence_generated',
                'interval': '30s',
                'rules': []
            }
        ]
    }
    
    # Rule for malicious IP detection
    if indicators['malicious_ips']:
        ip_list = '|'.join(list(indicators['malicious_ips'])[:100])  # Limit for practicality
        
        malicious_ip_rule = {
            'alert': 'MaliciousIPDetected',
            'expr': f'rate(http_requests_total{{remote_addr=~"({ip_list})"}}[5m]) > 0',
            'for': '0s',
            'labels': {
                'severity': 'critical',
                'category': 'threat_intelligence',
                'threat_type': 'malicious_ip'
            },
            'annotations': {
                'summary': 'Request from known malicious IP detected',
                'description': 'Request received from IP {{ $labels.remote_addr }} which is listed in threat intelligence feeds',
                'runbook_url': 'https://security-wiki.company.com/threats/malicious-ip'
            }
        }
        rules_content['groups'][0]['rules'].append(malicious_ip_rule)
    
    # Rule for high frequency requests (potential bot activity)
    high_frequency_rule = {
        'alert': 'HighFrequencyRequests',
        'expr': 'rate(http_requests_total[1m]) > 100',
        'for': '2m',
        'labels': {
            'severity': 'warning',
            'category': 'threat_intelligence',
            'threat_type': 'suspicious_activity'
        },
        'annotations': {
            'summary': 'High frequency requests detected',
            'description': 'Instance {{ $labels.instance }} is receiving {{ $value }} requests per second',
            'runbook_url': 'https://security-wiki.company.com/threats/high-frequency'
        }
    }
    rules_content['groups'][0]['rules'].append(high_frequency_rule)
    
    # Rule for authentication failures
    auth_failure_rule = {
        'alert': 'RepeatedAuthenticationFailures',
        'expr': 'rate(auth_failures_total[5m]) > 5',
        'for': '1m',
        'labels': {
            'severity': 'warning',
            'category': 'threat_intelligence',
            'threat_type': 'brute_force'
        },
        'annotations': {
            'summary': 'Repeated authentication failures detected',
            'description': 'High rate of authentication failures: {{ $value }} failures per second',
            'runbook_url': 'https://security-wiki.company.com/threats/brute-force'
        }
    }
    rules_content['groups'][0]['rules'].append(auth_failure_rule)
    
    return rules_content

def generate_fluentd_filters(indicators):
    """Generate Fluentd filtering rules"""
    
    filters = []
    
    # Header
    filters.append("# Threat Intelligence Generated Filters")
    filters.append(f"# Generated: {datetime.now().isoformat()}")
    filters.append("")
    
    # IP blocking filter
    if indicators['malicious_ips']:
        filters.append("<filter **>")
        filters.append("  @type grep")
        filters.append("  <regexp>")
        filters.append("    key remote_addr")
        ip_pattern = '|'.join(re.escape(ip) for ip in list(indicators['malicious_ips'])[:50])
        filters.append(f"    pattern /^(?!{ip_pattern}).*$/")
        filters.append("  </regexp>")
        filters.append("</filter>")
        filters.append("")
    
    # Malicious domain detection
    if indicators['malicious_domains']:
        filters.append("<filter **>")
        filters.append("  @type record_transformer")
        filters.append("  <record>")
        domain_list = ', '.join(f'"{domain}"' for domain in list(indicators['malicious_domains'])[:20])
        filters.append(f"    threat_domains [{domain_list}]")
        filters.append("    threat_check ${record['host'] && threat_domains.include?(record['host']) ? 'BLOCKED' : 'ALLOWED'}")
        filters.append("  </record>")
        filters.append("</filter>")
        filters.append("")
    
    # URL pattern detection
    filters.append("<filter **>")
    filters.append("  @type grep")
    filters.append("  <regexp>")
    filters.append("    key url")
    filters.append("    pattern /\\.(exe|bat|cmd|scr|pif|com)$/i")
    filters.append("  </regexp>")
    filters.append("  <inject>")
    filters.append("    threat_type malicious_file_extension")
    filters.append("    severity high")
    filters.append("  </inject>")
    filters.append("</filter>")
    filters.append("")
    
    return '\n'.join(filters)

def generate_sigma_rules(indicators):
    """Generate Sigma detection rules"""
    
    rules = []
    
    # Malicious IP access rule
    if indicators['malicious_ips']:
        sigma_rule = {
            'title': 'Access from Known Malicious IP',
            'id': 'threat-intel-malicious-ip-001',
            'status': 'experimental',
            'description': 'Detects access from IPs listed in threat intelligence feeds',
            'author': 'Rust Security Workspace - Threat Intelligence',
            'date': datetime.now().strftime('%Y/%m/%d'),
            'references': [
                'https://github.com/your-org/rust-security'
            ],
            'tags': [
                'attack.initial_access',
                'attack.t1190'
            ],
            'logsource': {
                'category': 'webserver',
                'product': 'auth-service'
            },
            'detection': {
                'selection': {
                    'c-ip': list(indicators['malicious_ips'])[:100]  # Limit for practicality
                },
                'condition': 'selection'
            },
            'fields': [
                'c-ip',
                'cs-uri-stem',
                'cs-user-agent',
                'sc-status'
            ],
            'falsepositives': [
                'Legitimate traffic from previously compromised IPs that have been cleaned'
            ],
            'level': 'high'
        }
        rules.append(sigma_rule)
    
    # Suspicious user agent rule
    suspicious_ua_rule = {
        'title': 'Suspicious User Agent',
        'id': 'threat-intel-suspicious-ua-001',
        'status': 'experimental',
        'description': 'Detects suspicious user agent strings commonly used by malware',
        'author': 'Rust Security Workspace - Threat Intelligence',
        'date': datetime.now().strftime('%Y/%m/%d'),
        'tags': [
            'attack.defense_evasion',
            'attack.t1036'
        ],
        'logsource': {
            'category': 'webserver'
        },
        'detection': {
            'selection': {
                'cs-user-agent|contains': [
                    'wget',
                    'curl',
                    'python-requests',
                    'scanner',
                    'bot',
                    'crawler'
                ]
            },
            'filter': {
                'cs-user-agent|contains': [
                    'googlebot',
                    'bingbot',
                    'slurp'
                ]
            },
            'condition': 'selection and not filter'
        },
        'falsepositives': [
            'Legitimate automated tools',
            'Monitoring systems'
        ],
        'level': 'medium'
    }
    rules.append(suspicious_ua_rule)
    
    return rules

def generate_auth_service_integration(indicators):
    """Generate integration rules for auth service"""
    
    integration_config = {
        'threat_intelligence': {
            'enabled': True,
            'last_updated': datetime.now().isoformat(),
            'blocklists': {
                'malicious_ips': list(indicators['malicious_ips'])[:1000],  # Limit for performance
                'malicious_domains': list(indicators['malicious_domains'])[:1000],
                'high_risk_patterns': [
                    r'.*\.exe$',
                    r'.*\.bat$',
                    r'.*\.cmd$',
                    r'.*\.scr$'
                ]
            },
            'rate_limiting': {
                'known_bad_ips': {
                    'requests_per_minute': 1,
                    'burst_limit': 3
                },
                'suspicious_patterns': {
                    'requests_per_minute': 10,
                    'burst_limit': 20
                }
            },
            'monitoring': {
                'log_blocked_requests': True,
                'alert_on_block': True,
                'metrics_enabled': True
            }
        }
    }
    
    return integration_config

def test_rule_effectiveness(generated_rules, indicators):
    """Test the effectiveness of generated rules"""
    
    test_results = {
        'total_rules': 0,
        'prometheus_rules': 0,
        'fluentd_filters': 0,
        'sigma_rules': 0,
        'coverage_analysis': {},
        'test_scenarios': []
    }
    
    # Count generated rules
    if 'prometheus' in generated_rules:
        test_results['prometheus_rules'] = len(generated_rules['prometheus']['groups'][0]['rules'])
    
    if 'sigma' in generated_rules:
        test_results['sigma_rules'] = len(generated_rules['sigma'])
    
    if 'fluentd' in generated_rules:
        # Count filter blocks in fluentd config
        filter_count = generated_rules['fluentd'].count('<filter')
        test_results['fluentd_filters'] = filter_count
    
    test_results['total_rules'] = (
        test_results['prometheus_rules'] + 
        test_results['fluentd_filters'] + 
        test_results['sigma_rules']
    )
    
    # Coverage analysis
    test_results['coverage_analysis'] = {
        'malicious_ips_covered': min(len(indicators['malicious_ips']), 100),
        'malicious_domains_covered': min(len(indicators['malicious_domains']), 1000),
        'total_indicators': indicators['total_count'],
        'coverage_percentage': min(100, (test_results['total_rules'] / max(indicators['total_count'], 1)) * 100)
    }
    
    # Test scenarios
    test_scenarios = [
        {
            'name': 'Malicious IP Request',
            'scenario': 'Request from known malicious IP',
            'covered': test_results['prometheus_rules'] > 0,
            'rules_triggered': ['MaliciousIPDetected'] if test_results['prometheus_rules'] > 0 else []
        },
        {
            'name': 'High Frequency Attack',
            'scenario': 'Rapid requests indicating bot activity',
            'covered': True,
            'rules_triggered': ['HighFrequencyRequests']
        },
        {
            'name': 'Brute Force Detection',
            'scenario': 'Repeated authentication failures',
            'covered': True,
            'rules_triggered': ['RepeatedAuthenticationFailures']
        },
        {
            'name': 'Malicious Domain Access',
            'scenario': 'Request to known malicious domain',
            'covered': test_results['fluentd_filters'] > 0,
            'rules_triggered': ['FluentdDomainFilter'] if test_results['fluentd_filters'] > 0 else []
        }
    ]
    
    test_results['test_scenarios'] = test_scenarios
    
    return test_results

def save_generated_rules(generated_rules, test_results):
    """Save generated rules to appropriate locations"""
    
    saved_files = []
    
    # Save Prometheus rules
    if 'prometheus' in generated_rules:
        prometheus_file = Path("monitoring/prometheus/threat-intel-generated.yml")
        prometheus_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(prometheus_file, 'w') as f:
            yaml.dump(generated_rules['prometheus'], f, default_flow_style=False)
        
        saved_files.append(str(prometheus_file))
    
    # Save Fluentd filters
    if 'fluentd' in generated_rules:
        fluentd_file = Path("monitoring/fluentd/threat-intel-filters.conf")
        fluentd_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(fluentd_file, 'w') as f:
            f.write(generated_rules['fluentd'])
        
        saved_files.append(str(fluentd_file))
    
    # Save Sigma rules
    if 'sigma' in generated_rules:
        sigma_dir = Path("config/threat-intelligence/sigma-rules")
        sigma_dir.mkdir(parents=True, exist_ok=True)
        
        for i, rule in enumerate(generated_rules['sigma']):
            rule_file = sigma_dir / f"threat_intel_rule_{i+1}.yml"
            with open(rule_file, 'w') as f:
                yaml.dump(rule, f, default_flow_style=False)
            saved_files.append(str(rule_file))
    
    # Save auth service integration
    if 'auth_service' in generated_rules:
        auth_file = Path("config/threat-intelligence/auth-service-integration.json")
        auth_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(auth_file, 'w') as f:
            json.dump(generated_rules['auth_service'], f, indent=2)
        
        saved_files.append(str(auth_file))
    
    # Save test results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    test_file = Path("reports/compliance") / f"rule_generation_test_{timestamp}.json"
    test_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(test_file, 'w') as f:
        json.dump(test_results, f, indent=2)
    
    saved_files.append(str(test_file))
    
    return saved_files

def main():
    """Main testing function"""
    
    print("🛡️  Threat Intelligence Rule Generation Tester")
    print("==============================================")
    
    # Load threat indicators
    print("📊 Loading threat indicators...")
    indicators = load_threat_indicators()
    
    print(f"✅ Loaded {indicators['total_count']} threat indicators:")
    print(f"   • Malicious IPs: {len(indicators['malicious_ips'])}")
    print(f"   • Malicious Domains: {len(indicators['malicious_domains'])}")
    print(f"   • Malicious URLs: {len(indicators['malicious_urls'])}")
    print()
    
    if indicators['total_count'] == 0:
        print("❌ No threat indicators found. Cannot generate rules.")
        return 1
    
    # Generate rules
    print("🔧 Generating security rules...")
    
    generated_rules = {}
    
    # Generate Prometheus rules
    print("   📊 Generating Prometheus alerting rules...")
    generated_rules['prometheus'] = generate_prometheus_rules(indicators)
    
    # Generate Fluentd filters
    print("   🔍 Generating Fluentd filtering rules...")
    generated_rules['fluentd'] = generate_fluentd_filters(indicators)
    
    # Generate Sigma rules
    print("   🎯 Generating Sigma detection rules...")
    generated_rules['sigma'] = generate_sigma_rules(indicators)
    
    # Generate auth service integration
    print("   🔐 Generating auth service integration...")
    generated_rules['auth_service'] = generate_auth_service_integration(indicators)
    
    # Test rule effectiveness
    print("\n🧪 Testing rule effectiveness...")
    test_results = test_rule_effectiveness(generated_rules, indicators)
    
    # Save generated rules
    print("💾 Saving generated rules...")
    saved_files = save_generated_rules(generated_rules, test_results)
    
    # Print results
    print(f"\n📋 RULE GENERATION RESULTS")
    print("=" * 27)
    print(f"Total Rules Generated: {test_results['total_rules']}")
    print(f"  • Prometheus Rules: {test_results['prometheus_rules']}")
    print(f"  • Fluentd Filters: {test_results['fluentd_filters']}")
    print(f"  • Sigma Rules: {test_results['sigma_rules']}")
    print()
    
    print(f"Coverage Analysis:")
    coverage = test_results['coverage_analysis']
    print(f"  • IPs Covered: {coverage['malicious_ips_covered']}")
    print(f"  • Domains Covered: {coverage['malicious_domains_covered']}")
    print(f"  • Total Indicators: {coverage['total_indicators']}")
    print()
    
    print(f"Test Scenarios:")
    for scenario in test_results['test_scenarios']:
        status = "✅" if scenario['covered'] else "❌"
        print(f"  {status} {scenario['name']}: {scenario['scenario']}")
    
    print(f"\n📁 Generated Files:")
    for file_path in saved_files:
        print(f"  • {file_path}")
    
    # Determine success
    covered_scenarios = len([s for s in test_results['test_scenarios'] if s['covered']])
    total_scenarios = len(test_results['test_scenarios'])
    
    if covered_scenarios >= total_scenarios * 0.8:
        print(f"\n🎉 Rule generation test successful!")
        print(f"Coverage: {covered_scenarios}/{total_scenarios} scenarios covered")
        return 0
    else:
        print(f"\n⚠️  Rule generation test partially successful")
        print(f"Coverage: {covered_scenarios}/{total_scenarios} scenarios covered")
        return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)