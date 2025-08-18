#!/usr/bin/env python3
"""
Threat Feed Validation Script
Validates threat intelligence feeds configuration and accessibility
"""

import sys
import yaml
import requests
import json
from datetime import datetime
from pathlib import Path
import time
import re
from urllib.parse import urlparse

def load_feeds_config():
    """Load threat feeds configuration"""
    config_files = [
        "config/threat-intelligence/enhanced_feeds.yaml",
        "config/threat-intelligence/config.yaml"
    ]
    
    for config_file in config_files:
        if Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    config = yaml.safe_load(f)
                    print(f"✅ Loaded config: {config_file}")
                    return config
            except Exception as e:
                print(f"❌ Error loading {config_file}: {e}")
    
    print("❌ No valid threat feeds configuration found")
    return None

def validate_feed_url(feed_name, feed_config):
    """Validate a single threat feed URL"""
    
    validation_result = {
        'feed_name': feed_name,
        'url': feed_config.get('url', 'N/A'),
        'enabled': feed_config.get('enabled', False),
        'status': 'unknown',
        'response_time': 0,
        'content_size': 0,
        'content_preview': '',
        'errors': []
    }
    
    if not validation_result['enabled']:
        validation_result['status'] = 'disabled'
        return validation_result
    
    # Skip static/test feeds
    if 'static_data' in feed_config:
        validation_result['status'] = 'static'
        validation_result['content_size'] = len(str(feed_config['static_data']))
        return validation_result
    
    url = feed_config.get('url')
    if not url:
        validation_result['status'] = 'no_url'
        validation_result['errors'].append('No URL specified')
        return validation_result
    
    try:
        # Validate URL format
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            validation_result['status'] = 'invalid_url'
            validation_result['errors'].append('Invalid URL format')
            return validation_result
        
        # Make request with timeout
        start_time = time.time()
        headers = {
            'User-Agent': 'Rust-Security-Workspace-ThreatIntel/1.0'
        }
        
        # Add any custom headers from config
        if 'headers' in feed_config:
            headers.update(feed_config['headers'])
        
        response = requests.get(url, headers=headers, timeout=30, stream=True)
        response_time = time.time() - start_time
        validation_result['response_time'] = round(response_time, 2)
        
        if response.status_code == 200:
            # Read first chunk to get content preview and size
            content_preview = ""
            content_size = 0
            
            for chunk in response.iter_content(chunk_size=1024):
                content_size += len(chunk)
                if not content_preview and chunk:
                    # Get first 200 characters for preview
                    try:
                        content_preview = chunk.decode('utf-8', errors='ignore')[:200]
                    except:
                        content_preview = "Binary content"
                
                # Stop after reading enough for validation (1MB max)
                if content_size > 1024 * 1024:
                    break
            
            validation_result['status'] = 'accessible'
            validation_result['content_size'] = content_size
            validation_result['content_preview'] = content_preview.strip()
            
            # Validate content format
            feed_format = feed_config.get('format', 'text')
            if feed_format == 'json' and content_preview:
                try:
                    json.loads(content_preview)
                    validation_result['format_valid'] = True
                except:
                    validation_result['format_valid'] = False
                    validation_result['errors'].append('Invalid JSON format')
            elif feed_format == 'csv' and content_preview:
                # Basic CSV validation - check for comma separators
                lines = content_preview.split('\n')
                if lines and ',' in lines[0]:
                    validation_result['format_valid'] = True
                else:
                    validation_result['format_valid'] = False
                    validation_result['errors'].append('Invalid CSV format')
            else:
                validation_result['format_valid'] = True
                
        else:
            validation_result['status'] = 'error'
            validation_result['errors'].append(f'HTTP {response.status_code}')
            
    except requests.exceptions.Timeout:
        validation_result['status'] = 'timeout'
        validation_result['errors'].append('Request timeout')
    except requests.exceptions.ConnectionError:
        validation_result['status'] = 'connection_error'
        validation_result['errors'].append('Connection failed')
    except Exception as e:
        validation_result['status'] = 'error'
        validation_result['errors'].append(str(e))
    
    return validation_result

def analyze_feed_content(validation_results):
    """Analyze feed content to extract indicators"""
    
    analysis = {
        'total_feeds': len(validation_results),
        'accessible_feeds': 0,
        'total_content_size': 0,
        'estimated_indicators': 0,
        'feed_types': {},
        'errors': []
    }
    
    for result in validation_results:
        if result['status'] == 'accessible':
            analysis['accessible_feeds'] += 1
            analysis['total_content_size'] += result['content_size']
            
            # Estimate indicators based on content
            content = result['content_preview'].lower()
            
            # Count IP addresses (simple regex)
            ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            ip_matches = len(re.findall(ip_pattern, content))
            
            # Count domain-like patterns
            domain_pattern = r'\b[a-z0-9.-]+\.[a-z]{2,}\b'
            domain_matches = len(re.findall(domain_pattern, content))
            
            # Count URL patterns
            url_pattern = r'https?://[^\s]+'
            url_matches = len(re.findall(url_pattern, content))
            
            estimated = max(ip_matches, domain_matches, url_matches)
            if estimated > 0:
                # Scale up based on content size vs preview size
                scale_factor = result['content_size'] / max(len(result['content_preview']), 1)
                estimated = int(estimated * scale_factor)
            
            analysis['estimated_indicators'] += estimated
            
            # Track feed types
            feed_type = result.get('feed_type', 'unknown')
            analysis['feed_types'][feed_type] = analysis['feed_types'].get(feed_type, 0) + 1
    
    return analysis

def generate_feed_report(validation_results, analysis):
    """Generate threat feed validation report"""
    
    report = {
        'metadata': {
            'validation_timestamp': datetime.now().isoformat(),
            'validator_version': '1.0.0'
        },
        'summary': analysis,
        'feed_results': validation_results,
        'recommendations': []
    }
    
    # Generate recommendations
    accessible_ratio = analysis['accessible_feeds'] / analysis['total_feeds'] if analysis['total_feeds'] > 0 else 0
    
    if accessible_ratio < 0.5:
        report['recommendations'].append({
            'priority': 'HIGH',
            'category': 'Accessibility',
            'recommendation': 'More than half of the configured feeds are not accessible. Review and update feed URLs.',
            'affected_feeds': [r['feed_name'] for r in validation_results if r['status'] not in ['accessible', 'disabled', 'static']]
        })
    
    if analysis['estimated_indicators'] < 1000:
        report['recommendations'].append({
            'priority': 'MEDIUM',
            'category': 'Coverage',
            'recommendation': 'Consider adding more threat intelligence feeds to increase indicator coverage.',
            'current_estimate': analysis['estimated_indicators']
        })
    
    # Check for feeds with errors
    error_feeds = [r for r in validation_results if r['errors']]
    if error_feeds:
        report['recommendations'].append({
            'priority': 'MEDIUM',
            'category': 'Reliability',
            'recommendation': 'Some feeds have validation errors that should be addressed.',
            'affected_feeds': [f"{r['feed_name']}: {', '.join(r['errors'])}" for r in error_feeds]
        })
    
    # Save report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = Path("reports/compliance") / f"threat_feeds_validation_{timestamp}.json"
    
    # Create directory if it doesn't exist
    report_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report_file, report

def main():
    """Main validation function"""
    
    print("🔍 Threat Intelligence Feeds Validator")
    print("=====================================")
    
    # Load configuration
    config = load_feeds_config()
    if not config:
        return 1
    
    # Extract feeds configuration
    feeds = config.get('feeds', {})
    if not feeds:
        print("❌ No feeds configured")
        return 1
    
    print(f"📊 Found {len(feeds)} configured threat feeds\n")
    
    # Validate each feed
    validation_results = []
    
    for feed_name, feed_config in feeds.items():
        print(f"🔍 Validating {feed_name}...")
        
        result = validate_feed_url(feed_name, feed_config)
        result['feed_type'] = feed_config.get('type', 'unknown')
        validation_results.append(result)
        
        # Print immediate result
        status_emoji = {
            'accessible': '✅',
            'disabled': '⚪',
            'static': '📝',
            'timeout': '⏰',
            'connection_error': '🔌',
            'error': '❌',
            'no_url': '❓',
            'invalid_url': '🔗'
        }.get(result['status'], '❓')
        
        print(f"   {status_emoji} {result['status'].upper()}", end='')
        
        if result['status'] == 'accessible':
            size_mb = result['content_size'] / (1024 * 1024)
            print(f" ({size_mb:.1f}MB, {result['response_time']}s)")
        elif result['errors']:
            print(f" - {', '.join(result['errors'])}")
        else:
            print()
    
    # Analyze results
    print(f"\n📊 Analyzing feed content...")
    analysis = analyze_feed_content(validation_results)
    
    # Generate report
    report_file, report_data = generate_feed_report(validation_results, analysis)
    
    # Print summary
    print(f"\n📋 VALIDATION SUMMARY")
    print("=" * 21)
    print(f"Total Feeds: {analysis['total_feeds']}")
    print(f"Accessible: {analysis['accessible_feeds']}")
    print(f"Total Content: {analysis['total_content_size'] / (1024*1024):.1f} MB")
    print(f"Estimated Indicators: {analysis['estimated_indicators']:,}")
    print(f"Feed Types: {len(analysis['feed_types'])}")
    
    if analysis['feed_types']:
        print(f"\nFeed Type Distribution:")
        for feed_type, count in analysis['feed_types'].items():
            print(f"  {feed_type}: {count}")
    
    print(f"\nValidation Report: {report_file}")
    
    # Print recommendations
    if report_data['recommendations']:
        print(f"\n💡 RECOMMENDATIONS")
        print("=" * 19)
        for rec in report_data['recommendations']:
            print(f"{rec['priority']}: {rec['recommendation']}")
    
    # Return appropriate exit code
    accessibility_ratio = analysis['accessible_feeds'] / analysis['total_feeds'] if analysis['total_feeds'] > 0 else 0
    
    if accessibility_ratio >= 0.8:
        print(f"\n🎉 Threat feeds validation successful!")
        return 0
    elif accessibility_ratio >= 0.5:
        print(f"\n⚠️  Threat feeds partially accessible - some issues need attention")
        return 0
    else:
        print(f"\n❌ Threat feeds validation failed - many feeds inaccessible")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)