#!/usr/bin/env python3
"""
Compliance Report Accuracy Validator
Cross-validates compliance report findings against actual implementation
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
import re
import yaml

def load_latest_compliance_report():
    """Load the most recent compliance report"""
    reports_dir = Path("reports/compliance")
    
    if not reports_dir.exists():
        print("❌ No compliance reports directory found")
        return None
    
    # Find the most recent comprehensive report
    report_files = list(reports_dir.glob("comprehensive_compliance_report_*.json"))
    
    if not report_files:
        print("❌ No comprehensive compliance reports found")
        return None
    
    # Sort by modification time and get the latest
    latest_report = max(report_files, key=lambda f: f.stat().st_mtime)
    
    try:
        with open(latest_report, 'r') as f:
            report_data = json.load(f)
        
        print(f"✅ Loaded compliance report: {latest_report}")
        return report_data, latest_report
    except Exception as e:
        print(f"❌ Error loading report: {e}")
        return None

def validate_security_modules_claims(report_data):
    """Validate security modules implementation claims"""
    
    print("🔍 Validating security modules implementation...")
    
    validation_results = {
        'category': 'Security Modules',
        'tests': [],
        'overall_status': 'unknown'
    }
    
    # Expected security modules from report
    reported_modules = report_data.get('implementation_analysis', {}).get('security_modules', {})
    
    # Validate each reported module
    for module_path, module_data in reported_modules.items():
        test_result = {
            'test': f"Module exists: {module_path}",
            'expected': True,
            'actual': Path(module_path).exists(),
            'status': 'unknown'
        }
        
        if test_result['actual'] == test_result['expected']:
            test_result['status'] = 'PASS'
            test_result['details'] = f"Module found with {module_data.get('lines_of_code', 0)} LOC"
        else:
            test_result['status'] = 'FAIL'
            test_result['details'] = "Module file not found"
        
        validation_results['tests'].append(test_result)
        
        # If module exists, validate its content claims
        if test_result['actual']:
            with open(module_path, 'r') as f:
                content = f.read()
            
            # Validate functions count
            actual_functions = len(re.findall(r'fn\s+\w+', content))
            reported_functions = module_data.get('functions', 0)
            
            function_test = {
                'test': f"Function count in {module_path}",
                'expected': reported_functions,
                'actual': actual_functions,
                'status': 'PASS' if abs(actual_functions - reported_functions) <= 2 else 'FAIL',  # Allow small variance
                'details': f"Expected ~{reported_functions}, found {actual_functions}"
            }
            validation_results['tests'].append(function_test)
            
            # Validate error handling claim
            has_error_handling = 'Result<' in content or 'Error' in content
            error_handling_test = {
                'test': f"Error handling in {module_path}",
                'expected': module_data.get('has_error_handling', False),
                'actual': has_error_handling,
                'status': 'PASS' if has_error_handling == module_data.get('has_error_handling', False) else 'FAIL',
                'details': f"Error handling patterns found: {has_error_handling}"
            }
            validation_results['tests'].append(error_handling_test)
    
    # Calculate overall status
    passed_tests = len([t for t in validation_results['tests'] if t['status'] == 'PASS'])
    total_tests = len(validation_results['tests'])
    
    if passed_tests == total_tests:
        validation_results['overall_status'] = 'PASS'
    elif passed_tests >= total_tests * 0.8:
        validation_results['overall_status'] = 'MOSTLY_PASS'
    else:
        validation_results['overall_status'] = 'FAIL'
    
    validation_results['summary'] = f"{passed_tests}/{total_tests} tests passed"
    
    return validation_results

def validate_compliance_scores(report_data):
    """Validate compliance framework scores"""
    
    print("🔍 Validating compliance scores...")
    
    validation_results = {
        'category': 'Compliance Scores',
        'tests': [],
        'overall_status': 'unknown'
    }
    
    compliance_assessment = report_data.get('compliance_assessment', {})
    
    # Validate score ranges (should be 0-100)
    for framework, controls in compliance_assessment.items():
        for control_id, control_data in controls.items():
            score = control_data.get('score', 0)
            
            score_test = {
                'test': f"{framework} {control_id} score range",
                'expected': 'between 0 and 100',
                'actual': score,
                'status': 'PASS' if 0 <= score <= 100 else 'FAIL',
                'details': f"Score: {score}%"
            }
            validation_results['tests'].append(score_test)
            
            # Validate that evidence matches status
            status = control_data.get('status', 'UNKNOWN')
            evidence_count = len(control_data.get('evidence', []))
            
            evidence_test = {
                'test': f"{framework} {control_id} evidence adequacy",
                'expected': 'evidence supports status',
                'actual': f"{evidence_count} evidence items for {status}",
                'status': 'PASS' if (status == 'COMPLIANT' and evidence_count > 0) or (status != 'COMPLIANT') else 'WARN',
                'details': f"Status: {status}, Evidence: {evidence_count} items"
            }
            validation_results['tests'].append(evidence_test)
    
    # Validate overall compliance score calculation
    all_scores = []
    for framework in compliance_assessment.values():
        for control in framework.values():
            all_scores.append(control.get('score', 0))
    
    if all_scores:
        calculated_average = sum(all_scores) / len(all_scores)
        reported_average = report_data.get('executive_summary', {}).get('overall_compliance_score', 0)
        
        avg_test = {
            'test': 'Overall compliance score calculation',
            'expected': round(calculated_average, 1),
            'actual': reported_average,
            'status': 'PASS' if abs(calculated_average - reported_average) < 1.0 else 'FAIL',
            'details': f"Calculated: {calculated_average:.1f}%, Reported: {reported_average}%"
        }
        validation_results['tests'].append(avg_test)
    
    # Calculate overall status
    passed_tests = len([t for t in validation_results['tests'] if t['status'] in ['PASS', 'WARN']])
    total_tests = len(validation_results['tests'])
    
    validation_results['overall_status'] = 'PASS' if passed_tests >= total_tests * 0.9 else 'FAIL'
    validation_results['summary'] = f"{passed_tests}/{total_tests} validations passed"
    
    return validation_results

def validate_monitoring_claims(report_data):
    """Validate monitoring configuration claims"""
    
    print("🔍 Validating monitoring configuration...")
    
    validation_results = {
        'category': 'Monitoring Configuration',
        'tests': [],
        'overall_status': 'unknown'
    }
    
    monitoring_config = report_data.get('implementation_analysis', {}).get('monitoring_config', {})
    
    # Expected monitoring files
    expected_files = {
        'prometheus_alerts': 'monitoring/prometheus/security-alerts.yml',
        'alertmanager_config': 'monitoring/alertmanager/alertmanager.yml',
        'fluentd_config': 'monitoring/fluentd/fluent.conf',
        'elasticsearch_ilm': 'monitoring/elasticsearch/ilm-policies.json'
    }
    
    for config_type, file_path in expected_files.items():
        reported_exists = monitoring_config.get(config_type, {}).get('exists', False)
        actual_exists = Path(file_path).exists()
        
        existence_test = {
            'test': f"Monitoring file exists: {file_path}",
            'expected': reported_exists,
            'actual': actual_exists,
            'status': 'PASS' if reported_exists == actual_exists else 'FAIL',
            'details': f"Reported: {reported_exists}, Actual: {actual_exists}"
        }
        validation_results['tests'].append(existence_test)
        
        # If file exists, validate content analysis
        if actual_exists and reported_exists:
            if config_type == 'prometheus_alerts':
                with open(file_path, 'r') as f:
                    content = f.read()
                
                actual_alerts = len(re.findall(r'alert:', content))
                reported_alerts = monitoring_config[config_type].get('alert_rules', 0)
                
                alerts_test = {
                    'test': f"Prometheus alert rules count",
                    'expected': reported_alerts,
                    'actual': actual_alerts,
                    'status': 'PASS' if actual_alerts == reported_alerts else 'FAIL',
                    'details': f"Expected: {reported_alerts}, Found: {actual_alerts}"
                }
                validation_results['tests'].append(alerts_test)
    
    # Calculate overall status
    passed_tests = len([t for t in validation_results['tests'] if t['status'] == 'PASS'])
    total_tests = len(validation_results['tests'])
    
    validation_results['overall_status'] = 'PASS' if passed_tests >= total_tests * 0.8 else 'FAIL'
    validation_results['summary'] = f"{passed_tests}/{total_tests} monitoring checks passed"
    
    return validation_results

def validate_test_coverage_claims(report_data):
    """Validate test coverage claims"""
    
    print("🔍 Validating test coverage claims...")
    
    validation_results = {
        'category': 'Test Coverage',
        'tests': [],
        'overall_status': 'unknown'
    }
    
    test_coverage = report_data.get('implementation_analysis', {}).get('test_coverage', {})
    
    # Validate test file counts
    reported_total = test_coverage.get('total_test_files', 0)
    reported_security = test_coverage.get('security_test_files', 0)
    
    # Count actual test files
    actual_test_files = list(Path('.').glob('**/tests/*.rs'))
    actual_total = len(actual_test_files)
    actual_security = len([f for f in actual_test_files if 'security' in str(f)])
    
    total_test = {
        'test': 'Total test files count',
        'expected': reported_total,
        'actual': actual_total,
        'status': 'PASS' if abs(actual_total - reported_total) <= 2 else 'FAIL',
        'details': f"Expected: {reported_total}, Found: {actual_total}"
    }
    validation_results['tests'].append(total_test)
    
    security_test = {
        'test': 'Security test files count',
        'expected': reported_security,
        'actual': actual_security,
        'status': 'PASS' if abs(actual_security - reported_security) <= 1 else 'FAIL',
        'details': f"Expected: {reported_security}, Found: {actual_security}"
    }
    validation_results['tests'].append(security_test)
    
    # Validate specific test files mentioned in report
    reported_files = test_coverage.get('test_files', [])
    missing_files = [f for f in reported_files if not Path(f).exists()]
    
    if missing_files:
        missing_test = {
            'test': 'Reported test files existence',
            'expected': 'all files exist',
            'actual': f'{len(missing_files)} missing files',
            'status': 'FAIL',
            'details': f"Missing: {missing_files[:3]}..."  # Show first 3
        }
        validation_results['tests'].append(missing_test)
    else:
        missing_test = {
            'test': 'Reported test files existence',
            'expected': 'all files exist',
            'actual': 'all files found',
            'status': 'PASS',
            'details': f"All {len(reported_files)} reported test files exist"
        }
        validation_results['tests'].append(missing_test)
    
    # Calculate overall status
    passed_tests = len([t for t in validation_results['tests'] if t['status'] == 'PASS'])
    total_tests = len(validation_results['tests'])
    
    validation_results['overall_status'] = 'PASS' if passed_tests == total_tests else 'PARTIAL'
    validation_results['summary'] = f"{passed_tests}/{total_tests} test coverage validations passed"
    
    return validation_results

def generate_validation_report(validation_results, report_file):
    """Generate validation report"""
    
    overall_results = {
        'metadata': {
            'validation_timestamp': datetime.now().isoformat(),
            'original_report': str(report_file),
            'validator_version': '1.0.0'
        },
        'validation_summary': {
            'total_categories': len(validation_results),
            'passed_categories': len([r for r in validation_results if r['overall_status'] in ['PASS', 'MOSTLY_PASS']]),
            'failed_categories': len([r for r in validation_results if r['overall_status'] == 'FAIL']),
            'overall_accuracy': 'unknown'
        },
        'detailed_results': validation_results
    }
    
    # Calculate overall accuracy
    total_tests = sum(len(r['tests']) for r in validation_results)
    passed_tests = sum(len([t for t in r['tests'] if t['status'] in ['PASS', 'WARN']]) for r in validation_results)
    
    accuracy_percentage = (passed_tests / total_tests * 100) if total_tests > 0 else 0
    
    if accuracy_percentage >= 95:
        overall_results['validation_summary']['overall_accuracy'] = 'EXCELLENT'
    elif accuracy_percentage >= 85:
        overall_results['validation_summary']['overall_accuracy'] = 'GOOD'
    elif accuracy_percentage >= 75:
        overall_results['validation_summary']['overall_accuracy'] = 'ACCEPTABLE'
    else:
        overall_results['validation_summary']['overall_accuracy'] = 'POOR'
    
    overall_results['validation_summary']['accuracy_percentage'] = round(accuracy_percentage, 1)
    overall_results['validation_summary']['tests_passed'] = passed_tests
    overall_results['validation_summary']['total_tests'] = total_tests
    
    # Save validation report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    validation_file = Path("reports/compliance") / f"report_validation_{timestamp}.json"
    
    with open(validation_file, 'w') as f:
        json.dump(overall_results, f, indent=2)
    
    return validation_file, overall_results

def main():
    """Main validation function"""
    
    print("✅ Compliance Report Accuracy Validator")
    print("======================================")
    
    # Load the latest compliance report
    report_result = load_latest_compliance_report()
    if not report_result:
        return 1
    
    report_data, report_file = report_result
    print(f"📊 Validating report generated at: {report_data['metadata']['generated_at']}\n")
    
    # Run validation tests
    validation_categories = [
        validate_security_modules_claims,
        validate_compliance_scores,
        validate_monitoring_claims,
        validate_test_coverage_claims
    ]
    
    validation_results = []
    for validator in validation_categories:
        try:
            result = validator(report_data)
            validation_results.append(result)
            
            # Print category results
            status_emoji = {
                'PASS': '✅',
                'MOSTLY_PASS': '⚠️',
                'PARTIAL': '⚠️',
                'FAIL': '❌',
                'unknown': '❓'
            }.get(result['overall_status'], '❓')
            
            print(f"{status_emoji} {result['category']}: {result['overall_status']}")
            print(f"   {result['summary']}")
            
            # Show failed tests
            failed_tests = [t for t in result['tests'] if t['status'] == 'FAIL']
            if failed_tests:
                print(f"   Failed tests:")
                for test in failed_tests[:3]:  # Show first 3 failures
                    print(f"     • {test['test']}: {test['details']}")
            print()
            
        except Exception as e:
            print(f"❌ Error in {validator.__name__}: {e}")
    
    # Generate validation report
    validation_file, validation_data = generate_validation_report(validation_results, report_file)
    
    # Print final summary
    print("📋 VALIDATION SUMMARY")
    print("=" * 21)
    summary = validation_data['validation_summary']
    print(f"Overall Accuracy: {summary['overall_accuracy']} ({summary['accuracy_percentage']}%)")
    print(f"Tests Passed: {summary['tests_passed']}/{summary['total_tests']}")
    print(f"Categories Passed: {summary['passed_categories']}/{summary['total_categories']}")
    print(f"Validation Report: {validation_file}")
    
    # Return appropriate exit code
    if summary['overall_accuracy'] in ['EXCELLENT', 'GOOD']:
        print("\n🎉 Compliance report accuracy validation successful!")
        return 0
    elif summary['overall_accuracy'] == 'ACCEPTABLE':
        print("\n⚠️  Compliance report accuracy is acceptable with minor issues")
        return 0
    else:
        print("\n❌ Compliance report accuracy needs improvement")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)