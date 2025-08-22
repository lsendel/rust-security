#!/usr/bin/env python3
"""
Performance Results Analysis Script
Analyzes K6 and other performance test results for the Rust Security Platform
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, Any, List
import statistics

def analyze_k6_results(results_file: Path) -> Dict[str, Any]:
    """Analyze K6 test results from JSON output"""
    try:
        with open(results_file, 'r') as f:
            data = json.load(f)
        
        metrics = data.get('metrics', {})
        
        # Extract key performance metrics
        analysis = {
            'http_req_duration': {
                'avg': metrics.get('http_req_duration', {}).get('avg', 0),
                'p95': metrics.get('http_req_duration', {}).get('p(95)', 0),
                'p99': metrics.get('http_req_duration', {}).get('p(99)', 0),
                'max': metrics.get('http_req_duration', {}).get('max', 0),
            },
            'http_reqs': {
                'count': metrics.get('http_reqs', {}).get('count', 0),
                'rate': metrics.get('http_reqs', {}).get('rate', 0),
            },
            'http_req_failed': {
                'rate': metrics.get('http_req_failed', {}).get('rate', 0),
            },
            'vus': {
                'max': metrics.get('vus_max', {}).get('value', 0),
            }
        }
        
        return analysis
        
    except Exception as e:
        print(f"Error analyzing K6 results: {e}")
        return {}

def check_performance_thresholds(analysis: Dict[str, Any]) -> List[str]:
    """Check if performance metrics meet defined thresholds"""
    issues = []
    
    # Define performance thresholds (in milliseconds)
    thresholds = {
        'p95_latency_ms': 100,  # P95 should be under 100ms
        'p99_latency_ms': 200,  # P99 should be under 200ms
        'error_rate_percent': 1.0,  # Error rate should be under 1%
        'min_rps': 100,  # Should handle at least 100 RPS
    }
    
    # Check P95 latency
    p95_ms = analysis.get('http_req_duration', {}).get('p95', 0)
    if p95_ms > thresholds['p95_latency_ms']:
        issues.append(f"P95 latency too high: {p95_ms:.2f}ms > {thresholds['p95_latency_ms']}ms")
    
    # Check P99 latency
    p99_ms = analysis.get('http_req_duration', {}).get('p99', 0)
    if p99_ms > thresholds['p99_latency_ms']:
        issues.append(f"P99 latency too high: {p99_ms:.2f}ms > {thresholds['p99_latency_ms']}ms")
    
    # Check error rate
    error_rate = analysis.get('http_req_failed', {}).get('rate', 0) * 100
    if error_rate > thresholds['error_rate_percent']:
        issues.append(f"Error rate too high: {error_rate:.2f}% > {thresholds['error_rate_percent']}%")
    
    # Check throughput
    rps = analysis.get('http_reqs', {}).get('rate', 0)
    if rps < thresholds['min_rps']:
        issues.append(f"Throughput too low: {rps:.2f} RPS < {thresholds['min_rps']} RPS")
    
    return issues

def generate_performance_report(analysis: Dict[str, Any], issues: List[str]) -> str:
    """Generate a human-readable performance report"""
    report = []
    report.append("🚀 Performance Analysis Report")
    report.append("=" * 40)
    report.append("")
    
    # Summary metrics
    if analysis:
        duration = analysis.get('http_req_duration', {})
        reqs = analysis.get('http_reqs', {})
        errors = analysis.get('http_req_failed', {})
        
        report.append("📊 Key Metrics:")
        report.append(f"  • Average Latency: {duration.get('avg', 0):.2f}ms")
        report.append(f"  • P95 Latency: {duration.get('p95', 0):.2f}ms")
        report.append(f"  • P99 Latency: {duration.get('p99', 0):.2f}ms")
        report.append(f"  • Max Latency: {duration.get('max', 0):.2f}ms")
        report.append(f"  • Throughput: {reqs.get('rate', 0):.2f} RPS")
        report.append(f"  • Total Requests: {reqs.get('count', 0)}")
        report.append(f"  • Error Rate: {errors.get('rate', 0) * 100:.2f}%")
        report.append("")
    
    # Performance assessment
    if not issues:
        report.append("✅ Performance Status: PASSED")
        report.append("All performance thresholds met!")
    else:
        report.append("❌ Performance Status: FAILED")
        report.append("Issues found:")
        for issue in issues:
            report.append(f"  • {issue}")
    
    report.append("")
    
    # Recommendations
    if issues:
        report.append("💡 Recommendations:")
        if any("latency" in issue.lower() for issue in issues):
            report.append("  • Consider optimizing database queries")
            report.append("  • Review caching strategies")
            report.append("  • Check for N+1 query problems")
        
        if any("error rate" in issue.lower() for issue in issues):
            report.append("  • Investigate error logs")
            report.append("  • Check resource limits")
            report.append("  • Verify service dependencies")
        
        if any("throughput" in issue.lower() for issue in issues):
            report.append("  • Consider horizontal scaling")
            report.append("  • Review connection pool settings")
            report.append("  • Optimize critical code paths")
    
    return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description='Analyze performance test results')
    parser.add_argument('results_file', help='Path to the results file (JSON format)')
    parser.add_argument('--format', choices=['k6', 'ab'], default='k6', 
                       help='Format of the results file')
    parser.add_argument('--output', help='Output file for the report')
    parser.add_argument('--fail-on-threshold', action='store_true',
                       help='Exit with error code if thresholds are not met')
    
    args = parser.parse_args()
    
    results_file = Path(args.results_file)
    
    if not results_file.exists():
        print(f"❌ Results file not found: {results_file}")
        sys.exit(1)
    
    print(f"📊 Analyzing performance results from: {results_file}")
    
    # Analyze results based on format
    if args.format == 'k6':
        analysis = analyze_k6_results(results_file)
    else:
        print(f"❌ Unsupported format: {args.format}")
        sys.exit(1)
    
    if not analysis:
        print("❌ Failed to analyze results")
        sys.exit(1)
    
    # Check thresholds
    issues = check_performance_thresholds(analysis)
    
    # Generate report
    report = generate_performance_report(analysis, issues)
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"📝 Report saved to: {args.output}")
    else:
        print(report)
    
    # Exit with appropriate code
    if args.fail_on_threshold and issues:
        print(f"\n❌ Performance thresholds not met ({len(issues)} issues)")
        sys.exit(1)
    else:
        print(f"\n✅ Analysis complete")
        sys.exit(0)

if __name__ == '__main__':
    main()
