#!/usr/bin/env python3
"""
Code Quality Monitor for Rust Security Platform
Tracks code quality metrics and generates improvement recommendations.
"""

import os
import json
import subprocess
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import argparse

@dataclass
class QualityMetrics:
    timestamp: str
    overall_score: float
    function_metrics: Dict[str, Any]
    complexity_metrics: Dict[str, Any]
    documentation_metrics: Dict[str, Any]
    test_metrics: Dict[str, Any]
    security_metrics: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    maintainability_score: float
    technical_debt_hours: float

class CodeQualityMonitor:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.src_dir = project_root / "src"
        self.auth_service_dir = project_root / "auth-service" / "src"
        
    def run_clippy_analysis(self) -> Dict[str, Any]:
        """Run clippy and analyze warnings."""
        try:
            result = subprocess.run(
                ["cargo", "clippy", "--workspace", "--all-features", "--", "-W", "clippy::all"],
                cwd=self.project_root,
                capture_output=True,
                text=True
            )
            
            warnings = []
            errors = []
            
            for line in result.stderr.split('\n'):
                if 'warning:' in line:
                    warnings.append(line.strip())
                elif 'error:' in line:
                    errors.append(line.strip())
            
            return {
                'total_warnings': len(warnings),
                'total_errors': len(errors),
                'warnings': warnings[:10],  # Top 10 warnings
                'errors': errors[:10],      # Top 10 errors
                'clippy_score': max(0, 100 - len(warnings) * 2 - len(errors) * 5)
            }
        except Exception as e:
            return {'error': str(e), 'clippy_score': 0}
    
    def analyze_function_metrics(self) -> Dict[str, Any]:
        """Analyze function-level metrics."""
        metrics = {
            'total_functions': 0,
            'large_functions': 0,
            'average_function_length': 0,
            'max_function_length': 0,
            'functions_over_50_lines': [],
            'function_length_distribution': {}
        }
        
        function_lengths = []
        large_functions = []
        
        for rust_file in self.project_root.rglob("*.rs"):
            if 'target' in str(rust_file) or 'node_modules' in str(rust_file):
                continue
                
            try:
                with open(rust_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Find function definitions
                function_pattern = re.compile(
                    r'^\s*(pub\s+)?(async\s+)?fn\s+(\w+)\s*\([^)]*\)\s*(?:->\s*[^{]+)?\s*\{',
                    re.MULTILINE
                )
                
                lines = content.split('\n')
                
                for match in function_pattern.finditer(content):
                    func_name = match.group(3)
                    start_line = content[:match.start()].count('\n') + 1
                    
                    # Find function end by counting braces
                    brace_count = 0
                    end_line = start_line
                    
                    for i, line in enumerate(lines[start_line-1:], start_line):
                        brace_count += line.count('{') - line.count('}')
                        if brace_count == 0 and i > start_line:
                            end_line = i
                            break
                    
                    func_length = end_line - start_line + 1
                    function_lengths.append(func_length)
                    
                    if func_length > 50:
                        large_functions.append({
                            'name': func_name,
                            'file': str(rust_file.relative_to(self.project_root)),
                            'lines': func_length,
                            'start_line': start_line
                        })
                        
            except Exception as e:
                print(f"Error analyzing {rust_file}: {e}")
        
        if function_lengths:
            metrics['total_functions'] = len(function_lengths)
            metrics['large_functions'] = len(large_functions)
            metrics['average_function_length'] = sum(function_lengths) / len(function_lengths)
            metrics['max_function_length'] = max(function_lengths)
            metrics['functions_over_50_lines'] = large_functions[:10]  # Top 10
            
            # Distribution
            distribution = {}
            for length in function_lengths:
                bucket = f"{(length // 10) * 10}-{(length // 10) * 10 + 9}"
                distribution[bucket] = distribution.get(bucket, 0) + 1
            metrics['function_length_distribution'] = distribution
        
        return metrics
    
    def analyze_complexity_metrics(self) -> Dict[str, Any]:
        """Analyze cyclomatic complexity."""
        try:
            # Use tokei for basic metrics
            result = subprocess.run(
                ["tokei", "--output", "json", str(self.project_root)],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                tokei_data = json.loads(result.stdout)
                rust_stats = tokei_data.get('Rust', {})
                
                return {
                    'total_lines': rust_stats.get('code', 0),
                    'comment_lines': rust_stats.get('comments', 0),
                    'blank_lines': rust_stats.get('blanks', 0),
                    'files': rust_stats.get('stats', []),
                    'comment_ratio': rust_stats.get('comments', 0) / max(rust_stats.get('code', 1), 1),
                    'complexity_score': min(100, max(0, 100 - (rust_stats.get('code', 0) / 1000)))
                }
        except Exception as e:
            print(f"Error running tokei: {e}")
        
        return {'error': 'Could not analyze complexity', 'complexity_score': 50}
    
    def analyze_documentation_metrics(self) -> Dict[str, Any]:
        """Analyze documentation coverage."""
        doc_metrics = {
            'total_public_items': 0,
            'documented_items': 0,
            'documentation_coverage': 0,
            'missing_docs': []
        }
        
        for rust_file in self.project_root.rglob("*.rs"):
            if 'target' in str(rust_file) or 'tests' in str(rust_file):
                continue
                
            try:
                with open(rust_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                lines = content.split('\n')
                
                # Find public items
                pub_pattern = re.compile(r'^\s*pub\s+(fn|struct|enum|trait|mod|const|static)\s+(\w+)')
                
                for i, line in enumerate(lines):
                    match = pub_pattern.match(line)
                    if match:
                        item_type = match.group(1)
                        item_name = match.group(2)
                        doc_metrics['total_public_items'] += 1
                        
                        # Check if previous lines contain documentation
                        has_doc = False
                        for j in range(max(0, i-5), i):
                            if lines[j].strip().startswith('///') or lines[j].strip().startswith('#[doc'):
                                has_doc = True
                                break
                        
                        if has_doc:
                            doc_metrics['documented_items'] += 1
                        else:
                            doc_metrics['missing_docs'].append({
                                'item': f"{item_type} {item_name}",
                                'file': str(rust_file.relative_to(self.project_root)),
                                'line': i + 1
                            })
                            
            except Exception as e:
                print(f"Error analyzing documentation in {rust_file}: {e}")
        
        if doc_metrics['total_public_items'] > 0:
            doc_metrics['documentation_coverage'] = (
                doc_metrics['documented_items'] / doc_metrics['total_public_items'] * 100
            )
        
        return doc_metrics
    
    def analyze_test_metrics(self) -> Dict[str, Any]:
        """Analyze test coverage and quality."""
        try:
            # Run tests and capture output
            test_result = subprocess.run(
                ["cargo", "test", "--workspace", "--", "--nocapture"],
                cwd=self.project_root,
                capture_output=True,
                text=True
            )
            
            # Parse test results
            test_lines = test_result.stdout.split('\n')
            passed_tests = len([line for line in test_lines if 'test result: ok' in line or '... ok' in line])
            failed_tests = len([line for line in test_lines if '... FAILED' in line])
            
            # Try to get coverage with tarpaulin if available
            coverage_result = subprocess.run(
                ["cargo", "tarpaulin", "--workspace", "--out", "json"],
                cwd=self.project_root,
                capture_output=True,
                text=True
            )
            
            coverage_percentage = 0
            if coverage_result.returncode == 0:
                try:
                    coverage_data = json.loads(coverage_result.stdout)
                    coverage_percentage = coverage_data.get('coverage', 0)
                except:
                    pass
            
            return {
                'total_tests': passed_tests + failed_tests,
                'passed_tests': passed_tests,
                'failed_tests': failed_tests,
                'test_success_rate': passed_tests / max(passed_tests + failed_tests, 1) * 100,
                'coverage_percentage': coverage_percentage,
                'test_score': min(100, (passed_tests / max(passed_tests + failed_tests, 1)) * 100 * 0.7 + coverage_percentage * 0.3)
            }
            
        except Exception as e:
            return {'error': str(e), 'test_score': 0}
    
    def analyze_security_metrics(self) -> Dict[str, Any]:
        """Analyze security-related metrics."""
        try:
            # Run cargo audit
            audit_result = subprocess.run(
                ["cargo", "audit", "--json"],
                cwd=self.project_root,
                capture_output=True,
                text=True
            )
            
            vulnerabilities = []
            if audit_result.returncode != 0:
                # Parse audit output for vulnerabilities
                for line in audit_result.stdout.split('\n'):
                    if line.strip():
                        try:
                            vuln_data = json.loads(line)
                            if vuln_data.get('type') == 'vulnerability':
                                vulnerabilities.append(vuln_data)
                        except:
                            pass
            
            # Check for unsafe code blocks
            unsafe_count = 0
            for rust_file in self.project_root.rglob("*.rs"):
                if 'target' in str(rust_file):
                    continue
                try:
                    with open(rust_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        unsafe_count += content.count('unsafe ')
                except:
                    pass
            
            security_score = max(0, 100 - len(vulnerabilities) * 20 - unsafe_count * 5)
            
            return {
                'vulnerabilities': len(vulnerabilities),
                'vulnerability_details': vulnerabilities[:5],  # Top 5
                'unsafe_blocks': unsafe_count,
                'security_score': security_score
            }
            
        except Exception as e:
            return {'error': str(e), 'security_score': 50}
    
    def calculate_technical_debt(self, metrics: Dict[str, Any]) -> float:
        """Calculate estimated technical debt in hours."""
        debt_hours = 0
        
        # Function-related debt
        function_metrics = metrics.get('function_metrics', {})
        large_functions = function_metrics.get('large_functions', 0)
        debt_hours += large_functions * 2  # 2 hours per large function to refactor
        
        # Documentation debt
        doc_metrics = metrics.get('documentation_metrics', {})
        missing_docs = len(doc_metrics.get('missing_docs', []))
        debt_hours += missing_docs * 0.5  # 30 minutes per missing doc
        
        # Test debt
        test_metrics = metrics.get('test_metrics', {})
        coverage = test_metrics.get('coverage_percentage', 0)
        if coverage < 80:
            debt_hours += (80 - coverage) * 0.5  # 30 minutes per % coverage needed
        
        # Security debt
        security_metrics = metrics.get('security_metrics', {})
        vulnerabilities = security_metrics.get('vulnerabilities', 0)
        debt_hours += vulnerabilities * 4  # 4 hours per vulnerability
        
        return debt_hours
    
    def generate_quality_report(self) -> QualityMetrics:
        """Generate comprehensive quality report."""
        print("🔍 Analyzing code quality...")
        
        # Collect all metrics
        clippy_metrics = self.run_clippy_analysis()
        function_metrics = self.analyze_function_metrics()
        complexity_metrics = self.analyze_complexity_metrics()
        documentation_metrics = self.analyze_documentation_metrics()
        test_metrics = self.analyze_test_metrics()
        security_metrics = self.analyze_security_metrics()
        
        # Calculate performance score (simplified)
        performance_score = min(100, max(0, 
            100 - function_metrics.get('large_functions', 0) * 2
        ))
        
        # Calculate overall scores
        scores = [
            clippy_metrics.get('clippy_score', 0),
            complexity_metrics.get('complexity_score', 0),
            documentation_metrics.get('documentation_coverage', 0),
            test_metrics.get('test_score', 0),
            security_metrics.get('security_score', 0),
            performance_score
        ]
        
        overall_score = sum(scores) / len(scores)
        maintainability_score = (
            clippy_metrics.get('clippy_score', 0) * 0.3 +
            function_metrics.get('average_function_length', 100) / 100 * 0.2 +
            documentation_metrics.get('documentation_coverage', 0) * 0.3 +
            test_metrics.get('test_score', 0) * 0.2
        )
        
        all_metrics = {
            'clippy_metrics': clippy_metrics,
            'function_metrics': function_metrics,
            'complexity_metrics': complexity_metrics,
            'documentation_metrics': documentation_metrics,
            'test_metrics': test_metrics,
            'security_metrics': security_metrics,
            'performance_metrics': {'performance_score': performance_score}
        }
        
        technical_debt = self.calculate_technical_debt(all_metrics)
        
        return QualityMetrics(
            timestamp=datetime.now().isoformat(),
            overall_score=overall_score,
            function_metrics=function_metrics,
            complexity_metrics=complexity_metrics,
            documentation_metrics=documentation_metrics,
            test_metrics=test_metrics,
            security_metrics=security_metrics,
            performance_metrics={'performance_score': performance_score},
            maintainability_score=maintainability_score,
            technical_debt_hours=technical_debt
        )
    
    def generate_markdown_report(self, metrics: QualityMetrics) -> str:
        """Generate a markdown report from metrics."""
        report = []
        
        report.append("# 📊 Code Quality Report")
        report.append(f"**Generated**: {metrics.timestamp}")
        report.append("")
        
        # Overall score
        score_emoji = "🟢" if metrics.overall_score >= 90 else "🟡" if metrics.overall_score >= 70 else "🔴"
        report.append(f"## Overall Quality Score: {metrics.overall_score:.1f}/100 {score_emoji}")
        report.append("")
        
        # Summary table
        report.append("| Metric | Score | Status |")
        report.append("|--------|-------|--------|")
        
        metric_scores = [
            ("Code Style (Clippy)", metrics.function_metrics.get('clippy_score', 0)),
            ("Function Design", 100 - min(100, metrics.function_metrics.get('large_functions', 0) * 10)),
            ("Documentation", metrics.documentation_metrics.get('documentation_coverage', 0)),
            ("Test Coverage", metrics.test_metrics.get('test_score', 0)),
            ("Security", metrics.security_metrics.get('security_score', 0)),
            ("Performance", metrics.performance_metrics.get('performance_score', 0))
        ]
        
        for name, score in metric_scores:
            status = "✅ Excellent" if score >= 90 else "⚠️ Good" if score >= 70 else "❌ Needs Work"
            report.append(f"| {name} | {score:.1f} | {status} |")
        
        report.append("")
        
        # Technical debt
        report.append(f"## 💰 Technical Debt: {metrics.technical_debt_hours:.1f} hours")
        report.append("")
        
        # Detailed sections
        if metrics.function_metrics.get('functions_over_50_lines'):
            report.append("## 🔧 Functions Needing Refactoring")
            report.append("")
            for func in metrics.function_metrics['functions_over_50_lines'][:5]:
                report.append(f"- **{func['name']}** ({func['lines']} lines)")
                report.append(f"  - File: `{func['file']}:{func['start_line']}`")
            report.append("")
        
        if metrics.documentation_metrics.get('missing_docs'):
            report.append("## 📚 Missing Documentation")
            report.append("")
            for item in metrics.documentation_metrics['missing_docs'][:5]:
                report.append(f"- **{item['item']}**")
                report.append(f"  - File: `{item['file']}:{item['line']}`")
            report.append("")
        
        if metrics.security_metrics.get('vulnerability_details'):
            report.append("## 🛡️ Security Issues")
            report.append("")
            for vuln in metrics.security_metrics['vulnerability_details']:
                report.append(f"- **{vuln.get('advisory', {}).get('title', 'Unknown')}**")
                report.append(f"  - Severity: {vuln.get('advisory', {}).get('severity', 'Unknown')}")
            report.append("")
        
        # Recommendations
        report.append("## 🎯 Improvement Recommendations")
        report.append("")
        
        recommendations = []
        
        if metrics.function_metrics.get('large_functions', 0) > 5:
            recommendations.append("Refactor large functions using Single Responsibility Principle")
        
        if metrics.documentation_metrics.get('documentation_coverage', 0) < 80:
            recommendations.append("Improve documentation coverage for public APIs")
        
        if metrics.test_metrics.get('coverage_percentage', 0) < 80:
            recommendations.append("Increase test coverage, especially for critical paths")
        
        if metrics.security_metrics.get('vulnerabilities', 0) > 0:
            recommendations.append("Address security vulnerabilities immediately")
        
        if not recommendations:
            recommendations.append("Excellent work! Continue maintaining high code quality standards")
        
        for rec in recommendations:
            report.append(f"- {rec}")
        
        return '\n'.join(report)

def main():
    parser = argparse.ArgumentParser(description='Monitor code quality metrics')
    parser.add_argument('--project-root', type=Path, default=Path('.'),
                       help='Project root directory')
    parser.add_argument('--output', type=Path, default=Path('quality_report.md'),
                       help='Output report file')
    parser.add_argument('--json-output', type=Path,
                       help='JSON output file for metrics')
    
    args = parser.parse_args()
    
    monitor = CodeQualityMonitor(args.project_root)
    metrics = monitor.generate_quality_report()
    
    # Generate markdown report
    markdown_report = monitor.generate_markdown_report(metrics)
    with open(args.output, 'w') as f:
        f.write(markdown_report)
    
    print(f"📄 Quality report generated: {args.output}")
    
    # Save JSON metrics if requested
    if args.json_output:
        with open(args.json_output, 'w') as f:
            json.dump(asdict(metrics), f, indent=2)
        print(f"📊 JSON metrics saved: {args.json_output}")
    
    # Print summary
    print(f"\n🎯 Overall Quality Score: {metrics.overall_score:.1f}/100")
    print(f"💰 Technical Debt: {metrics.technical_debt_hours:.1f} hours")
    
    if metrics.overall_score >= 95:
        print("🏆 Excellent! Your code quality is outstanding.")
    elif metrics.overall_score >= 85:
        print("✅ Good job! Minor improvements needed.")
    elif metrics.overall_score >= 70:
        print("⚠️ Moderate quality. Focus on key improvements.")
    else:
        print("❌ Significant improvements needed. Review the report carefully.")
    
    return 0

if __name__ == '__main__':
    exit(main())
