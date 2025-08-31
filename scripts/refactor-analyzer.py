#!/usr/bin/env python3
"""
Advanced Refactoring Analyzer - AST-based code analysis and automated improvements
Uses Rust syntax tree analysis for intelligent refactoring suggestions
"""

import ast
import os
import re
import sys
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import argparse

class RefactoringSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class RefactoringOpportunity:
    file_path: str
    line_number: int
    severity: RefactoringSeverity
    category: str
    title: str
    description: str
    suggestion: str
    code_snippet: str
    estimated_effort: str
    impact: str

class RustRefactoringAnalyzer:
    """Advanced Rust code analyzer for refactoring opportunities"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.opportunities: List[RefactoringOpportunity] = []
        
        # Refactoring rules configuration
        self.max_function_lines = 50
        self.max_complexity = 10
        self.max_parameters = 5
        self.max_nesting = 3
        
    def find_rust_files(self) -> List[Path]:
        """Find all Rust source files in the project"""
        rust_files = []
        for path in self.project_root.rglob("*.rs"):
            # Skip target directory and dependencies
            if "target" not in str(path) and ".cargo" not in str(path):
                rust_files.append(path)
        return rust_files
    
    def analyze_function_length(self, file_path: Path, content: str):
        """Analyze function length and suggest refactoring for long functions"""
        lines = content.split('\n')
        in_function = False
        function_start = 0
        function_name = ""
        brace_count = 0
        
        for i, line in enumerate(lines):
            # Detect function start
            fn_match = re.match(r'\s*(pub\s+)?(async\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)', line)
            if fn_match and not line.strip().startswith('//'):
                if '{' in line:
                    in_function = True
                    function_start = i + 1
                    function_name = fn_match.group(3)
                    brace_count = line.count('{') - line.count('}')
            
            # Track brace nesting
            if in_function:
                brace_count += line.count('{') - line.count('}')
                
                # Function ends when braces are balanced
                if brace_count == 0:
                    function_length = i - function_start + 1
                    
                    if function_length > self.max_function_lines:
                        severity = RefactoringSeverity.HIGH if function_length > 80 else RefactoringSeverity.MEDIUM
                        
                        self.opportunities.append(RefactoringOpportunity(
                            file_path=str(file_path),
                            line_number=function_start,
                            severity=severity,
                            category="Function Design",
                            title=f"Long Function: {function_name}",
                            description=f"Function has {function_length} lines, exceeding limit of {self.max_function_lines}",
                            suggestion=f"Break {function_name} into smaller, focused functions. Consider extracting logical blocks into separate functions.",
                            code_snippet='\n'.join(lines[function_start-1:function_start+5]),
                            estimated_effort="30-60 minutes",
                            impact="Improves readability and maintainability"
                        ))
                    
                    in_function = False
    
    def analyze_parameter_count(self, file_path: Path, content: str):
        """Analyze function parameter counts"""
        # Match function signatures
        fn_pattern = r'fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.*?)\)\s*(?:->\s*[^{]+)?'
        
        for match in re.finditer(fn_pattern, content, re.DOTALL):
            function_name = match.group(1)
            params_str = match.group(2)
            line_num = content[:match.start()].count('\n') + 1
            
            # Count parameters (simplified - doesn't handle complex generic types perfectly)
            if params_str.strip():
                # Split by comma, but be careful with generic types
                params = []
                depth = 0
                current_param = ""
                
                for char in params_str:
                    if char in '<(':
                        depth += 1
                    elif char in '>)':
                        depth -= 1
                    elif char == ',' and depth == 0:
                        if current_param.strip():
                            params.append(current_param.strip())
                        current_param = ""
                        continue
                    current_param += char
                
                if current_param.strip():
                    params.append(current_param.strip())
                
                param_count = len(params)
                
                if param_count > self.max_parameters:
                    severity = RefactoringSeverity.HIGH if param_count > 8 else RefactoringSeverity.MEDIUM
                    
                    self.opportunities.append(RefactoringOpportunity(
                        file_path=str(file_path),
                        line_number=line_num,
                        severity=severity,
                        category="Function Design",
                        title=f"Too Many Parameters: {function_name}",
                        description=f"Function has {param_count} parameters, exceeding limit of {self.max_parameters}",
                        suggestion="Consider using a struct to group related parameters, or breaking the function into smaller ones.",
                        code_snippet=match.group(0)[:200],
                        estimated_effort="15-30 minutes",
                        impact="Improves function readability and reduces coupling"
                    ))
    
    def analyze_error_handling(self, file_path: Path, content: str):
        """Analyze error handling patterns"""
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            line_num = i + 1
            
            # Check for unwrap() usage
            if '.unwrap()' in line and not line.strip().startswith('//'):
                if 'test' not in str(file_path).lower():
                    self.opportunities.append(RefactoringOpportunity(
                        file_path=str(file_path),
                        line_number=line_num,
                        severity=RefactoringSeverity.HIGH,
                        category="Error Handling",
                        title="Dangerous unwrap() Usage",
                        description="Using unwrap() can cause panics in production",
                        suggestion="Replace with proper error handling using ? operator or match statement",
                        code_snippet=line.strip(),
                        estimated_effort="5-15 minutes",
                        impact="Prevents runtime panics and improves error resilience"
                    ))
            
            # Check for panic! usage
            if 'panic!' in line and not line.strip().startswith('//'):
                if 'test' not in str(file_path).lower():
                    self.opportunities.append(RefactoringOpportunity(
                        file_path=str(file_path),
                        line_number=line_num,
                        severity=RefactoringSeverity.CRITICAL,
                        category="Error Handling",
                        title="Production panic! Usage",
                        description="panic! calls can crash the application",
                        suggestion="Replace with proper error types and return Result<T, E>",
                        code_snippet=line.strip(),
                        estimated_effort="15-30 minutes",
                        impact="Critical for production stability"
                    ))
            
            # Check for expect() with poor messages
            expect_match = re.search(r'\.expect\(\s*"([^"]*)"', line)
            if expect_match and not line.strip().startswith('//'):
                message = expect_match.group(1)
                if len(message) < 10 or message.lower() in ['error', 'failed', 'oops']:
                    self.opportunities.append(RefactoringOpportunity(
                        file_path=str(file_path),
                        line_number=line_num,
                        severity=RefactoringSeverity.MEDIUM,
                        category="Error Handling",
                        title="Poor Error Message",
                        description="expect() message is too generic or unhelpful",
                        suggestion="Provide specific, actionable error messages that help with debugging",
                        code_snippet=line.strip(),
                        estimated_effort="2-5 minutes",
                        impact="Improves debugging experience"
                    ))
    
    def analyze_code_duplication(self, rust_files: List[Path]):
        """Analyze potential code duplication across files"""
        function_signatures = {}
        
        for file_path in rust_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Find function signatures
                fn_pattern = r'fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)'
                matches = re.finditer(fn_pattern, content)
                
                for match in matches:
                    func_name = match.group(1)
                    line_num = content[:match.start()].count('\n') + 1
                    
                    if func_name in function_signatures:
                        function_signatures[func_name].append((file_path, line_num))
                    else:
                        function_signatures[func_name] = [(file_path, line_num)]
            
            except Exception as e:
                print(f"Warning: Could not analyze {file_path}: {e}")
        
        # Report potential duplicates
        for func_name, occurrences in function_signatures.items():
            if len(occurrences) > 1:
                for file_path, line_num in occurrences:
                    self.opportunities.append(RefactoringOpportunity(
                        file_path=str(file_path),
                        line_number=line_num,
                        severity=RefactoringSeverity.MEDIUM,
                        category="Code Duplication",
                        title=f"Potential Duplicate Function: {func_name}",
                        description=f"Function name '{func_name}' appears in {len(occurrences)} files",
                        suggestion="Review functions with same names. Consider extracting common functionality into shared modules.",
                        code_snippet=f"fn {func_name}(...)",
                        estimated_effort="20-40 minutes",
                        impact="Reduces code duplication and maintenance burden"
                    ))
    
    def analyze_performance_opportunities(self, file_path: Path, content: str):
        """Analyze potential performance improvements"""
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            line_num = i + 1
            
            # Check for unnecessary clones
            if '.clone()' in line and not line.strip().startswith('//'):
                # Heuristic: clones in return statements might be unnecessary
                if 'return' in line:
                    self.opportunities.append(RefactoringOpportunity(
                        file_path=str(file_path),
                        line_number=line_num,
                        severity=RefactoringSeverity.LOW,
                        category="Performance",
                        title="Potentially Unnecessary Clone",
                        description="Clone operation in return statement might be avoidable",
                        suggestion="Consider if ownership can be transferred instead of cloning",
                        code_snippet=line.strip(),
                        estimated_effort="5-10 minutes",
                        impact="Reduces memory allocations and improves performance"
                    ))
            
            # Check for string allocations in comparisons
            if re.search(r'\.to_string\(\)\s*[=!]=', line):
                self.opportunities.append(RefactoringOpportunity(
                    file_path=str(file_path),
                    line_number=line_num,
                    severity=RefactoringSeverity.MEDIUM,
                    category="Performance",
                    title="Inefficient String Comparison",
                    description="Converting to String for comparison is inefficient",
                    suggestion="Compare with string literals directly or use &str",
                    code_snippet=line.strip(),
                    estimated_effort="2-5 minutes",
                    impact="Reduces unnecessary string allocations"
                ))
    
    def analyze_documentation(self, file_path: Path, content: str):
        """Analyze documentation completeness"""
        lines = content.split('\n')
        
        # Find public functions without documentation
        for i, line in enumerate(lines):
            if re.match(r'\s*pub\s+(async\s+)?fn\s+', line) and not line.strip().startswith('//'):
                line_num = i + 1
                
                # Check if previous lines contain documentation
                has_doc = False
                for j in range(max(0, i-5), i):
                    if '///' in lines[j] or '#[doc' in lines[j]:
                        has_doc = True
                        break
                
                if not has_doc:
                    fn_match = re.search(r'fn\s+([a-zA-Z_][a-zA-Z0-9_]*)', line)
                    if fn_match:
                        function_name = fn_match.group(1)
                        
                        self.opportunities.append(RefactoringOpportunity(
                            file_path=str(file_path),
                            line_number=line_num,
                            severity=RefactoringSeverity.LOW,
                            category="Documentation",
                            title=f"Missing Documentation: {function_name}",
                            description="Public function lacks documentation",
                            suggestion="Add /// documentation comments explaining the function's purpose, parameters, and return value",
                            code_snippet=line.strip(),
                            estimated_effort="5-15 minutes",
                            impact="Improves code maintainability and developer experience"
                        ))
    
    def analyze_security_patterns(self, file_path: Path, content: str):
        """Analyze security-related patterns"""
        lines = content.split('\n')
        
        # Patterns that might indicate security issues
        security_patterns = [
            (r'password\s*[:=]\s*"[^"]*"', "Hardcoded Password", "CRITICAL"),
            (r'secret\s*[:=]\s*"[^"]*"', "Hardcoded Secret", "CRITICAL"),
            (r'token\s*[:=]\s*"[^"]*"', "Hardcoded Token", "HIGH"),
            (r'api[_-]?key\s*[:=]\s*"[^"]*"', "Hardcoded API Key", "HIGH"),
            (r'rand::thread_rng\(\)', "Non-Crypto Random", "MEDIUM"),
        ]
        
        for i, line in enumerate(lines):
            line_num = i + 1
            
            for pattern, title, severity_str in security_patterns:
                if re.search(pattern, line, re.IGNORECASE) and not line.strip().startswith('//'):
                    severity = RefactoringSeverity(severity_str.lower())
                    
                    suggestions = {
                        "Hardcoded Password": "Use environment variables or secure configuration files",
                        "Hardcoded Secret": "Use environment variables or secure vaults",
                        "Hardcoded Token": "Load tokens from secure configuration",
                        "Hardcoded API Key": "Use environment variables for API keys",
                        "Non-Crypto Random": "Use ring::rand for cryptographic operations"
                    }
                    
                    self.opportunities.append(RefactoringOpportunity(
                        file_path=str(file_path),
                        line_number=line_num,
                        severity=severity,
                        category="Security",
                        title=title,
                        description="Potential security vulnerability detected",
                        suggestion=suggestions.get(title, "Review for security implications"),
                        code_snippet=line.strip()[:100],
                        estimated_effort="10-30 minutes",
                        impact="Critical for application security"
                    ))
    
    def analyze_file(self, file_path: Path):
        """Analyze a single Rust file for refactoring opportunities"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            print(f"Analyzing {file_path.relative_to(self.project_root)}...")
            
            # Run all analysis methods
            self.analyze_function_length(file_path, content)
            self.analyze_parameter_count(file_path, content)
            self.analyze_error_handling(file_path, content)
            self.analyze_performance_opportunities(file_path, content)
            self.analyze_documentation(file_path, content)
            self.analyze_security_patterns(file_path, content)
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
    
    def analyze_project(self):
        """Analyze the entire project for refactoring opportunities"""
        print(f"🔍 Analyzing Rust project at {self.project_root}")
        
        rust_files = self.find_rust_files()
        print(f"Found {len(rust_files)} Rust files")
        
        if not rust_files:
            print("No Rust files found!")
            return
        
        # Analyze individual files
        for file_path in rust_files:
            self.analyze_file(file_path)
        
        # Analyze cross-file patterns
        self.analyze_code_duplication(rust_files)
        
        print(f"✅ Analysis complete. Found {len(self.opportunities)} opportunities")
    
    def generate_report(self, output_format: str = "markdown") -> str:
        """Generate a comprehensive refactoring report"""
        if output_format == "json":
            return json.dumps([asdict(opp) for opp in self.opportunities], indent=2)
        
        # Markdown report
        report = [
            "# Refactoring Analysis Report",
            f"*Generated for project: {self.project_root.name}*",
            "",
            f"**Total Opportunities Found:** {len(self.opportunities)}",
            ""
        ]
        
        # Summary by severity
        severity_counts = {}
        category_counts = {}
        
        for opp in self.opportunities:
            severity_counts[opp.severity.value] = severity_counts.get(opp.severity.value, 0) + 1
            category_counts[opp.category] = category_counts.get(opp.category, 0) + 1
        
        report.extend([
            "## Summary",
            "",
            "### By Severity",
            ""
        ])
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}[severity]
                report.append(f"- {emoji} **{severity.title()}**: {count}")
        
        report.extend([
            "",
            "### By Category",
            ""
        ])
        
        for category, count in sorted(category_counts.items()):
            report.append(f"- **{category}**: {count}")
        
        # Detailed opportunities
        report.extend([
            "",
            "## Detailed Analysis",
            ""
        ])
        
        # Sort by severity (critical first) then by file
        sorted_opportunities = sorted(
            self.opportunities,
            key=lambda x: (
                ["critical", "high", "medium", "low", "info"].index(x.severity.value),
                x.file_path,
                x.line_number
            )
        )
        
        current_file = None
        for opp in sorted_opportunities:
            if opp.file_path != current_file:
                current_file = opp.file_path
                rel_path = Path(opp.file_path).relative_to(self.project_root)
                report.extend([
                    f"### 📁 {rel_path}",
                    ""
                ])
            
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠", 
                "medium": "🟡",
                "low": "🔵",
                "info": "⚪"
            }[opp.severity.value]
            
            report.extend([
                f"#### {severity_emoji} {opp.title} (Line {opp.line_number})",
                "",
                f"**Category:** {opp.category}  ",
                f"**Severity:** {opp.severity.value.title()}  ",
                f"**Effort:** {opp.estimated_effort}  ",
                "",
                f"**Description:** {opp.description}",
                "",
                f"**Suggestion:** {opp.suggestion}",
                "",
                "```rust",
                opp.code_snippet,
                "```",
                "",
                f"**Impact:** {opp.impact}",
                "",
                "---",
                ""
            ])
        
        # Add recommendations
        report.extend([
            "## Recommendations",
            "",
            "### Priority Actions",
            ""
        ])
        
        critical_high = [o for o in self.opportunities if o.severity.value in ["critical", "high"]]
        if critical_high:
            report.append("1. **Address Critical & High Severity Issues First**")
            for opp in critical_high[:5]:  # Top 5
                rel_path = Path(opp.file_path).relative_to(self.project_root)
                report.append(f"   - {opp.title} in `{rel_path}:{opp.line_number}`")
            if len(critical_high) > 5:
                report.append(f"   - ... and {len(critical_high) - 5} more")
        
        report.extend([
            "",
            "2. **Focus on High-Impact Categories**"
        ])
        
        high_impact = ["Security", "Error Handling", "Function Design"]
        for category in high_impact:
            count = category_counts.get(category, 0)
            if count > 0:
                report.append(f"   - **{category}**: {count} opportunities")
        
        report.extend([
            "",
            "3. **Gradual Improvement Strategy**",
            "   - Fix 2-3 critical issues per day",
            "   - Address one category at a time",
            "   - Run automated tools after manual fixes",
            "   - Test thoroughly after each batch of changes",
            "",
            "---",
            "",
            f"*Analysis completed with {len(self.opportunities)} total opportunities identified*"
        ])
        
        return "\n".join(report)
    
    def save_report(self, output_path: Optional[str] = None, format: str = "markdown"):
        """Save the refactoring report to a file"""
        if output_path is None:
            ext = "json" if format == "json" else "md"
            output_path = self.project_root / "quality-monitoring" / f"refactoring-analysis.{ext}"
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        report_content = self.generate_report(format)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"📊 Report saved to {output_path}")
        return str(output_path)

def main():
    parser = argparse.ArgumentParser(description="Advanced Rust refactoring analyzer")
    parser.add_argument("--project-root", "-p", default=".", help="Project root directory")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--format", "-f", choices=["markdown", "json"], default="markdown", help="Output format")
    parser.add_argument("--max-function-lines", type=int, default=50, help="Maximum function length")
    parser.add_argument("--max-parameters", type=int, default=5, help="Maximum function parameters")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    try:
        analyzer = RustRefactoringAnalyzer(args.project_root)
        analyzer.max_function_lines = args.max_function_lines
        analyzer.max_parameters = args.max_parameters
        
        # Run analysis
        analyzer.analyze_project()
        
        # Generate and save report
        output_path = analyzer.save_report(args.output, args.format)
        
        # Print summary
        print("\n" + "="*60)
        print("📋 REFACTORING ANALYSIS SUMMARY")
        print("="*60)
        
        severity_counts = {}
        for opp in analyzer.opportunities:
            severity_counts[opp.severity.value] = severity_counts.get(opp.severity.value, 0) + 1
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}[severity]
                print(f"{emoji} {severity.title()}: {count}")
        
        print(f"\n📊 Full report: {output_path}")
        
        # Return appropriate exit code
        critical_count = severity_counts.get("critical", 0)
        high_count = severity_counts.get("high", 0)
        
        if critical_count > 0:
            print(f"\n🚨 {critical_count} critical issues require immediate attention!")
            return 2
        elif high_count > 0:
            print(f"\n⚠️  {high_count} high-priority issues should be addressed soon")
            return 1
        else:
            print("\n✅ No critical issues found!")
            return 0
    
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())