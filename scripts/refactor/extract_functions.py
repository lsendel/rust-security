#!/usr/bin/env python3
"""
Function Extraction Tool for Rust Clean Code
Identifies large functions and suggests decomposition strategies.
"""

import os
import re
import ast
from pathlib import Path
from typing import List, Dict, Tuple, NamedTuple
from dataclasses import dataclass
import argparse

@dataclass
class FunctionInfo:
    name: str
    file_path: str
    start_line: int
    end_line: int
    line_count: int
    complexity_score: int
    parameters: List[str]
    return_type: str
    is_async: bool
    visibility: str

class RustFunctionAnalyzer:
    def __init__(self, max_lines: int = 50, max_complexity: int = 10):
        self.max_lines = max_lines
        self.max_complexity = max_complexity
        self.function_pattern = re.compile(
            r'^\s*(pub\s+)?(async\s+)?fn\s+(\w+)\s*\([^)]*\)\s*(?:->\s*[^{]+)?\s*\{',
            re.MULTILINE
        )
        
    def analyze_file(self, file_path: Path) -> List[FunctionInfo]:
        """Analyze a Rust file and extract function information."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return []
            
        functions = []
        lines = content.split('\n')
        
        for match in self.function_pattern.finditer(content):
            func_info = self._extract_function_info(match, lines, str(file_path))
            if func_info:
                functions.append(func_info)
                
        return functions
    
    def _extract_function_info(self, match, lines: List[str], file_path: str) -> FunctionInfo:
        """Extract detailed information about a function."""
        visibility = 'pub' if match.group(1) else 'private'
        is_async = bool(match.group(2))
        name = match.group(3)
        
        # Find function boundaries
        start_line = content[:match.start()].count('\n') + 1
        brace_count = 0
        end_line = start_line
        
        # Find the end of the function by counting braces
        for i, line in enumerate(lines[start_line-1:], start_line):
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0 and i > start_line:
                end_line = i
                break
        
        line_count = end_line - start_line + 1
        
        # Extract parameters and return type from the match
        func_signature = match.group(0)
        parameters = self._extract_parameters(func_signature)
        return_type = self._extract_return_type(func_signature)
        
        # Calculate complexity score (simplified)
        complexity_score = self._calculate_complexity(lines[start_line-1:end_line])
        
        return FunctionInfo(
            name=name,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            line_count=line_count,
            complexity_score=complexity_score,
            parameters=parameters,
            return_type=return_type,
            is_async=is_async,
            visibility=visibility
        )
    
    def _extract_parameters(self, signature: str) -> List[str]:
        """Extract parameter names from function signature."""
        # Simplified parameter extraction
        param_match = re.search(r'\(([^)]*)\)', signature)
        if not param_match:
            return []
            
        params_str = param_match.group(1)
        if not params_str.strip():
            return []
            
        # Split by comma and extract parameter names
        params = []
        for param in params_str.split(','):
            param = param.strip()
            if param and ':' in param:
                param_name = param.split(':')[0].strip()
                # Handle &self, &mut self, self
                if param_name in ['&self', '&mut self', 'self']:
                    params.append(param_name)
                else:
                    params.append(param_name)
        
        return params
    
    def _extract_return_type(self, signature: str) -> str:
        """Extract return type from function signature."""
        return_match = re.search(r'->\s*([^{]+)', signature)
        if return_match:
            return return_match.group(1).strip()
        return 'unit'
    
    def _calculate_complexity(self, function_lines: List[str]) -> int:
        """Calculate cyclomatic complexity (simplified)."""
        complexity = 1  # Base complexity
        
        complexity_keywords = [
            'if', 'else if', 'match', 'while', 'for', 'loop',
            '&&', '||', '?', 'catch', 'try'
        ]
        
        for line in function_lines:
            line = line.strip()
            for keyword in complexity_keywords:
                if keyword in line:
                    complexity += line.count(keyword)
        
        return complexity
    
    def find_large_functions(self, src_dir: Path) -> List[FunctionInfo]:
        """Find all functions that exceed size or complexity thresholds."""
        large_functions = []
        
        for rust_file in src_dir.rglob("*.rs"):
            if 'target' in str(rust_file) or 'tests' in str(rust_file):
                continue
                
            functions = self.analyze_file(rust_file)
            for func in functions:
                if (func.line_count > self.max_lines or 
                    func.complexity_score > self.max_complexity):
                    large_functions.append(func)
        
        return sorted(large_functions, key=lambda f: f.line_count, reverse=True)
    
    def suggest_decomposition(self, func: FunctionInfo) -> Dict[str, str]:
        """Suggest decomposition strategies for a large function."""
        suggestions = {}
        
        if func.line_count > 100:
            suggestions['priority'] = 'HIGH - Critical refactoring needed'
        elif func.line_count > 50:
            suggestions['priority'] = 'MEDIUM - Should be refactored'
        else:
            suggestions['priority'] = 'LOW - Consider refactoring'
        
        # Suggest decomposition strategies
        strategies = []
        
        if func.complexity_score > 15:
            strategies.append("Extract conditional logic into separate functions")
        
        if len(func.parameters) > 7:
            strategies.append("Consider using a configuration struct for parameters")
        
        if func.is_async and func.line_count > 30:
            strategies.append("Split async operations into smaller async functions")
        
        if 'Result' in func.return_type and func.line_count > 40:
            strategies.append("Extract error handling into helper functions")
        
        strategies.append("Apply Single Responsibility Principle")
        strategies.append("Extract pure functions for business logic")
        
        suggestions['strategies'] = strategies
        
        return suggestions

def generate_refactoring_report(functions: List[FunctionInfo], analyzer: RustFunctionAnalyzer) -> str:
    """Generate a comprehensive refactoring report."""
    report = []
    report.append("# 🔧 Function Refactoring Report")
    report.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")
    
    # Summary statistics
    total_functions = len(functions)
    large_functions = [f for f in functions if f.line_count > analyzer.max_lines]
    complex_functions = [f for f in functions if f.complexity_score > analyzer.max_complexity]
    
    report.append("## 📊 Summary")
    report.append(f"- **Total large functions**: {len(large_functions)}")
    report.append(f"- **Complex functions**: {len(complex_functions)}")
    report.append(f"- **Average function size**: {sum(f.line_count for f in functions) / len(functions):.1f} lines")
    report.append("")
    
    # Top offenders
    report.append("## 🎯 Priority Refactoring Targets")
    report.append("")
    
    for i, func in enumerate(functions[:10], 1):
        suggestions = analyzer.suggest_decomposition(func)
        
        report.append(f"### {i}. `{func.name}` - {suggestions['priority']}")
        report.append(f"**File**: `{func.file_path}`")
        report.append(f"**Lines**: {func.line_count} (lines {func.start_line}-{func.end_line})")
        report.append(f"**Complexity**: {func.complexity_score}")
        report.append(f"**Parameters**: {len(func.parameters)}")
        report.append(f"**Async**: {'Yes' if func.is_async else 'No'}")
        report.append("")
        
        report.append("**Refactoring Strategies**:")
        for strategy in suggestions['strategies']:
            report.append(f"- {strategy}")
        report.append("")
        
        # Suggest new function structure
        report.append("**Suggested Structure**:")
        report.append("```rust")
        report.append(f"// Original function: {func.line_count} lines")
        report.append(f"pub {'async ' if func.is_async else ''}fn {func.name}(...) -> {func.return_type} {{")
        report.append("    // Step 1: Validation")
        report.append(f"    let validated_input = validate_{func.name}_input(...)?;")
        report.append("")
        report.append("    // Step 2: Core logic")
        report.append(f"    let result = process_{func.name}_core(&validated_input){'await' if func.is_async else ''}?;")
        report.append("")
        report.append("    // Step 3: Post-processing")
        report.append(f"    finalize_{func.name}_result(result)")
        report.append("}")
        report.append("")
        report.append("// Helper functions (each < 20 lines)")
        report.append(f"fn validate_{func.name}_input(...) -> Result<ValidatedInput, Error> {{ ... }}")
        report.append(f"{'async ' if func.is_async else ''}fn process_{func.name}_core(...) -> Result<ProcessedData, Error> {{ ... }}")
        report.append(f"fn finalize_{func.name}_result(...) -> {func.return_type} {{ ... }}")
        report.append("```")
        report.append("")
    
    return '\n'.join(report)

def main():
    parser = argparse.ArgumentParser(description='Analyze Rust functions for refactoring opportunities')
    parser.add_argument('--src-dir', type=Path, default=Path('src'), 
                       help='Source directory to analyze')
    parser.add_argument('--max-lines', type=int, default=50,
                       help='Maximum lines per function')
    parser.add_argument('--max-complexity', type=int, default=10,
                       help='Maximum cyclomatic complexity')
    parser.add_argument('--output', type=Path, default=Path('refactoring_report.md'),
                       help='Output report file')
    
    args = parser.parse_args()
    
    if not args.src_dir.exists():
        print(f"Error: Source directory {args.src_dir} does not exist")
        return 1
    
    analyzer = RustFunctionAnalyzer(args.max_lines, args.max_complexity)
    large_functions = analyzer.find_large_functions(args.src_dir)
    
    if not large_functions:
        print("✅ No large functions found! Code is well-structured.")
        return 0
    
    print(f"Found {len(large_functions)} functions that need refactoring")
    
    # Generate report
    from datetime import datetime
    report = generate_refactoring_report(large_functions, analyzer)
    
    with open(args.output, 'w') as f:
        f.write(report)
    
    print(f"📄 Report generated: {args.output}")
    
    # Print summary to console
    print("\n🎯 Top 5 Refactoring Priorities:")
    for i, func in enumerate(large_functions[:5], 1):
        print(f"{i}. {func.name} ({func.line_count} lines, complexity {func.complexity_score})")
        print(f"   📁 {func.file_path}:{func.start_line}")
    
    return 0

if __name__ == '__main__':
    exit(main())
