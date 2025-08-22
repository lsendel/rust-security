#!/usr/bin/env python3
"""
NIST 800-53 Compliance Check Script
Validates security controls implementation for the Rust Security Platform
"""

import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Any
import re

class NIST80053Checker:
    """NIST 800-53 compliance checker"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.findings = []
        
        # Define key NIST 800-53 controls relevant to authentication systems
        self.controls = {
            'AC-2': 'Account Management',
            'AC-3': 'Access Enforcement', 
            'AC-6': 'Least Privilege',
            'AC-7': 'Unsuccessful Logon Attempts',
            'AC-8': 'System Use Notification',
            'AC-11': 'Session Lock',
            'AC-12': 'Session Termination',
            'AU-2': 'Event Logging',
            'AU-3': 'Content of Audit Records',
            'AU-6': 'Audit Review, Analysis, and Reporting',
            'AU-12': 'Audit Generation',
            'IA-2': 'Identification and Authentication',
            'IA-3': 'Device Identification and Authentication',
            'IA-4': 'Identifier Management',
            'IA-5': 'Authenticator Management',
            'IA-8': 'Identification and Authentication (Non-Organizational Users)',
            'SC-8': 'Transmission Confidentiality and Integrity',
            'SC-13': 'Cryptographic Protection',
            'SC-23': 'Session Authenticity',
            'SI-4': 'Information System Monitoring',
        }
    
    def check_access_control(self) -> List[Dict[str, Any]]:
        """Check Access Control (AC) family controls"""
        findings = []
        
        # AC-2: Account Management
        auth_service_files = list(self.project_root.glob("**/auth-service/**/*.rs"))
        has_account_mgmt = any(
            self._file_contains_patterns(f, ['user.*create', 'account.*management', 'user.*disable'])
            for f in auth_service_files
        )
        
        if has_account_mgmt:
            findings.append({
                'control': 'AC-2',
                'status': 'IMPLEMENTED',
                'description': 'Account management functionality found in auth-service'
            })
        else:
            findings.append({
                'control': 'AC-2', 
                'status': 'PARTIAL',
                'description': 'Account management implementation needs verification'
            })
        
        # AC-3: Access Enforcement
        policy_files = list(self.project_root.glob("**/policy-service/**/*.rs"))
        has_access_enforcement = any(
            self._file_contains_patterns(f, ['authorize', 'permission', 'access.*control'])
            for f in policy_files
        )
        
        if has_access_enforcement:
            findings.append({
                'control': 'AC-3',
                'status': 'IMPLEMENTED', 
                'description': 'Access enforcement found in policy-service'
            })
        else:
            findings.append({
                'control': 'AC-3',
                'status': 'NOT_IMPLEMENTED',
                'description': 'Access enforcement mechanisms not clearly implemented'
            })
        
        # AC-7: Unsuccessful Logon Attempts
        has_rate_limiting = any(
            self._file_contains_patterns(f, ['rate.*limit', 'failed.*attempt', 'lockout'])
            for f in auth_service_files
        )
        
        findings.append({
            'control': 'AC-7',
            'status': 'IMPLEMENTED' if has_rate_limiting else 'NEEDS_REVIEW',
            'description': 'Rate limiting and failed attempt handling' + 
                          (' found' if has_rate_limiting else ' needs verification')
        })
        
        return findings
    
    def check_audit_accountability(self) -> List[Dict[str, Any]]:
        """Check Audit and Accountability (AU) family controls"""
        findings = []
        
        # AU-2: Event Logging
        all_rust_files = list(self.project_root.glob("**/*.rs"))
        has_logging = any(
            self._file_contains_patterns(f, ['log::', 'tracing::', 'audit'])
            for f in all_rust_files
        )
        
        findings.append({
            'control': 'AU-2',
            'status': 'IMPLEMENTED' if has_logging else 'NOT_IMPLEMENTED',
            'description': 'Event logging infrastructure' + 
                          (' implemented' if has_logging else ' missing')
        })
        
        # AU-3: Content of Audit Records
        has_structured_logging = any(
            self._file_contains_patterns(f, ['structured.*log', 'audit.*record', 'event.*context'])
            for f in all_rust_files
        )
        
        findings.append({
            'control': 'AU-3',
            'status': 'PARTIAL' if has_structured_logging else 'NEEDS_IMPLEMENTATION',
            'description': 'Structured audit record content needs verification'
        })
        
        return findings
    
    def check_identification_authentication(self) -> List[Dict[str, Any]]:
        """Check Identification and Authentication (IA) family controls"""
        findings = []
        
        auth_files = list(self.project_root.glob("**/auth-*/**/*.rs"))
        
        # IA-2: Identification and Authentication
        has_multi_factor = any(
            self._file_contains_patterns(f, ['mfa', 'multi.*factor', 'totp', '2fa'])
            for f in auth_files
        )
        
        findings.append({
            'control': 'IA-2',
            'status': 'IMPLEMENTED' if has_multi_factor else 'PARTIAL',
            'description': 'Multi-factor authentication' + 
                          (' implemented' if has_multi_factor else ' needs full implementation')
        })
        
        # IA-5: Authenticator Management
        has_password_policy = any(
            self._file_contains_patterns(f, ['password.*policy', 'credential.*validation', 'strength'])
            for f in auth_files
        )
        
        findings.append({
            'control': 'IA-5',
            'status': 'IMPLEMENTED' if has_password_policy else 'NEEDS_REVIEW',
            'description': 'Authenticator management and password policies'
        })
        
        return findings
    
    def check_system_communications_protection(self) -> List[Dict[str, Any]]:
        """Check System and Communications Protection (SC) family controls"""
        findings = []
        
        # SC-8: Transmission Confidentiality and Integrity
        config_files = list(self.project_root.glob("**/*.toml")) + list(self.project_root.glob("**/*.yaml"))
        has_tls_config = any(
            self._file_contains_patterns(f, ['tls', 'ssl', 'https', 'certificate'])
            for f in config_files
        )
        
        findings.append({
            'control': 'SC-8',
            'status': 'IMPLEMENTED' if has_tls_config else 'NEEDS_CONFIGURATION',
            'description': 'TLS/HTTPS configuration for secure transmission'
        })
        
        # SC-13: Cryptographic Protection
        rust_files = list(self.project_root.glob("**/*.rs"))
        has_crypto = any(
            self._file_contains_patterns(f, ['crypto', 'encrypt', 'hash', 'jwt', 'bcrypt'])
            for f in rust_files
        )
        
        findings.append({
            'control': 'SC-13',
            'status': 'IMPLEMENTED' if has_crypto else 'NOT_IMPLEMENTED',
            'description': 'Cryptographic protection mechanisms'
        })
        
        return findings
    
    def check_system_information_integrity(self) -> List[Dict[str, Any]]:
        """Check System and Information Integrity (SI) family controls"""
        findings = []
        
        # SI-4: Information System Monitoring
        has_monitoring = (
            (self.project_root / "docker-compose.yml").exists() or
            any(self.project_root.glob("**/prometheus/**")) or
            any(self.project_root.glob("**/grafana/**"))
        )
        
        findings.append({
            'control': 'SI-4',
            'status': 'IMPLEMENTED' if has_monitoring else 'PARTIAL',
            'description': 'System monitoring and observability infrastructure'
        })
        
        return findings
    
    def _file_contains_patterns(self, file_path: Path, patterns: List[str]) -> bool:
        """Check if file contains any of the given patterns"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
                return any(re.search(pattern.lower(), content) for pattern in patterns)
        except Exception:
            return False
    
    def run_compliance_check(self) -> Dict[str, Any]:
        """Run complete NIST 800-53 compliance check"""
        print("🔍 Running NIST 800-53 compliance check...")
        
        all_findings = []
        
        # Check each control family
        all_findings.extend(self.check_access_control())
        all_findings.extend(self.check_audit_accountability())
        all_findings.extend(self.check_identification_authentication())
        all_findings.extend(self.check_system_communications_protection())
        all_findings.extend(self.check_system_information_integrity())
        
        # Calculate compliance summary
        implemented = len([f for f in all_findings if f['status'] == 'IMPLEMENTED'])
        partial = len([f for f in all_findings if f['status'] == 'PARTIAL'])
        needs_review = len([f for f in all_findings if f['status'] in ['NEEDS_REVIEW', 'NEEDS_IMPLEMENTATION', 'NEEDS_CONFIGURATION']])
        not_implemented = len([f for f in all_findings if f['status'] == 'NOT_IMPLEMENTED'])
        
        total = len(all_findings)
        compliance_score = (implemented + (partial * 0.5)) / total * 100 if total > 0 else 0
        
        return {
            'compliance_score': compliance_score,
            'total_controls': total,
            'implemented': implemented,
            'partial': partial,
            'needs_attention': needs_review + not_implemented,
            'findings': all_findings
        }

def generate_compliance_report(results: Dict[str, Any]) -> str:
    """Generate human-readable compliance report"""
    report = []
    report.append("🛡️  NIST 800-53 Compliance Report")
    report.append("=" * 50)
    report.append("")
    
    # Summary
    score = results['compliance_score']
    report.append(f"📊 Compliance Score: {score:.1f}%")
    report.append(f"📋 Total Controls Assessed: {results['total_controls']}")
    report.append(f"✅ Implemented: {results['implemented']}")
    report.append(f"🟡 Partial: {results['partial']}")
    report.append(f"🔴 Needs Attention: {results['needs_attention']}")
    report.append("")
    
    # Status assessment
    if score >= 80:
        report.append("🎯 Status: GOOD - Strong compliance posture")
    elif score >= 60:
        report.append("⚠️  Status: MODERATE - Some gaps need attention")
    else:
        report.append("❌ Status: NEEDS IMPROVEMENT - Significant gaps")
    
    report.append("")
    
    # Detailed findings
    report.append("📋 Detailed Findings:")
    report.append("-" * 30)
    
    for finding in results['findings']:
        status_emoji = {
            'IMPLEMENTED': '✅',
            'PARTIAL': '🟡',
            'NEEDS_REVIEW': '🔍',
            'NEEDS_IMPLEMENTATION': '🔴',
            'NEEDS_CONFIGURATION': '⚙️',
            'NOT_IMPLEMENTED': '❌'
        }.get(finding['status'], '❓')
        
        report.append(f"{status_emoji} {finding['control']}: {finding['description']}")
    
    report.append("")
    
    # Recommendations
    if results['needs_attention'] > 0:
        report.append("💡 Priority Recommendations:")
        report.append("• Implement missing audit logging mechanisms")
        report.append("• Complete multi-factor authentication setup")
        report.append("• Configure TLS/HTTPS for all communications")
        report.append("• Set up comprehensive system monitoring")
        report.append("• Document security control implementations")
    
    return "\n".join(report)

def main():
    """Main function"""
    if len(sys.argv) > 1:
        project_root = Path(sys.argv[1])
    else:
        project_root = Path.cwd()
    
    if not project_root.exists():
        print(f"❌ Project root not found: {project_root}")
        sys.exit(1)
    
    print(f"🔍 Checking NIST 800-53 compliance for: {project_root}")
    
    checker = NIST80053Checker(project_root)
    results = checker.run_compliance_check()
    
    # Generate and display report
    report = generate_compliance_report(results)
    print(report)
    
    # Save report to file
    report_file = project_root / "compliance-report.txt"
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"\n📝 Report saved to: {report_file}")
    
    # Exit with appropriate code based on compliance score
    if results['compliance_score'] >= 70:
        print("✅ Compliance check passed")
        sys.exit(0)
    else:
        print("⚠️  Compliance check needs attention")
        sys.exit(1)

if __name__ == '__main__':
    main()
