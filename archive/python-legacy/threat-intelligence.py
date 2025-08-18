#!/usr/bin/env python3
"""
Supply Chain Threat Intelligence Integration
Integrates with threat intelligence feeds to enhance supply chain security
"""

import json
import requests
import hashlib
import datetime
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatIntelligenceCollector:
    """Collect and analyze threat intelligence for supply chain security"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root).resolve()
        self.cache_dir = self.project_root / ".threat-intel-cache"
        self.cache_dir.mkdir(exist_ok=True)
        
        # Threat intelligence sources
        self.sources = {
            "rustsec": "https://github.com/rustsec/advisory-db",
            "osv": "https://osv.dev/",
            "cve": "https://cve.mitre.org/",
            "github": "https://github.com/advisories"
        }
        
    def collect_intelligence(self) -> Dict[str, Any]:
        """Collect threat intelligence from multiple sources"""
        logger.info("🔍 Collecting threat intelligence...")
        
        intelligence = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "sources": {},
            "vulnerabilities": [],
            "indicators": [],
            "recommendations": []
        }
        
        # Collect from each source
        intelligence["sources"]["rustsec"] = self._collect_rustsec()
        intelligence["sources"]["osv"] = self._collect_osv()
        intelligence["sources"]["github"] = self._collect_github_advisories()
        
        # Analyze collected data
        self._analyze_dependencies(intelligence)
        self._generate_recommendations(intelligence)
        
        return intelligence
    
    def _collect_rustsec(self) -> Dict[str, Any]:
        """Collect RustSec advisory database"""
        logger.info("📡 Collecting RustSec advisories...")
        
        try:
            # Run cargo audit to get vulnerability data
            result = subprocess.run(
                ["cargo", "audit", "--json"],
                cwd=self.project_root,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {"status": "success", "vulnerabilities": []}
            else:
                audit_data = json.loads(result.stdout) if result.stdout else {}
                return {
                    "status": "vulnerabilities_found",
                    "vulnerabilities": audit_data.get("vulnerabilities", []),
                    "warnings": audit_data.get("warnings", [])
                }
                
        except Exception as e:
            logger.error(f"Error collecting RustSec data: {e}")
            return {"status": "error", "error": str(e)}
    
    def _collect_osv(self) -> Dict[str, Any]:
        """Collect OSV (Open Source Vulnerabilities) data"""
        logger.info("📡 Collecting OSV data...")
        
        try:
            # Use OSV scanner if available
            result = subprocess.run(
                ["osv-scanner", "--lockfile=Cargo.lock", "--format=json"],
                cwd=self.project_root,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {"status": "success", "vulnerabilities": []}
            else:
                osv_data = json.loads(result.stdout) if result.stdout else {}
                return {
                    "status": "vulnerabilities_found",
                    "results": osv_data.get("results", [])
                }
                
        except FileNotFoundError:
            logger.warning("OSV scanner not found, skipping OSV collection")
            return {"status": "tool_not_available"}
        except Exception as e:
            logger.error(f"Error collecting OSV data: {e}")
            return {"status": "error", "error": str(e)}
    
    def _collect_github_advisories(self) -> Dict[str, Any]:
        """Collect GitHub Security Advisories"""
        logger.info("📡 Collecting GitHub Security Advisories...")
        
        try:
            # GitHub API endpoint for security advisories
            url = "https://api.github.com/advisories"
            params = {
                "ecosystem": "rust",
                "sort": "updated",
                "per_page": 100
            }
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            advisories = response.json()
            
            # Filter relevant advisories
            relevant_advisories = self._filter_relevant_advisories(advisories)
            
            return {
                "status": "success",
                "advisories": relevant_advisories,
                "total_collected": len(advisories),
                "relevant_count": len(relevant_advisories)
            }
            
        except Exception as e:
            logger.error(f"Error collecting GitHub advisories: {e}")
            return {"status": "error", "error": str(e)}
    
    def _filter_relevant_advisories(self, advisories: List[Dict]) -> List[Dict]:
        """Filter advisories relevant to project dependencies"""
        relevant = []
        
        # Get project dependencies
        dependencies = self._get_project_dependencies()
        
        for advisory in advisories:
            # Check if advisory affects any of our dependencies
            for vuln in advisory.get("vulnerabilities", []):
                package_name = vuln.get("package", {}).get("name", "")
                if package_name in dependencies:
                    relevant.append({
                        "advisory_id": advisory.get("ghsa_id"),
                        "summary": advisory.get("summary"),
                        "severity": advisory.get("severity"),
                        "package": package_name,
                        "affected_versions": vuln.get("vulnerable_version_range"),
                        "patched_versions": vuln.get("patched_versions", []),
                        "published_at": advisory.get("published_at"),
                        "updated_at": advisory.get("updated_at")
                    })
                    break
        
        return relevant
    
    def _get_project_dependencies(self) -> set:
        """Get list of project dependencies"""
        dependencies = set()
        
        try:
            result = subprocess.run(
                ["cargo", "metadata", "--format-version", "1"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                check=True
            )
            
            metadata = json.loads(result.stdout)
            
            for package in metadata.get("packages", []):
                if package.get("source"):  # External dependency
                    dependencies.add(package["name"])
                    
        except Exception as e:
            logger.error(f"Error getting dependencies: {e}")
            
        return dependencies
    
    def _analyze_dependencies(self, intelligence: Dict[str, Any]):
        """Analyze dependencies for security risks"""
        logger.info("🔬 Analyzing dependency security risks...")
        
        # Collect all vulnerabilities from different sources
        all_vulns = []
        
        # RustSec vulnerabilities
        rustsec_data = intelligence["sources"].get("rustsec", {})
        if rustsec_data.get("vulnerabilities"):
            all_vulns.extend(rustsec_data["vulnerabilities"])
        
        # OSV vulnerabilities
        osv_data = intelligence["sources"].get("osv", {})
        if osv_data.get("results"):
            for result in osv_data["results"]:
                all_vulns.extend(result.get("packages", []))
        
        # GitHub advisories
        github_data = intelligence["sources"].get("github", {})
        if github_data.get("advisories"):
            all_vulns.extend(github_data["advisories"])
        
        # Deduplicate and prioritize
        intelligence["vulnerabilities"] = self._deduplicate_vulnerabilities(all_vulns)
        
        # Generate risk indicators
        intelligence["indicators"] = self._generate_risk_indicators(intelligence["vulnerabilities"])
    
    def _deduplicate_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """Deduplicate vulnerabilities from multiple sources"""
        seen = set()
        deduplicated = []
        
        for vuln in vulns:
            # Create a unique identifier for the vulnerability
            identifier = self._create_vuln_identifier(vuln)
            
            if identifier not in seen:
                seen.add(identifier)
                deduplicated.append(vuln)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        deduplicated.sort(key=lambda v: severity_order.get(
            v.get("severity", "unknown").lower(), 4
        ))
        
        return deduplicated
    
    def _create_vuln_identifier(self, vuln: Dict) -> str:
        """Create unique identifier for vulnerability"""
        # Use package name + advisory ID or create hash from content
        package = vuln.get("package", vuln.get("package_name", ""))
        advisory_id = vuln.get("advisory_id", vuln.get("id", vuln.get("ghsa_id", "")))
        
        if package and advisory_id:
            return f"{package}:{advisory_id}"
        
        # Fallback to content hash
        content = json.dumps(vuln, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _generate_risk_indicators(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate risk indicators based on vulnerabilities"""
        indicators = []
        
        # Count vulnerabilities by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Overall risk score (0-100)
        risk_score = (
            severity_counts["critical"] * 40 +
            severity_counts["high"] * 20 +
            severity_counts["medium"] * 10 +
            severity_counts["low"] * 5
        )
        
        indicators.append({
            "type": "overall_risk",
            "score": min(risk_score, 100),
            "severity_breakdown": severity_counts,
            "total_vulnerabilities": sum(severity_counts.values())
        })
        
        # Check for critical vulnerabilities
        if severity_counts["critical"] > 0:
            indicators.append({
                "type": "critical_vulnerabilities",
                "count": severity_counts["critical"],
                "urgency": "immediate",
                "recommended_action": "Address immediately"
            })
        
        # Check for outdated dependencies
        outdated_deps = self._check_outdated_dependencies()
        if outdated_deps:
            indicators.append({
                "type": "outdated_dependencies",
                "count": len(outdated_deps),
                "urgency": "medium",
                "recommended_action": "Update dependencies"
            })
        
        return indicators
    
    def _check_outdated_dependencies(self) -> List[str]:
        """Check for outdated dependencies"""
        try:
            result = subprocess.run(
                ["cargo", "outdated", "--format", "json"],
                cwd=self.project_root,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return []  # No outdated dependencies
            else:
                # Parse outdated dependencies
                return ["example-outdated-dep"]  # Placeholder
                
        except FileNotFoundError:
            logger.warning("cargo-outdated not found")
            return []
        except Exception as e:
            logger.error(f"Error checking outdated dependencies: {e}")
            return []
    
    def _generate_recommendations(self, intelligence: Dict[str, Any]):
        """Generate security recommendations"""
        logger.info("💡 Generating security recommendations...")
        
        recommendations = []
        
        # Vulnerability-based recommendations
        for vuln in intelligence["vulnerabilities"]:
            severity = vuln.get("severity", "unknown").lower()
            
            if severity == "critical":
                recommendations.append({
                    "priority": "critical",
                    "action": f"Immediately update or replace {vuln.get('package', 'affected package')}",
                    "reason": "Critical vulnerability detected",
                    "package": vuln.get("package"),
                    "advisory": vuln.get("advisory_id")
                })
            elif severity == "high":
                recommendations.append({
                    "priority": "high",
                    "action": f"Update {vuln.get('package', 'affected package')} within 7 days",
                    "reason": "High severity vulnerability",
                    "package": vuln.get("package"),
                    "advisory": vuln.get("advisory_id")
                })
        
        # General security recommendations
        recommendations.extend([
            {
                "priority": "medium",
                "action": "Enable automated dependency updates",
                "reason": "Proactive security maintenance"
            },
            {
                "priority": "medium", 
                "action": "Implement continuous security monitoring",
                "reason": "Early threat detection"
            },
            {
                "priority": "low",
                "action": "Regular security audits and penetration testing",
                "reason": "Comprehensive security validation"
            }
        ])
        
        intelligence["recommendations"] = recommendations
    
    def save_intelligence(self, intelligence: Dict[str, Any], output_path: str):
        """Save threat intelligence to file"""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(intelligence, f, indent=2, sort_keys=True)
        
        logger.info(f"✅ Threat intelligence saved to: {output_file}")
    
    def generate_report(self, intelligence: Dict[str, Any]) -> str:
        """Generate human-readable threat intelligence report"""
        
        report = f"""# Threat Intelligence Report

**Generated:** {intelligence['timestamp']}
**Repository:** {self.project_root.name}

## Executive Summary

"""
        
        # Add vulnerability summary
        total_vulns = len(intelligence['vulnerabilities'])
        if total_vulns > 0:
            report += f"⚠️  **{total_vulns} vulnerabilities** detected in supply chain dependencies.\n\n"
            
            # Severity breakdown
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for vuln in intelligence['vulnerabilities']:
                severity = vuln.get('severity', 'unknown').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            report += "**Severity Breakdown:**\n"
            for severity, count in severity_counts.items():
                if count > 0:
                    icon = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡" if severity == "medium" else "🟢"
                    report += f"- {icon} {severity.title()}: {count}\n"
            report += "\n"
        else:
            report += "✅ No vulnerabilities detected in current dependencies.\n\n"
        
        # Add recommendations
        if intelligence['recommendations']:
            report += "## Immediate Actions Required\n\n"
            
            critical_recs = [r for r in intelligence['recommendations'] if r['priority'] == 'critical']
            high_recs = [r for r in intelligence['recommendations'] if r['priority'] == 'high']
            
            if critical_recs:
                report += "### 🔴 Critical (Immediate)\n\n"
                for rec in critical_recs:
                    report += f"- **{rec['action']}**\n"
                    report += f"  - Reason: {rec['reason']}\n"
                    if rec.get('package'):
                        report += f"  - Package: {rec['package']}\n"
                    report += "\n"
            
            if high_recs:
                report += "### 🟠 High Priority (Within 7 days)\n\n"
                for rec in high_recs:
                    report += f"- **{rec['action']}**\n"
                    report += f"  - Reason: {rec['reason']}\n"
                    if rec.get('package'):
                        report += f"  - Package: {rec['package']}\n"
                    report += "\n"
        
        # Add detailed findings
        if intelligence['vulnerabilities']:
            report += "## Detailed Vulnerability Analysis\n\n"
            
            for vuln in intelligence['vulnerabilities'][:10]:  # Top 10
                package = vuln.get('package', vuln.get('package_name', 'Unknown'))
                severity = vuln.get('severity', 'Unknown')
                advisory = vuln.get('advisory_id', vuln.get('id', 'N/A'))
                summary = vuln.get('summary', vuln.get('title', 'No description available'))
                
                report += f"### {package} - {advisory}\n\n"
                report += f"**Severity:** {severity}\n"
                report += f"**Summary:** {summary}\n\n"
        
        return report


def main():
    parser = argparse.ArgumentParser(description="Collect threat intelligence for supply chain security")
    parser.add_argument("--project-root", default=".", help="Project root directory")
    parser.add_argument("--output", default="threat-intelligence.json", help="Output file path")
    parser.add_argument("--report", default="threat-intelligence-report.md", help="Report file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    collector = ThreatIntelligenceCollector(args.project_root)
    
    try:
        # Collect threat intelligence
        intelligence = collector.collect_intelligence()
        
        # Save intelligence data
        collector.save_intelligence(intelligence, args.output)
        
        # Generate and save report
        report = collector.generate_report(intelligence)
        with open(args.report, 'w') as f:
            f.write(report)
        
        logger.info(f"✅ Threat intelligence report saved to: {args.report}")
        
        # Print summary
        total_vulns = len(intelligence['vulnerabilities'])
        critical_count = len([v for v in intelligence['vulnerabilities'] 
                            if v.get('severity', '').lower() == 'critical'])
        
        print(f"\n📊 Threat Intelligence Summary:")
        print(f"  Total Vulnerabilities: {total_vulns}")
        print(f"  Critical: {critical_count}")
        print(f"  Recommendations: {len(intelligence['recommendations'])}")
        
        if critical_count > 0:
            print(f"\n🚨 {critical_count} CRITICAL vulnerabilities require immediate attention!")
            sys.exit(1)
        
    except Exception as e:
        logger.error(f"❌ Error collecting threat intelligence: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
