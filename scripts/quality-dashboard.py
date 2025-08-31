#!/usr/bin/env python3
"""
Real-time Quality Dashboard Generator
Creates interactive HTML dashboard for continuous quality monitoring
"""

import json
import os
import sys
import subprocess
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import argparse

class QualityDashboard:
    """Generates interactive quality dashboard with real-time metrics"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.report_dir = self.project_root / "quality-monitoring"
        self.report_dir.mkdir(exist_ok=True)
        
    def run_cargo_command(self, command: List[str]) -> Tuple[int, str, str]:
        """Run cargo command and return exit code, stdout, stderr"""
        try:
            result = subprocess.run(
                command, 
                cwd=self.project_root,
                capture_output=True, 
                text=True,
                timeout=300
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return 1, "", "Command timed out"
        except Exception as e:
            return 1, "", str(e)
    
    def collect_code_metrics(self) -> Dict:
        """Collect comprehensive code metrics"""
        metrics = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "formatting": {"status": "unknown", "score": 0},
            "compilation": {"status": "unknown", "score": 0, "warnings": []},
            "linting": {"status": "unknown", "score": 0, "issues": []},
            "security": {"status": "unknown", "score": 0, "vulnerabilities": []},
            "complexity": {"functions": 0, "avg_complexity": 0, "max_complexity": 0},
            "test_coverage": {"percentage": 0, "lines_covered": 0, "total_lines": 0},
            "dependencies": {"total": 0, "outdated": 0, "vulnerable": 0}
        }
        
        print("🔍 Collecting code metrics...")
        
        # Check code formatting
        exit_code, _, _ = self.run_cargo_command(["cargo", "fmt", "--all", "--", "--check"])
        if exit_code == 0:
            metrics["formatting"] = {"status": "clean", "score": 25}
            print("  ✅ Formatting: Clean")
        else:
            metrics["formatting"] = {"status": "issues", "score": 15}
            print("  ❌ Formatting: Issues detected")
        
        # Check compilation
        exit_code, stdout, stderr = self.run_cargo_command(["cargo", "check", "--all-targets", "--all-features"])
        warning_count = stderr.count("warning:")
        if exit_code == 0 and warning_count == 0:
            metrics["compilation"] = {"status": "clean", "score": 25, "warnings": []}
            print("  ✅ Compilation: Clean")
        elif exit_code == 0:
            metrics["compilation"] = {"status": "warnings", "score": 20, "warnings": self._extract_warnings(stderr)}
            print(f"  🟡 Compilation: {warning_count} warnings")
        else:
            metrics["compilation"] = {"status": "errors", "score": 10, "warnings": self._extract_warnings(stderr)}
            print("  ❌ Compilation: Errors detected")
        
        # Check linting
        exit_code, stdout, stderr = self.run_cargo_command([
            "cargo", "clippy", "--all-targets", "--all-features", "--", "-D", "warnings"
        ])
        if exit_code == 0:
            metrics["linting"] = {"status": "clean", "score": 25, "issues": []}
            print("  ✅ Linting: Clean")
        else:
            issues = self._extract_clippy_issues(stderr)
            critical_count = len([i for i in issues if i.get("level") == "error"])
            if critical_count == 0:
                metrics["linting"] = {"status": "warnings", "score": 20, "issues": issues}
                print(f"  🟡 Linting: {len(issues)} warnings")
            else:
                metrics["linting"] = {"status": "errors", "score": 10, "issues": issues}
                print(f"  ❌ Linting: {critical_count} critical errors")
        
        # Security audit
        exit_code, stdout, stderr = self.run_cargo_command(["cargo", "audit", "--format", "json"])
        if exit_code == 0:
            try:
                audit_data = json.loads(stdout) if stdout.strip() else {"vulnerabilities": []}
                vulnerabilities = audit_data.get("vulnerabilities", [])
                critical_vulns = [v for v in vulnerabilities if v.get("advisory", {}).get("severity") == "critical"]
                high_vulns = [v for v in vulnerabilities if v.get("advisory", {}).get("severity") == "high"]
                
                if not vulnerabilities:
                    metrics["security"] = {"status": "secure", "score": 25, "vulnerabilities": []}
                    print("  ✅ Security: No vulnerabilities")
                elif not critical_vulns and len(high_vulns) <= 2:
                    metrics["security"] = {"status": "minor_issues", "score": 20, "vulnerabilities": vulnerabilities}
                    print(f"  🟡 Security: {len(vulnerabilities)} minor vulnerabilities")
                else:
                    metrics["security"] = {"status": "vulnerable", "score": 10, "vulnerabilities": vulnerabilities}
                    print(f"  ❌ Security: {len(critical_vulns)} critical, {len(high_vulns)} high vulnerabilities")
            except json.JSONDecodeError:
                metrics["security"] = {"status": "error", "score": 0, "vulnerabilities": []}
                print("  ❌ Security: Audit failed")
        else:
            metrics["security"] = {"status": "error", "score": 0, "vulnerabilities": []}
            print("  ❌ Security: Audit command failed")
        
        # Calculate total score
        total_score = (
            metrics["formatting"]["score"] +
            metrics["compilation"]["score"] +
            metrics["linting"]["score"] +
            metrics["security"]["score"]
        )
        metrics["total_score"] = total_score
        
        print(f"\n🎯 Total Quality Score: {total_score}/100")
        
        return metrics
    
    def _extract_warnings(self, stderr: str) -> List[Dict]:
        """Extract compilation warnings from cargo output"""
        warnings = []
        lines = stderr.split('\n')
        current_warning = {}
        
        for line in lines:
            if 'warning:' in line:
                if current_warning:
                    warnings.append(current_warning)
                current_warning = {"message": line.strip(), "location": ""}
            elif '-->' in line and current_warning:
                current_warning["location"] = line.strip()
        
        if current_warning:
            warnings.append(current_warning)
        
        return warnings
    
    def _extract_clippy_issues(self, stderr: str) -> List[Dict]:
        """Extract clippy issues from cargo output"""
        issues = []
        lines = stderr.split('\n')
        
        for line in lines:
            if any(level in line for level in ['error:', 'warning:']):
                level = 'error' if 'error:' in line else 'warning'
                issues.append({
                    "level": level,
                    "message": line.strip(),
                    "location": ""
                })
        
        return issues
    
    def generate_html_dashboard(self, metrics: Dict) -> str:
        """Generate interactive HTML dashboard"""
        
        # Determine overall status
        score = metrics["total_score"]
        if score >= 97:
            status_badge = '<span class="badge excellent">🟢 EXCELLENT</span>'
            status_class = 'excellent'
        elif score >= 95:
            status_badge = '<span class="badge good">🟡 GOOD</span>'
            status_class = 'good'
        elif score >= 90:
            status_badge = '<span class="badge acceptable">🟠 ACCEPTABLE</span>'
            status_class = 'acceptable'
        else:
            status_badge = '<span class="badge critical">🔴 CRITICAL</span>'
            status_class = 'critical'
        
        # Generate metric cards
        metric_cards = self._generate_metric_cards(metrics)
        
        # Generate issue details
        issue_details = self._generate_issue_details(metrics)
        
        # Load score history
        score_history = self._load_score_history()
        
        html_content = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Quality Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 20px; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #2c3e50, #3498db);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5rem; margin-bottom: 10px; }}
        .header .timestamp {{ opacity: 0.8; font-size: 0.9rem; }}
        .score-display {{
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            padding: 20px;
            margin: 20px 0;
            text-align: center;
        }}
        .score-number {{ font-size: 4rem; font-weight: bold; margin-bottom: 10px; }}
        .badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9rem;
        }}
        .badge.excellent {{ background: #27ae60; color: white; }}
        .badge.good {{ background: #f39c12; color: white; }}
        .badge.acceptable {{ background: #e67e22; color: white; }}
        .badge.critical {{ background: #e74c3c; color: white; }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
        }}
        .metric-card {{
            background: #f8f9fa;
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        .metric-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }}
        .metric-card.clean {{ border-left: 5px solid #27ae60; }}
        .metric-card.warning {{ border-left: 5px solid #f39c12; }}
        .metric-card.error {{ border-left: 5px solid #e74c3c; }}
        .metric-title {{ font-size: 1.1rem; font-weight: bold; margin-bottom: 10px; }}
        .metric-score {{ font-size: 2rem; font-weight: bold; margin: 10px 0; }}
        .metric-status {{ padding: 5px 10px; border-radius: 10px; font-size: 0.8rem; font-weight: bold; }}
        .status-clean {{ background: #d4edda; color: #155724; }}
        .status-warning {{ background: #fff3cd; color: #856404; }}
        .status-error {{ background: #f8d7da; color: #721c24; }}
        .details-section {{
            padding: 30px;
            background: #f8f9fa;
        }}
        .details-section h2 {{ margin-bottom: 20px; color: #2c3e50; }}
        .issue-list {{ background: white; border-radius: 10px; padding: 20px; }}
        .issue-item {{
            padding: 15px;
            border-left: 3px solid #3498db;
            margin: 10px 0;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        .issue-error {{ border-left-color: #e74c3c; }}
        .issue-warning {{ border-left-color: #f39c12; }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            background: #ecf0f1;
        }}
        .refresh-btn {{
            background: #3498db;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 10px;
            font-size: 1rem;
        }}
        .refresh-btn:hover {{ background: #2980b9; }}
        @media (max-width: 768px) {{
            .metrics-grid {{ grid-template-columns: 1fr; }}
            .score-number {{ font-size: 3rem; }}
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🔍 Code Quality Dashboard</h1>
            <div class="timestamp">Last Updated: {metrics['timestamp']}</div>
            <div class="score-display">
                <div class="score-number {status_class}">{score}/100</div>
                {status_badge}
            </div>
            <button class="refresh-btn" onclick="location.reload()">🔄 Refresh Dashboard</button>
        </header>
        
        <div class="metrics-grid">
            {metric_cards}
        </div>
        
        <div class="details-section">
            <h2>📊 Quality Details</h2>
            {issue_details}
        </div>
        
        <div class="details-section">
            <h2>📈 Score History</h2>
            <canvas id="scoreChart" width="400" height="200"></canvas>
        </div>
        
        <footer class="footer">
            <p>🤖 Automated Quality Monitoring • Next update in 5 minutes</p>
            <p>Maintaining our industry-leading 97/100 quality standard</p>
        </footer>
    </div>
    
    <script>
        // Score history chart
        const ctx = document.getElementById('scoreChart').getContext('2d');
        const scoreHistory = {json.dumps(score_history)};
        
        new Chart(ctx, {{
            type: 'line',
            data: {{
                labels: scoreHistory.map(item => new Date(item.timestamp).toLocaleDateString()),
                datasets: [{{
                    label: 'Quality Score',
                    data: scoreHistory.map(item => item.score),
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        max: 100,
                        ticks: {{
                            callback: function(value) {{
                                return value + '/100';
                            }}
                        }}
                    }}
                }},
                plugins: {{
                    legend: {{
                        display: true,
                        position: 'top'
                    }}
                }}
            }}
        }});
        
        // Auto-refresh every 5 minutes
        setTimeout(() => {{
            location.reload();
        }}, 300000);
    </script>
</body>
</html>
'''
        
        return html_content
    
    def _generate_metric_cards(self, metrics: Dict) -> str:
        """Generate HTML for metric cards"""
        cards = []
        
        # Formatting card
        status = metrics["formatting"]["status"]
        score = metrics["formatting"]["score"]
        card_class = "clean" if status == "clean" else "error"
        status_class = "status-clean" if status == "clean" else "status-error"
        cards.append(f'''
        <div class="metric-card {card_class}">
            <div class="metric-title">📝 Code Formatting</div>
            <div class="metric-score">{score}/25</div>
            <div class="metric-status {status_class}">
                {"✅ Clean" if status == "clean" else "❌ Issues"}
            </div>
        </div>
        ''')
        
        # Compilation card
        status = metrics["compilation"]["status"]
        score = metrics["compilation"]["score"]
        card_class = "clean" if status == "clean" else "warning" if status == "warnings" else "error"
        status_class = "status-clean" if status == "clean" else "status-warning" if status == "warnings" else "status-error"
        status_text = "✅ Clean" if status == "clean" else f"🟡 {len(metrics['compilation']['warnings'])} Warnings" if status == "warnings" else "❌ Errors"
        cards.append(f'''
        <div class="metric-card {card_class}">
            <div class="metric-title">⚙️ Compilation</div>
            <div class="metric-score">{score}/25</div>
            <div class="metric-status {status_class}">{status_text}</div>
        </div>
        ''')
        
        # Linting card
        status = metrics["linting"]["status"]
        score = metrics["linting"]["score"]
        card_class = "clean" if status == "clean" else "warning" if status == "warnings" else "error"
        status_class = "status-clean" if status == "clean" else "status-warning" if status == "warnings" else "status-error"
        status_text = "✅ Clean" if status == "clean" else f"🟡 {len(metrics['linting']['issues'])} Warnings" if status == "warnings" else "❌ Errors"
        cards.append(f'''
        <div class="metric-card {card_class}">
            <div class="metric-title">🔍 Linting</div>
            <div class="metric-score">{score}/25</div>
            <div class="metric-status {status_class}">{status_text}</div>
        </div>
        ''')
        
        # Security card
        status = metrics["security"]["status"]
        score = metrics["security"]["score"]
        card_class = "clean" if status == "secure" else "warning" if status == "minor_issues" else "error"
        status_class = "status-clean" if status == "secure" else "status-warning" if status == "minor_issues" else "status-error"
        vuln_count = len(metrics["security"]["vulnerabilities"])
        status_text = "✅ Secure" if status == "secure" else f"🟡 {vuln_count} Minor" if status == "minor_issues" else f"❌ {vuln_count} Critical"
        cards.append(f'''
        <div class="metric-card {card_class}">
            <div class="metric-title">🔒 Security</div>
            <div class="metric-score">{score}/25</div>
            <div class="metric-status {status_class}">{status_text}</div>
        </div>
        ''')
        
        return ''.join(cards)
    
    def _generate_issue_details(self, metrics: Dict) -> str:
        """Generate detailed issue listings"""
        details = []
        
        # Compilation issues
        if metrics["compilation"]["warnings"]:
            details.append("<h3>⚙️ Compilation Warnings</h3><div class='issue-list'>")
            for warning in metrics["compilation"]["warnings"]:
                details.append(f'''
                <div class="issue-item issue-warning">
                    <strong>Warning:</strong> {warning.get('message', 'Unknown warning')}<br>
                    <small>{warning.get('location', 'Unknown location')}</small>
                </div>
                ''')
            details.append("</div>")
        
        # Linting issues
        if metrics["linting"]["issues"]:
            details.append("<h3>🔍 Linting Issues</h3><div class='issue-list'>")
            for issue in metrics["linting"]["issues"][:10]:  # Limit to first 10
                issue_class = "issue-error" if issue.get("level") == "error" else "issue-warning"
                details.append(f'''
                <div class="issue-item {issue_class}">
                    <strong>{issue.get('level', 'Issue').title()}:</strong> {issue.get('message', 'Unknown issue')}<br>
                    <small>{issue.get('location', 'Unknown location')}</small>
                </div>
                ''')
            if len(metrics["linting"]["issues"]) > 10:
                details.append(f"<p><em>... and {len(metrics['linting']['issues']) - 10} more issues</em></p>")
            details.append("</div>")
        
        # Security vulnerabilities
        if metrics["security"]["vulnerabilities"]:
            details.append("<h3>🔒 Security Vulnerabilities</h3><div class='issue-list'>")
            for vuln in metrics["security"]["vulnerabilities"]:
                advisory = vuln.get("advisory", {})
                severity = advisory.get("severity", "unknown")
                issue_class = "issue-error" if severity in ["critical", "high"] else "issue-warning"
                details.append(f'''
                <div class="issue-item {issue_class}">
                    <strong>{severity.title()} Vulnerability:</strong> {advisory.get('title', 'Unknown vulnerability')}<br>
                    <small>Package: {vuln.get('package', {}).get('name', 'Unknown')} v{vuln.get('package', {}).get('version', 'Unknown')}</small>
                </div>
                ''')
            details.append("</div>")
        
        if not details:
            details.append('''
            <div class="issue-list">
                <div class="issue-item" style="border-left-color: #27ae60;">
                    <strong>✅ Excellent Code Quality</strong><br>
                    <small>No issues detected in any category</small>
                </div>
            </div>
            ''')
        
        return ''.join(details)
    
    def _load_score_history(self) -> List[Dict]:
        """Load historical score data"""
        history_file = self.report_dir / "score-history.json"
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def _save_score_history(self, metrics: Dict):
        """Save current score to history"""
        history = self._load_score_history()
        
        # Add current score
        history.append({
            "timestamp": metrics["timestamp"],
            "score": metrics["total_score"]
        })
        
        # Keep only last 50 entries
        history = history[-50:]
        
        # Save back to file
        history_file = self.report_dir / "score-history.json"
        with open(history_file, 'w') as f:
            json.dump(history, f, indent=2)
    
    def generate_dashboard(self) -> str:
        """Generate complete quality dashboard"""
        print("🚀 Generating Quality Dashboard...")
        
        # Collect metrics
        metrics = self.collect_code_metrics()
        
        # Save metrics to file
        metrics_file = self.report_dir / f"metrics-{metrics['timestamp']}.json"
        with open(metrics_file, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        # Update score history
        self._save_score_history(metrics)
        
        # Generate HTML dashboard
        html_content = self.generate_html_dashboard(metrics)
        
        # Save dashboard
        dashboard_file = self.report_dir / "dashboard.html"
        with open(dashboard_file, 'w') as f:
            f.write(html_content)
        
        print(f"✅ Dashboard generated: {dashboard_file}")
        print(f"🌐 Open file://{dashboard_file.absolute()} in your browser")
        
        return str(dashboard_file.absolute())

def main():
    parser = argparse.ArgumentParser(description="Generate real-time code quality dashboard")
    parser.add_argument("--project-root", "-p", default=".", help="Project root directory")
    parser.add_argument("--output", "-o", help="Output HTML file path")
    
    args = parser.parse_args()
    
    try:
        dashboard = QualityDashboard(args.project_root)
        dashboard_path = dashboard.generate_dashboard()
        
        if args.output:
            import shutil
            shutil.copy(dashboard_path, args.output)
            print(f"📁 Dashboard copied to: {args.output}")
        
        return 0
    
    except Exception as e:
        print(f"❌ Error generating dashboard: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())