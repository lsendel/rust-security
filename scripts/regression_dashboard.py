#!/usr/bin/env python3
"""
Real-time Regression Testing Dashboard
Provides live monitoring and visualization of regression test results
"""

import json
import time
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
import socketserver

class RegressionDashboard:
    def __init__(self, port=8090):
        self.port = port
        self.data_dir = Path("regression_reports")
        self.baseline_dir = Path("tests/baseline")
        self.dashboard_data = {
            "last_update": None,
            "test_results": [],
            "performance_metrics": {},
            "alerts": [],
            "system_status": "healthy"
        }
        
    def collect_metrics(self):
        """Collect current regression metrics"""
        try:
            # Run quick regression test
            result = subprocess.run([
                "make", "-f", "Makefile.regression", "regression-quick"
            ], capture_output=True, text=True, timeout=300)
            
            # Parse results
            success = result.returncode == 0
            
            # Collect performance data
            metrics = {}
            if self.baseline_dir.exists():
                for baseline_file in self.baseline_dir.glob("*.json"):
                    try:
                        with open(baseline_file) as f:
                            data = json.load(f)
                            metrics[data["metric_name"]] = {
                                "baseline": data["baseline_value"],
                                "tolerance": data["tolerance"],
                                "validations": data["validation_count"],
                                "deviations": data["deviation_count"]
                            }
                    except (json.JSONDecodeError, KeyError):
                        continue
            
            # Update dashboard data
            self.dashboard_data.update({
                "last_update": datetime.now().isoformat(),
                "test_results": [{
                    "timestamp": datetime.now().isoformat(),
                    "success": success,
                    "duration": 0,  # Would be calculated from actual execution
                    "test_count": 5  # Placeholder
                }] + self.dashboard_data["test_results"][:9],  # Keep last 10
                "performance_metrics": metrics,
                "system_status": "healthy" if success else "degraded"
            })
            
            # Check for alerts
            self._check_alerts()
            
        except subprocess.TimeoutExpired:
            self._add_alert("Test execution timeout", "warning")
        except Exception as e:
            self._add_alert(f"Monitoring error: {str(e)}", "error")
    
    def _check_alerts(self):
        """Check for performance alerts"""
        alerts = []
        
        for metric, data in self.dashboard_data["performance_metrics"].items():
            deviation_rate = data["deviations"] / max(data["validations"], 1)
            if deviation_rate > 0.2:  # 20% deviation rate
                alerts.append({
                    "timestamp": datetime.now().isoformat(),
                    "level": "warning",
                    "message": f"{metric}: High deviation rate ({deviation_rate:.1%})"
                })
        
        # Keep only recent alerts (last 24 hours)
        cutoff = datetime.now() - timedelta(hours=24)
        self.dashboard_data["alerts"] = [
            alert for alert in alerts + self.dashboard_data.get("alerts", [])
            if datetime.fromisoformat(alert["timestamp"]) > cutoff
        ][:20]  # Keep max 20 alerts
    
    def _add_alert(self, message, level="info"):
        """Add alert to dashboard"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        }
        self.dashboard_data["alerts"].insert(0, alert)
        self.dashboard_data["alerts"] = self.dashboard_data["alerts"][:20]
    
    def generate_html_dashboard(self):
        """Generate HTML dashboard"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Regression Testing Dashboard</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .status-healthy {{ color: #27ae60; }}
        .status-degraded {{ color: #e74c3c; }}
        .card {{ background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .metric {{ display: inline-block; margin: 10px; padding: 15px; background: #ecf0f1; border-radius: 5px; }}
        .alert-warning {{ background: #f39c12; color: white; padding: 10px; margin: 5px 0; border-radius: 5px; }}
        .alert-error {{ background: #e74c3c; color: white; padding: 10px; margin: 5px 0; border-radius: 5px; }}
        .alert-info {{ background: #3498db; color: white; padding: 10px; margin: 5px 0; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #34495e; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔄 Regression Testing Dashboard</h1>
            <p>Last Update: {self.dashboard_data.get('last_update', 'Never')}</p>
            <p>System Status: <span class="status-{self.dashboard_data['system_status']}">{self.dashboard_data['system_status'].upper()}</span></p>
        </div>
        
        <div class="card">
            <h2>📊 Performance Metrics</h2>
            <div>
                {self._generate_metrics_html()}
            </div>
        </div>
        
        <div class="card">
            <h2>📈 Recent Test Results</h2>
            <table>
                <tr><th>Timestamp</th><th>Status</th><th>Tests</th></tr>
                {self._generate_results_html()}
            </table>
        </div>
        
        <div class="card">
            <h2>🚨 Alerts</h2>
            {self._generate_alerts_html()}
        </div>
    </div>
</body>
</html>
"""
        return html_content
    
    def _generate_metrics_html(self):
        """Generate metrics HTML"""
        html = ""
        for metric, data in self.dashboard_data["performance_metrics"].items():
            deviation_rate = data["deviations"] / max(data["validations"], 1)
            status_color = "#e74c3c" if deviation_rate > 0.2 else "#27ae60"
            
            html += f"""
            <div class="metric">
                <strong>{metric.replace('_', ' ').title()}</strong><br>
                Baseline: {data['baseline']}<br>
                Tolerance: {data['tolerance']:.1%}<br>
                <span style="color: {status_color}">Deviation Rate: {deviation_rate:.1%}</span>
            </div>
            """
        return html
    
    def _generate_results_html(self):
        """Generate test results HTML"""
        html = ""
        for result in self.dashboard_data["test_results"]:
            status = "✅ PASS" if result["success"] else "❌ FAIL"
            status_color = "#27ae60" if result["success"] else "#e74c3c"
            
            html += f"""
            <tr>
                <td>{result['timestamp'][:19]}</td>
                <td style="color: {status_color}">{status}</td>
                <td>{result['test_count']}</td>
            </tr>
            """
        return html
    
    def _generate_alerts_html(self):
        """Generate alerts HTML"""
        if not self.dashboard_data["alerts"]:
            return "<p>No recent alerts</p>"
        
        html = ""
        for alert in self.dashboard_data["alerts"]:
            html += f'<div class="alert-{alert["level"]}">{alert["timestamp"][:19]}: {alert["message"]}</div>'
        
        return html
    
    def save_dashboard(self):
        """Save dashboard HTML to file"""
        dashboard_file = Path("regression_dashboard.html")
        with open(dashboard_file, 'w') as f:
            f.write(self.generate_html_dashboard())
        
        # Also save JSON data
        data_file = Path("dashboard_data.json")
        with open(data_file, 'w') as f:
            json.dump(self.dashboard_data, f, indent=2)
    
    def start_monitoring(self, interval=30):
        """Start continuous monitoring"""
        print(f"🚀 Starting regression monitoring (interval: {interval}s)")
        print(f"📊 Dashboard will be available at: regression_dashboard.html")
        
        while True:
            try:
                print(f"🔄 Collecting metrics at {datetime.now()}")
                self.collect_metrics()
                self.save_dashboard()
                print(f"✅ Dashboard updated - Status: {self.dashboard_data['system_status']}")
                
                time.sleep(interval)
                
            except KeyboardInterrupt:
                print("\n🛑 Monitoring stopped")
                break
            except Exception as e:
                print(f"❌ Monitoring error: {e}")
                time.sleep(interval)

def main():
    dashboard = RegressionDashboard()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "start":
            interval = int(sys.argv[2]) if len(sys.argv) > 2 else 30
            dashboard.start_monitoring(interval)
        
        elif command == "generate":
            dashboard.collect_metrics()
            dashboard.save_dashboard()
            print("📊 Dashboard generated: regression_dashboard.html")
        
        elif command == "status":
            dashboard.collect_metrics()
            status = dashboard.dashboard_data["system_status"]
            print(f"System Status: {status}")
            
            for alert in dashboard.dashboard_data["alerts"][:5]:
                print(f"  {alert['level'].upper()}: {alert['message']}")
    else:
        print("Usage: regression_dashboard.py [start|generate|status] [interval]")

if __name__ == "__main__":
    main()
