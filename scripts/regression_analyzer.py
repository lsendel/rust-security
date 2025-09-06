#!/usr/bin/env python3
"""
Advanced Regression Test Analyzer
Provides trend analysis, anomaly detection, and intelligent reporting
"""

import json
import sys
import os
from datetime import datetime, timedelta
from pathlib import Path
import statistics
from typing import Dict, List, Any, Optional

class RegressionAnalyzer:
    def __init__(self, baseline_dir: str = "tests/baseline", reports_dir: str = "regression_reports"):
        self.baseline_dir = Path(baseline_dir)
        self.reports_dir = Path(reports_dir)
        self.thresholds = {
            "performance_degradation": 0.15,  # 15% performance degradation threshold
            "success_rate": 0.95,  # 95% minimum success rate
            "anomaly_score": 2.0   # Standard deviations for anomaly detection
        }
    
    def analyze_trends(self, metric_name: str, days: int = 7) -> Dict[str, Any]:
        """Analyze performance trends over specified days"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        # Collect historical data
        historical_data = []
        for report_file in self.reports_dir.glob(f"*{metric_name}*.json"):
            try:
                with open(report_file) as f:
                    data = json.load(f)
                    timestamp = datetime.fromisoformat(data.get('timestamp', ''))
                    if timestamp >= cutoff_date:
                        historical_data.append({
                            'timestamp': timestamp,
                            'value': data.get('value', 0),
                            'success': data.get('success', True)
                        })
            except (json.JSONDecodeError, ValueError):
                continue
        
        if not historical_data:
            return {"status": "insufficient_data", "message": f"No data found for {metric_name}"}
        
        # Calculate trend metrics
        values = [d['value'] for d in historical_data]
        success_rate = sum(1 for d in historical_data if d['success']) / len(historical_data)
        
        trend_analysis = {
            "metric": metric_name,
            "period_days": days,
            "data_points": len(historical_data),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "std_dev": statistics.stdev(values) if len(values) > 1 else 0,
            "min": min(values),
            "max": max(values),
            "success_rate": success_rate,
            "trend": self._calculate_trend(historical_data),
            "anomalies": self._detect_anomalies(values),
            "status": "healthy" if success_rate >= self.thresholds["success_rate"] else "degraded"
        }
        
        return trend_analysis
    
    def _calculate_trend(self, data: List[Dict]) -> str:
        """Calculate trend direction using linear regression"""
        if len(data) < 3:
            return "insufficient_data"
        
        # Simple trend calculation using first and last quartile
        sorted_data = sorted(data, key=lambda x: x['timestamp'])
        n = len(sorted_data)
        first_quarter = sorted_data[:n//4] if n >= 4 else sorted_data[:1]
        last_quarter = sorted_data[-n//4:] if n >= 4 else sorted_data[-1:]
        
        first_avg = statistics.mean(d['value'] for d in first_quarter)
        last_avg = statistics.mean(d['value'] for d in last_quarter)
        
        change_percent = ((last_avg - first_avg) / first_avg) * 100 if first_avg > 0 else 0
        
        if abs(change_percent) < 5:
            return "stable"
        elif change_percent > 0:
            return "improving" if "latency" not in data[0].get('metric', '') else "degrading"
        else:
            return "degrading" if "latency" not in data[0].get('metric', '') else "improving"
    
    def _detect_anomalies(self, values: List[float]) -> List[int]:
        """Detect anomalies using statistical methods"""
        if len(values) < 3:
            return []
        
        mean = statistics.mean(values)
        std_dev = statistics.stdev(values)
        threshold = self.thresholds["anomaly_score"]
        
        anomalies = []
        for i, value in enumerate(values):
            z_score = abs((value - mean) / std_dev) if std_dev > 0 else 0
            if z_score > threshold:
                anomalies.append(i)
        
        return anomalies
    
    def generate_report(self, output_file: str = None) -> Dict[str, Any]:
        """Generate comprehensive regression analysis report"""
        metrics = ["auth_latency", "db_query_time", "jwt_generation", "memory_usage"]
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "analysis": {},
            "summary": {
                "total_metrics": len(metrics),
                "healthy_metrics": 0,
                "degraded_metrics": 0,
                "overall_status": "healthy"
            },
            "recommendations": []
        }
        
        for metric in metrics:
            analysis = self.analyze_trends(metric)
            report["analysis"][metric] = analysis
            
            if analysis.get("status") == "healthy":
                report["summary"]["healthy_metrics"] += 1
            else:
                report["summary"]["degraded_metrics"] += 1
        
        # Overall status
        if report["summary"]["degraded_metrics"] > 0:
            report["summary"]["overall_status"] = "attention_required"
        
        # Generate recommendations
        report["recommendations"] = self._generate_recommendations(report["analysis"])
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
        
        return report
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        for metric, data in analysis.items():
            if data.get("status") == "degraded":
                recommendations.append(f"⚠️  {metric}: Success rate below threshold ({data.get('success_rate', 0):.2%})")
            
            if data.get("trend") == "degrading":
                recommendations.append(f"📉 {metric}: Performance degrading trend detected")
            
            if data.get("anomalies"):
                recommendations.append(f"🔍 {metric}: {len(data['anomalies'])} anomalies detected - investigate recent changes")
        
        if not recommendations:
            recommendations.append("✅ All metrics within acceptable ranges")
        
        return recommendations

def main():
    analyzer = RegressionAnalyzer()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "analyze":
            metric = sys.argv[2] if len(sys.argv) > 2 else "auth_latency"
            days = int(sys.argv[3]) if len(sys.argv) > 3 else 7
            result = analyzer.analyze_trends(metric, days)
            print(json.dumps(result, indent=2))
        
        elif command == "report":
            output_file = sys.argv[2] if len(sys.argv) > 2 else "regression_analysis_report.json"
            report = analyzer.generate_report(output_file)
            print(f"📊 Analysis report generated: {output_file}")
            print(f"Overall Status: {report['summary']['overall_status']}")
            
            for rec in report["recommendations"]:
                print(rec)
    else:
        print("Usage: regression_analyzer.py [analyze|report] [options]")

if __name__ == "__main__":
    main()
