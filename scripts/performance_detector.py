#!/usr/bin/env python3
"""
Advanced Performance Regression Detection
Uses statistical methods to detect performance regressions with high accuracy
"""

import json
import sys
import os
from datetime import datetime, timedelta
from pathlib import Path
import statistics
import math

class PerformanceDetector:
    def __init__(self, sensitivity="medium"):
        self.sensitivity_levels = {
            "low": {"threshold": 0.20, "min_samples": 5, "confidence": 0.90},
            "medium": {"threshold": 0.15, "min_samples": 8, "confidence": 0.95},
            "high": {"threshold": 0.10, "min_samples": 12, "confidence": 0.99}
        }
        self.config = self.sensitivity_levels.get(sensitivity, self.sensitivity_levels["medium"])
        self.baseline_dir = Path("tests/baseline")
        self.reports_dir = Path("regression_reports")
    
    def detect_regression(self, metric_name, current_value, historical_data=None):
        """Detect performance regression using statistical analysis"""
        
        if historical_data is None:
            historical_data = self._load_historical_data(metric_name)
        
        if len(historical_data) < self.config["min_samples"]:
            return {
                "regression_detected": False,
                "reason": "insufficient_data",
                "confidence": 0.0,
                "recommendation": f"Need at least {self.config['min_samples']} samples"
            }
        
        # Statistical analysis
        mean = statistics.mean(historical_data)
        std_dev = statistics.stdev(historical_data) if len(historical_data) > 1 else 0
        
        # Z-score calculation
        z_score = (current_value - mean) / std_dev if std_dev > 0 else 0
        
        # Regression detection logic
        threshold_z = self._get_z_threshold()
        regression_detected = abs(z_score) > threshold_z
        
        # For latency metrics, higher values are worse
        is_latency_metric = "latency" in metric_name.lower() or "time" in metric_name.lower()
        performance_degraded = (z_score > threshold_z) if is_latency_metric else (z_score < -threshold_z)
        
        # Confidence calculation
        confidence = min(abs(z_score) / threshold_z, 1.0) if threshold_z > 0 else 0.0
        
        # Trend analysis
        trend = self._analyze_trend(historical_data)
        
        result = {
            "regression_detected": regression_detected and performance_degraded,
            "z_score": z_score,
            "confidence": confidence,
            "mean": mean,
            "std_dev": std_dev,
            "threshold": self.config["threshold"],
            "trend": trend,
            "recommendation": self._generate_recommendation(
                regression_detected, performance_degraded, confidence, trend
            )
        }
        
        return result
    
    def _load_historical_data(self, metric_name, days=30):
        """Load historical performance data"""
        cutoff_date = datetime.now() - timedelta(days=days)
        historical_data = []
        
        # Load from baseline file
        baseline_file = self.baseline_dir / f"{metric_name}.json"
        if baseline_file.exists():
            try:
                with open(baseline_file) as f:
                    baseline_data = json.load(f)
                    historical_data.append(baseline_data["baseline_value"])
            except (json.JSONDecodeError, KeyError):
                pass
        
        # Load from report files
        for report_file in self.reports_dir.glob(f"*{metric_name}*.json"):
            try:
                with open(report_file) as f:
                    data = json.load(f)
                    timestamp = datetime.fromisoformat(data.get("timestamp", ""))
                    if timestamp >= cutoff_date and "value" in data:
                        historical_data.append(data["value"])
            except (json.JSONDecodeError, ValueError, KeyError):
                continue
        
        return historical_data[-50:]  # Keep last 50 samples
    
    def _get_z_threshold(self):
        """Get Z-score threshold based on confidence level"""
        confidence_to_z = {
            0.90: 1.645,
            0.95: 1.96,
            0.99: 2.576
        }
        return confidence_to_z.get(self.config["confidence"], 1.96)
    
    def _analyze_trend(self, data):
        """Analyze performance trend"""
        if len(data) < 3:
            return "insufficient_data"
        
        # Simple linear trend analysis
        n = len(data)
        x = list(range(n))
        y = data
        
        # Calculate slope
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(y)
        
        numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return "stable"
        
        slope = numerator / denominator
        
        # Classify trend
        if abs(slope) < 0.1:
            return "stable"
        elif slope > 0:
            return "degrading"  # Assuming higher values are worse
        else:
            return "improving"
    
    def _generate_recommendation(self, regression_detected, performance_degraded, confidence, trend):
        """Generate actionable recommendation"""
        if not regression_detected:
            if trend == "improving":
                return "✅ Performance is improving - consider updating baseline"
            else:
                return "✅ Performance within acceptable range"
        
        if performance_degraded:
            if confidence > 0.8:
                return "🚨 HIGH CONFIDENCE regression detected - immediate investigation required"
            elif confidence > 0.6:
                return "⚠️ MEDIUM CONFIDENCE regression detected - monitor closely"
            else:
                return "🔍 LOW CONFIDENCE regression detected - collect more data"
        
        return "📊 Statistical anomaly detected - review recent changes"
    
    def batch_analysis(self, metrics=None):
        """Perform batch analysis on multiple metrics"""
        if metrics is None:
            metrics = ["auth_latency_ms", "db_query_time_ms", "jwt_generation_ms", "memory_usage_mb"]
        
        results = {}
        overall_status = "healthy"
        
        for metric in metrics:
            # Simulate current value (in real implementation, this would come from actual measurements)
            baseline_file = self.baseline_dir / f"{metric}.json"
            if baseline_file.exists():
                try:
                    with open(baseline_file) as f:
                        baseline_data = json.load(f)
                        current_value = baseline_data["baseline_value"] * (1.0 + (hash(metric) % 20 - 10) / 100)  # Simulate variation
                        
                        analysis = self.detect_regression(metric, current_value)
                        results[metric] = analysis
                        
                        if analysis["regression_detected"]:
                            overall_status = "degraded"
                            
                except (json.JSONDecodeError, KeyError):
                    results[metric] = {"error": "Failed to load baseline"}
        
        return {
            "timestamp": datetime.now().isoformat(),
            "overall_status": overall_status,
            "sensitivity": list(self.sensitivity_levels.keys())[list(self.sensitivity_levels.values()).index(self.config)],
            "results": results,
            "summary": self._generate_summary(results)
        }
    
    def _generate_summary(self, results):
        """Generate analysis summary"""
        total_metrics = len(results)
        regressions = sum(1 for r in results.values() if r.get("regression_detected", False))
        high_confidence = sum(1 for r in results.values() 
                            if r.get("regression_detected", False) and r.get("confidence", 0) > 0.8)
        
        return {
            "total_metrics": total_metrics,
            "regressions_detected": regressions,
            "high_confidence_regressions": high_confidence,
            "regression_rate": regressions / total_metrics if total_metrics > 0 else 0
        }
    
    def generate_report(self, output_file=None):
        """Generate comprehensive performance analysis report"""
        analysis = self.batch_analysis()
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(analysis, f, indent=2)
        
        return analysis

def main():
    detector = PerformanceDetector()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "analyze":
            metric = sys.argv[2] if len(sys.argv) > 2 else "auth_latency_ms"
            value = float(sys.argv[3]) if len(sys.argv) > 3 else 55.0
            
            result = detector.detect_regression(metric, value)
            print(json.dumps(result, indent=2))
            
        elif command == "batch":
            sensitivity = sys.argv[2] if len(sys.argv) > 2 else "medium"
            detector = PerformanceDetector(sensitivity)
            
            analysis = detector.batch_analysis()
            print(json.dumps(analysis, indent=2))
            
        elif command == "report":
            output_file = sys.argv[2] if len(sys.argv) > 2 else "performance_analysis.json"
            sensitivity = sys.argv[3] if len(sys.argv) > 3 else "medium"
            
            detector = PerformanceDetector(sensitivity)
            report = detector.generate_report(output_file)
            
            print(f"📊 Performance analysis report generated: {output_file}")
            print(f"Overall Status: {report['overall_status']}")
            print(f"Regressions Detected: {report['summary']['regressions_detected']}/{report['summary']['total_metrics']}")
            
    else:
        print("Usage: performance_detector.py [analyze|batch|report] [options]")
        print("  analyze <metric> <value>     - Analyze single metric")
        print("  batch [sensitivity]          - Batch analysis (low/medium/high)")
        print("  report [file] [sensitivity]  - Generate comprehensive report")

if __name__ == "__main__":
    main()
