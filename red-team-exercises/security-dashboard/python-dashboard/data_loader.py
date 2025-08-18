"""
Data loading utilities for the Security Dashboard
"""
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
import pandas as pd
from models import RedTeamReport, ScenarioResult, ValidationResult
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReportLoader:
    """Handles loading and caching of red team reports"""
    
    def __init__(self, reports_directory: str = "reports"):
        self.reports_dir = Path(reports_directory)
        self.reports_dir.mkdir(exist_ok=True)
        self._cached_reports: Dict[str, RedTeamReport] = {}
        self._last_load_time: Optional[datetime] = None
        
    def load_all_reports(self, force_reload: bool = False) -> List[RedTeamReport]:
        """Load all available reports from the reports directory"""
        if not force_reload and self._cached_reports and self._last_load_time:
            # Check if we loaded recently (within 5 minutes)
            if datetime.now() - self._last_load_time < timedelta(minutes=5):
                return list(self._cached_reports.values())
        
        reports = []
        json_files = list(self.reports_dir.glob("*.json"))
        
        logger.info(f"Loading {len(json_files)} report files from {self.reports_dir}")
        
        for file_path in json_files:
            try:
                report = RedTeamReport.from_json_file(file_path)
                reports.append(report)
                self._cached_reports[str(file_path)] = report
                logger.debug(f"Loaded report: {file_path}")
            except Exception as e:
                logger.error(f"Failed to load report {file_path}: {e}")
                continue
                
        self._last_load_time = datetime.now()
        logger.info(f"Successfully loaded {len(reports)} reports")
        return reports
    
    def load_report_by_id(self, report_id: str) -> Optional[RedTeamReport]:
        """Load a specific report by ID"""
        report_file = self.reports_dir / f"{report_id}.json"
        if report_file.exists():
            try:
                return RedTeamReport.from_json_file(report_file)
            except Exception as e:
                logger.error(f"Failed to load report {report_id}: {e}")
        return None
    
    def get_reports_in_date_range(self, 
                                  start_date: datetime, 
                                  end_date: datetime) -> List[RedTeamReport]:
        """Get reports within a specific date range"""
        all_reports = self.load_all_reports()
        filtered_reports = []
        
        for report in all_reports:
            report_date = report.exercise_metadata.datetime
            if start_date <= report_date <= end_date:
                filtered_reports.append(report)
                
        return sorted(filtered_reports, 
                     key=lambda r: r.exercise_metadata.datetime, 
                     reverse=True)
    
    def get_latest_report(self) -> Optional[RedTeamReport]:
        """Get the most recent report"""
        reports = self.load_all_reports()
        if not reports:
            return None
            
        return max(reports, key=lambda r: r.exercise_metadata.datetime)
    
    def create_sample_report(self) -> RedTeamReport:
        """Create a sample report for testing purposes"""
        from models import (
            ExerciseMetadata, ExecutiveSummary, ScenarioResult, 
            ValidationResult, SecurityMetrics, Recommendation, 
            DetailedFinding
        )
        
        # Create sample data
        metadata = ExerciseMetadata(
            timestamp=datetime.now().isoformat(),
            target_url="https://example.com",
            exercise_duration="300.0s",
            scenarios_executed=5,
            controls_validated=10,
            red_team_framework_version="1.0.0"
        )
        
        executive_summary = ExecutiveSummary(
            overall_security_posture="Fair",
            critical_findings=1,
            high_findings=3,
            medium_findings=5,
            low_findings=2,
            controls_passing=7,
            controls_failing=3,
            attack_success_rate=0.3,
            detection_rate=0.7,
            response_effectiveness=0.8
        )
        
        scenarios = [
            ScenarioResult(
                scenario_name="Authentication Bypass",
                success=True,
                attacks_attempted=10,
                attacks_successful=3,
                attacks_detected=7,
                attacks_blocked=4,
                scenario_data={"method": "credential_stuffing"},
                key_findings=["Weak password policy", "No rate limiting"]
            ),
            ScenarioResult(
                scenario_name="IDOR Attack",
                success=False,
                attacks_attempted=5,
                attacks_successful=0,
                attacks_detected=5,
                attacks_blocked=5,
                scenario_data={"method": "parameter_manipulation"},
                key_findings=["IDOR protection effective"]
            )
        ]
        
        validation_results = [
            ValidationResult(
                control_name="Rate Limiting",
                test_name="Request Rate Control",
                passed=False,
                description="Verify rate limiting is enforced",
                expected_behavior="429 after 100 requests/min",
                actual_behavior="No rate limiting detected",
                risk_level="High",
                remediation="Implement rate limiting middleware",
                evidence=["Unlimited requests accepted"]
            )
        ]
        
        security_metrics = SecurityMetrics(
            detection_accuracy=0.75,
            false_positive_rate=0.05,
            response_time_ms=250,
            attack_surface_coverage=0.85,
            control_effectiveness={"IDOR Protection": 1.0, "Rate Limiting": 0.0}
        )
        
        recommendations = [
            Recommendation(
                priority="High",
                category="Authentication",
                title="Implement Strong Rate Limiting",
                description="Add rate limiting to prevent brute force attacks",
                impact="Reduces authentication bypass risk by 80%",
                effort="Medium",
                implementation_steps=[
                    "Choose rate limiting strategy",
                    "Implement middleware",
                    "Configure thresholds",
                    "Test and monitor"
                ]
            )
        ]
        
        detailed_findings = [
            DetailedFinding(
                id="RTX-0001",
                title="Missing Rate Limiting on Authentication Endpoints",
                severity="High",
                category="Authentication",
                description="Authentication endpoints lack rate limiting",
                attack_vector="Brute force attack",
                impact="Account takeover possible",
                evidence=["100+ requests accepted without blocking"],
                remediation="Implement exponential backoff rate limiting",
                cve_references=[],
                owasp_mapping=["A07:2021-Identification and Authentication Failures"]
            )
        ]
        
        return RedTeamReport(
            exercise_metadata=metadata,
            executive_summary=executive_summary,
            attack_scenarios=scenarios,
            validation_results=validation_results,
            security_metrics=security_metrics,
            recommendations=recommendations,
            detailed_findings=detailed_findings
        )
    
    def save_sample_report(self) -> None:
        """Save a sample report for testing"""
        sample_report = self.create_sample_report()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sample_report_{timestamp}.json"
        filepath = self.reports_dir / filename
        
        # Convert to dict for JSON serialization
        report_dict = {
            "exercise_metadata": sample_report.exercise_metadata.__dict__,
            "executive_summary": sample_report.executive_summary.__dict__,
            "attack_scenarios": [scenario.__dict__ for scenario in sample_report.attack_scenarios],
            "validation_results": [result.__dict__ for result in sample_report.validation_results],
            "security_metrics": sample_report.security_metrics.__dict__,
            "recommendations": [rec.__dict__ for rec in sample_report.recommendations],
            "detailed_findings": [finding.__dict__ for finding in sample_report.detailed_findings]
        }
        
        with open(filepath, 'w') as f:
            json.dump(report_dict, f, indent=2)
            
        logger.info(f"Sample report saved to {filepath}")


class DataAggregator:
    """Aggregates data across multiple reports for trend analysis"""
    
    def __init__(self, reports: List[RedTeamReport]):
        self.reports = reports
        
    def get_trend_data(self) -> Dict[str, Any]:
        """Generate trend data across all reports"""
        if not self.reports:
            return {}
            
        trend_data = {
            "dates": [],
            "attack_success_rates": [],
            "detection_rates": [],
            "findings_by_severity": {"Critical": [], "High": [], "Medium": [], "Low": []},
            "controls_pass_rates": [],
            "response_times": []
        }
        
        # Sort reports by date
        sorted_reports = sorted(self.reports, 
                              key=lambda r: r.exercise_metadata.datetime)
        
        for report in sorted_reports:
            date = report.exercise_metadata.datetime
            summary = report.executive_summary
            
            trend_data["dates"].append(date)
            trend_data["attack_success_rates"].append(summary.attack_success_rate)
            trend_data["detection_rates"].append(summary.detection_rate)
            trend_data["controls_pass_rates"].append(summary.control_pass_rate)
            trend_data["response_times"].append(report.security_metrics.response_time_ms)
            
            # Findings by severity
            trend_data["findings_by_severity"]["Critical"].append(summary.critical_findings)
            trend_data["findings_by_severity"]["High"].append(summary.high_findings)
            trend_data["findings_by_severity"]["Medium"].append(summary.medium_findings)
            trend_data["findings_by_severity"]["Low"].append(summary.low_findings)
            
        return trend_data
    
    def get_summary_statistics(self) -> Dict[str, Any]:
        """Generate summary statistics across all reports"""
        if not self.reports:
            return {}
            
        stats = {
            "total_reports": len(self.reports),
            "date_range": {
                "start": min(r.exercise_metadata.datetime for r in self.reports),
                "end": max(r.exercise_metadata.datetime for r in self.reports)
            },
            "avg_attack_success_rate": sum(r.executive_summary.attack_success_rate for r in self.reports) / len(self.reports),
            "avg_detection_rate": sum(r.executive_summary.detection_rate for r in self.reports) / len(self.reports),
            "total_scenarios": sum(len(r.attack_scenarios) for r in self.reports),
            "total_findings": sum(r.executive_summary.total_findings for r in self.reports),
            "security_posture_distribution": {}
        }
        
        # Security posture distribution
        postures = [r.executive_summary.overall_security_posture for r in self.reports]
        for posture in set(postures):
            stats["security_posture_distribution"][posture] = postures.count(posture)
            
        return stats
    
    def to_dataframe(self) -> pd.DataFrame:
        """Convert reports to a pandas DataFrame for analysis"""
        data = []
        
        for report in self.reports:
            row = {
                "timestamp": report.exercise_metadata.datetime,
                "target_url": report.exercise_metadata.target_url,
                "duration_seconds": report.exercise_metadata.duration_seconds,
                "scenarios_executed": report.exercise_metadata.scenarios_executed,
                "controls_validated": report.exercise_metadata.controls_validated,
                "security_posture": report.executive_summary.overall_security_posture,
                "critical_findings": report.executive_summary.critical_findings,
                "high_findings": report.executive_summary.high_findings,
                "medium_findings": report.executive_summary.medium_findings,
                "low_findings": report.executive_summary.low_findings,
                "attack_success_rate": report.executive_summary.attack_success_rate,
                "detection_rate": report.executive_summary.detection_rate,
                "response_effectiveness": report.executive_summary.response_effectiveness,
                "controls_passing": report.executive_summary.controls_passing,
                "controls_failing": report.executive_summary.controls_failing,
                "response_time_ms": report.security_metrics.response_time_ms,
                "detection_accuracy": report.security_metrics.detection_accuracy,
                "false_positive_rate": report.security_metrics.false_positive_rate
            }
            data.append(row)
            
        return pd.DataFrame(data)