"""
Data models for the Red Team Security Dashboard
Mirrors the Rust data structures for JSON report parsing
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Optional, Any
import json
from pathlib import Path


class SecurityPosture(Enum):
    EXCELLENT = "Excellent"
    GOOD = "Good"
    FAIR = "Fair"
    POOR = "Poor"
    CRITICAL = "Critical"


class RiskLevel(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Priority(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Effort(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass
class ExerciseMetadata:
    timestamp: str
    target_url: str
    exercise_duration: str  # Duration as string from Rust
    scenarios_executed: int
    controls_validated: int
    red_team_framework_version: str

    @property
    def datetime(self) -> datetime:
        """Parse timestamp to datetime object"""
        return datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))

    @property
    def duration_seconds(self) -> float:
        """Parse duration to seconds"""
        # Parse Rust Duration format like "123.456789s"
        if 's' in self.exercise_duration:
            return float(self.exercise_duration.replace('s', ''))
        return 0.0


@dataclass
class ExecutiveSummary:
    overall_security_posture: str
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    controls_passing: int
    controls_failing: int
    attack_success_rate: float
    detection_rate: float
    response_effectiveness: float

    @property
    def total_findings(self) -> int:
        return self.critical_findings + self.high_findings + self.medium_findings + self.low_findings

    @property
    def total_controls(self) -> int:
        return self.controls_passing + self.controls_failing

    @property
    def control_pass_rate(self) -> float:
        if self.total_controls == 0:
            return 0.0
        return self.controls_passing / self.total_controls


@dataclass
class ScenarioResult:
    scenario_name: str
    success: bool
    attacks_attempted: int
    attacks_successful: int
    attacks_detected: int
    attacks_blocked: int
    scenario_data: Dict[str, Any]
    key_findings: List[str]

    @property
    def success_rate(self) -> float:
        if self.attacks_attempted == 0:
            return 0.0
        return self.attacks_successful / self.attacks_attempted

    @property
    def detection_rate(self) -> float:
        if self.attacks_attempted == 0:
            return 0.0
        return self.attacks_detected / self.attacks_attempted

    @property
    def block_rate(self) -> float:
        if self.attacks_attempted == 0:
            return 0.0
        return self.attacks_blocked / self.attacks_attempted


@dataclass
class ValidationResult:
    control_name: str
    test_name: str
    passed: bool
    description: str
    expected_behavior: str
    actual_behavior: str
    risk_level: str
    remediation: Optional[str]
    evidence: List[str]

    @property
    def status(self) -> str:
        return "PASS" if self.passed else "FAIL"


@dataclass
class SecurityMetrics:
    detection_accuracy: float
    false_positive_rate: float
    response_time_ms: int
    attack_surface_coverage: float
    control_effectiveness: Dict[str, float]

    @property
    def response_time_seconds(self) -> float:
        return self.response_time_ms / 1000.0


@dataclass
class Recommendation:
    priority: str
    category: str
    title: str
    description: str
    impact: str
    effort: str
    implementation_steps: List[str]


@dataclass
class DetailedFinding:
    id: str
    title: str
    severity: str
    category: str
    description: str
    attack_vector: str
    impact: str
    evidence: List[str]
    remediation: str
    cve_references: List[str]
    owasp_mapping: List[str]


@dataclass
class RedTeamReport:
    exercise_metadata: ExerciseMetadata
    executive_summary: ExecutiveSummary
    attack_scenarios: List[ScenarioResult]
    validation_results: List[ValidationResult]
    security_metrics: SecurityMetrics
    recommendations: List[Recommendation]
    detailed_findings: List[DetailedFinding]

    @classmethod
    def from_json_file(cls, file_path: Path) -> 'RedTeamReport':
        """Load a report from a JSON file"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RedTeamReport':
        """Create a report from a dictionary"""
        return cls(
            exercise_metadata=ExerciseMetadata(**data['exercise_metadata']),
            executive_summary=ExecutiveSummary(**data['executive_summary']),
            attack_scenarios=[ScenarioResult(**scenario) for scenario in data['attack_scenarios']],
            validation_results=[ValidationResult(**result) for result in data['validation_results']],
            security_metrics=SecurityMetrics(**data['security_metrics']),
            recommendations=[Recommendation(**rec) for rec in data['recommendations']],
            detailed_findings=[DetailedFinding(**finding) for finding in data['detailed_findings']]
        )

    def get_findings_by_severity(self) -> Dict[str, int]:
        """Get count of findings by severity level"""
        findings = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        for finding in self.detailed_findings:
            if finding.severity in findings:
                findings[finding.severity] += 1
                
        return findings

    def get_scenarios_by_success(self) -> Dict[str, int]:
        """Get count of scenarios by success status"""
        return {
            "Successful": sum(1 for s in self.attack_scenarios if s.success),
            "Failed": sum(1 for s in self.attack_scenarios if not s.success)
        }

    def get_controls_by_category(self) -> Dict[str, Dict[str, int]]:
        """Get control results grouped by category"""
        categories = {}
        for result in self.validation_results:
            category = result.control_name
            if category not in categories:
                categories[category] = {"passed": 0, "failed": 0}
            
            if result.passed:
                categories[category]["passed"] += 1
            else:
                categories[category]["failed"] += 1
                
        return categories

    def get_attack_timeline(self) -> List[Dict[str, Any]]:
        """Generate timeline data for attacks"""
        timeline = []
        base_time = self.exercise_metadata.datetime
        
        for i, scenario in enumerate(self.attack_scenarios):
            # Simulate timeline based on scenario order
            timestamp = base_time + timedelta(minutes=i*5)
            timeline.append({
                "timestamp": timestamp,
                "scenario": scenario.scenario_name,
                "success": scenario.success,
                "attacks_attempted": scenario.attacks_attempted,
                "attacks_successful": scenario.attacks_successful
            })
            
        return timeline