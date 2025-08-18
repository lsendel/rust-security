"""
Core type definitions for the ML Attack Detection System.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
import uuid


class ThreatLevel(Enum):
    """Enumeration of threat severity levels."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        """Return color code for display."""
        colors = {
            ThreatLevel.NONE: "green",
            ThreatLevel.LOW: "yellow", 
            ThreatLevel.MEDIUM: "orange",
            ThreatLevel.HIGH: "red",
            ThreatLevel.CRITICAL: "magenta"
        }
        return colors[self]


class AttackCategory(Enum):
    """Categories of attack types."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INJECTION = "injection"
    BRUTE_FORCE = "brute_force"
    DDoS = "ddos"
    RECONNAISSANCE = "reconnaissance"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE = "malware"
    SOCIAL_ENGINEERING = "social_engineering"
    NETWORK_INTRUSION = "network_intrusion"
    WEB_APPLICATION = "web_application"
    UNKNOWN = "unknown"


class MitigationAction(Enum):
    """Recommended mitigation actions."""
    MONITOR = "monitor"
    ALERT = "alert"
    BLOCK_IP = "block_ip"
    BLOCK_USER = "block_user"
    RATE_LIMIT = "rate_limit"
    QUARANTINE = "quarantine"
    IMMEDIATE_RESPONSE = "immediate_response"
    INVESTIGATE = "investigate"


@dataclass
class AttackPattern:
    """Represents a detected attack pattern."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: AttackCategory = AttackCategory.UNKNOWN
    description: str = ""
    indicators: List[str] = field(default_factory=list)
    confidence: float = 0.0
    severity: ThreatLevel = ThreatLevel.NONE
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "indicators": self.indicators,
            "confidence": self.confidence,
            "severity": self.severity.name,
            "created_at": self.created_at.isoformat()
        }


@dataclass
class DetectionResult:
    """Result of threat detection analysis."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Detection results
    is_threat: bool = False
    threat_level: ThreatLevel = ThreatLevel.NONE
    confidence: float = 0.0
    
    # Attack classification
    attack_category: AttackCategory = AttackCategory.UNKNOWN
    attack_patterns: List[AttackPattern] = field(default_factory=list)
    
    # Analysis details
    risk_score: float = 0.0
    anomaly_score: float = 0.0
    features_analyzed: List[str] = field(default_factory=list)
    model_predictions: Dict[str, Any] = field(default_factory=dict)
    
    # Response recommendations
    mitigation: MitigationAction = MitigationAction.MONITOR
    recommended_actions: List[str] = field(default_factory=list)
    
    # Metadata
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "is_threat": self.is_threat,
            "threat_level": self.threat_level.name,
            "confidence": self.confidence,
            "attack_category": self.attack_category.value,
            "attack_patterns": [pattern.to_dict() for pattern in self.attack_patterns],
            "risk_score": self.risk_score,
            "anomaly_score": self.anomaly_score,
            "features_analyzed": self.features_analyzed,
            "model_predictions": self.model_predictions,
            "mitigation": self.mitigation.value,
            "recommended_actions": self.recommended_actions,
            "source_ip": self.source_ip,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "raw_data": self.raw_data
        }
    
    def add_attack_pattern(self, pattern: AttackPattern) -> None:
        """Add an attack pattern to the detection result."""
        self.attack_patterns.append(pattern)
        
        # Update overall threat level if pattern is more severe
        if pattern.severity.value > self.threat_level.value:
            self.threat_level = pattern.severity
    
    def update_risk_score(self) -> None:
        """Calculate and update the overall risk score."""
        if not self.attack_patterns:
            self.risk_score = 0.0
            return
        
        # Weighted average of pattern confidences and severities
        total_weight = 0.0
        weighted_score = 0.0
        
        for pattern in self.attack_patterns:
            weight = pattern.confidence * (pattern.severity.value / 4.0)
            weighted_score += weight * pattern.confidence
            total_weight += weight
        
        self.risk_score = weighted_score / total_weight if total_weight > 0 else 0.0


@dataclass
class EventData:
    """Structured event data for analysis."""
    timestamp: datetime
    event_type: str
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    user_agent: Optional[str] = None
    request_path: Optional[str] = None
    request_method: Optional[str] = None
    response_code: Optional[int] = None
    response_time: Optional[float] = None
    payload_size: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EventData':
        """Create EventData from dictionary."""
        timestamp = data.get('timestamp')
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        elif timestamp is None:
            timestamp = datetime.utcnow()
        
        return cls(
            timestamp=timestamp,
            event_type=data.get('event_type', 'unknown'),
            source_ip=data.get('source_ip'),
            user_id=data.get('user_id'),
            session_id=data.get('session_id'),
            user_agent=data.get('user_agent'),
            request_path=data.get('request_path'),
            request_method=data.get('request_method'),
            response_code=data.get('response_code'),
            response_time=data.get('response_time'),
            payload_size=data.get('payload_size'),
            headers=data.get('headers', {}),
            body=data.get('body'),
            metadata=data.get('metadata', {})
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "user_agent": self.user_agent,
            "request_path": self.request_path,
            "request_method": self.request_method,
            "response_code": self.response_code,
            "response_time": self.response_time,
            "payload_size": self.payload_size,
            "headers": self.headers,
            "body": self.body,
            "metadata": self.metadata
        }


@dataclass
class ModelMetrics:
    """Metrics for model performance evaluation."""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    auc_roc: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    true_positive_rate: float = 0.0
    true_negative_rate: float = 0.0
    
    # Additional metrics
    training_time: float = 0.0
    inference_time: float = 0.0
    model_size: int = 0
    feature_importance: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "auc_roc": self.auc_roc,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "true_positive_rate": self.true_positive_rate,
            "true_negative_rate": self.true_negative_rate,
            "training_time": self.training_time,
            "inference_time": self.inference_time,
            "model_size": self.model_size,
            "feature_importance": self.feature_importance
        }


# Type aliases for common data structures
FeatureVector = Dict[str, Union[int, float, str]]
TrainingData = List[Dict[str, Any]]
PredictionProb = Dict[str, float]