"""
Comprehensive Threat Hunting Toolkit for Rust Authentication Service

This package provides advanced threat detection, behavioral analysis, machine learning-based
user profiling, real-time threat intelligence correlation, and automated response capabilities.

Main Components:
- behavioral_analyzer: Advanced threat detection using behavioral analysis
- ml_user_profiler: Machine learning-based user behavior profiling and risk assessment
- threat_intelligence: Real-time threat intelligence correlation and IOC matching
- attack_pattern_detector: Sophisticated attack pattern and sequence detection
- automated_response: Automated threat response and orchestration
- integration_bridge: Seamless integration with Rust authentication service

Example Usage:
    from threat_hunting import ThreatHuntingOrchestrator
    
    config = {
        'rust_service': {'url': 'http://localhost:8080', 'api_key': 'key'},
        'redis_url': 'redis://localhost:6379',
        'postgres_url': 'postgresql://localhost/security_db'
    }
    
    orchestrator = ThreatHuntingOrchestrator(config)
    await orchestrator.initialize()
    await orchestrator.process_log_file('/var/log/auth-service.log')
"""

__version__ = "1.0.0"
__author__ = "Security Team"
__description__ = "Comprehensive Threat Hunting Toolkit for Rust Authentication Service"

# Main orchestrator for easy import
from .integration_bridge import ThreatHuntingOrchestrator

# Individual components for advanced usage
from .behavioral_analyzer import AdvancedThreatDetector, SecurityEvent, ThreatSignature
from .ml_user_profiler import AdvancedUserProfiler, RiskAssessment, UserFeatures
from .threat_intelligence import ThreatIntelligenceCorrelator, ThreatIndicator, ThreatMatch
from .attack_pattern_detector import AttackPatternDetector, AttackSequence, AttackStep
from .automated_response import (
    AutomatedResponseOrchestrator, 
    ThreatContext, 
    ResponseAction, 
    ResponsePlan
)

__all__ = [
    # Main orchestrator
    'ThreatHuntingOrchestrator',
    
    # Behavioral analysis
    'AdvancedThreatDetector',
    'SecurityEvent', 
    'ThreatSignature',
    
    # User profiling
    'AdvancedUserProfiler',
    'RiskAssessment',
    'UserFeatures',
    
    # Threat intelligence
    'ThreatIntelligenceCorrelator',
    'ThreatIndicator',
    'ThreatMatch',
    
    # Attack pattern detection
    'AttackPatternDetector',
    'AttackSequence',
    'AttackStep',
    
    # Automated response
    'AutomatedResponseOrchestrator',
    'ThreatContext',
    'ResponseAction',
    'ResponsePlan'
]