#!/usr/bin/env python3
"""
Comprehensive Behavioral Analysis and Anomaly Detection System
for Rust Authentication Service Threat Hunting

This module implements advanced behavioral analysis patterns to detect
sophisticated threats including credential stuffing, account takeover,
and advanced persistent threats (APTs).
"""

import asyncio
import json
import logging
import numpy as np
import pandas as pd
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import asyncpg
import redis.asyncio as redis
from prometheus_client import Counter, Histogram, Gauge


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Prometheus metrics for threat hunting
THREAT_PATTERNS_DETECTED = Counter(
    'threat_patterns_detected_total',
    'Total threat patterns detected',
    ['pattern_type', 'severity', 'source_ip']
)

BEHAVIORAL_ANOMALIES = Counter(
    'behavioral_anomalies_detected_total',
    'Total behavioral anomalies detected',
    ['anomaly_type', 'user_id', 'confidence']
)

ANALYSIS_DURATION = Histogram(
    'behavioral_analysis_duration_seconds',
    'Duration of behavioral analysis operations',
    ['analysis_type']
)

ACTIVE_THREATS = Gauge(
    'active_threats_count',
    'Number of currently active threats being monitored'
)


@dataclass
class SecurityEvent:
    """Represents a security event from the Rust auth service"""
    event_id: str
    timestamp: datetime
    event_type: str
    severity: str
    source: str
    client_id: Optional[str]
    user_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    request_id: Optional[str]
    session_id: Optional[str]
    description: str
    details: Dict[str, Any]
    outcome: str
    resource: Optional[str]
    action: Optional[str]
    risk_score: Optional[int]
    location: Optional[str]
    device_fingerprint: Optional[str]


@dataclass
class ThreatSignature:
    """Represents a detected threat pattern"""
    threat_id: str
    threat_type: str
    severity: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    indicators: List[str]
    affected_entities: Set[str]
    risk_score: int
    mitigation_actions: List[str]
    related_events: List[str]


@dataclass
class UserBehaviorProfile:
    """User behavior profile for anomaly detection"""
    user_id: str
    typical_login_hours: List[int]
    typical_locations: Set[str]
    typical_devices: Set[str]
    typical_user_agents: Set[str]
    avg_session_duration: float
    login_frequency_pattern: Dict[str, int]  # day_of_week -> count
    failed_login_baseline: float
    mfa_usage_pattern: str
    risk_baseline: float
    last_updated: datetime


class AdvancedThreatDetector:
    """Advanced threat detection using machine learning and behavioral analysis"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379", 
                 postgres_url: str = "postgresql://localhost/security_db"):
        self.redis_url = redis_url
        self.postgres_url = postgres_url
        self.redis_client = None
        self.db_pool = None
        
        # Behavioral models
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        
        # Threat pattern buffers
        self.event_buffer = deque(maxlen=10000)
        self.user_profiles = {}
        self.active_threats = {}
        
        # Pattern detection thresholds
        self.thresholds = {
            'credential_stuffing': {
                'failed_logins_per_minute': 10,
                'unique_usernames_per_ip': 20,
                'time_window_minutes': 5
            },
            'account_takeover': {
                'location_anomaly_threshold': 1000,  # km
                'device_change_threshold': 3,
                'behavior_deviation_threshold': 2.5
            },
            'brute_force': {
                'failed_attempts_threshold': 15,
                'time_window_minutes': 10,
                'lockout_threshold': 5
            },
            'session_hijacking': {
                'concurrent_sessions_threshold': 3,
                'location_jump_threshold': 500,  # km
                'time_threshold_minutes': 5
            }
        }

    async def initialize(self):
        """Initialize connections and load models"""
        try:
            # Initialize Redis connection
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logger.info("Redis connection established")
            
            # Initialize PostgreSQL connection pool
            self.db_pool = await asyncpg.create_pool(self.postgres_url)
            logger.info("PostgreSQL connection pool established")
            
            # Load existing user profiles
            await self._load_user_profiles()
            
            # Initialize ML models
            await self._initialize_ml_models()
            
        except Exception as e:
            logger.error(f"Failed to initialize threat detector: {e}")
            raise

    async def _load_user_profiles(self):
        """Load user behavioral profiles from Redis"""
        try:
            keys = await self.redis_client.keys("user_profile:*")
            for key in keys:
                profile_data = await self.redis_client.get(key)
                if profile_data:
                    profile = json.loads(profile_data)
                    user_id = key.decode().split(":")[-1]
                    self.user_profiles[user_id] = UserBehaviorProfile(**profile)
            
            logger.info(f"Loaded {len(self.user_profiles)} user profiles")
        except Exception as e:
            logger.error(f"Failed to load user profiles: {e}")

    async def _initialize_ml_models(self):
        """Initialize and train ML models with historical data"""
        try:
            # Fetch historical data for model training
            async with self.db_pool.acquire() as conn:
                query = """
                SELECT user_id, ip_address, timestamp, event_type, outcome, risk_score
                FROM security_events 
                WHERE timestamp > NOW() - INTERVAL '30 days'
                AND event_type IN ('authentication_attempt', 'authentication_success', 'authentication_failure')
                ORDER BY timestamp DESC
                LIMIT 50000
                """
                rows = await conn.fetch(query)
                
                if rows:
                    # Prepare training data
                    training_data = []
                    for row in rows:
                        features = self._extract_features_for_ml(dict(row))
                        training_data.append(features)
                    
                    if training_data:
                        X = np.array(training_data)
                        X_scaled = self.scaler.fit_transform(X)
                        self.isolation_forest.fit(X_scaled)
                        logger.info("ML models trained successfully")
                
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")

    def _extract_features_for_ml(self, event: Dict) -> List[float]:
        """Extract numerical features from security event for ML"""
        features = []
        
        # Time-based features
        if event.get('timestamp'):
            dt = event['timestamp'] if isinstance(event['timestamp'], datetime) else datetime.fromisoformat(str(event['timestamp']))
            features.extend([
                dt.hour,
                dt.weekday(),
                dt.minute
            ])
        else:
            features.extend([0, 0, 0])
        
        # Risk score
        features.append(event.get('risk_score', 0) or 0)
        
        # Event type encoding
        event_types = {'authentication_attempt': 1, 'authentication_success': 2, 'authentication_failure': 3}
        features.append(event_types.get(event.get('event_type', ''), 0))
        
        # Outcome encoding
        outcome_types = {'success': 1, 'failure': 0, 'blocked': -1}
        features.append(outcome_types.get(event.get('outcome', ''), 0))
        
        return features

    async def analyze_event(self, event: SecurityEvent) -> List[ThreatSignature]:
        """Analyze a security event for threat patterns"""
        threats_detected = []
        
        try:
            with ANALYSIS_DURATION.labels(analysis_type='event_analysis').time():
                # Add event to buffer
                self.event_buffer.append(event)
                
                # Update user profile
                if event.user_id:
                    await self._update_user_profile(event)
                
                # Run threat detection patterns
                threats_detected.extend(await self._detect_credential_stuffing(event))
                threats_detected.extend(await self._detect_account_takeover(event))
                threats_detected.extend(await self._detect_brute_force(event))
                threats_detected.extend(await self._detect_session_hijacking(event))
                threats_detected.extend(await self._detect_anomalous_behavior(event))
                
                # Update metrics
                for threat in threats_detected:
                    THREAT_PATTERNS_DETECTED.labels(
                        pattern_type=threat.threat_type,
                        severity=threat.severity,
                        source_ip=event.ip_address or 'unknown'
                    ).inc()
                
                # Store threats in Redis for correlation
                for threat in threats_detected:
                    await self._store_threat(threat)
                
                ACTIVE_THREATS.set(len(self.active_threats))
                
        except Exception as e:
            logger.error(f"Error analyzing event {event.event_id}: {e}")
        
        return threats_detected

    async def _detect_credential_stuffing(self, event: SecurityEvent) -> List[ThreatSignature]:
        """Detect credential stuffing attacks"""
        threats = []
        
        if event.event_type not in ['authentication_failure', 'authentication_attempt']:
            return threats
        
        if not event.ip_address:
            return threats
        
        try:
            # Count recent failures from this IP
            recent_failures = 0
            unique_users = set()
            
            cutoff_time = datetime.now() - timedelta(minutes=self.thresholds['credential_stuffing']['time_window_minutes'])
            
            for buffered_event in self.event_buffer:
                if (buffered_event.ip_address == event.ip_address and 
                    buffered_event.timestamp > cutoff_time and
                    buffered_event.event_type == 'authentication_failure'):
                    
                    recent_failures += 1
                    if buffered_event.user_id:
                        unique_users.add(buffered_event.user_id)
            
            # Check thresholds
            if (recent_failures >= self.thresholds['credential_stuffing']['failed_logins_per_minute'] and
                len(unique_users) >= self.thresholds['credential_stuffing']['unique_usernames_per_ip']):
                
                threat = ThreatSignature(
                    threat_id=f"cred_stuff_{event.ip_address}_{int(datetime.now().timestamp())}",
                    threat_type="credential_stuffing",
                    severity="high",
                    confidence=0.85,
                    first_seen=cutoff_time,
                    last_seen=event.timestamp,
                    indicators=[
                        f"High failure rate: {recent_failures} failures",
                        f"Multiple users targeted: {len(unique_users)} users",
                        f"Source IP: {event.ip_address}"
                    ],
                    affected_entities=unique_users,
                    risk_score=85,
                    mitigation_actions=[
                        "Block source IP temporarily",
                        "Enable additional MFA for targeted accounts",
                        "Notify security team"
                    ],
                    related_events=[e.event_id for e in self.event_buffer if e.ip_address == event.ip_address][-20:]
                )
                threats.append(threat)
                
        except Exception as e:
            logger.error(f"Error in credential stuffing detection: {e}")
        
        return threats

    async def _detect_account_takeover(self, event: SecurityEvent) -> List[ThreatSignature]:
        """Detect account takeover attempts"""
        threats = []
        
        if not event.user_id or event.event_type != 'authentication_success':
            return threats
        
        try:
            user_profile = self.user_profiles.get(event.user_id)
            if not user_profile:
                return threats  # No baseline for comparison
            
            anomalies = []
            confidence = 0.0
            
            # Check location anomaly
            if event.location and event.location not in user_profile.typical_locations:
                # Simplified distance check (in real implementation, use geospatial calculations)
                anomalies.append("Unusual login location")
                confidence += 0.3
            
            # Check device fingerprint
            if event.device_fingerprint and event.device_fingerprint not in user_profile.typical_devices:
                anomalies.append("New device detected")
                confidence += 0.2
            
            # Check timing patterns
            login_hour = event.timestamp.hour
            if login_hour not in user_profile.typical_login_hours:
                anomalies.append("Unusual login time")
                confidence += 0.2
            
            # Check user agent
            if event.user_agent and event.user_agent not in user_profile.typical_user_agents:
                anomalies.append("New user agent")
                confidence += 0.15
            
            # Check if there were recent failed attempts
            recent_failures = sum(1 for e in self.event_buffer 
                                if e.user_id == event.user_id and 
                                e.event_type == 'authentication_failure' and
                                e.timestamp > event.timestamp - timedelta(hours=1))
            
            if recent_failures > user_profile.failed_login_baseline * 3:
                anomalies.append(f"Unusual failure pattern: {recent_failures} recent failures")
                confidence += 0.25
            
            # If multiple anomalies detected, create threat signature
            if len(anomalies) >= 2 and confidence >= 0.5:
                threat = ThreatSignature(
                    threat_id=f"ato_{event.user_id}_{int(event.timestamp.timestamp())}",
                    threat_type="account_takeover",
                    severity="high" if confidence > 0.7 else "medium",
                    confidence=confidence,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    indicators=anomalies,
                    affected_entities={event.user_id},
                    risk_score=int(confidence * 100),
                    mitigation_actions=[
                        "Require additional authentication",
                        "Notify user of suspicious login",
                        "Monitor account activity closely",
                        "Consider temporary account restrictions"
                    ],
                    related_events=[event.event_id]
                )
                threats.append(threat)
                
        except Exception as e:
            logger.error(f"Error in account takeover detection: {e}")
        
        return threats

    async def _detect_brute_force(self, event: SecurityEvent) -> List[ThreatSignature]:
        """Detect brute force attacks"""
        threats = []
        
        if not event.user_id or event.event_type != 'authentication_failure':
            return threats
        
        try:
            # Count recent failures for this user
            cutoff_time = datetime.now() - timedelta(minutes=self.thresholds['brute_force']['time_window_minutes'])
            recent_failures = sum(1 for e in self.event_buffer 
                                if e.user_id == event.user_id and 
                                e.event_type == 'authentication_failure' and
                                e.timestamp > cutoff_time)
            
            # Check if threshold exceeded
            if recent_failures >= self.thresholds['brute_force']['failed_attempts_threshold']:
                # Get unique IPs involved
                source_ips = set(e.ip_address for e in self.event_buffer 
                               if e.user_id == event.user_id and 
                               e.event_type == 'authentication_failure' and
                               e.timestamp > cutoff_time and e.ip_address)
                
                threat = ThreatSignature(
                    threat_id=f"brute_force_{event.user_id}_{int(datetime.now().timestamp())}",
                    threat_type="brute_force",
                    severity="medium",
                    confidence=0.8,
                    first_seen=cutoff_time,
                    last_seen=event.timestamp,
                    indicators=[
                        f"High failure rate: {recent_failures} failures in {self.thresholds['brute_force']['time_window_minutes']} minutes",
                        f"Source IPs: {', '.join(source_ips)}"
                    ],
                    affected_entities={event.user_id},
                    risk_score=70,
                    mitigation_actions=[
                        "Temporarily lock account",
                        "Require password reset",
                        "Enable additional MFA",
                        "Block attacking IPs"
                    ],
                    related_events=[e.event_id for e in self.event_buffer 
                                  if e.user_id == event.user_id and e.timestamp > cutoff_time][-10:]
                )
                threats.append(threat)
                
        except Exception as e:
            logger.error(f"Error in brute force detection: {e}")
        
        return threats

    async def _detect_session_hijacking(self, event: SecurityEvent) -> List[ThreatSignature]:
        """Detect session hijacking attempts"""
        threats = []
        
        if not event.session_id or event.event_type not in ['authentication_success', 'token_issued']:
            return threats
        
        try:
            # Find other recent events for this session
            session_events = [e for e in self.event_buffer 
                            if e.session_id == event.session_id and 
                            e.timestamp > datetime.now() - timedelta(hours=1)]
            
            if len(session_events) < 2:
                return threats
            
            # Check for location jumps
            locations = [e.location for e in session_events if e.location]
            if len(set(locations)) > 1:
                # Simplified check - in production, calculate actual distances
                anomalies = ["Multiple locations in short time"]
                confidence = 0.6
                
                # Check for IP changes
                ips = [e.ip_address for e in session_events if e.ip_address]
                if len(set(ips)) > 1:
                    anomalies.append("Multiple IP addresses")
                    confidence += 0.3
                
                if confidence >= 0.6:
                    threat = ThreatSignature(
                        threat_id=f"session_hijack_{event.session_id}_{int(datetime.now().timestamp())}",
                        threat_type="session_hijacking",
                        severity="high",
                        confidence=confidence,
                        first_seen=min(e.timestamp for e in session_events),
                        last_seen=max(e.timestamp for e in session_events),
                        indicators=anomalies,
                        affected_entities={event.user_id} if event.user_id else set(),
                        risk_score=int(confidence * 100),
                        mitigation_actions=[
                            "Invalidate session immediately",
                            "Force re-authentication",
                            "Monitor user account closely",
                            "Investigate source IPs"
                        ],
                        related_events=[e.event_id for e in session_events]
                    )
                    threats.append(threat)
                    
        except Exception as e:
            logger.error(f"Error in session hijacking detection: {e}")
        
        return threats

    async def _detect_anomalous_behavior(self, event: SecurityEvent) -> List[ThreatSignature]:
        """Detect anomalous behavior using ML models"""
        threats = []
        
        try:
            # Extract features for ML analysis
            features = self._extract_features_for_ml(asdict(event))
            if not features:
                return threats
            
            # Scale features
            features_scaled = self.scaler.transform([features])
            
            # Predict anomaly
            anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
            is_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
            
            if is_anomaly and anomaly_score < -0.3:  # Threshold for significant anomalies
                confidence = min(0.9, abs(anomaly_score))
                
                threat = ThreatSignature(
                    threat_id=f"ml_anomaly_{event.event_id}",
                    threat_type="behavioral_anomaly",
                    severity="medium" if confidence < 0.7 else "high",
                    confidence=confidence,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    indicators=[
                        f"ML anomaly score: {anomaly_score:.3f}",
                        "Behavioral pattern deviation detected"
                    ],
                    affected_entities={event.user_id} if event.user_id else set(),
                    risk_score=int(confidence * 100),
                    mitigation_actions=[
                        "Investigate user activity",
                        "Review recent authentication patterns",
                        "Consider additional verification"
                    ],
                    related_events=[event.event_id]
                )
                threats.append(threat)
                
                BEHAVIORAL_ANOMALIES.labels(
                    anomaly_type="ml_detection",
                    user_id=event.user_id or "unknown",
                    confidence=str(int(confidence * 10) / 10)
                ).inc()
                
        except Exception as e:
            logger.error(f"Error in ML anomaly detection: {e}")
        
        return threats

    async def _update_user_profile(self, event: SecurityEvent):
        """Update user behavioral profile"""
        if not event.user_id:
            return
        
        try:
            profile = self.user_profiles.get(event.user_id)
            if not profile:
                # Create new profile
                profile = UserBehaviorProfile(
                    user_id=event.user_id,
                    typical_login_hours=[],
                    typical_locations=set(),
                    typical_devices=set(),
                    typical_user_agents=set(),
                    avg_session_duration=0.0,
                    login_frequency_pattern={},
                    failed_login_baseline=0.0,
                    mfa_usage_pattern="unknown",
                    risk_baseline=0.0,
                    last_updated=datetime.now()
                )
                self.user_profiles[event.user_id] = profile
            
            # Update profile based on event
            if event.event_type == 'authentication_success':
                profile.typical_login_hours.append(event.timestamp.hour)
                profile.typical_login_hours = list(set(profile.typical_login_hours[-50:]))  # Keep recent patterns
                
                if event.location:
                    profile.typical_locations.add(event.location)
                
                if event.device_fingerprint:
                    profile.typical_devices.add(event.device_fingerprint)
                
                if event.user_agent:
                    profile.typical_user_agents.add(event.user_agent)
                
                # Update login frequency pattern
                day_of_week = event.timestamp.strftime('%A')
                profile.login_frequency_pattern[day_of_week] = profile.login_frequency_pattern.get(day_of_week, 0) + 1
            
            profile.last_updated = datetime.now()
            
            # Save updated profile to Redis
            profile_data = asdict(profile)
            # Convert sets to lists for JSON serialization
            profile_data['typical_locations'] = list(profile_data['typical_locations'])
            profile_data['typical_devices'] = list(profile_data['typical_devices'])
            profile_data['typical_user_agents'] = list(profile_data['typical_user_agents'])
            profile_data['last_updated'] = profile_data['last_updated'].isoformat()
            
            await self.redis_client.set(
                f"user_profile:{event.user_id}",
                json.dumps(profile_data, default=str),
                ex=86400 * 30  # 30 days expiry
            )
            
        except Exception as e:
            logger.error(f"Error updating user profile for {event.user_id}: {e}")

    async def _store_threat(self, threat: ThreatSignature):
        """Store threat signature for correlation and tracking"""
        try:
            # Store in active threats
            self.active_threats[threat.threat_id] = threat
            
            # Store in Redis for persistence
            threat_data = asdict(threat)
            threat_data['affected_entities'] = list(threat_data['affected_entities'])
            threat_data['first_seen'] = threat_data['first_seen'].isoformat()
            threat_data['last_seen'] = threat_data['last_seen'].isoformat()
            
            await self.redis_client.set(
                f"threat:{threat.threat_id}",
                json.dumps(threat_data, default=str),
                ex=86400 * 7  # 7 days expiry
            )
            
            # Store in PostgreSQL for long-term analysis
            if self.db_pool:
                async with self.db_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO threat_signatures 
                        (threat_id, threat_type, severity, confidence, first_seen, last_seen, 
                         indicators, affected_entities, risk_score, mitigation_actions, related_events)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                        ON CONFLICT (threat_id) DO UPDATE SET
                        last_seen = EXCLUDED.last_seen,
                        confidence = EXCLUDED.confidence,
                        indicators = EXCLUDED.indicators,
                        related_events = EXCLUDED.related_events
                    """, 
                    threat.threat_id, threat.threat_type, threat.severity, threat.confidence,
                    threat.first_seen, threat.last_seen, json.dumps(threat.indicators),
                    json.dumps(list(threat.affected_entities)), threat.risk_score,
                    json.dumps(threat.mitigation_actions), json.dumps(threat.related_events))
            
        except Exception as e:
            logger.error(f"Error storing threat {threat.threat_id}: {e}")

    async def get_active_threats(self, severity_filter: Optional[str] = None) -> List[ThreatSignature]:
        """Get currently active threats"""
        threats = list(self.active_threats.values())
        
        if severity_filter:
            threats = [t for t in threats if t.severity == severity_filter]
        
        return sorted(threats, key=lambda t: t.last_seen, reverse=True)

    async def correlate_threats(self) -> List[Dict[str, Any]]:
        """Correlate related threats to identify campaign patterns"""
        correlations = []
        
        try:
            threats = list(self.active_threats.values())
            
            # Group by affected entities
            entity_groups = defaultdict(list)
            for threat in threats:
                for entity in threat.affected_entities:
                    entity_groups[entity].append(threat)
            
            # Find entities with multiple threat types
            for entity, entity_threats in entity_groups.items():
                if len(entity_threats) > 1:
                    threat_types = set(t.threat_type for t in entity_threats)
                    if len(threat_types) > 1:
                        correlations.append({
                            'correlation_type': 'multi_threat_entity',
                            'affected_entity': entity,
                            'threat_types': list(threat_types),
                            'threat_count': len(entity_threats),
                            'max_severity': max(t.severity for t in entity_threats),
                            'time_span': max(t.last_seen for t in entity_threats) - min(t.first_seen for t in entity_threats)
                        })
            
            # Group by time windows (potential coordinated attacks)
            time_groups = defaultdict(list)
            for threat in threats:
                time_bucket = threat.first_seen.replace(minute=0, second=0, microsecond=0)
                time_groups[time_bucket].append(threat)
            
            for time_bucket, time_threats in time_groups.items():
                if len(time_threats) > 3:  # Multiple threats in same hour
                    correlations.append({
                        'correlation_type': 'temporal_clustering',
                        'time_window': time_bucket.isoformat(),
                        'threat_count': len(time_threats),
                        'threat_types': list(set(t.threat_type for t in time_threats)),
                        'affected_entities': len(set().union(*[t.affected_entities for t in time_threats]))
                    })
                    
        except Exception as e:
            logger.error(f"Error correlating threats: {e}")
        
        return correlations

    async def cleanup_old_threats(self):
        """Clean up old threat signatures"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=24)
            
            # Remove old threats from active tracking
            old_threats = [tid for tid, threat in self.active_threats.items() 
                          if threat.last_seen < cutoff_time]
            
            for threat_id in old_threats:
                del self.active_threats[threat_id]
            
            logger.info(f"Cleaned up {len(old_threats)} old threats")
            
        except Exception as e:
            logger.error(f"Error cleaning up old threats: {e}")

    async def close(self):
        """Close connections and cleanup"""
        try:
            if self.redis_client:
                await self.redis_client.close()
            
            if self.db_pool:
                await self.db_pool.close()
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


async def main():
    """Example usage of the behavioral analyzer"""
    # Initialize the threat detector
    detector = AdvancedThreatDetector()
    await detector.initialize()
    
    # Example security event
    event = SecurityEvent(
        event_id="test_event_001",
        timestamp=datetime.now(),
        event_type="authentication_failure",
        severity="medium",
        source="auth-service",
        client_id="client_123",
        user_id="user_456",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0...",
        request_id="req_789",
        session_id="sess_abc",
        description="Authentication failed",
        details={"reason": "invalid_password"},
        outcome="failure",
        resource="/oauth/token",
        action="authenticate",
        risk_score=60,
        location="New York, US",
        device_fingerprint="device_xyz"
    )
    
    # Analyze the event
    threats = await detector.analyze_event(event)
    
    for threat in threats:
        print(f"Threat detected: {threat.threat_type} (confidence: {threat.confidence})")
        print(f"Indicators: {threat.indicators}")
        print(f"Mitigation: {threat.mitigation_actions}")
        print("---")
    
    # Get active threats
    active_threats = await detector.get_active_threats()
    print(f"Active threats: {len(active_threats)}")
    
    # Correlate threats
    correlations = await detector.correlate_threats()
    print(f"Threat correlations: {len(correlations)}")
    
    await detector.close()


if __name__ == "__main__":
    asyncio.run(main())