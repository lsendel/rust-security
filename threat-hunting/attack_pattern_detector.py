#!/usr/bin/env python3
"""
Advanced Attack Pattern Detection System
for Rust Authentication Service

This module implements sophisticated pattern detection algorithms
to identify complex attack sequences, including APTs, credential
stuffing campaigns, and multi-stage attacks.
"""

import asyncio
import json
import logging
import numpy as np
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
import networkx as nx
from sklearn.cluster import DBSCAN
from scipy.spatial.distance import cosine
import asyncpg
import redis.asyncio as redis
from prometheus_client import Counter, Histogram, Gauge

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Prometheus metrics
ATTACK_PATTERNS_DETECTED = Counter(
    'attack_patterns_detected_total',
    'Total attack patterns detected',
    ['pattern_type', 'severity', 'confidence_level']
)

PATTERN_PROCESSING_DURATION = Histogram(
    'pattern_processing_duration_seconds',
    'Duration of pattern detection processing',
    ['detector_type']
)

ACTIVE_ATTACK_SEQUENCES = Gauge(
    'active_attack_sequences_count',
    'Number of currently tracked attack sequences'
)

PATTERN_COMPLEXITY_SCORE = Histogram(
    'pattern_complexity_scores',
    'Distribution of attack pattern complexity scores',
    buckets=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
)


@dataclass
class AttackStep:
    """Represents a single step in an attack sequence"""
    step_id: str
    timestamp: datetime
    event_type: str
    source_ip: str
    user_id: Optional[str]
    target_resource: str
    action: str
    outcome: str
    risk_score: int
    indicators: List[str]
    metadata: Dict[str, Any]


@dataclass
class AttackSequence:
    """Represents a complete attack sequence"""
    sequence_id: str
    attack_type: str
    severity: str
    confidence: float
    start_time: datetime
    end_time: datetime
    steps: List[AttackStep]
    affected_entities: Set[str]
    source_ips: Set[str]
    pattern_signature: str
    complexity_score: int
    mitigation_priority: str
    recommended_actions: List[str]


@dataclass
class PatternRule:
    """Represents an attack pattern detection rule"""
    rule_id: str
    rule_name: str
    pattern_type: str
    sequence_conditions: List[Dict]
    time_window_seconds: int
    minimum_steps: int
    confidence_threshold: float
    severity: str
    enabled: bool
    false_positive_rate: float


class AttackPatternDetector:
    """Advanced attack pattern detection and sequence analysis"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379", 
                 postgres_url: str = "postgresql://localhost/security_db"):
        self.redis_url = redis_url
        self.postgres_url = postgres_url
        self.redis_client = None
        self.db_pool = None
        
        # Pattern tracking
        self.active_sequences = {}  # sequence_id -> AttackSequence
        self.event_buffer = deque(maxlen=50000)  # Sliding window of events
        self.ip_activity_graph = nx.DiGraph()  # Network activity graph
        
        # Detection rules
        self.pattern_rules = {}
        self.sequence_trackers = defaultdict(list)  # Track partial sequences
        
        # Time windows for different pattern types
        self.time_windows = {
            'credential_stuffing': 300,     # 5 minutes
            'brute_force': 900,             # 15 minutes
            'account_takeover': 3600,       # 1 hour
            'lateral_movement': 7200,       # 2 hours
            'apt_campaign': 86400,          # 24 hours
            'privilege_escalation': 1800,   # 30 minutes
            'data_exfiltration': 3600,      # 1 hour
            'reconnaissance': 1800,         # 30 minutes
        }
        
        # Complexity scoring weights
        self.complexity_weights = {
            'unique_ips': 1.0,
            'unique_users': 1.5,
            'time_span': 0.5,
            'step_count': 2.0,
            'resource_diversity': 1.0,
            'technique_variety': 2.5
        }

    async def initialize(self):
        """Initialize the attack pattern detector"""
        try:
            # Initialize connections
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logger.info("Redis connection established for pattern detector")
            
            self.db_pool = await asyncpg.create_pool(self.postgres_url)
            logger.info("PostgreSQL connection pool established for pattern detector")
            
            # Load pattern rules
            await self._load_pattern_rules()
            
            # Load active sequences from cache
            await self._load_active_sequences()
            
            logger.info("Attack pattern detector initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize pattern detector: {e}")
            raise

    async def _load_pattern_rules(self):
        """Load attack pattern detection rules"""
        try:
            # Load rules from database
            async with self.db_pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT * FROM attack_pattern_rules WHERE enabled = true
                """)
                
                for row in rows:
                    rule = PatternRule(
                        rule_id=row['rule_id'],
                        rule_name=row['rule_name'],
                        pattern_type=row['pattern_type'],
                        sequence_conditions=json.loads(row['sequence_conditions']),
                        time_window_seconds=row['time_window_seconds'],
                        minimum_steps=row['minimum_steps'],
                        confidence_threshold=row['confidence_threshold'],
                        severity=row['severity'],
                        enabled=row['enabled'],
                        false_positive_rate=row['false_positive_rate']
                    )
                    self.pattern_rules[rule.rule_id] = rule
            
            # If no rules in database, create default rules
            if not self.pattern_rules:
                await self._create_default_rules()
                
            logger.info(f"Loaded {len(self.pattern_rules)} pattern detection rules")
            
        except Exception as e:
            logger.error(f"Error loading pattern rules: {e}")
            # Create default rules as fallback
            await self._create_default_rules()

    async def _create_default_rules(self):
        """Create default attack pattern detection rules"""
        default_rules = [
            {
                'rule_id': 'credential_stuffing_001',
                'rule_name': 'Credential Stuffing Campaign',
                'pattern_type': 'credential_stuffing',
                'sequence_conditions': [
                    {'event_type': 'authentication_failure', 'min_count': 10},
                    {'unique_users': {'min': 10}},
                    {'failure_rate': {'min': 0.8}}
                ],
                'time_window_seconds': 300,
                'minimum_steps': 3,
                'confidence_threshold': 0.8,
                'severity': 'high',
                'enabled': True,
                'false_positive_rate': 0.1
            },
            {
                'rule_id': 'apt_lateral_movement_001',
                'rule_name': 'APT Lateral Movement',
                'pattern_type': 'lateral_movement',
                'sequence_conditions': [
                    {'event_type': 'authentication_success', 'min_count': 1},
                    {'privilege_escalation': True},
                    {'resource_access': {'count': {'min': 3}}},
                    {'time_anomaly': True}
                ],
                'time_window_seconds': 7200,
                'minimum_steps': 4,
                'confidence_threshold': 0.7,
                'severity': 'critical',
                'enabled': True,
                'false_positive_rate': 0.05
            },
            {
                'rule_id': 'account_takeover_001',
                'rule_name': 'Account Takeover Sequence',
                'pattern_type': 'account_takeover',
                'sequence_conditions': [
                    {'event_type': 'authentication_failure', 'min_count': 5},
                    {'event_type': 'authentication_success', 'min_count': 1},
                    {'location_anomaly': True},
                    {'device_change': True}
                ],
                'time_window_seconds': 3600,
                'minimum_steps': 3,
                'confidence_threshold': 0.75,
                'severity': 'high',
                'enabled': True,
                'false_positive_rate': 0.15
            }
        ]
        
        for rule_data in default_rules:
            rule = PatternRule(**rule_data)
            self.pattern_rules[rule.rule_id] = rule

    async def _load_active_sequences(self):
        """Load active attack sequences from cache"""
        try:
            keys = await self.redis_client.keys("attack_sequence:*")
            loaded_count = 0
            
            for key in keys:
                sequence_data = await self.redis_client.get(key)
                if sequence_data:
                    data = json.loads(sequence_data)
                    # Reconstruct AttackSequence object
                    # Note: This is simplified - in production, implement proper deserialization
                    sequence_id = key.decode().split(":")[-1]
                    # Add to active sequences if not expired
                    if self._is_sequence_active(data):
                        loaded_count += 1
            
            logger.info(f"Loaded {loaded_count} active attack sequences")
            
        except Exception as e:
            logger.error(f"Error loading active sequences: {e}")

    def _is_sequence_active(self, sequence_data: Dict) -> bool:
        """Check if attack sequence is still active"""
        try:
            end_time = datetime.fromisoformat(sequence_data.get('end_time', ''))
            return datetime.now() - end_time < timedelta(hours=24)
        except:
            return False

    async def process_event(self, event_data: Dict) -> List[AttackSequence]:
        """Process a security event and detect attack patterns"""
        detected_sequences = []
        
        try:
            with PATTERN_PROCESSING_DURATION.labels(detector_type='event_processing').time():
                # Create attack step from event
                attack_step = self._create_attack_step(event_data)
                
                # Add to event buffer
                self.event_buffer.append(attack_step)
                
                # Update network activity graph
                self._update_activity_graph(attack_step)
                
                # Check against all pattern rules
                for rule in self.pattern_rules.values():
                    if rule.enabled:
                        sequences = await self._check_pattern_rule(rule, attack_step)
                        detected_sequences.extend(sequences)
                
                # Run advanced pattern detection
                advanced_sequences = await self._detect_advanced_patterns(attack_step)
                detected_sequences.extend(advanced_sequences)
                
                # Update metrics
                for sequence in detected_sequences:
                    ATTACK_PATTERNS_DETECTED.labels(
                        pattern_type=sequence.attack_type,
                        severity=sequence.severity,
                        confidence_level=self._get_confidence_level(sequence.confidence)
                    ).inc()
                    
                    PATTERN_COMPLEXITY_SCORE.observe(sequence.complexity_score)
                
                # Store detected sequences
                for sequence in detected_sequences:
                    await self._store_attack_sequence(sequence)
                
                ACTIVE_ATTACK_SEQUENCES.set(len(self.active_sequences))
                
        except Exception as e:
            logger.error(f"Error processing event for pattern detection: {e}")
        
        return detected_sequences

    def _create_attack_step(self, event_data: Dict) -> AttackStep:
        """Create an AttackStep from event data"""
        return AttackStep(
            step_id=event_data.get('event_id', f"step_{int(datetime.now().timestamp())}"),
            timestamp=datetime.fromisoformat(event_data.get('timestamp', datetime.now().isoformat())),
            event_type=event_data.get('event_type', 'unknown'),
            source_ip=event_data.get('ip_address', 'unknown'),
            user_id=event_data.get('user_id'),
            target_resource=event_data.get('resource', 'unknown'),
            action=event_data.get('action', 'unknown'),
            outcome=event_data.get('outcome', 'unknown'),
            risk_score=event_data.get('risk_score', 0) or 0,
            indicators=event_data.get('indicators', []),
            metadata=event_data.get('details', {}) or {}
        )

    def _update_activity_graph(self, step: AttackStep):
        """Update network activity graph with new step"""
        try:
            # Add nodes for IP and user (if present)
            self.ip_activity_graph.add_node(step.source_ip, 
                                          node_type='ip', 
                                          last_seen=step.timestamp)
            
            if step.user_id:
                self.ip_activity_graph.add_node(step.user_id, 
                                              node_type='user', 
                                              last_seen=step.timestamp)
                
                # Add edge between IP and user
                self.ip_activity_graph.add_edge(step.source_ip, step.user_id,
                                              event_type=step.event_type,
                                              timestamp=step.timestamp,
                                              outcome=step.outcome)
            
            # Add resource node
            if step.target_resource != 'unknown':
                self.ip_activity_graph.add_node(step.target_resource,
                                              node_type='resource',
                                              last_seen=step.timestamp)
                
                self.ip_activity_graph.add_edge(step.source_ip, step.target_resource,
                                              event_type=step.event_type,
                                              timestamp=step.timestamp,
                                              action=step.action)
            
            # Limit graph size to prevent memory issues
            if len(self.ip_activity_graph.nodes) > 10000:
                self._prune_activity_graph()
                
        except Exception as e:
            logger.error(f"Error updating activity graph: {e}")

    def _prune_activity_graph(self):
        """Prune old nodes from activity graph"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=24)
            old_nodes = []
            
            for node, data in self.ip_activity_graph.nodes(data=True):
                if data.get('last_seen', datetime.min) < cutoff_time:
                    old_nodes.append(node)
            
            self.ip_activity_graph.remove_nodes_from(old_nodes)
            logger.info(f"Pruned {len(old_nodes)} old nodes from activity graph")
            
        except Exception as e:
            logger.error(f"Error pruning activity graph: {e}")

    async def _check_pattern_rule(self, rule: PatternRule, 
                                current_step: AttackStep) -> List[AttackSequence]:
        """Check if current step triggers a pattern rule"""
        sequences = []
        
        try:
            # Get relevant events within time window
            cutoff_time = current_step.timestamp - timedelta(seconds=rule.time_window_seconds)
            relevant_steps = [step for step in self.event_buffer 
                            if step.timestamp >= cutoff_time]
            
            if len(relevant_steps) < rule.minimum_steps:
                return sequences
            
            # Check sequence conditions
            if self._evaluate_sequence_conditions(rule.sequence_conditions, relevant_steps):
                # Create attack sequence
                confidence = self._calculate_pattern_confidence(rule, relevant_steps)
                
                if confidence >= rule.confidence_threshold:
                    sequence = AttackSequence(
                        sequence_id=f"{rule.pattern_type}_{int(current_step.timestamp.timestamp())}",
                        attack_type=rule.pattern_type,
                        severity=rule.severity,
                        confidence=confidence,
                        start_time=min(step.timestamp for step in relevant_steps),
                        end_time=current_step.timestamp,
                        steps=relevant_steps,
                        affected_entities=set(step.user_id for step in relevant_steps if step.user_id),
                        source_ips=set(step.source_ip for step in relevant_steps),
                        pattern_signature=self._generate_pattern_signature(relevant_steps),
                        complexity_score=self._calculate_complexity_score(relevant_steps),
                        mitigation_priority=self._determine_mitigation_priority(rule.severity, confidence),
                        recommended_actions=self._generate_mitigation_actions(rule.pattern_type, rule.severity)
                    )
                    
                    sequences.append(sequence)
                    
        except Exception as e:
            logger.error(f"Error checking pattern rule {rule.rule_id}: {e}")
        
        return sequences

    def _evaluate_sequence_conditions(self, conditions: List[Dict], 
                                    steps: List[AttackStep]) -> bool:
        """Evaluate if sequence conditions are met"""
        try:
            for condition in conditions:
                if not self._evaluate_single_condition(condition, steps):
                    return False
            return True
            
        except Exception as e:
            logger.error(f"Error evaluating sequence conditions: {e}")
            return False

    def _evaluate_single_condition(self, condition: Dict, 
                                 steps: List[AttackStep]) -> bool:
        """Evaluate a single condition against steps"""
        try:
            if 'event_type' in condition:
                event_type = condition['event_type']
                min_count = condition.get('min_count', 1)
                matching_steps = [s for s in steps if s.event_type == event_type]
                if len(matching_steps) < min_count:
                    return False
            
            if 'unique_users' in condition:
                unique_users = len(set(s.user_id for s in steps if s.user_id))
                min_users = condition['unique_users'].get('min', 1)
                if unique_users < min_users:
                    return False
            
            if 'failure_rate' in condition:
                total_steps = len(steps)
                failed_steps = len([s for s in steps if s.outcome == 'failure'])
                failure_rate = failed_steps / total_steps if total_steps > 0 else 0
                min_rate = condition['failure_rate'].get('min', 0)
                if failure_rate < min_rate:
                    return False
            
            if 'privilege_escalation' in condition:
                has_escalation = any('privilege' in s.action.lower() or 
                                   'admin' in s.target_resource.lower() 
                                   for s in steps)
                if not has_escalation:
                    return False
            
            if 'location_anomaly' in condition:
                # Simplified location anomaly check
                locations = [s.metadata.get('location') for s in steps 
                           if s.metadata.get('location')]
                unique_locations = len(set(locations))
                if unique_locations <= 1:
                    return False
            
            if 'device_change' in condition:
                # Check for device fingerprint changes
                devices = [s.metadata.get('device_fingerprint') for s in steps 
                         if s.metadata.get('device_fingerprint')]
                unique_devices = len(set(devices))
                if unique_devices <= 1:
                    return False
            
            if 'time_anomaly' in condition:
                # Check for unusual timing patterns
                if not self._detect_time_anomaly(steps):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error evaluating condition: {e}")
            return False

    def _detect_time_anomaly(self, steps: List[AttackStep]) -> bool:
        """Detect timing anomalies in attack steps"""
        try:
            if len(steps) < 3:
                return False
            
            # Calculate time intervals between steps
            sorted_steps = sorted(steps, key=lambda s: s.timestamp)
            intervals = []
            
            for i in range(1, len(sorted_steps)):
                interval = (sorted_steps[i].timestamp - sorted_steps[i-1].timestamp).total_seconds()
                intervals.append(interval)
            
            if not intervals:
                return False
            
            # Check for unusually regular intervals (bot-like behavior)
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            
            # If standard deviation is very low, it might be automated
            if std_interval < mean_interval * 0.1 and mean_interval < 60:  # Less than 1 minute
                return True
            
            # Check for burst patterns (many events in short time)
            if len(steps) > 10 and (sorted_steps[-1].timestamp - sorted_steps[0].timestamp).total_seconds() < 300:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error detecting time anomaly: {e}")
            return False

    def _calculate_pattern_confidence(self, rule: PatternRule, 
                                    steps: List[AttackStep]) -> float:
        """Calculate confidence score for pattern match"""
        try:
            base_confidence = 0.5
            
            # Adjust based on number of steps
            step_factor = min(1.0, len(steps) / (rule.minimum_steps * 2))
            base_confidence += step_factor * 0.2
            
            # Adjust based on risk scores
            avg_risk = np.mean([s.risk_score for s in steps])
            risk_factor = avg_risk / 100.0
            base_confidence += risk_factor * 0.2
            
            # Adjust based on time concentration
            time_span = (max(s.timestamp for s in steps) - min(s.timestamp for s in steps)).total_seconds()
            if time_span < rule.time_window_seconds * 0.5:
                base_confidence += 0.1  # Events concentrated in time
            
            # Adjust for false positive rate
            base_confidence *= (1 - rule.false_positive_rate)
            
            return min(1.0, base_confidence)
            
        except Exception as e:
            logger.error(f"Error calculating pattern confidence: {e}")
            return 0.5

    def _generate_pattern_signature(self, steps: List[AttackStep]) -> str:
        """Generate a signature for the attack pattern"""
        try:
            # Create signature based on event types and actions
            event_types = [s.event_type for s in steps]
            actions = [s.action for s in steps]
            outcomes = [s.outcome for s in steps]
            
            # Count occurrences
            type_counts = {}
            for event_type in set(event_types):
                type_counts[event_type] = event_types.count(event_type)
            
            action_counts = {}
            for action in set(actions):
                action_counts[action] = actions.count(action)
            
            outcome_counts = {}
            for outcome in set(outcomes):
                outcome_counts[outcome] = outcomes.count(outcome)
            
            # Create signature
            signature_parts = []
            signature_parts.append(f"types:{','.join(f'{k}:{v}' for k, v in sorted(type_counts.items()))}")
            signature_parts.append(f"actions:{','.join(f'{k}:{v}' for k, v in sorted(action_counts.items()))}")
            signature_parts.append(f"outcomes:{','.join(f'{k}:{v}' for k, v in sorted(outcome_counts.items()))}")
            
            return "|".join(signature_parts)
            
        except Exception as e:
            logger.error(f"Error generating pattern signature: {e}")
            return "unknown_pattern"

    def _calculate_complexity_score(self, steps: List[AttackStep]) -> int:
        """Calculate complexity score for attack sequence"""
        try:
            score = 0
            
            # Unique IPs
            unique_ips = len(set(s.source_ip for s in steps))
            score += unique_ips * self.complexity_weights['unique_ips']
            
            # Unique users
            unique_users = len(set(s.user_id for s in steps if s.user_id))
            score += unique_users * self.complexity_weights['unique_users']
            
            # Time span (normalized to hours)
            time_span_hours = (max(s.timestamp for s in steps) - min(s.timestamp for s in steps)).total_seconds() / 3600
            score += time_span_hours * self.complexity_weights['time_span']
            
            # Step count
            score += len(steps) * self.complexity_weights['step_count'] / 10  # Normalize
            
            # Resource diversity
            unique_resources = len(set(s.target_resource for s in steps))
            score += unique_resources * self.complexity_weights['resource_diversity']
            
            # Technique variety (different action types)
            unique_actions = len(set(s.action for s in steps))
            score += unique_actions * self.complexity_weights['technique_variety']
            
            return min(10, max(1, int(score)))
            
        except Exception as e:
            logger.error(f"Error calculating complexity score: {e}")
            return 1

    def _determine_mitigation_priority(self, severity: str, confidence: float) -> str:
        """Determine mitigation priority based on severity and confidence"""
        priority_matrix = {
            'critical': {'high': 'immediate', 'medium': 'urgent', 'low': 'high'},
            'high': {'high': 'urgent', 'medium': 'high', 'low': 'medium'},
            'medium': {'high': 'high', 'medium': 'medium', 'low': 'low'},
            'low': {'high': 'medium', 'medium': 'low', 'low': 'low'}
        }
        
        confidence_level = 'high' if confidence >= 0.8 else 'medium' if confidence >= 0.6 else 'low'
        return priority_matrix.get(severity, {}).get(confidence_level, 'low')

    def _generate_mitigation_actions(self, attack_type: str, severity: str) -> List[str]:
        """Generate recommended mitigation actions"""
        base_actions = {
            'credential_stuffing': [
                'Implement rate limiting',
                'Block attacking IP addresses',
                'Enable CAPTCHA for affected accounts',
                'Force password resets for targeted accounts'
            ],
            'brute_force': [
                'Lock affected accounts temporarily',
                'Block source IP addresses',
                'Require additional authentication factors',
                'Alert affected users'
            ],
            'account_takeover': [
                'Immediately suspend affected accounts',
                'Force re-authentication',
                'Review and revoke active sessions',
                'Investigate account activities'
            ],
            'lateral_movement': [
                'Isolate affected systems',
                'Revoke elevated privileges',
                'Audit access permissions',
                'Monitor for further compromise'
            ],
            'apt_campaign': [
                'Initiate incident response procedure',
                'Preserve evidence',
                'Coordinate with threat intelligence',
                'Implement emergency containment measures'
            ]
        }
        
        actions = base_actions.get(attack_type, ['Monitor situation closely'])
        
        # Add severity-specific actions
        if severity in ['critical', 'high']:
            actions.extend([
                'Notify security team immediately',
                'Consider activating incident response team'
            ])
        
        return actions

    async def _detect_advanced_patterns(self, current_step: AttackStep) -> List[AttackSequence]:
        """Detect advanced attack patterns using ML and graph analysis"""
        sequences = []
        
        try:
            # Graph-based pattern detection
            graph_sequences = await self._detect_graph_patterns(current_step)
            sequences.extend(graph_sequences)
            
            # Clustering-based detection
            cluster_sequences = await self._detect_cluster_patterns(current_step)
            sequences.extend(cluster_sequences)
            
            # Behavioral deviation detection
            behavioral_sequences = await self._detect_behavioral_deviations(current_step)
            sequences.extend(behavioral_sequences)
            
        except Exception as e:
            logger.error(f"Error in advanced pattern detection: {e}")
        
        return sequences

    async def _detect_graph_patterns(self, current_step: AttackStep) -> List[AttackSequence]:
        """Detect patterns using graph analysis"""
        sequences = []
        
        try:
            # Look for suspicious subgraphs
            if current_step.source_ip in self.ip_activity_graph:
                # Get subgraph for this IP
                neighbors = list(self.ip_activity_graph.neighbors(current_step.source_ip))
                
                if len(neighbors) > 5:  # IP connected to many entities
                    # Check for potential lateral movement
                    user_nodes = [n for n in neighbors if self.ip_activity_graph.nodes[n].get('node_type') == 'user']
                    resource_nodes = [n for n in neighbors if self.ip_activity_graph.nodes[n].get('node_type') == 'resource']
                    
                    if len(user_nodes) > 2 and len(resource_nodes) > 3:
                        # Potential lateral movement pattern
                        sequence = AttackSequence(
                            sequence_id=f"graph_lateral_{int(current_step.timestamp.timestamp())}",
                            attack_type='lateral_movement',
                            severity='high',
                            confidence=0.7,
                            start_time=current_step.timestamp - timedelta(hours=2),
                            end_time=current_step.timestamp,
                            steps=[current_step],  # Simplified
                            affected_entities=set(user_nodes),
                            source_ips={current_step.source_ip},
                            pattern_signature=f"graph_lateral_{current_step.source_ip}",
                            complexity_score=min(10, len(neighbors)),
                            mitigation_priority='urgent',
                            recommended_actions=[
                                'Investigate IP activity',
                                'Review access patterns',
                                'Consider IP blocking'
                            ]
                        )
                        sequences.append(sequence)
                        
        except Exception as e:
            logger.error(f"Error in graph pattern detection: {e}")
        
        return sequences

    async def _detect_cluster_patterns(self, current_step: AttackStep) -> List[AttackSequence]:
        """Detect patterns using clustering analysis"""
        sequences = []
        
        try:
            # Get recent steps for clustering
            recent_steps = [step for step in self.event_buffer 
                          if step.timestamp > current_step.timestamp - timedelta(hours=1)]
            
            if len(recent_steps) < 10:
                return sequences
            
            # Create feature vectors for clustering
            features = []
            for step in recent_steps:
                feature_vector = [
                    hash(step.source_ip) % 1000,  # IP hash
                    hash(step.event_type) % 100,  # Event type hash
                    step.risk_score,
                    step.timestamp.hour,
                    step.timestamp.minute,
                    len(step.indicators)
                ]
                features.append(feature_vector)
            
            # Perform DBSCAN clustering
            if len(features) >= 10:
                clustering = DBSCAN(eps=50, min_samples=3)
                labels = clustering.fit_predict(features)
                
                # Look for clusters with suspicious characteristics
                unique_labels = set(labels)
                for label in unique_labels:
                    if label != -1:  # Not noise
                        cluster_steps = [recent_steps[i] for i, l in enumerate(labels) if l == label]
                        
                        if len(cluster_steps) >= 5:
                            # Analyze cluster characteristics
                            cluster_ips = set(s.source_ip for s in cluster_steps)
                            cluster_risk = np.mean([s.risk_score for s in cluster_steps])
                            
                            if len(cluster_ips) == 1 and cluster_risk > 50:  # Same IP, high risk
                                sequence = AttackSequence(
                                    sequence_id=f"cluster_{label}_{int(current_step.timestamp.timestamp())}",
                                    attack_type='coordinated_attack',
                                    severity='medium',
                                    confidence=0.6,
                                    start_time=min(s.timestamp for s in cluster_steps),
                                    end_time=max(s.timestamp for s in cluster_steps),
                                    steps=cluster_steps,
                                    affected_entities=set(s.user_id for s in cluster_steps if s.user_id),
                                    source_ips=cluster_ips,
                                    pattern_signature=f"cluster_{label}",
                                    complexity_score=len(cluster_steps),
                                    mitigation_priority='medium',
                                    recommended_actions=[
                                        'Investigate clustered activity',
                                        'Monitor source IPs',
                                        'Review for automation'
                                    ]
                                )
                                sequences.append(sequence)
                                
        except Exception as e:
            logger.error(f"Error in cluster pattern detection: {e}")
        
        return sequences

    async def _detect_behavioral_deviations(self, current_step: AttackStep) -> List[AttackSequence]:
        """Detect behavioral deviation patterns"""
        sequences = []
        
        try:
            if not current_step.user_id:
                return sequences
            
            # Get user's historical behavior
            user_steps = [step for step in self.event_buffer 
                         if step.user_id == current_step.user_id and 
                         step.timestamp > current_step.timestamp - timedelta(days=7)]
            
            if len(user_steps) < 10:
                return sequences
            
            # Analyze behavioral patterns
            historical_hours = [s.timestamp.hour for s in user_steps[:-5]]  # Exclude recent
            recent_hours = [s.timestamp.hour for s in user_steps[-5:]]      # Recent activity
            
            if historical_hours and recent_hours:
                # Calculate behavioral deviation
                hist_mean = np.mean(historical_hours)
                recent_mean = np.mean(recent_hours)
                
                deviation = abs(recent_mean - hist_mean)
                
                if deviation > 6:  # Significant time shift
                    sequence = AttackSequence(
                        sequence_id=f"behavioral_dev_{current_step.user_id}_{int(current_step.timestamp.timestamp())}",
                        attack_type='behavioral_anomaly',
                        severity='medium',
                        confidence=0.6,
                        start_time=user_steps[-5].timestamp,
                        end_time=current_step.timestamp,
                        steps=user_steps[-5:],
                        affected_entities={current_step.user_id},
                        source_ips=set(s.source_ip for s in user_steps[-5:]),
                        pattern_signature=f"behavioral_dev_{deviation:.1f}",
                        complexity_score=3,
                        mitigation_priority='low',
                        recommended_actions=[
                            'Verify user identity',
                            'Review recent activities',
                            'Consider additional authentication'
                        ]
                    )
                    sequences.append(sequence)
                    
        except Exception as e:
            logger.error(f"Error in behavioral deviation detection: {e}")
        
        return sequences

    def _get_confidence_level(self, confidence: float) -> str:
        """Convert confidence score to level"""
        if confidence >= 0.8:
            return 'high'
        elif confidence >= 0.6:
            return 'medium'
        else:
            return 'low'

    async def _store_attack_sequence(self, sequence: AttackSequence):
        """Store detected attack sequence"""
        try:
            # Store in memory
            self.active_sequences[sequence.sequence_id] = sequence
            
            # Store in Redis
            sequence_data = asdict(sequence)
            # Convert sets to lists for JSON serialization
            sequence_data['affected_entities'] = list(sequence_data['affected_entities'])
            sequence_data['source_ips'] = list(sequence_data['source_ips'])
            sequence_data['start_time'] = sequence_data['start_time'].isoformat()
            sequence_data['end_time'] = sequence_data['end_time'].isoformat()
            
            # Simplify steps for storage
            sequence_data['steps'] = [
                {
                    'step_id': step.step_id,
                    'timestamp': step.timestamp.isoformat(),
                    'event_type': step.event_type,
                    'source_ip': step.source_ip,
                    'risk_score': step.risk_score
                }
                for step in sequence.steps[:10]  # Limit to prevent large payloads
            ]
            
            await self.redis_client.set(
                f"attack_sequence:{sequence.sequence_id}",
                json.dumps(sequence_data, default=str),
                ex=86400 * 3  # 3 days expiry
            )
            
            # Store in PostgreSQL
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO attack_sequences 
                    (sequence_id, attack_type, severity, confidence, start_time, end_time,
                     affected_entities, source_ips, pattern_signature, complexity_score,
                     mitigation_priority, recommended_actions, detected_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                    ON CONFLICT (sequence_id) DO UPDATE SET
                    end_time = EXCLUDED.end_time,
                    confidence = EXCLUDED.confidence,
                    complexity_score = EXCLUDED.complexity_score
                """, 
                sequence.sequence_id, sequence.attack_type, sequence.severity,
                sequence.confidence, sequence.start_time, sequence.end_time,
                json.dumps(list(sequence.affected_entities)),
                json.dumps(list(sequence.source_ips)),
                sequence.pattern_signature, sequence.complexity_score,
                sequence.mitigation_priority, json.dumps(sequence.recommended_actions),
                datetime.now())
                
        except Exception as e:
            logger.error(f"Error storing attack sequence {sequence.sequence_id}: {e}")

    async def get_active_sequences(self, severity_filter: Optional[str] = None) -> List[AttackSequence]:
        """Get currently active attack sequences"""
        sequences = list(self.active_sequences.values())
        
        if severity_filter:
            sequences = [s for s in sequences if s.severity == severity_filter]
        
        return sorted(sequences, key=lambda s: s.end_time, reverse=True)

    async def get_sequence_analysis(self, time_window_hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive analysis of attack sequences"""
        analysis = {
            'total_sequences': len(self.active_sequences),
            'severity_breakdown': defaultdict(int),
            'attack_type_breakdown': defaultdict(int),
            'complexity_distribution': defaultdict(int),
            'top_source_ips': defaultdict(int),
            'trending_patterns': [],
            'mitigation_recommendations': []
        }
        
        try:
            cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
            recent_sequences = [s for s in self.active_sequences.values() 
                              if s.end_time > cutoff_time]
            
            # Breakdown analysis
            for sequence in recent_sequences:
                analysis['severity_breakdown'][sequence.severity] += 1
                analysis['attack_type_breakdown'][sequence.attack_type] += 1
                analysis['complexity_distribution'][sequence.complexity_score] += 1
                
                for ip in sequence.source_ips:
                    analysis['top_source_ips'][ip] += 1
            
            # Convert defaultdicts to regular dicts for JSON serialization
            for key in ['severity_breakdown', 'attack_type_breakdown', 
                       'complexity_distribution', 'top_source_ips']:
                analysis[key] = dict(analysis[key])
            
            # Top source IPs
            analysis['top_source_ips'] = dict(sorted(
                analysis['top_source_ips'].items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10])
            
            # Generate trending patterns
            if recent_sequences:
                pattern_counts = defaultdict(int)
                for seq in recent_sequences:
                    pattern_counts[seq.attack_type] += 1
                
                analysis['trending_patterns'] = [
                    {'pattern': pattern, 'count': count}
                    for pattern, count in sorted(pattern_counts.items(), 
                                               key=lambda x: x[1], reverse=True)[:5]
                ]
            
            # Generate mitigation recommendations
            critical_sequences = [s for s in recent_sequences if s.severity == 'critical']
            high_sequences = [s for s in recent_sequences if s.severity == 'high']
            
            if critical_sequences:
                analysis['mitigation_recommendations'].append(
                    'Immediate attention required for critical attack sequences'
                )
            
            if len(high_sequences) > 5:
                analysis['mitigation_recommendations'].append(
                    'High volume of high-severity attacks detected'
                )
            
            if analysis['top_source_ips']:
                top_ip = next(iter(analysis['top_source_ips']))
                if analysis['top_source_ips'][top_ip] > 3:
                    analysis['mitigation_recommendations'].append(
                        f'Consider blocking IP {top_ip} (involved in {analysis["top_source_ips"][top_ip]} sequences)'
                    )
                    
        except Exception as e:
            logger.error(f"Error generating sequence analysis: {e}")
        
        return analysis

    async def cleanup_old_sequences(self):
        """Clean up old attack sequences"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=48)
            old_sequences = []
            
            for seq_id, sequence in self.active_sequences.items():
                if sequence.end_time < cutoff_time:
                    old_sequences.append(seq_id)
            
            for seq_id in old_sequences:
                del self.active_sequences[seq_id]
                await self.redis_client.delete(f"attack_sequence:{seq_id}")
            
            logger.info(f"Cleaned up {len(old_sequences)} old attack sequences")
            
        except Exception as e:
            logger.error(f"Error cleaning up old sequences: {e}")

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
    """Example usage of attack pattern detector"""
    detector = AttackPatternDetector()
    await detector.initialize()
    
    # Example event
    event_data = {
        'event_id': 'test_event_001',
        'timestamp': datetime.now().isoformat(),
        'event_type': 'authentication_failure',
        'ip_address': '192.168.1.100',
        'user_id': 'user123',
        'resource': '/api/login',
        'action': 'authenticate',
        'outcome': 'failure',
        'risk_score': 75,
        'details': {'location': 'Unknown'}
    }
    
    # Process event
    sequences = await detector.process_event(event_data)
    print(f"Detected {len(sequences)} attack sequences")
    
    # Get analysis
    analysis = await detector.get_sequence_analysis()
    print(f"Sequence analysis: {analysis}")
    
    await detector.close()


if __name__ == "__main__":
    asyncio.run(main())