#!/usr/bin/env python3
"""
Integration Bridge for Rust Authentication Service
Threat Hunting Toolkit

This module provides seamless integration between the Python threat hunting
components and the Rust authentication service, handling event streaming,
log parsing, and bidirectional communication.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
import aiofiles
import aiohttp
import asyncpg
import redis.asyncio as redis
from dataclasses import dataclass, asdict
from prometheus_client import Counter, Histogram, Gauge

# Import threat hunting components
from behavioral_analyzer import AdvancedThreatDetector, SecurityEvent
from ml_user_profiler import AdvancedUserProfiler, RiskAssessment
from threat_intelligence import ThreatIntelligenceCorrelator
from attack_pattern_detector import AttackPatternDetector
from automated_response import AutomatedResponseOrchestrator, ThreatContext

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Prometheus metrics
EVENTS_PROCESSED = Counter(
    'threat_hunting_events_processed_total',
    'Total security events processed by threat hunting system',
    ['source', 'event_type']
)

PROCESSING_DURATION = Histogram(
    'threat_hunting_processing_duration_seconds',
    'Duration of threat hunting event processing',
    ['component']
)

INTEGRATION_HEALTH = Gauge(
    'threat_hunting_integration_health',
    'Health status of threat hunting integration components',
    ['component']
)

THREATS_DETECTED = Counter(
    'threats_detected_by_component_total',
    'Total threats detected by each component',
    ['component', 'threat_type', 'severity']
)


@dataclass
class ProcessingResult:
    """Result of threat hunting processing"""
    event_id: str
    threats_detected: List[Dict[str, Any]]
    risk_assessment: Optional[Dict[str, Any]]
    threat_intelligence: Optional[Dict[str, Any]]
    attack_patterns: List[Dict[str, Any]]
    response_plan_id: Optional[str]
    processing_time: float
    timestamp: datetime


class RustLogParser:
    """Parser for Rust authentication service security logs"""
    
    def __init__(self):
        # Regex patterns for parsing structured logs
        self.patterns = {
            'security_event': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+'
                r'(?P<level>\w+)\s+'
                r'(?P<target>[\w:]+)\s*'
                r'SECURITY_EVENT:\s*(?P<json_data>.+)'
            ),
            'auth_attempt': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+'
                r'(?P<level>\w+)\s+'
                r'.*Authentication attempt.*client_id=(?P<client_id>\w+).*'
                r'ip_address=(?P<ip_address>[\d.]+).*'
                r'outcome=(?P<outcome>\w+)'
            ),
            'rate_limit': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+'
                r'(?P<level>\w+)\s+'
                r'.*Rate limit exceeded.*client_id=(?P<client_id>\w+).*'
                r'ip_address=(?P<ip_address>[\d.]+)'
            ),
            'token_operation': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+'
                r'(?P<level>\w+)\s+'
                r'.*Token (?P<operation>issue|revoke).*'
                r'client_id=(?P<client_id>\w+)'
            )
        }
    
    def parse_log_line(self, line: str) -> Optional[SecurityEvent]:
        """Parse a single log line into a SecurityEvent"""
        try:
            line = line.strip()
            if not line:
                return None
            
            # Try security event pattern first (JSON structured logs)
            match = self.patterns['security_event'].search(line)
            if match:
                return self._parse_security_event(match)
            
            # Try other patterns
            for pattern_name, pattern in self.patterns.items():
                if pattern_name == 'security_event':
                    continue
                
                match = pattern.search(line)
                if match:
                    return self._parse_legacy_event(pattern_name, match)
            
            return None
            
        except Exception as e:
            logger.error(f"Error parsing log line: {e}")
            return None
    
    def _parse_security_event(self, match) -> SecurityEvent:
        """Parse structured security event JSON"""
        try:
            json_data = json.loads(match.group('json_data'))
            
            # Convert timestamp
            timestamp_str = json_data.get('timestamp', match.group('timestamp'))
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            
            return SecurityEvent(
                event_id=json_data.get('event_id', f"parsed_{int(timestamp.timestamp())}"),
                timestamp=timestamp,
                event_type=json_data.get('event_type', 'unknown'),
                severity=json_data.get('severity', 'medium'),
                source=json_data.get('source', 'auth-service'),
                client_id=json_data.get('client_id'),
                user_id=json_data.get('user_id'),
                ip_address=json_data.get('ip_address'),
                user_agent=json_data.get('user_agent'),
                request_id=json_data.get('request_id'),
                session_id=json_data.get('session_id'),
                description=json_data.get('description', ''),
                details=json_data.get('details', {}),
                outcome=json_data.get('outcome', 'unknown'),
                resource=json_data.get('resource'),
                action=json_data.get('action'),
                risk_score=json_data.get('risk_score'),
                location=json_data.get('location'),
                device_fingerprint=json_data.get('device_fingerprint')
            )
            
        except Exception as e:
            logger.error(f"Error parsing security event JSON: {e}")
            raise
    
    def _parse_legacy_event(self, pattern_name: str, match) -> SecurityEvent:
        """Parse legacy log format events"""
        try:
            timestamp = datetime.fromisoformat(match.group('timestamp').replace('Z', '+00:00'))
            event_id = f"{pattern_name}_{int(timestamp.timestamp())}"
            
            if pattern_name == 'auth_attempt':
                return SecurityEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    event_type='authentication_attempt',
                    severity='low' if match.group('outcome') == 'success' else 'medium',
                    source='auth-service',
                    client_id=match.group('client_id'),
                    user_id=None,
                    ip_address=match.group('ip_address'),
                    user_agent=None,
                    request_id=None,
                    session_id=None,
                    description=f"Authentication {match.group('outcome')}",
                    details={},
                    outcome=match.group('outcome'),
                    resource='/oauth/token',
                    action='authenticate',
                    risk_score=20 if match.group('outcome') == 'success' else 50,
                    location=None,
                    device_fingerprint=None
                )
            
            elif pattern_name == 'rate_limit':
                return SecurityEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    event_type='rate_limit_exceeded',
                    severity='medium',
                    source='auth-service',
                    client_id=match.group('client_id'),
                    user_id=None,
                    ip_address=match.group('ip_address'),
                    user_agent=None,
                    request_id=None,
                    session_id=None,
                    description="Rate limit exceeded",
                    details={},
                    outcome='blocked',
                    resource='/oauth/token',
                    action='rate_limit',
                    risk_score=60,
                    location=None,
                    device_fingerprint=None
                )
            
            elif pattern_name == 'token_operation':
                return SecurityEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    event_type=f"token_{match.group('operation')}",
                    severity='low',
                    source='auth-service',
                    client_id=match.group('client_id'),
                    user_id=None,
                    ip_address=None,
                    user_agent=None,
                    request_id=None,
                    session_id=None,
                    description=f"Token {match.group('operation')}",
                    details={'operation': match.group('operation')},
                    outcome='success',
                    resource='/oauth/token',
                    action=match.group('operation'),
                    risk_score=10,
                    location=None,
                    device_fingerprint=None
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error parsing legacy event: {e}")
            raise


class RustServiceIntegration:
    """Integration layer for communicating with Rust auth service"""
    
    def __init__(self, service_url: str, api_key: str):
        self.service_url = service_url
        self.api_key = api_key
        self.session = None
    
    async def initialize(self):
        """Initialize HTTP session"""
        self.session = aiohttp.ClientSession(
            headers={'Authorization': f'Bearer {self.api_key}'},
            timeout=aiohttp.ClientTimeout(total=30)
        )
    
    async def get_security_metrics(self) -> Dict[str, Any]:
        """Get current security metrics from Rust service"""
        try:
            async with self.session.get(f"{self.service_url}/metrics") as response:
                if response.status == 200:
                    text = await response.text()
                    return self._parse_prometheus_metrics(text)
                else:
                    logger.error(f"Failed to get metrics: {response.status}")
                    return {}
        except Exception as e:
            logger.error(f"Error getting security metrics: {e}")
            return {}
    
    def _parse_prometheus_metrics(self, metrics_text: str) -> Dict[str, Any]:
        """Parse Prometheus metrics format"""
        metrics = {}
        
        for line in metrics_text.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                try:
                    parts = line.split(' ')
                    if len(parts) >= 2:
                        metric_name = parts[0]
                        metric_value = float(parts[1])
                        
                        # Extract labels if present
                        if '{' in metric_name:
                            name_part = metric_name.split('{')[0]
                            labels_part = metric_name.split('{')[1].split('}')[0]
                            
                            if name_part not in metrics:
                                metrics[name_part] = {}
                            
                            metrics[name_part][labels_part] = metric_value
                        else:
                            metrics[metric_name] = metric_value
                            
                except ValueError:
                    continue
        
        return metrics
    
    async def block_ip(self, ip_address: str, duration_minutes: int, reason: str) -> bool:
        """Block an IP address via the Rust service"""
        try:
            payload = {
                'ip_address': ip_address,
                'duration_minutes': duration_minutes,
                'reason': reason
            }
            
            async with self.session.post(f"{self.service_url}/admin/block-ip", 
                                       json=payload) as response:
                return response.status == 200
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False
    
    async def lock_user(self, user_id: str, duration_minutes: int, reason: str) -> bool:
        """Lock a user account via the Rust service"""
        try:
            payload = {
                'user_id': user_id,
                'duration_minutes': duration_minutes,
                'reason': reason
            }
            
            async with self.session.post(f"{self.service_url}/admin/lock-user", 
                                       json=payload) as response:
                return response.status == 200
                
        except Exception as e:
            logger.error(f"Error locking user {user_id}: {e}")
            return False
    
    async def revoke_tokens(self, user_id: str, token_type: str = 'all') -> bool:
        """Revoke user tokens via the Rust service"""
        try:
            payload = {
                'user_id': user_id,
                'token_type': token_type
            }
            
            async with self.session.post(f"{self.service_url}/admin/revoke-tokens", 
                                       json=payload) as response:
                return response.status == 200
                
        except Exception as e:
            logger.error(f"Error revoking tokens for {user_id}: {e}")
            return False
    
    async def get_user_activity(self, user_id: str, hours: int = 24) -> List[Dict]:
        """Get user activity from the Rust service"""
        try:
            params = {'user_id': user_id, 'hours': hours}
            
            async with self.session.get(f"{self.service_url}/admin/user-activity", 
                                      params=params) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting user activity for {user_id}: {e}")
            return []
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()


class ThreatHuntingOrchestrator:
    """Main orchestrator for the threat hunting toolkit"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Initialize components
        self.log_parser = RustLogParser()
        self.rust_integration = None
        self.threat_detector = None
        self.user_profiler = None
        self.threat_intel = None
        self.pattern_detector = None
        self.response_orchestrator = None
        
        # Event processing
        self.event_queue = asyncio.Queue(maxsize=10000)
        self.processing_tasks = []
        
        # Health monitoring
        self.component_health = {}
        
        # Callbacks for threat detection
        self.threat_callbacks = []
    
    async def initialize(self):
        """Initialize all threat hunting components"""
        try:
            logger.info("Initializing threat hunting orchestrator...")
            
            # Initialize Rust service integration
            self.rust_integration = RustServiceIntegration(
                self.config['rust_service']['url'],
                self.config['rust_service']['api_key']
            )
            await self.rust_integration.initialize()
            self.component_health['rust_integration'] = True
            
            # Initialize threat detection components
            self.threat_detector = AdvancedThreatDetector(
                self.config.get('redis_url', 'redis://localhost:6379'),
                self.config.get('postgres_url', 'postgresql://localhost/security_db')
            )
            await self.threat_detector.initialize()
            self.component_health['threat_detector'] = True
            
            self.user_profiler = AdvancedUserProfiler(
                self.config.get('redis_url', 'redis://localhost:6379'),
                self.config.get('postgres_url', 'postgresql://localhost/security_db')
            )
            await self.user_profiler.initialize()
            self.component_health['user_profiler'] = True
            
            self.threat_intel = ThreatIntelligenceCorrelator(
                self.config.get('redis_url', 'redis://localhost:6379'),
                self.config.get('postgres_url', 'postgresql://localhost/security_db')
            )
            await self.threat_intel.initialize()
            self.component_health['threat_intel'] = True
            
            self.pattern_detector = AttackPatternDetector(
                self.config.get('redis_url', 'redis://localhost:6379'),
                self.config.get('postgres_url', 'postgresql://localhost/security_db')
            )
            await self.pattern_detector.initialize()
            self.component_health['pattern_detector'] = True
            
            self.response_orchestrator = AutomatedResponseOrchestrator(
                self.config.get('redis_url', 'redis://localhost:6379'),
                self.config.get('postgres_url', 'postgresql://localhost/security_db'),
                self.config.get('response_config', {})
            )
            await self.response_orchestrator.initialize()
            self.component_health['response_orchestrator'] = True
            
            # Start processing tasks
            num_workers = self.config.get('processing_workers', 4)
            for i in range(num_workers):
                task = asyncio.create_task(self._event_processing_worker(i))
                self.processing_tasks.append(task)
            
            # Start monitoring tasks
            asyncio.create_task(self._health_monitor_loop())
            asyncio.create_task(self._metrics_collection_loop())
            
            # Update health metrics
            for component, health in self.component_health.items():
                INTEGRATION_HEALTH.labels(component=component).set(1 if health else 0)
            
            logger.info("Threat hunting orchestrator initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize threat hunting orchestrator: {e}")
            raise
    
    async def process_log_file(self, file_path: str):
        """Process a log file from the Rust service"""
        try:
            logger.info(f"Processing log file: {file_path}")
            
            async with aiofiles.open(file_path, 'r') as file:
                async for line in file:
                    event = self.log_parser.parse_log_line(line)
                    if event:
                        await self.event_queue.put(event)
                        EVENTS_PROCESSED.labels(
                            source='log_file',
                            event_type=event.event_type
                        ).inc()
            
            logger.info(f"Finished processing log file: {file_path}")
            
        except Exception as e:
            logger.error(f"Error processing log file {file_path}: {e}")
    
    async def process_log_stream(self, log_stream):
        """Process a real-time log stream"""
        try:
            logger.info("Starting log stream processing")
            
            async for line in log_stream:
                try:
                    event = self.log_parser.parse_log_line(line)
                    if event:
                        await self.event_queue.put(event)
                        EVENTS_PROCESSED.labels(
                            source='log_stream',
                            event_type=event.event_type
                        ).inc()
                except asyncio.QueueFull:
                    logger.warning("Event queue full, dropping event")
                except Exception as e:
                    logger.error(f"Error processing log line: {e}")
            
        except Exception as e:
            logger.error(f"Error in log stream processing: {e}")
    
    async def process_event_directly(self, event: SecurityEvent) -> ProcessingResult:
        """Process a single event directly (for testing or API integration)"""
        try:
            start_time = datetime.now()
            
            result = await self._process_security_event(event)
            
            processing_time = (datetime.now() - start_time).total_seconds()
            result.processing_time = processing_time
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing event directly: {e}")
            raise
    
    async def _event_processing_worker(self, worker_id: int):
        """Background worker for processing events from the queue"""
        logger.info(f"Starting event processing worker {worker_id}")
        
        while True:
            try:
                # Get event from queue with timeout
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                
                try:
                    await self._process_security_event(event)
                except Exception as e:
                    logger.error(f"Worker {worker_id} error processing event {event.event_id}: {e}")
                finally:
                    self.event_queue.task_done()
                    
            except asyncio.TimeoutError:
                # No events in queue, continue
                continue
            except Exception as e:
                logger.error(f"Worker {worker_id} unexpected error: {e}")
                await asyncio.sleep(1)
    
    async def _process_security_event(self, event: SecurityEvent) -> ProcessingResult:
        """Process a security event through all threat hunting components"""
        try:
            start_time = datetime.now()
            
            result = ProcessingResult(
                event_id=event.event_id,
                threats_detected=[],
                risk_assessment=None,
                threat_intelligence=None,
                attack_patterns=[],
                response_plan_id=None,
                processing_time=0.0,
                timestamp=start_time
            )
            
            # 1. Behavioral Analysis and Threat Detection
            with PROCESSING_DURATION.labels(component='behavioral_analyzer').time():
                if self.threat_detector:
                    threats = await self.threat_detector.analyze_event(event)
                    result.threats_detected = [asdict(threat) for threat in threats]
                    
                    for threat in threats:
                        THREATS_DETECTED.labels(
                            component='behavioral_analyzer',
                            threat_type=threat.threat_type,
                            severity=threat.severity
                        ).inc()
            
            # 2. User Behavior Profiling (if user_id present)
            if event.user_id:
                with PROCESSING_DURATION.labels(component='user_profiler').time():
                    if self.user_profiler:
                        assessment = await self.user_profiler.analyze_user_behavior(event.user_id)
                        result.risk_assessment = asdict(assessment)
                        
                        if assessment.risk_score >= 0.6:
                            THREATS_DETECTED.labels(
                                component='user_profiler',
                                threat_type='behavioral_anomaly',
                                severity=assessment.risk_level
                            ).inc()
            
            # 3. Threat Intelligence Correlation
            with PROCESSING_DURATION.labels(component='threat_intelligence').time():
                if self.threat_intel:
                    enrichment = await self.threat_intel.enrich_event(asdict(event))
                    result.threat_intelligence = enrichment
                    
                    if enrichment.get('threat_matches'):
                        for match in enrichment['threat_matches']:
                            THREATS_DETECTED.labels(
                                component='threat_intelligence',
                                threat_type=match.get('threat_type', 'unknown'),
                                severity=match.get('severity', 'medium')
                            ).inc()
            
            # 4. Attack Pattern Detection
            with PROCESSING_DURATION.labels(component='pattern_detector').time():
                if self.pattern_detector:
                    patterns = await self.pattern_detector.process_event(asdict(event))
                    result.attack_patterns = [asdict(pattern) for pattern in patterns]
                    
                    for pattern in patterns:
                        THREATS_DETECTED.labels(
                            component='pattern_detector',
                            threat_type=pattern.attack_type,
                            severity=pattern.severity
                        ).inc()
            
            # 5. Automated Response (if threats detected)
            high_severity_threats = [
                t for t in result.threats_detected 
                if t.get('severity') in ['high', 'critical']
            ]
            
            high_risk_assessment = (
                result.risk_assessment and 
                result.risk_assessment.get('risk_score', 0) >= 0.7
            )
            
            high_intel_matches = (
                result.threat_intelligence and 
                result.threat_intelligence.get('risk_enhancement', 0) >= 70
            )
            
            critical_patterns = [
                p for p in result.attack_patterns 
                if p.get('severity') in ['high', 'critical']
            ]
            
            if (high_severity_threats or high_risk_assessment or 
                high_intel_matches or critical_patterns):
                
                if self.response_orchestrator:
                    # Create threat context for response
                    threat_context = self._create_threat_context(event, result)
                    
                    # Create and potentially execute response plan
                    plan = await self.response_orchestrator.create_response_plan(threat_context)
                    result.response_plan_id = plan.plan_id
                    
                    # Execute if auto-approval enabled
                    if not plan.approval_required:
                        await self.response_orchestrator.execute_response_plan(plan.plan_id)
            
            # 6. Call registered threat callbacks
            if result.threats_detected or result.attack_patterns:
                for callback in self.threat_callbacks:
                    try:
                        await callback(event, result)
                    except Exception as e:
                        logger.error(f"Error in threat callback: {e}")
            
            result.processing_time = (datetime.now() - start_time).total_seconds()
            return result
            
        except Exception as e:
            logger.error(f"Error processing security event {event.event_id}: {e}")
            raise
    
    def _create_threat_context(self, event: SecurityEvent, 
                              result: ProcessingResult) -> ThreatContext:
        """Create threat context for response orchestration"""
        # Determine primary threat type
        threat_type = 'suspicious_activity'
        
        if result.threats_detected:
            threat_type = result.threats_detected[0].get('threat_type', threat_type)
        elif result.attack_patterns:
            threat_type = result.attack_patterns[0].get('attack_type', threat_type)
        
        # Determine severity
        severity = 'medium'
        if result.threats_detected:
            severity = result.threats_detected[0].get('severity', severity)
        if result.attack_patterns:
            pattern_severity = result.attack_patterns[0].get('severity', 'medium')
            if pattern_severity in ['high', 'critical']:
                severity = pattern_severity
        
        # Calculate confidence
        confidence = 0.5
        if result.threats_detected:
            confidence = max(confidence, result.threats_detected[0].get('confidence', 0.5))
        if result.risk_assessment:
            confidence = max(confidence, result.risk_assessment.get('confidence', 0.5))
        
        # Gather affected entities
        affected_entities = set()
        if event.user_id:
            affected_entities.add(event.user_id)
        if event.client_id:
            affected_entities.add(event.client_id)
        
        # Gather source IPs
        source_ips = set()
        if event.ip_address:
            source_ips.add(event.ip_address)
        
        # Gather indicators
        indicators = []
        if result.threats_detected:
            for threat in result.threats_detected:
                indicators.extend(threat.get('indicators', []))
        
        # Calculate risk score
        risk_score = 50
        if result.risk_assessment:
            risk_score = int(result.risk_assessment.get('risk_score', 0) * 100)
        if result.threat_intelligence:
            risk_score = max(risk_score, result.threat_intelligence.get('risk_enhancement', 0))
        
        return ThreatContext(
            threat_id=f"threat_{event.event_id}",
            threat_type=threat_type,
            severity=severity,
            confidence=confidence,
            affected_entities=affected_entities,
            source_ips=source_ips,
            indicators=indicators,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            risk_score=risk_score,
            related_events=[event.event_id]
        )
    
    def register_threat_callback(self, callback: Callable):
        """Register a callback for threat detection events"""
        self.threat_callbacks.append(callback)
    
    async def _health_monitor_loop(self):
        """Monitor health of all components"""
        while True:
            try:
                # Check component health
                for component_name, component in [
                    ('threat_detector', self.threat_detector),
                    ('user_profiler', self.user_profiler),
                    ('threat_intel', self.threat_intel),
                    ('pattern_detector', self.pattern_detector),
                    ('response_orchestrator', self.response_orchestrator)
                ]:
                    try:
                        # Simple health check - component exists and has required attributes
                        healthy = (component is not None and 
                                 hasattr(component, 'redis_client') and 
                                 hasattr(component, 'db_pool'))
                        
                        self.component_health[component_name] = healthy
                        INTEGRATION_HEALTH.labels(component=component_name).set(1 if healthy else 0)
                        
                    except Exception as e:
                        logger.error(f"Health check failed for {component_name}: {e}")
                        self.component_health[component_name] = False
                        INTEGRATION_HEALTH.labels(component=component_name).set(0)
                
                # Log overall health status
                unhealthy_components = [name for name, health in self.component_health.items() if not health]
                if unhealthy_components:
                    logger.warning(f"Unhealthy components: {unhealthy_components}")
                else:
                    logger.debug("All components healthy")
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in health monitor loop: {e}")
                await asyncio.sleep(60)
    
    async def _metrics_collection_loop(self):
        """Collect metrics from Rust service periodically"""
        while True:
            try:
                if self.rust_integration:
                    metrics = await self.rust_integration.get_security_metrics()
                    
                    # Process metrics and update Prometheus counters
                    # This would depend on your specific metrics format
                    logger.debug(f"Collected {len(metrics)} metrics from Rust service")
                
                await asyncio.sleep(30)  # Collect every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                await asyncio.sleep(30)
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        return {
            'component_health': self.component_health,
            'event_queue_size': self.event_queue.qsize(),
            'processing_workers': len(self.processing_tasks),
            'active_threats': await self._get_active_threats_count(),
            'uptime': (datetime.now() - self.start_time).total_seconds() if hasattr(self, 'start_time') else 0
        }
    
    async def _get_active_threats_count(self) -> int:
        """Get count of currently active threats"""
        try:
            count = 0
            if self.threat_detector:
                threats = await self.threat_detector.get_active_threats()
                count += len(threats)
            if self.pattern_detector:
                sequences = await self.pattern_detector.get_active_sequences()
                count += len(sequences)
            return count
        except Exception as e:
            logger.error(f"Error getting active threats count: {e}")
            return 0
    
    async def close(self):
        """Shutdown the orchestrator and all components"""
        try:
            logger.info("Shutting down threat hunting orchestrator...")
            
            # Cancel processing tasks
            for task in self.processing_tasks:
                task.cancel()
            
            # Close components
            if self.rust_integration:
                await self.rust_integration.close()
            if self.threat_detector:
                await self.threat_detector.close()
            if self.user_profiler:
                await self.user_profiler.close()
            if self.threat_intel:
                await self.threat_intel.close()
            if self.pattern_detector:
                await self.pattern_detector.close()
            if self.response_orchestrator:
                await self.response_orchestrator.close()
            
            logger.info("Threat hunting orchestrator shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")


async def main():
    """Example usage of the threat hunting integration"""
    config = {
        'rust_service': {
            'url': 'http://localhost:8080',
            'api_key': 'your_api_key'
        },
        'redis_url': 'redis://localhost:6379',
        'postgres_url': 'postgresql://localhost/security_db',
        'processing_workers': 4,
        'response_config': {
            'firewall': {
                'api_url': 'https://firewall.company.com/api',
                'api_key': 'your_firewall_key'
            },
            'auth_service': {
                'api_url': 'http://localhost:8080',
                'api_key': 'your_api_key'
            }
        }
    }
    
    orchestrator = ThreatHuntingOrchestrator(config)
    orchestrator.start_time = datetime.now()
    
    # Register a custom threat callback
    async def threat_callback(event: SecurityEvent, result: ProcessingResult):
        print(f"THREAT DETECTED: {len(result.threats_detected)} threats for event {event.event_id}")
        for threat in result.threats_detected:
            print(f"  - {threat.get('threat_type')} (severity: {threat.get('severity')})")
    
    orchestrator.register_threat_callback(threat_callback)
    
    await orchestrator.initialize()
    
    # Example: Process a log file
    # await orchestrator.process_log_file('/path/to/auth-service.log')
    
    # Example: Process a single event
    example_event = SecurityEvent(
        event_id='test_001',
        timestamp=datetime.now(),
        event_type='authentication_failure',
        severity='medium',
        source='auth-service',
        client_id='client123',
        user_id='user456',
        ip_address='192.168.1.100',
        user_agent='Mozilla/5.0...',
        request_id='req789',
        session_id='sess_abc',
        description='Authentication failed',
        details={'reason': 'invalid_password'},
        outcome='failure',
        resource='/oauth/token',
        action='authenticate',
        risk_score=60,
        location='New York, US',
        device_fingerprint='device_xyz'
    )
    
    result = await orchestrator.process_event_directly(example_event)
    print(f"Processing result: {result}")
    
    # Get system status
    status = await orchestrator.get_system_status()
    print(f"System status: {status}")
    
    # Keep running for a while to demonstrate real-time processing
    print("Threat hunting system is running. Press Ctrl+C to stop.")
    try:
        await asyncio.sleep(3600)  # Run for 1 hour
    except KeyboardInterrupt:
        print("Shutting down...")
    
    await orchestrator.close()


if __name__ == "__main__":
    asyncio.run(main())