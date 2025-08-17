#!/usr/bin/env python3
"""
Real-time Threat Intelligence Correlation System
for Rust Authentication Service

This module provides comprehensive threat intelligence gathering,
correlation, and real-time monitoring capabilities to detect
known attack patterns, IOCs, and emerging threats.
"""

import asyncio
import json
import logging
import aiohttp
import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
import ipaddress
import re
from urllib.parse import urlparse

# Database and caching
import asyncpg
import redis.asyncio as redis

# Monitoring
from prometheus_client import Counter, Histogram, Gauge

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Prometheus metrics
THREAT_INTEL_QUERIES = Counter(
    'threat_intel_queries_total',
    'Total threat intelligence queries',
    ['source', 'indicator_type', 'result']
)

IOC_MATCHES = Counter(
    'ioc_matches_total',
    'Total IOC matches detected',
    ['ioc_type', 'severity', 'source']
)

THREAT_FEED_STATUS = Gauge(
    'threat_feed_status',
    'Status of threat intelligence feeds',
    ['feed_name', 'status']  # status: 1=healthy, 0=failed
)

INTEL_PROCESSING_DURATION = Histogram(
    'threat_intel_processing_duration_seconds',
    'Duration of threat intelligence processing operations',
    ['operation_type']
)


@dataclass
class ThreatIndicator:
    """Represents a threat indicator from intelligence feeds"""
    indicator: str
    indicator_type: str  # ip, domain, hash, url, email
    threat_type: str
    severity: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    source: str
    description: str
    tags: List[str]
    ttl: int  # Time to live in seconds
    false_positive_probability: float
    
    def is_expired(self) -> bool:
        """Check if indicator has expired"""
        return datetime.now() > self.first_seen + timedelta(seconds=self.ttl)


@dataclass
class ThreatMatch:
    """Represents a match between event data and threat intelligence"""
    match_id: str
    indicator: ThreatIndicator
    matched_value: str
    event_id: str
    confidence: float
    context: Dict[str, Any]
    detected_at: datetime
    false_positive_score: float
    risk_score: int


@dataclass
class ThreatCampaign:
    """Represents a coordinated threat campaign"""
    campaign_id: str
    campaign_name: str
    threat_actor: str
    start_date: datetime
    end_date: Optional[datetime]
    indicators: List[ThreatIndicator]
    ttps: List[str]  # Tactics, Techniques, and Procedures
    targeted_sectors: List[str]
    description: str
    severity: str


class ThreatIntelligenceCorrelator:
    """Advanced threat intelligence correlation and monitoring system"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379", 
                 postgres_url: str = "postgresql://localhost/security_db"):
        self.redis_url = redis_url
        self.postgres_url = postgres_url
        self.redis_client = None
        self.db_pool = None
        
        # Threat intelligence storage
        self.indicators = {}  # indicator -> ThreatIndicator
        self.campaigns = {}   # campaign_id -> ThreatCampaign
        self.recent_matches = deque(maxlen=10000)
        
        # Feed configurations
        self.threat_feeds = {
            'misp': {
                'url': 'https://your-misp-instance.com/events/restSearch',
                'api_key': 'your_misp_api_key',
                'enabled': True,
                'refresh_interval': 3600  # 1 hour
            },
            'virustotal': {
                'url': 'https://www.virustotal.com/vtapi/v2',
                'api_key': 'your_virustotal_api_key',
                'enabled': True,
                'refresh_interval': 7200  # 2 hours
            },
            'abuse_ch': {
                'url': 'https://urlhaus-api.abuse.ch/v1/download/text',
                'enabled': True,
                'refresh_interval': 1800  # 30 minutes
            },
            'alienvault': {
                'url': 'https://otx.alienvault.com/api/v1/indicators',
                'api_key': 'your_alienvault_api_key',
                'enabled': True,
                'refresh_interval': 3600  # 1 hour
            },
            'custom_feeds': []  # Add custom threat feeds
        }
        
        # Indicator patterns for detection
        self.patterns = {
            'ip': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'domain': re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b')
        }
        
        # Whitelist for known good indicators
        self.whitelist = set()
        
        # Feed update tasks
        self.feed_tasks = []

    async def initialize(self):
        """Initialize the threat intelligence correlator"""
        try:
            # Initialize connections
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logger.info("Redis connection established for threat intelligence")
            
            self.db_pool = await asyncpg.create_pool(self.postgres_url)
            logger.info("PostgreSQL connection pool established for threat intelligence")
            
            # Load existing indicators from cache
            await self._load_cached_indicators()
            
            # Load whitelist
            await self._load_whitelist()
            
            # Start threat feed updates
            await self._start_feed_updates()
            
            logger.info("Threat intelligence correlator initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize threat intelligence correlator: {e}")
            raise

    async def _load_cached_indicators(self):
        """Load cached threat indicators from Redis"""
        try:
            keys = await self.redis_client.keys("threat_indicator:*")
            loaded_count = 0
            
            for key in keys:
                indicator_data = await self.redis_client.get(key)
                if indicator_data:
                    data = json.loads(indicator_data)
                    # Convert datetime strings back to datetime objects
                    data['first_seen'] = datetime.fromisoformat(data['first_seen'])
                    data['last_seen'] = datetime.fromisoformat(data['last_seen'])
                    
                    indicator = ThreatIndicator(**data)
                    if not indicator.is_expired():
                        self.indicators[indicator.indicator] = indicator
                        loaded_count += 1
                    else:
                        # Remove expired indicator
                        await self.redis_client.delete(key)
            
            logger.info(f"Loaded {loaded_count} cached threat indicators")
            
        except Exception as e:
            logger.error(f"Error loading cached indicators: {e}")

    async def _load_whitelist(self):
        """Load whitelist from database"""
        try:
            async with self.db_pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT indicator, indicator_type FROM threat_whitelist 
                    WHERE active = true
                """)
                
                for row in rows:
                    self.whitelist.add(row['indicator'])
                
                logger.info(f"Loaded {len(self.whitelist)} whitelisted indicators")
                
        except Exception as e:
            logger.error(f"Error loading whitelist: {e}")

    async def _start_feed_updates(self):
        """Start background tasks for threat feed updates"""
        for feed_name, config in self.threat_feeds.items():
            if config.get('enabled', False):
                task = asyncio.create_task(self._feed_update_loop(feed_name, config))
                self.feed_tasks.append(task)
                logger.info(f"Started update task for {feed_name} feed")

    async def _feed_update_loop(self, feed_name: str, config: Dict):
        """Background loop for updating threat feeds"""
        while True:
            try:
                logger.info(f"Updating {feed_name} threat feed")
                
                with INTEL_PROCESSING_DURATION.labels(operation_type='feed_update').time():
                    if feed_name == 'misp':
                        await self._update_misp_feed(config)
                    elif feed_name == 'virustotal':
                        await self._update_virustotal_feed(config)
                    elif feed_name == 'abuse_ch':
                        await self._update_abuse_ch_feed(config)
                    elif feed_name == 'alienvault':
                        await self._update_alienvault_feed(config)
                
                THREAT_FEED_STATUS.labels(feed_name=feed_name, status='healthy').set(1)
                THREAT_FEED_STATUS.labels(feed_name=feed_name, status='failed').set(0)
                
                logger.info(f"Successfully updated {feed_name} feed")
                
            except Exception as e:
                logger.error(f"Error updating {feed_name} feed: {e}")
                THREAT_FEED_STATUS.labels(feed_name=feed_name, status='healthy').set(0)
                THREAT_FEED_STATUS.labels(feed_name=feed_name, status='failed').set(1)
            
            # Wait for next update
            await asyncio.sleep(config['refresh_interval'])

    async def _update_misp_feed(self, config: Dict):
        """Update indicators from MISP feed"""
        try:
            headers = {
                'Authorization': config['api_key'],
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            # Get recent events (last 24 hours)
            payload = {
                'returnFormat': 'json',
                'last': '1d',
                'type': ['ip-src', 'ip-dst', 'domain', 'hostname', 'url', 'md5', 'sha1', 'sha256'],
                'published': True
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(config['url'], 
                                      headers=headers, 
                                      json=payload,
                                      timeout=aiohttp.ClientTimeout(total=60)) as response:
                    if response.status == 200:
                        data = await response.json()
                        await self._process_misp_events(data)
                    else:
                        logger.error(f"MISP API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error updating MISP feed: {e}")
            raise

    async def _process_misp_events(self, events: List[Dict]):
        """Process MISP events and extract indicators"""
        for event in events.get('response', []):
            try:
                event_data = event.get('Event', {})
                event_info = event_data.get('info', '')
                threat_level = event_data.get('threat_level_id', '3')
                
                # Convert MISP threat level to severity
                severity_map = {'1': 'critical', '2': 'high', '3': 'medium', '4': 'low'}
                severity = severity_map.get(threat_level, 'medium')
                
                # Process attributes
                for attribute in event_data.get('Attribute', []):
                    await self._create_indicator_from_misp_attribute(
                        attribute, event_info, severity
                    )
                    
            except Exception as e:
                logger.error(f"Error processing MISP event: {e}")

    async def _create_indicator_from_misp_attribute(self, attribute: Dict, 
                                                  event_info: str, severity: str):
        """Create threat indicator from MISP attribute"""
        try:
            indicator_value = attribute.get('value', '').strip()
            indicator_type = attribute.get('type', '')
            
            if not indicator_value or indicator_value in self.whitelist:
                return
            
            # Map MISP types to our types
            type_mapping = {
                'ip-src': 'ip', 'ip-dst': 'ip',
                'domain': 'domain', 'hostname': 'domain',
                'url': 'url',
                'md5': 'md5', 'sha1': 'sha1', 'sha256': 'sha256',
                'email': 'email'
            }
            
            mapped_type = type_mapping.get(indicator_type)
            if not mapped_type:
                return
            
            # Create indicator
            indicator = ThreatIndicator(
                indicator=indicator_value,
                indicator_type=mapped_type,
                threat_type='malicious',
                severity=severity,
                confidence=0.8,  # MISP indicators generally high confidence
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                source='misp',
                description=f"MISP: {event_info}",
                tags=attribute.get('Tag', []),
                ttl=86400 * 7,  # 7 days
                false_positive_probability=0.1
            )
            
            await self._store_indicator(indicator)
            
        except Exception as e:
            logger.error(f"Error creating MISP indicator: {e}")

    async def _update_virustotal_feed(self, config: Dict):
        """Update indicators from VirusTotal"""
        try:
            # This is a simplified example - in practice, you'd use VT's intelligence API
            # or consume their feeds for recent malicious indicators
            pass
        except Exception as e:
            logger.error(f"Error updating VirusTotal feed: {e}")
            raise

    async def _update_abuse_ch_feed(self, config: Dict):
        """Update indicators from Abuse.ch URLhaus"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(config['url'],
                                     timeout=aiohttp.ClientTimeout(total=60)) as response:
                    if response.status == 200:
                        content = await response.text()
                        await self._process_abuse_ch_data(content)
                    else:
                        logger.error(f"Abuse.ch API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error updating Abuse.ch feed: {e}")
            raise

    async def _process_abuse_ch_data(self, content: str):
        """Process Abuse.ch URLhaus data"""
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                try:
                    # URLhaus format: URL
                    if line.startswith('http'):
                        indicator = ThreatIndicator(
                            indicator=line,
                            indicator_type='url',
                            threat_type='malware',
                            severity='high',
                            confidence=0.9,
                            first_seen=datetime.now(),
                            last_seen=datetime.now(),
                            source='abuse_ch',
                            description="Malicious URL from URLhaus",
                            tags=['malware', 'c2'],
                            ttl=86400 * 3,  # 3 days
                            false_positive_probability=0.05
                        )
                        
                        await self._store_indicator(indicator)
                        
                except Exception as e:
                    logger.error(f"Error processing URLhaus line: {e}")

    async def _update_alienvault_feed(self, config: Dict):
        """Update indicators from AlienVault OTX"""
        try:
            headers = {
                'X-OTX-API-KEY': config['api_key'],
                'Content-Type': 'application/json'
            }
            
            # Get recent pulses
            url = f"{config['url']}/general"
            params = {'modified_since': (datetime.now() - timedelta(days=1)).isoformat()}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params,
                                     timeout=aiohttp.ClientTimeout(total=60)) as response:
                    if response.status == 200:
                        data = await response.json()
                        await self._process_otx_pulses(data.get('results', []))
                    else:
                        logger.error(f"OTX API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error updating OTX feed: {e}")
            raise

    async def _process_otx_pulses(self, pulses: List[Dict]):
        """Process OTX pulses and extract indicators"""
        for pulse in pulses:
            try:
                pulse_name = pulse.get('name', '')
                tags = [tag['name'] for tag in pulse.get('tags', [])]
                
                for indicator_data in pulse.get('indicators', []):
                    indicator_value = indicator_data.get('indicator', '').strip()
                    indicator_type = indicator_data.get('type', '')
                    
                    if not indicator_value or indicator_value in self.whitelist:
                        continue
                    
                    # Map OTX types to our types
                    type_mapping = {
                        'IPv4': 'ip', 'IPv6': 'ip',
                        'domain': 'domain', 'hostname': 'domain',
                        'URL': 'url',
                        'FileHash-MD5': 'md5',
                        'FileHash-SHA1': 'sha1',
                        'FileHash-SHA256': 'sha256',
                        'email': 'email'
                    }
                    
                    mapped_type = type_mapping.get(indicator_type)
                    if not mapped_type:
                        continue
                    
                    indicator = ThreatIndicator(
                        indicator=indicator_value,
                        indicator_type=mapped_type,
                        threat_type='malicious',
                        severity='medium',
                        confidence=0.7,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        source='alienvault_otx',
                        description=f"OTX Pulse: {pulse_name}",
                        tags=tags,
                        ttl=86400 * 5,  # 5 days
                        false_positive_probability=0.15
                    )
                    
                    await self._store_indicator(indicator)
                    
            except Exception as e:
                logger.error(f"Error processing OTX pulse: {e}")

    async def _store_indicator(self, indicator: ThreatIndicator):
        """Store threat indicator in cache and database"""
        try:
            # Store in memory
            self.indicators[indicator.indicator] = indicator
            
            # Store in Redis
            indicator_data = asdict(indicator)
            indicator_data['first_seen'] = indicator_data['first_seen'].isoformat()
            indicator_data['last_seen'] = indicator_data['last_seen'].isoformat()
            
            await self.redis_client.set(
                f"threat_indicator:{indicator.indicator}",
                json.dumps(indicator_data),
                ex=indicator.ttl
            )
            
            # Store in PostgreSQL for persistence
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO threat_indicators 
                    (indicator, indicator_type, threat_type, severity, confidence,
                     first_seen, last_seen, source, description, tags, ttl, false_positive_probability)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    ON CONFLICT (indicator) DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    confidence = EXCLUDED.confidence,
                    severity = EXCLUDED.severity
                """, 
                indicator.indicator, indicator.indicator_type, indicator.threat_type,
                indicator.severity, indicator.confidence, indicator.first_seen, indicator.last_seen,
                indicator.source, indicator.description, json.dumps(indicator.tags),
                indicator.ttl, indicator.false_positive_probability)
            
        except Exception as e:
            logger.error(f"Error storing indicator {indicator.indicator}: {e}")

    async def check_indicators(self, event_data: Dict) -> List[ThreatMatch]:
        """Check event data against threat intelligence indicators"""
        matches = []
        
        try:
            with INTEL_PROCESSING_DURATION.labels(operation_type='indicator_check').time():
                # Extract potential indicators from event data
                extracted_indicators = self._extract_indicators_from_event(event_data)
                
                for indicator_type, values in extracted_indicators.items():
                    for value in values:
                        # Check against known threat indicators
                        threat_indicator = self.indicators.get(value)
                        
                        if threat_indicator and not threat_indicator.is_expired():
                            # Calculate match confidence
                            confidence = self._calculate_match_confidence(
                                threat_indicator, event_data
                            )
                            
                            # Calculate false positive score
                            fp_score = self._calculate_false_positive_score(
                                threat_indicator, event_data
                            )
                            
                            if confidence > 0.5 and fp_score < 0.8:  # Thresholds
                                match = ThreatMatch(
                                    match_id=f"match_{hashlib.md5(f'{event_data.get('event_id', '')}{value}'.encode()).hexdigest()}",
                                    indicator=threat_indicator,
                                    matched_value=value,
                                    event_id=event_data.get('event_id', ''),
                                    confidence=confidence,
                                    context=event_data,
                                    detected_at=datetime.now(),
                                    false_positive_score=fp_score,
                                    risk_score=self._calculate_risk_score(threat_indicator, confidence)
                                )
                                
                                matches.append(match)
                                self.recent_matches.append(match)
                                
                                # Record metrics
                                IOC_MATCHES.labels(
                                    ioc_type=threat_indicator.indicator_type,
                                    severity=threat_indicator.severity,
                                    source=threat_indicator.source
                                ).inc()
                
                # Check for campaign patterns
                campaign_matches = await self._check_campaign_patterns(event_data, matches)
                matches.extend(campaign_matches)
                
        except Exception as e:
            logger.error(f"Error checking indicators: {e}")
        
        return matches

    def _extract_indicators_from_event(self, event_data: Dict) -> Dict[str, Set[str]]:
        """Extract potential indicators from event data"""
        indicators = defaultdict(set)
        
        # Text fields to search
        text_fields = [
            'ip_address', 'user_agent', 'description', 'details',
            'location', 'resource', 'action'
        ]
        
        for field in text_fields:
            value = event_data.get(field)
            if isinstance(value, str):
                # Extract different types of indicators
                for indicator_type, pattern in self.patterns.items():
                    matches = pattern.findall(value)
                    for match in matches:
                        # Additional validation
                        if self._validate_indicator(indicator_type, match):
                            indicators[indicator_type].add(match)
            elif isinstance(value, dict):
                # Recursively search in nested dictionaries
                nested_indicators = self._extract_indicators_from_event(value)
                for ind_type, values in nested_indicators.items():
                    indicators[ind_type].update(values)
        
        return indicators

    def _validate_indicator(self, indicator_type: str, value: str) -> bool:
        """Validate extracted indicator"""
        try:
            if indicator_type == 'ip':
                # Validate IP address
                ip = ipaddress.ip_address(value)
                # Exclude private IPs and loopback
                return not (ip.is_private or ip.is_loopback or ip.is_link_local)
            
            elif indicator_type == 'domain':
                # Basic domain validation
                return '.' in value and len(value) > 3 and not value.startswith('.')
            
            elif indicator_type == 'url':
                # Validate URL
                parsed = urlparse(value)
                return parsed.scheme in ['http', 'https'] and parsed.netloc
            
            elif indicator_type in ['md5', 'sha1', 'sha256']:
                # Hash validation (already done by regex)
                return True
            
            elif indicator_type == 'email':
                # Email validation (basic)
                return '@' in value and '.' in value.split('@')[-1]
            
            return True
            
        except Exception:
            return False

    def _calculate_match_confidence(self, threat_indicator: ThreatIndicator, 
                                   event_data: Dict) -> float:
        """Calculate confidence score for indicator match"""
        base_confidence = threat_indicator.confidence
        
        # Adjust based on indicator source reliability
        source_weights = {
            'misp': 1.0,
            'virustotal': 0.9,
            'abuse_ch': 0.95,
            'alienvault_otx': 0.8,
            'custom': 0.7
        }
        
        source_weight = source_weights.get(threat_indicator.source, 0.5)
        confidence = base_confidence * source_weight
        
        # Adjust based on indicator age
        age_days = (datetime.now() - threat_indicator.first_seen).days
        if age_days > 30:
            confidence *= 0.8  # Older indicators less reliable
        
        # Adjust based on event context
        if event_data.get('severity') in ['high', 'critical']:
            confidence *= 1.1  # Higher confidence for already flagged events
        
        return min(1.0, confidence)

    def _calculate_false_positive_score(self, threat_indicator: ThreatIndicator,
                                       event_data: Dict) -> float:
        """Calculate false positive probability for match"""
        base_fp = threat_indicator.false_positive_probability
        
        # Adjust based on indicator type
        type_fp_rates = {
            'ip': 0.2,      # IPs change hands frequently
            'domain': 0.1,   # Domains more stable
            'url': 0.05,     # URLs very specific
            'hash': 0.01,    # Hashes most reliable
            'email': 0.15    # Emails can be spoofed
        }
        
        type_fp = type_fp_rates.get(threat_indicator.indicator_type, 0.2)
        
        # Combine base and type-specific rates
        combined_fp = (base_fp + type_fp) / 2
        
        # Adjust based on event legitimacy indicators
        if event_data.get('outcome') == 'success':
            combined_fp *= 1.5  # Successful events less likely to be malicious
        
        return min(1.0, combined_fp)

    def _calculate_risk_score(self, threat_indicator: ThreatIndicator, 
                             confidence: float) -> int:
        """Calculate risk score for threat match"""
        severity_scores = {
            'critical': 90,
            'high': 75,
            'medium': 50,
            'low': 25
        }
        
        base_score = severity_scores.get(threat_indicator.severity, 50)
        
        # Adjust by confidence
        adjusted_score = base_score * confidence
        
        # Adjust by source reliability
        source_multipliers = {
            'misp': 1.0,
            'virustotal': 0.9,
            'abuse_ch': 0.95,
            'alienvault_otx': 0.8
        }
        
        multiplier = source_multipliers.get(threat_indicator.source, 0.7)
        final_score = adjusted_score * multiplier
        
        return int(min(100, max(1, final_score)))

    async def _check_campaign_patterns(self, event_data: Dict, 
                                     matches: List[ThreatMatch]) -> List[ThreatMatch]:
        """Check for threat campaign patterns"""
        campaign_matches = []
        
        try:
            # Look for multiple indicators from same campaign
            matched_sources = set(match.indicator.source for match in matches)
            
            if len(matched_sources) > 1:
                # Multiple sources indicating same threat - higher confidence
                for match in matches:
                    if match.confidence < 0.9:
                        # Create enhanced match for campaign correlation
                        enhanced_match = ThreatMatch(
                            match_id=f"campaign_{match.match_id}",
                            indicator=match.indicator,
                            matched_value=match.matched_value,
                            event_id=match.event_id,
                            confidence=min(0.95, match.confidence + 0.2),
                            context={**match.context, 'campaign_correlation': True},
                            detected_at=match.detected_at,
                            false_positive_score=match.false_positive_score * 0.7,
                            risk_score=min(100, match.risk_score + 15)
                        )
                        campaign_matches.append(enhanced_match)
            
        except Exception as e:
            logger.error(f"Error checking campaign patterns: {e}")
        
        return campaign_matches

    async def enrich_event(self, event_data: Dict) -> Dict[str, Any]:
        """Enrich event data with threat intelligence"""
        enrichment = {
            'threat_matches': [],
            'risk_enhancement': 0,
            'intelligence_sources': [],
            'recommended_actions': []
        }
        
        try:
            # Check for threat indicators
            matches = await self.check_indicators(event_data)
            
            for match in matches:
                match_info = {
                    'indicator': match.indicator.indicator,
                    'type': match.indicator.indicator_type,
                    'threat_type': match.indicator.threat_type,
                    'severity': match.indicator.severity,
                    'confidence': match.confidence,
                    'source': match.indicator.source,
                    'description': match.indicator.description,
                    'risk_score': match.risk_score
                }
                enrichment['threat_matches'].append(match_info)
                enrichment['intelligence_sources'].append(match.indicator.source)
            
            # Calculate risk enhancement
            if matches:
                max_risk = max(match.risk_score for match in matches)
                enrichment['risk_enhancement'] = max_risk
                
                # Generate recommendations based on matches
                if max_risk >= 80:
                    enrichment['recommended_actions'].extend([
                        'Block indicator immediately',
                        'Investigate all related activities',
                        'Alert security team'
                    ])
                elif max_risk >= 60:
                    enrichment['recommended_actions'].extend([
                        'Monitor activity closely',
                        'Apply additional verification',
                        'Log for investigation'
                    ])
                else:
                    enrichment['recommended_actions'].append('Continue monitoring')
            
            # Store enriched data
            if matches:
                await self._store_enrichment_data(event_data, enrichment)
            
        except Exception as e:
            logger.error(f"Error enriching event: {e}")
        
        return enrichment

    async def _store_enrichment_data(self, event_data: Dict, enrichment: Dict):
        """Store threat intelligence enrichment data"""
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO threat_enrichments 
                    (event_id, enrichment_data, risk_enhancement, created_at)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (event_id) DO UPDATE SET
                    enrichment_data = EXCLUDED.enrichment_data,
                    risk_enhancement = EXCLUDED.risk_enhancement,
                    updated_at = NOW()
                """,
                event_data.get('event_id', ''),
                json.dumps(enrichment),
                enrichment.get('risk_enhancement', 0),
                datetime.now())
                
        except Exception as e:
            logger.error(f"Error storing enrichment data: {e}")

    async def get_threat_summary(self, time_window_hours: int = 24) -> Dict[str, Any]:
        """Get threat intelligence summary for specified time window"""
        summary = {
            'total_indicators': len(self.indicators),
            'recent_matches': 0,
            'severity_breakdown': defaultdict(int),
            'source_breakdown': defaultdict(int),
            'type_breakdown': defaultdict(int),
            'top_threats': [],
            'trending_indicators': []
        }
        
        try:
            cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
            
            # Analyze recent matches
            recent_matches = [m for m in self.recent_matches if m.detected_at > cutoff_time]
            summary['recent_matches'] = len(recent_matches)
            
            # Breakdown by severity, source, and type
            for match in recent_matches:
                summary['severity_breakdown'][match.indicator.severity] += 1
                summary['source_breakdown'][match.indicator.source] += 1
                summary['type_breakdown'][match.indicator.indicator_type] += 1
            
            # Top threats by risk score
            sorted_matches = sorted(recent_matches, key=lambda m: m.risk_score, reverse=True)
            summary['top_threats'] = [
                {
                    'indicator': m.indicator.indicator,
                    'type': m.indicator.indicator_type,
                    'risk_score': m.risk_score,
                    'description': m.indicator.description
                }
                for m in sorted_matches[:10]
            ]
            
            # Trending indicators (appearing multiple times)
            indicator_counts = defaultdict(int)
            for match in recent_matches:
                indicator_counts[match.indicator.indicator] += 1
            
            trending = sorted(indicator_counts.items(), key=lambda x: x[1], reverse=True)
            summary['trending_indicators'] = [
                {'indicator': ind, 'count': count}
                for ind, count in trending[:5] if count > 1
            ]
            
        except Exception as e:
            logger.error(f"Error generating threat summary: {e}")
        
        return summary

    async def add_custom_indicator(self, indicator: str, indicator_type: str,
                                 threat_type: str, severity: str, 
                                 description: str, ttl: int = 86400) -> bool:
        """Add custom threat indicator"""
        try:
            custom_indicator = ThreatIndicator(
                indicator=indicator,
                indicator_type=indicator_type,
                threat_type=threat_type,
                severity=severity,
                confidence=0.8,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                source='custom',
                description=description,
                tags=['custom'],
                ttl=ttl,
                false_positive_probability=0.1
            )
            
            await self._store_indicator(custom_indicator)
            logger.info(f"Added custom indicator: {indicator}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding custom indicator: {e}")
            return False

    async def add_to_whitelist(self, indicator: str, reason: str) -> bool:
        """Add indicator to whitelist"""
        try:
            self.whitelist.add(indicator)
            
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO threat_whitelist (indicator, reason, created_at, active)
                    VALUES ($1, $2, $3, true)
                    ON CONFLICT (indicator) DO UPDATE SET
                    reason = EXCLUDED.reason,
                    updated_at = NOW(),
                    active = true
                """, indicator, reason, datetime.now())
            
            # Remove from active indicators if present
            if indicator in self.indicators:
                del self.indicators[indicator]
                await self.redis_client.delete(f"threat_indicator:{indicator}")
            
            logger.info(f"Added to whitelist: {indicator}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding to whitelist: {e}")
            return False

    async def cleanup_expired_indicators(self):
        """Clean up expired threat indicators"""
        try:
            expired_count = 0
            expired_indicators = []
            
            for indicator_value, indicator in self.indicators.items():
                if indicator.is_expired():
                    expired_indicators.append(indicator_value)
                    expired_count += 1
            
            # Remove expired indicators
            for indicator_value in expired_indicators:
                del self.indicators[indicator_value]
                await self.redis_client.delete(f"threat_indicator:{indicator_value}")
            
            logger.info(f"Cleaned up {expired_count} expired indicators")
            
        except Exception as e:
            logger.error(f"Error cleaning up expired indicators: {e}")

    async def close(self):
        """Close connections and cleanup"""
        try:
            # Cancel feed update tasks
            for task in self.feed_tasks:
                task.cancel()
            
            if self.redis_client:
                await self.redis_client.close()
            
            if self.db_pool:
                await self.db_pool.close()
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


async def main():
    """Example usage of threat intelligence correlator"""
    correlator = ThreatIntelligenceCorrelator()
    await correlator.initialize()
    
    # Example event data
    event_data = {
        'event_id': 'test_event_001',
        'ip_address': '192.168.1.100',  # Example IP
        'user_agent': 'Mozilla/5.0...',
        'description': 'Authentication attempt',
        'severity': 'medium'
    }
    
    # Check for threat indicators
    matches = await correlator.check_indicators(event_data)
    print(f"Found {len(matches)} threat matches")
    
    # Enrich event
    enrichment = await correlator.enrich_event(event_data)
    print(f"Event enrichment: {enrichment}")
    
    # Get threat summary
    summary = await correlator.get_threat_summary()
    print(f"Threat summary: {summary}")
    
    await correlator.close()


if __name__ == "__main__":
    asyncio.run(main())