#!/usr/bin/env python3
"""
Automated Threat Response and Orchestration System
for Rust Authentication Service

This module provides comprehensive automated response capabilities
for detected threats, including containment, investigation, and
recovery actions with proper escalation procedures.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Callable
import aiohttp
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
RESPONSE_ACTIONS_EXECUTED = Counter(
    'response_actions_executed_total',
    'Total automated response actions executed',
    ['action_type', 'severity', 'outcome']
)

RESPONSE_DURATION = Histogram(
    'response_action_duration_seconds',
    'Duration of automated response actions',
    ['action_type']
)

ACTIVE_RESPONSES = Gauge(
    'active_responses_count',
    'Number of currently active automated responses'
)

ESCALATION_EVENTS = Counter(
    'escalation_events_total',
    'Total escalation events triggered',
    ['escalation_level', 'reason']
)


class ResponseStatus(Enum):
    """Response action status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REQUIRES_APPROVAL = "requires_approval"


class EscalationLevel(Enum):
    """Escalation levels for incident response"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatContext:
    """Context information about a detected threat"""
    threat_id: str
    threat_type: str
    severity: str
    confidence: float
    affected_entities: Set[str]
    source_ips: Set[str]
    indicators: List[str]
    first_seen: datetime
    last_seen: datetime
    risk_score: int
    related_events: List[str]


@dataclass
class ResponseAction:
    """Represents an automated response action"""
    action_id: str
    action_type: str
    priority: int
    status: ResponseStatus
    created_at: datetime
    scheduled_at: Optional[datetime]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    parameters: Dict[str, Any]
    prerequisites: List[str]
    timeout_seconds: int
    retry_count: int
    max_retries: int
    result: Optional[Dict[str, Any]]
    error_message: Optional[str]
    requires_approval: bool
    approved_by: Optional[str]
    approved_at: Optional[datetime]


@dataclass
class ResponsePlan:
    """Complete response plan for a threat"""
    plan_id: str
    threat_context: ThreatContext
    actions: List[ResponseAction]
    created_at: datetime
    status: str
    escalation_level: EscalationLevel
    estimated_duration: int
    approval_required: bool
    executed_actions: int
    failed_actions: int


class ResponseActionExecutor(ABC):
    """Abstract base class for response action executors"""
    
    @abstractmethod
    async def execute(self, action: ResponseAction, context: ThreatContext) -> Dict[str, Any]:
        """Execute the response action"""
        pass
    
    @abstractmethod
    def validate_parameters(self, parameters: Dict[str, Any]) -> bool:
        """Validate action parameters"""
        pass
    
    @abstractmethod
    def get_required_permissions(self) -> List[str]:
        """Get required permissions for this action"""
        pass


class IPBlockExecutor(ResponseActionExecutor):
    """Executor for IP blocking actions"""
    
    def __init__(self, firewall_api_url: str, api_key: str):
        self.firewall_api_url = firewall_api_url
        self.api_key = api_key
    
    async def execute(self, action: ResponseAction, context: ThreatContext) -> Dict[str, Any]:
        """Block IP addresses in firewall"""
        try:
            ips_to_block = action.parameters.get('ip_addresses', [])
            duration = action.parameters.get('duration_minutes', 60)
            reason = action.parameters.get('reason', f'Threat detected: {context.threat_type}')
            
            blocked_ips = []
            failed_ips = []
            
            for ip in ips_to_block:
                try:
                    success = await self._block_ip(ip, duration, reason)
                    if success:
                        blocked_ips.append(ip)
                    else:
                        failed_ips.append(ip)
                except Exception as e:
                    logger.error(f"Failed to block IP {ip}: {e}")
                    failed_ips.append(ip)
            
            return {
                'blocked_ips': blocked_ips,
                'failed_ips': failed_ips,
                'total_blocked': len(blocked_ips),
                'duration_minutes': duration
            }
            
        except Exception as e:
            logger.error(f"IP block executor error: {e}")
            raise
    
    async def _block_ip(self, ip: str, duration: int, reason: str) -> bool:
        """Block a single IP address"""
        try:
            payload = {
                'ip_address': ip,
                'duration_minutes': duration,
                'reason': reason,
                'action': 'block'
            }
            
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.firewall_api_url}/block",
                                      json=payload, headers=headers,
                                      timeout=aiohttp.ClientTimeout(total=30)) as response:
                    return response.status == 200
                    
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return False
    
    def validate_parameters(self, parameters: Dict[str, Any]) -> bool:
        """Validate IP blocking parameters"""
        required_fields = ['ip_addresses']
        return all(field in parameters for field in required_fields)
    
    def get_required_permissions(self) -> List[str]:
        """Get required permissions"""
        return ['firewall.block', 'network.modify']


class AccountLockExecutor(ResponseActionExecutor):
    """Executor for account locking actions"""
    
    def __init__(self, auth_api_url: str, api_key: str):
        self.auth_api_url = auth_api_url
        self.api_key = api_key
    
    async def execute(self, action: ResponseAction, context: ThreatContext) -> Dict[str, Any]:
        """Lock user accounts"""
        try:
            accounts_to_lock = action.parameters.get('user_accounts', [])
            duration = action.parameters.get('duration_minutes', 30)
            reason = action.parameters.get('reason', f'Security threat: {context.threat_type}')
            
            locked_accounts = []
            failed_accounts = []
            
            for account in accounts_to_lock:
                try:
                    success = await self._lock_account(account, duration, reason)
                    if success:
                        locked_accounts.append(account)
                    else:
                        failed_accounts.append(account)
                except Exception as e:
                    logger.error(f"Failed to lock account {account}: {e}")
                    failed_accounts.append(account)
            
            return {
                'locked_accounts': locked_accounts,
                'failed_accounts': failed_accounts,
                'total_locked': len(locked_accounts),
                'duration_minutes': duration
            }
            
        except Exception as e:
            logger.error(f"Account lock executor error: {e}")
            raise
    
    async def _lock_account(self, account: str, duration: int, reason: str) -> bool:
        """Lock a single account"""
        try:
            payload = {
                'user_id': account,
                'lock_duration_minutes': duration,
                'reason': reason,
                'lock_type': 'security_incident'
            }
            
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.auth_api_url}/admin/lock-account",
                                      json=payload, headers=headers,
                                      timeout=aiohttp.ClientTimeout(total=30)) as response:
                    return response.status == 200
                    
        except Exception as e:
            logger.error(f"Error locking account {account}: {e}")
            return False
    
    def validate_parameters(self, parameters: Dict[str, Any]) -> bool:
        """Validate account locking parameters"""
        required_fields = ['user_accounts']
        return all(field in parameters for field in required_fields)
    
    def get_required_permissions(self) -> List[str]:
        """Get required permissions"""
        return ['user.lock', 'admin.security_action']


class TokenRevokeExecutor(ResponseActionExecutor):
    """Executor for token revocation actions"""
    
    def __init__(self, auth_api_url: str, api_key: str):
        self.auth_api_url = auth_api_url
        self.api_key = api_key
    
    async def execute(self, action: ResponseAction, context: ThreatContext) -> Dict[str, Any]:
        """Revoke tokens for affected users"""
        try:
            users = action.parameters.get('user_accounts', [])
            token_types = action.parameters.get('token_types', ['access', 'refresh'])
            
            revoked_tokens = []
            failed_revocations = []
            
            for user in users:
                for token_type in token_types:
                    try:
                        success = await self._revoke_user_tokens(user, token_type)
                        if success:
                            revoked_tokens.append(f"{user}:{token_type}")
                        else:
                            failed_revocations.append(f"{user}:{token_type}")
                    except Exception as e:
                        logger.error(f"Failed to revoke {token_type} tokens for {user}: {e}")
                        failed_revocations.append(f"{user}:{token_type}")
            
            return {
                'revoked_tokens': revoked_tokens,
                'failed_revocations': failed_revocations,
                'total_revoked': len(revoked_tokens)
            }
            
        except Exception as e:
            logger.error(f"Token revoke executor error: {e}")
            raise
    
    async def _revoke_user_tokens(self, user_id: str, token_type: str) -> bool:
        """Revoke tokens for a user"""
        try:
            payload = {
                'user_id': user_id,
                'token_type': token_type,
                'reason': 'security_incident'
            }
            
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.auth_api_url}/admin/revoke-tokens",
                                      json=payload, headers=headers,
                                      timeout=aiohttp.ClientTimeout(total=30)) as response:
                    return response.status == 200
                    
        except Exception as e:
            logger.error(f"Error revoking tokens for {user_id}: {e}")
            return False
    
    def validate_parameters(self, parameters: Dict[str, Any]) -> bool:
        """Validate token revocation parameters"""
        required_fields = ['user_accounts']
        return all(field in parameters for field in required_fields)
    
    def get_required_permissions(self) -> List[str]:
        """Get required permissions"""
        return ['token.revoke', 'admin.security_action']


class NotificationExecutor(ResponseActionExecutor):
    """Executor for notification actions"""
    
    def __init__(self, notification_config: Dict[str, Any]):
        self.config = notification_config
    
    async def execute(self, action: ResponseAction, context: ThreatContext) -> Dict[str, Any]:
        """Send notifications about the threat"""
        try:
            notification_types = action.parameters.get('notification_types', ['email'])
            recipients = action.parameters.get('recipients', [])
            message = action.parameters.get('message', self._generate_default_message(context))
            
            sent_notifications = []
            failed_notifications = []
            
            for notification_type in notification_types:
                try:
                    if notification_type == 'email':
                        success = await self._send_email_notification(recipients, message, context)
                    elif notification_type == 'slack':
                        success = await self._send_slack_notification(message, context)
                    elif notification_type == 'webhook':
                        success = await self._send_webhook_notification(message, context)
                    else:
                        success = False
                    
                    if success:
                        sent_notifications.append(notification_type)
                    else:
                        failed_notifications.append(notification_type)
                        
                except Exception as e:
                    logger.error(f"Failed to send {notification_type} notification: {e}")
                    failed_notifications.append(notification_type)
            
            return {
                'sent_notifications': sent_notifications,
                'failed_notifications': failed_notifications,
                'total_sent': len(sent_notifications)
            }
            
        except Exception as e:
            logger.error(f"Notification executor error: {e}")
            raise
    
    def _generate_default_message(self, context: ThreatContext) -> str:
        """Generate default notification message"""
        return f"""
        SECURITY ALERT: {context.threat_type.upper()}
        
        Threat ID: {context.threat_id}
        Severity: {context.severity}
        Confidence: {context.confidence:.2f}
        Risk Score: {context.risk_score}
        
        Affected Entities: {', '.join(context.affected_entities)}
        Source IPs: {', '.join(context.source_ips)}
        
        First Seen: {context.first_seen}
        Last Seen: {context.last_seen}
        
        Automated response actions are being executed.
        """
    
    async def _send_email_notification(self, recipients: List[str], 
                                     message: str, context: ThreatContext) -> bool:
        """Send email notification"""
        # Implementation would depend on your email service
        logger.info(f"Email notification sent to {len(recipients)} recipients")
        return True
    
    async def _send_slack_notification(self, message: str, context: ThreatContext) -> bool:
        """Send Slack notification"""
        try:
            webhook_url = self.config.get('slack_webhook_url')
            if not webhook_url:
                return False
            
            payload = {
                'text': f'Security Alert: {context.threat_type}',
                'attachments': [{
                    'color': 'danger' if context.severity in ['high', 'critical'] else 'warning',
                    'fields': [
                        {'title': 'Threat ID', 'value': context.threat_id, 'short': True},
                        {'title': 'Severity', 'value': context.severity, 'short': True},
                        {'title': 'Risk Score', 'value': str(context.risk_score), 'short': True},
                        {'title': 'Confidence', 'value': f'{context.confidence:.2f}', 'short': True}
                    ],
                    'text': message
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload,
                                      timeout=aiohttp.ClientTimeout(total=30)) as response:
                    return response.status == 200
                    
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
            return False
    
    async def _send_webhook_notification(self, message: str, context: ThreatContext) -> bool:
        """Send webhook notification"""
        try:
            webhook_url = self.config.get('webhook_url')
            if not webhook_url:
                return False
            
            payload = {
                'threat_id': context.threat_id,
                'threat_type': context.threat_type,
                'severity': context.severity,
                'confidence': context.confidence,
                'risk_score': context.risk_score,
                'affected_entities': list(context.affected_entities),
                'source_ips': list(context.source_ips),
                'message': message,
                'timestamp': datetime.now().isoformat()
            }
            
            headers = {'Content-Type': 'application/json'}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, headers=headers,
                                      timeout=aiohttp.ClientTimeout(total=30)) as response:
                    return response.status == 200
                    
        except Exception as e:
            logger.error(f"Error sending webhook notification: {e}")
            return False
    
    def validate_parameters(self, parameters: Dict[str, Any]) -> bool:
        """Validate notification parameters"""
        return 'notification_types' in parameters
    
    def get_required_permissions(self) -> List[str]:
        """Get required permissions"""
        return ['notification.send']


class AutomatedResponseOrchestrator:
    """Main orchestrator for automated threat response"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379", 
                 postgres_url: str = "postgresql://localhost/security_db",
                 config: Dict[str, Any] = None):
        self.redis_url = redis_url
        self.postgres_url = postgres_url
        self.redis_client = None
        self.db_pool = None
        self.config = config or {}
        
        # Response executors
        self.executors = {}
        
        # Active response plans
        self.active_plans = {}
        
        # Response rules and policies
        self.response_rules = {}
        self.approval_policies = {}
        
        # Escalation callbacks
        self.escalation_handlers = {}

    async def initialize(self):
        """Initialize the response orchestrator"""
        try:
            # Initialize connections
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logger.info("Redis connection established for response orchestrator")
            
            self.db_pool = await asyncpg.create_pool(self.postgres_url)
            logger.info("PostgreSQL connection pool established for response orchestrator")
            
            # Initialize executors
            await self._initialize_executors()
            
            # Load response rules
            await self._load_response_rules()
            
            # Load approval policies
            await self._load_approval_policies()
            
            # Start background tasks
            asyncio.create_task(self._response_executor_loop())
            asyncio.create_task(self._plan_monitor_loop())
            
            logger.info("Automated response orchestrator initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize response orchestrator: {e}")
            raise

    async def _initialize_executors(self):
        """Initialize response action executors"""
        try:
            # Initialize IP blocking executor
            if 'firewall' in self.config:
                self.executors['ip_block'] = IPBlockExecutor(
                    self.config['firewall']['api_url'],
                    self.config['firewall']['api_key']
                )
            
            # Initialize account locking executor
            if 'auth_service' in self.config:
                self.executors['account_lock'] = AccountLockExecutor(
                    self.config['auth_service']['api_url'],
                    self.config['auth_service']['api_key']
                )
                
                self.executors['token_revoke'] = TokenRevokeExecutor(
                    self.config['auth_service']['api_url'],
                    self.config['auth_service']['api_key']
                )
            
            # Initialize notification executor
            self.executors['notification'] = NotificationExecutor(
                self.config.get('notifications', {})
            )
            
            logger.info(f"Initialized {len(self.executors)} response executors")
            
        except Exception as e:
            logger.error(f"Error initializing executors: {e}")

    async def _load_response_rules(self):
        """Load automated response rules"""
        try:
            # Load from database or use defaults
            default_rules = {
                'credential_stuffing': {
                    'severity_thresholds': {'high': 0.8, 'critical': 0.9},
                    'actions': [
                        {'type': 'ip_block', 'priority': 1, 'auto_approve': True},
                        {'type': 'notification', 'priority': 2, 'auto_approve': True}
                    ]
                },
                'account_takeover': {
                    'severity_thresholds': {'medium': 0.6, 'high': 0.8},
                    'actions': [
                        {'type': 'account_lock', 'priority': 1, 'auto_approve': False},
                        {'type': 'token_revoke', 'priority': 2, 'auto_approve': True},
                        {'type': 'notification', 'priority': 3, 'auto_approve': True}
                    ]
                },
                'brute_force': {
                    'severity_thresholds': {'medium': 0.7, 'high': 0.85},
                    'actions': [
                        {'type': 'ip_block', 'priority': 1, 'auto_approve': True},
                        {'type': 'account_lock', 'priority': 2, 'auto_approve': False},
                        {'type': 'notification', 'priority': 3, 'auto_approve': True}
                    ]
                }
            }
            
            self.response_rules = default_rules
            logger.info(f"Loaded {len(self.response_rules)} response rules")
            
        except Exception as e:
            logger.error(f"Error loading response rules: {e}")

    async def _load_approval_policies(self):
        """Load approval policies for response actions"""
        try:
            default_policies = {
                'account_lock': {
                    'requires_approval': True,
                    'auto_approve_conditions': {
                        'severity': ['critical'],
                        'confidence': 0.9,
                        'risk_score': 90
                    },
                    'approvers': ['security_team', 'incident_commander']
                },
                'ip_block': {
                    'requires_approval': False,
                    'auto_approve_conditions': {},
                    'approvers': []
                },
                'token_revoke': {
                    'requires_approval': False,
                    'auto_approve_conditions': {},
                    'approvers': []
                }
            }
            
            self.approval_policies = default_policies
            logger.info(f"Loaded {len(self.approval_policies)} approval policies")
            
        except Exception as e:
            logger.error(f"Error loading approval policies: {e}")

    async def create_response_plan(self, threat_context: ThreatContext) -> ResponsePlan:
        """Create automated response plan for detected threat"""
        try:
            plan_id = f"plan_{threat_context.threat_id}_{int(datetime.now().timestamp())}"
            
            # Get applicable response rules
            rules = self.response_rules.get(threat_context.threat_type, {})
            if not rules:
                # Fallback to default notification
                rules = {
                    'actions': [{'type': 'notification', 'priority': 1, 'auto_approve': True}]
                }
            
            # Create response actions
            actions = []
            for rule_action in rules.get('actions', []):
                action = await self._create_response_action(rule_action, threat_context)
                if action:
                    actions.append(action)
            
            # Determine escalation level
            escalation_level = self._determine_escalation_level(threat_context)
            
            # Check if approval is required
            approval_required = any(action.requires_approval for action in actions)
            
            # Create response plan
            plan = ResponsePlan(
                plan_id=plan_id,
                threat_context=threat_context,
                actions=actions,
                created_at=datetime.now(),
                status='created',
                escalation_level=escalation_level,
                estimated_duration=sum(action.timeout_seconds for action in actions),
                approval_required=approval_required,
                executed_actions=0,
                failed_actions=0
            )
            
            # Store plan
            self.active_plans[plan_id] = plan
            await self._store_response_plan(plan)
            
            logger.info(f"Created response plan {plan_id} for threat {threat_context.threat_id}")
            return plan
            
        except Exception as e:
            logger.error(f"Error creating response plan: {e}")
            raise

    async def _create_response_action(self, rule_action: Dict, 
                                    context: ThreatContext) -> Optional[ResponseAction]:
        """Create a response action from rule configuration"""
        try:
            action_type = rule_action['type']
            
            if action_type not in self.executors:
                logger.warning(f"No executor available for action type: {action_type}")
                return None
            
            # Generate action parameters based on threat context
            parameters = await self._generate_action_parameters(action_type, context)
            
            # Check approval requirements
            requires_approval = await self._check_approval_requirements(action_type, context)
            
            action_id = f"action_{action_type}_{int(datetime.now().timestamp())}"
            
            action = ResponseAction(
                action_id=action_id,
                action_type=action_type,
                priority=rule_action.get('priority', 5),
                status=ResponseStatus.PENDING,
                created_at=datetime.now(),
                scheduled_at=None,
                started_at=None,
                completed_at=None,
                parameters=parameters,
                prerequisites=[],
                timeout_seconds=self._get_action_timeout(action_type),
                retry_count=0,
                max_retries=3,
                result=None,
                error_message=None,
                requires_approval=requires_approval,
                approved_by=None,
                approved_at=None
            )
            
            return action
            
        except Exception as e:
            logger.error(f"Error creating response action: {e}")
            return None

    async def _generate_action_parameters(self, action_type: str, 
                                        context: ThreatContext) -> Dict[str, Any]:
        """Generate parameters for response action"""
        try:
            if action_type == 'ip_block':
                return {
                    'ip_addresses': list(context.source_ips),
                    'duration_minutes': self._calculate_block_duration(context),
                    'reason': f'Automated response to {context.threat_type}'
                }
            
            elif action_type == 'account_lock':
                return {
                    'user_accounts': list(context.affected_entities),
                    'duration_minutes': self._calculate_lock_duration(context),
                    'reason': f'Security incident: {context.threat_type}'
                }
            
            elif action_type == 'token_revoke':
                return {
                    'user_accounts': list(context.affected_entities),
                    'token_types': ['access', 'refresh']
                }
            
            elif action_type == 'notification':
                return {
                    'notification_types': ['slack', 'email'],
                    'recipients': self._get_notification_recipients(context),
                    'urgency': context.severity
                }
            
            return {}
            
        except Exception as e:
            logger.error(f"Error generating action parameters: {e}")
            return {}

    def _calculate_block_duration(self, context: ThreatContext) -> int:
        """Calculate IP block duration based on threat context"""
        base_duration = 60  # 1 hour
        
        if context.severity == 'critical':
            return base_duration * 24  # 24 hours
        elif context.severity == 'high':
            return base_duration * 4   # 4 hours
        elif context.severity == 'medium':
            return base_duration * 2   # 2 hours
        else:
            return base_duration       # 1 hour

    def _calculate_lock_duration(self, context: ThreatContext) -> int:
        """Calculate account lock duration based on threat context"""
        base_duration = 30  # 30 minutes
        
        if context.severity == 'critical':
            return base_duration * 8   # 4 hours
        elif context.severity == 'high':
            return base_duration * 4   # 2 hours
        elif context.severity == 'medium':
            return base_duration * 2   # 1 hour
        else:
            return base_duration       # 30 minutes

    def _get_notification_recipients(self, context: ThreatContext) -> List[str]:
        """Get notification recipients based on threat context"""
        recipients = ['security-team@company.com']
        
        if context.severity in ['critical', 'high']:
            recipients.extend([
                'incident-response@company.com',
                'soc@company.com'
            ])
        
        if context.severity == 'critical':
            recipients.append('ciso@company.com')
        
        return recipients

    async def _check_approval_requirements(self, action_type: str, 
                                         context: ThreatContext) -> bool:
        """Check if action requires approval"""
        try:
            policy = self.approval_policies.get(action_type, {})
            
            if not policy.get('requires_approval', False):
                return False
            
            # Check auto-approval conditions
            auto_conditions = policy.get('auto_approve_conditions', {})
            
            if 'severity' in auto_conditions:
                if context.severity in auto_conditions['severity']:
                    return False
            
            if 'confidence' in auto_conditions:
                if context.confidence >= auto_conditions['confidence']:
                    return False
            
            if 'risk_score' in auto_conditions:
                if context.risk_score >= auto_conditions['risk_score']:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking approval requirements: {e}")
            return True  # Default to requiring approval

    def _get_action_timeout(self, action_type: str) -> int:
        """Get timeout for action type"""
        timeouts = {
            'ip_block': 120,        # 2 minutes
            'account_lock': 60,     # 1 minute
            'token_revoke': 60,     # 1 minute
            'notification': 30      # 30 seconds
        }
        return timeouts.get(action_type, 300)  # Default 5 minutes

    def _determine_escalation_level(self, context: ThreatContext) -> EscalationLevel:
        """Determine escalation level based on threat context"""
        if context.severity == 'critical' and context.confidence > 0.8:
            return EscalationLevel.CRITICAL
        elif context.severity == 'high' and context.confidence > 0.7:
            return EscalationLevel.HIGH
        elif context.severity == 'medium':
            return EscalationLevel.MEDIUM
        elif context.severity == 'low':
            return EscalationLevel.LOW
        else:
            return EscalationLevel.NONE

    async def execute_response_plan(self, plan_id: str) -> bool:
        """Execute a response plan"""
        try:
            plan = self.active_plans.get(plan_id)
            if not plan:
                logger.error(f"Response plan {plan_id} not found")
                return False
            
            plan.status = 'executing'
            
            # Sort actions by priority
            sorted_actions = sorted(plan.actions, key=lambda a: a.priority)
            
            for action in sorted_actions:
                if action.requires_approval and not action.approved_at:
                    action.status = ResponseStatus.REQUIRES_APPROVAL
                    logger.info(f"Action {action.action_id} requires approval")
                    await self._request_approval(action, plan)
                    continue
                
                success = await self._execute_action(action, plan.threat_context)
                
                if success:
                    plan.executed_actions += 1
                else:
                    plan.failed_actions += 1
            
            # Update plan status
            if plan.failed_actions == 0:
                plan.status = 'completed'
            elif plan.executed_actions > 0:
                plan.status = 'partially_completed'
            else:
                plan.status = 'failed'
            
            await self._store_response_plan(plan)
            
            # Handle escalation if needed
            if plan.failed_actions > 0 or plan.escalation_level in [EscalationLevel.HIGH, EscalationLevel.CRITICAL]:
                await self._handle_escalation(plan)
            
            logger.info(f"Response plan {plan_id} execution completed: {plan.status}")
            return plan.status in ['completed', 'partially_completed']
            
        except Exception as e:
            logger.error(f"Error executing response plan {plan_id}: {e}")
            return False

    async def _execute_action(self, action: ResponseAction, 
                            context: ThreatContext) -> bool:
        """Execute a single response action"""
        try:
            with RESPONSE_DURATION.labels(action_type=action.action_type).time():
                action.status = ResponseStatus.IN_PROGRESS
                action.started_at = datetime.now()
                
                executor = self.executors.get(action.action_type)
                if not executor:
                    action.status = ResponseStatus.FAILED
                    action.error_message = f"No executor for action type: {action.action_type}"
                    return False
                
                # Validate parameters
                if not executor.validate_parameters(action.parameters):
                    action.status = ResponseStatus.FAILED
                    action.error_message = "Invalid action parameters"
                    return False
                
                # Execute action with timeout
                try:
                    result = await asyncio.wait_for(
                        executor.execute(action, context),
                        timeout=action.timeout_seconds
                    )
                    
                    action.result = result
                    action.status = ResponseStatus.COMPLETED
                    action.completed_at = datetime.now()
                    
                    RESPONSE_ACTIONS_EXECUTED.labels(
                        action_type=action.action_type,
                        severity=context.severity,
                        outcome='success'
                    ).inc()
                    
                    logger.info(f"Action {action.action_id} completed successfully")
                    return True
                    
                except asyncio.TimeoutError:
                    action.status = ResponseStatus.FAILED
                    action.error_message = "Action timed out"
                    
                except Exception as e:
                    action.status = ResponseStatus.FAILED
                    action.error_message = str(e)
                
                RESPONSE_ACTIONS_EXECUTED.labels(
                    action_type=action.action_type,
                    severity=context.severity,
                    outcome='failure'
                ).inc()
                
                return False
                
        except Exception as e:
            logger.error(f"Error executing action {action.action_id}: {e}")
            action.status = ResponseStatus.FAILED
            action.error_message = str(e)
            return False

    async def _request_approval(self, action: ResponseAction, plan: ResponsePlan):
        """Request approval for an action"""
        try:
            approval_request = {
                'action_id': action.action_id,
                'action_type': action.action_type,
                'plan_id': plan.plan_id,
                'threat_id': plan.threat_context.threat_id,
                'severity': plan.threat_context.severity,
                'parameters': action.parameters,
                'requested_at': datetime.now().isoformat()
            }
            
            # Store approval request
            await self.redis_client.set(
                f"approval_request:{action.action_id}",
                json.dumps(approval_request, default=str),
                ex=3600  # 1 hour expiry
            )
            
            # Send notification to approvers
            approvers = self.approval_policies.get(action.action_type, {}).get('approvers', [])
            for approver in approvers:
                await self._notify_approver(approver, approval_request)
            
            logger.info(f"Approval requested for action {action.action_id}")
            
        except Exception as e:
            logger.error(f"Error requesting approval: {e}")

    async def _notify_approver(self, approver: str, request: Dict):
        """Notify approver about pending approval"""
        try:
            # Implementation depends on your notification system
            logger.info(f"Approval notification sent to {approver}")
        except Exception as e:
            logger.error(f"Error notifying approver {approver}: {e}")

    async def approve_action(self, action_id: str, approver: str) -> bool:
        """Approve a pending action"""
        try:
            # Find the action in active plans
            for plan in self.active_plans.values():
                for action in plan.actions:
                    if action.action_id == action_id:
                        action.approved_by = approver
                        action.approved_at = datetime.now()
                        action.status = ResponseStatus.PENDING
                        
                        # Remove approval request
                        await self.redis_client.delete(f"approval_request:{action_id}")
                        
                        logger.info(f"Action {action_id} approved by {approver}")
                        return True
            
            logger.warning(f"Action {action_id} not found for approval")
            return False
            
        except Exception as e:
            logger.error(f"Error approving action {action_id}: {e}")
            return False

    async def _handle_escalation(self, plan: ResponsePlan):
        """Handle escalation for response plan"""
        try:
            escalation_level = plan.escalation_level
            
            ESCALATION_EVENTS.labels(
                escalation_level=escalation_level.value,
                reason=f"plan_{plan.status}"
            ).inc()
            
            # Call escalation handlers
            handler = self.escalation_handlers.get(escalation_level)
            if handler:
                await handler(plan)
            else:
                # Default escalation - send notification
                await self._send_escalation_notification(plan)
            
            logger.info(f"Escalation handled for plan {plan.plan_id}, level: {escalation_level.value}")
            
        except Exception as e:
            logger.error(f"Error handling escalation: {e}")

    async def _send_escalation_notification(self, plan: ResponsePlan):
        """Send escalation notification"""
        try:
            message = f"""
            ESCALATION REQUIRED
            
            Response Plan: {plan.plan_id}
            Threat: {plan.threat_context.threat_type}
            Severity: {plan.threat_context.severity}
            Escalation Level: {plan.escalation_level.value}
            
            Plan Status: {plan.status}
            Executed Actions: {plan.executed_actions}
            Failed Actions: {plan.failed_actions}
            
            Manual intervention may be required.
            """
            
            # Send via notification executor
            if 'notification' in self.executors:
                notification_action = ResponseAction(
                    action_id=f"escalation_{plan.plan_id}",
                    action_type='notification',
                    priority=1,
                    status=ResponseStatus.PENDING,
                    created_at=datetime.now(),
                    scheduled_at=None,
                    started_at=None,
                    completed_at=None,
                    parameters={
                        'notification_types': ['email', 'slack'],
                        'recipients': ['incident-response@company.com'],
                        'message': message
                    },
                    prerequisites=[],
                    timeout_seconds=30,
                    retry_count=0,
                    max_retries=3,
                    result=None,
                    error_message=None,
                    requires_approval=False,
                    approved_by=None,
                    approved_at=None
                )
                
                await self._execute_action(notification_action, plan.threat_context)
                
        except Exception as e:
            logger.error(f"Error sending escalation notification: {e}")

    async def _response_executor_loop(self):
        """Background loop for executing pending response actions"""
        while True:
            try:
                # Find plans with pending actions
                for plan in list(self.active_plans.values()):
                    if plan.status in ['created', 'executing']:
                        pending_actions = [a for a in plan.actions 
                                         if a.status == ResponseStatus.PENDING and 
                                         (not a.requires_approval or a.approved_at)]
                        
                        if pending_actions:
                            await self.execute_response_plan(plan.plan_id)
                
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Error in response executor loop: {e}")
                await asyncio.sleep(30)

    async def _plan_monitor_loop(self):
        """Background loop for monitoring response plans"""
        while True:
            try:
                # Clean up old completed plans
                cutoff_time = datetime.now() - timedelta(hours=24)
                old_plans = []
                
                for plan_id, plan in self.active_plans.items():
                    if (plan.status in ['completed', 'failed'] and 
                        plan.created_at < cutoff_time):
                        old_plans.append(plan_id)
                
                for plan_id in old_plans:
                    del self.active_plans[plan_id]
                
                # Update metrics
                ACTIVE_RESPONSES.set(len(self.active_plans))
                
                logger.info(f"Plan monitor: {len(self.active_plans)} active plans, cleaned up {len(old_plans)} old plans")
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in plan monitor loop: {e}")
                await asyncio.sleep(300)

    async def _store_response_plan(self, plan: ResponsePlan):
        """Store response plan in database"""
        try:
            plan_data = asdict(plan)
            
            # Convert complex objects for JSON storage
            plan_data['threat_context']['affected_entities'] = list(plan_data['threat_context']['affected_entities'])
            plan_data['threat_context']['source_ips'] = list(plan_data['threat_context']['source_ips'])
            plan_data['threat_context']['first_seen'] = plan_data['threat_context']['first_seen'].isoformat()
            plan_data['threat_context']['last_seen'] = plan_data['threat_context']['last_seen'].isoformat()
            plan_data['created_at'] = plan_data['created_at'].isoformat()
            plan_data['escalation_level'] = plan_data['escalation_level'].value
            
            # Store actions separately for better querying
            for action in plan_data['actions']:
                action['status'] = action['status'].value
                for time_field in ['created_at', 'scheduled_at', 'started_at', 'completed_at', 'approved_at']:
                    if action[time_field]:
                        action[time_field] = action[time_field].isoformat() if isinstance(action[time_field], datetime) else action[time_field]
            
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO response_plans 
                    (plan_id, threat_id, threat_type, severity, status, escalation_level,
                     executed_actions, failed_actions, plan_data, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ON CONFLICT (plan_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    executed_actions = EXCLUDED.executed_actions,
                    failed_actions = EXCLUDED.failed_actions,
                    plan_data = EXCLUDED.plan_data,
                    updated_at = NOW()
                """, 
                plan.plan_id, plan.threat_context.threat_id, plan.threat_context.threat_type,
                plan.threat_context.severity, plan.status, plan.escalation_level.value,
                plan.executed_actions, plan.failed_actions, json.dumps(plan_data, default=str),
                plan.created_at)
                
        except Exception as e:
            logger.error(f"Error storing response plan: {e}")

    async def get_response_status(self, plan_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a response plan"""
        try:
            plan = self.active_plans.get(plan_id)
            if not plan:
                return None
            
            status = {
                'plan_id': plan.plan_id,
                'threat_id': plan.threat_context.threat_id,
                'status': plan.status,
                'escalation_level': plan.escalation_level.value,
                'executed_actions': plan.executed_actions,
                'failed_actions': plan.failed_actions,
                'total_actions': len(plan.actions),
                'created_at': plan.created_at.isoformat(),
                'actions': []
            }
            
            for action in plan.actions:
                action_status = {
                    'action_id': action.action_id,
                    'action_type': action.action_type,
                    'status': action.status.value,
                    'priority': action.priority,
                    'requires_approval': action.requires_approval,
                    'approved_by': action.approved_by,
                    'error_message': action.error_message
                }
                status['actions'].append(action_status)
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting response status: {e}")
            return None

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
    """Example usage of automated response orchestrator"""
    config = {
        'firewall': {
            'api_url': 'https://firewall.company.com/api',
            'api_key': 'your_firewall_api_key'
        },
        'auth_service': {
            'api_url': 'https://auth.company.com/api',
            'api_key': 'your_auth_api_key'
        },
        'notifications': {
            'slack_webhook_url': 'https://hooks.slack.com/your/webhook',
            'webhook_url': 'https://your-notification-endpoint.com/webhook'
        }
    }
    
    orchestrator = AutomatedResponseOrchestrator(config=config)
    await orchestrator.initialize()
    
    # Example threat context
    threat_context = ThreatContext(
        threat_id='threat_001',
        threat_type='credential_stuffing',
        severity='high',
        confidence=0.85,
        affected_entities={'user1', 'user2'},
        source_ips={'192.168.1.100', '10.0.1.50'},
        indicators=['high_failure_rate', 'multiple_users'],
        first_seen=datetime.now() - timedelta(minutes=10),
        last_seen=datetime.now(),
        risk_score=85,
        related_events=['event1', 'event2']
    )
    
    # Create and execute response plan
    plan = await orchestrator.create_response_plan(threat_context)
    print(f"Created response plan: {plan.plan_id}")
    
    success = await orchestrator.execute_response_plan(plan.plan_id)
    print(f"Response plan execution: {'success' if success else 'failed'}")
    
    # Get status
    status = await orchestrator.get_response_status(plan.plan_id)
    print(f"Response status: {status}")
    
    await orchestrator.close()


if __name__ == "__main__":
    asyncio.run(main())