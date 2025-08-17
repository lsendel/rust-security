#!/usr/bin/env python3
"""
Example Usage of Threat Hunting Toolkit

This script demonstrates how to use the comprehensive threat hunting toolkit
with the Rust authentication service. It shows various usage patterns and
integration scenarios.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any

# Import the threat hunting components
from integration_bridge import ThreatHuntingOrchestrator, ProcessingResult
from behavioral_analyzer import SecurityEvent, AdvancedThreatDetector
from ml_user_profiler import AdvancedUserProfiler
from threat_intelligence import ThreatIntelligenceCorrelator
from attack_pattern_detector import AttackPatternDetector
from automated_response import AutomatedResponseOrchestrator, ThreatContext

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_example_config() -> Dict[str, Any]:
    """Load example configuration for demonstration"""
    return {
        'rust_service': {
            'url': 'http://localhost:8080',
            'api_key': 'demo_api_key_replace_in_production'
        },
        'redis_url': 'redis://localhost:6379/0',
        'postgres_url': 'postgresql://threat_user:demo_password@localhost/security_demo',
        'processing_workers': 2,  # Reduced for demo
        'response_config': {
            'firewall': {
                'api_url': 'https://demo-firewall.com/api',
                'api_key': 'demo_firewall_key'
            },
            'auth_service': {
                'api_url': 'http://localhost:8080',
                'api_key': 'demo_api_key'
            },
            'notifications': {
                'slack_webhook_url': 'https://hooks.slack.com/services/DEMO/WEBHOOK',
                'email_config': {
                    'smtp_server': 'localhost',
                    'from_address': 'demo@company.com'
                }
            }
        }
    }


def create_sample_events() -> list[SecurityEvent]:
    """Create sample security events for demonstration"""
    base_time = datetime.now()
    
    events = []
    
    # Simulate credential stuffing attack
    for i in range(15):
        event = SecurityEvent(
            event_id=f'cred_stuff_{i:03d}',
            timestamp=base_time + timedelta(seconds=i * 10),
            event_type='authentication_failure',
            severity='medium',
            source='auth-service',
            client_id='malicious_client',
            user_id=f'user_{i % 5}',  # Targeting 5 different users
            ip_address='192.168.100.50',  # Same IP for all attempts
            user_agent='BadBot/1.0',
            description='Failed authentication attempt',
            details={'reason': 'invalid_password', 'attempt_count': i + 1},
            outcome='failure',
            resource='/oauth/token',
            action='authenticate',
            risk_score=60 + (i * 2),  # Increasing risk
            location='Unknown',
            device_fingerprint='suspicious_device'
        )
        events.append(event)
    
    # Simulate successful account takeover
    takeover_event = SecurityEvent(
        event_id='takeover_001',
        timestamp=base_time + timedelta(minutes=5),
        event_type='authentication_success',
        severity='high',
        source='auth-service',
        client_id='malicious_client',
        user_id='user_1',
        ip_address='192.168.100.50',
        user_agent='BadBot/1.0',
        description='Successful authentication after multiple failures',
        details={'previous_failures': 3, 'location_change': True},
        outcome='success',
        resource='/oauth/token',
        action='authenticate',
        risk_score=85,
        location='Unknown Location',
        device_fingerprint='new_device_fingerprint'
    )
    events.append(takeover_event)
    
    # Simulate normal user activity
    for i in range(5):
        event = SecurityEvent(
            event_id=f'normal_{i:03d}',
            timestamp=base_time + timedelta(minutes=10 + i),
            event_type='authentication_success',
            severity='low',
            source='auth-service',
            client_id='legitimate_client',
            user_id='legitimate_user',
            ip_address='10.0.0.100',
            user_agent='Mozilla/5.0 (legitimate browser)',
            description='Normal authentication',
            details={'normal_activity': True},
            outcome='success',
            resource='/oauth/token',
            action='authenticate',
            risk_score=10,
            location='New York, US',
            device_fingerprint='known_device'
        )
        events.append(event)
    
    # Simulate brute force on single account
    for i in range(20):
        event = SecurityEvent(
            event_id=f'brute_force_{i:03d}',
            timestamp=base_time + timedelta(minutes=15, seconds=i * 3),
            event_type='authentication_failure',
            severity='medium',
            source='auth-service',
            client_id='attacker_client',
            user_id='target_user',  # Same user for all attempts
            ip_address='203.0.113.100',
            user_agent='AttackTool/2.0',
            description='Brute force attempt',
            details={'password_attempts': i + 1},
            outcome='failure',
            resource='/oauth/token',
            action='authenticate',
            risk_score=50 + i,
            location='Unknown',
            device_fingerprint='automated_tool'
        )
        events.append(event)
    
    return events


async def demo_individual_components():
    """Demonstrate usage of individual threat hunting components"""
    logger.info("=== Demonstrating Individual Components ===")
    
    config = load_example_config()
    
    # 1. Behavioral Analysis Demo
    logger.info("1. Testing Behavioral Analyzer...")
    try:
        threat_detector = AdvancedThreatDetector(
            config['redis_url'], 
            config['postgres_url']
        )
        await threat_detector.initialize()
        
        # Test with a suspicious event
        suspicious_event = SecurityEvent(
            event_id='demo_001',
            timestamp=datetime.now(),
            event_type='authentication_failure',
            severity='high',
            source='auth-service',
            client_id='suspicious_client',
            user_id='test_user',
            ip_address='192.168.1.100',
            description='Suspicious login attempt',
            outcome='failure',
            risk_score=80
        )
        
        threats = await threat_detector.analyze_event(suspicious_event)
        logger.info(f"Behavioral Analyzer detected {len(threats)} threats")
        for threat in threats:
            logger.info(f"  - {threat.threat_type}: {threat.severity} (confidence: {threat.confidence:.2f})")
        
        await threat_detector.close()
        
    except Exception as e:
        logger.error(f"Behavioral Analyzer demo failed: {e}")
    
    # 2. User Profiling Demo
    logger.info("2. Testing ML User Profiler...")
    try:
        user_profiler = AdvancedUserProfiler(
            config['redis_url'], 
            config['postgres_url']
        )
        await user_profiler.initialize()
        
        # Analyze a user's behavior
        assessment = await user_profiler.analyze_user_behavior('test_user')
        logger.info(f"User Risk Assessment:")
        logger.info(f"  - Risk Score: {assessment.risk_score:.2f}")
        logger.info(f"  - Risk Level: {assessment.risk_level}")
        logger.info(f"  - Confidence: {assessment.confidence:.2f}")
        logger.info(f"  - Contributing Factors: {assessment.contributing_factors}")
        
        await user_profiler.close()
        
    except Exception as e:
        logger.error(f"User Profiler demo failed: {e}")
    
    # 3. Threat Intelligence Demo
    logger.info("3. Testing Threat Intelligence...")
    try:
        threat_intel = ThreatIntelligenceCorrelator(
            config['redis_url'], 
            config['postgres_url']
        )
        await threat_intel.initialize()
        
        # Add a custom indicator for demo
        await threat_intel.add_custom_indicator(
            indicator='192.168.1.100',
            indicator_type='ip',
            threat_type='malicious',
            severity='high',
            description='Known malicious IP from demo',
            ttl=3600
        )
        
        # Check event against threat intelligence
        event_data = {
            'event_id': 'intel_demo_001',
            'ip_address': '192.168.1.100',
            'description': 'Event with malicious IP'
        }
        
        matches = await threat_intel.check_indicators(event_data)
        logger.info(f"Threat Intelligence found {len(matches)} matches")
        for match in matches:
            logger.info(f"  - {match.indicator.indicator}: {match.indicator.threat_type} (risk: {match.risk_score})")
        
        await threat_intel.close()
        
    except Exception as e:
        logger.error(f"Threat Intelligence demo failed: {e}")
    
    # 4. Attack Pattern Detection Demo
    logger.info("4. Testing Attack Pattern Detector...")
    try:
        pattern_detector = AttackPatternDetector(
            config['redis_url'], 
            config['postgres_url']
        )
        await pattern_detector.initialize()
        
        # Process multiple events to build patterns
        events = create_sample_events()[:5]  # Use first 5 events
        
        all_sequences = []
        for event in events:
            event_dict = {
                'event_id': event.event_id,
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'ip_address': event.ip_address,
                'user_id': event.user_id,
                'outcome': event.outcome,
                'risk_score': event.risk_score,
                'details': event.details
            }
            
            sequences = await pattern_detector.process_event(event_dict)
            all_sequences.extend(sequences)
        
        logger.info(f"Attack Pattern Detector found {len(all_sequences)} sequences")
        for sequence in all_sequences:
            logger.info(f"  - {sequence.attack_type}: {sequence.severity} (complexity: {sequence.complexity_score})")
        
        await pattern_detector.close()
        
    except Exception as e:
        logger.error(f"Attack Pattern Detector demo failed: {e}")


async def demo_integrated_orchestrator():
    """Demonstrate the integrated threat hunting orchestrator"""
    logger.info("=== Demonstrating Integrated Orchestrator ===")
    
    config = load_example_config()
    
    try:
        # Initialize orchestrator
        orchestrator = ThreatHuntingOrchestrator(config)
        orchestrator.start_time = datetime.now()
        
        # Register a custom threat callback
        async def demo_threat_callback(event: SecurityEvent, result: ProcessingResult):
            logger.info(f"🚨 THREAT CALLBACK: Event {event.event_id}")
            logger.info(f"   Threats detected: {len(result.threats_detected)}")
            logger.info(f"   Attack patterns: {len(result.attack_patterns)}")
            if result.risk_assessment:
                logger.info(f"   User risk: {result.risk_assessment.get('risk_level', 'unknown')}")
            if result.response_plan_id:
                logger.info(f"   Response plan: {result.response_plan_id}")
        
        orchestrator.register_threat_callback(demo_threat_callback)
        
        await orchestrator.initialize()
        
        # Process sample events
        logger.info("Processing sample security events...")
        events = create_sample_events()
        
        results = []
        for i, event in enumerate(events[:10]):  # Process first 10 events
            logger.info(f"Processing event {i+1}/10: {event.event_id}")
            
            try:
                result = await orchestrator.process_event_directly(event)
                results.append(result)
                
                # Add small delay to simulate real-time processing
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error processing event {event.event_id}: {e}")
        
        # Analyze results
        logger.info("=== Processing Results Summary ===")
        total_threats = sum(len(r.threats_detected) for r in results)
        total_patterns = sum(len(r.attack_patterns) for r in results)
        response_plans = sum(1 for r in results if r.response_plan_id)
        
        logger.info(f"Total events processed: {len(results)}")
        logger.info(f"Total threats detected: {total_threats}")
        logger.info(f"Total attack patterns: {total_patterns}")
        logger.info(f"Response plans created: {response_plans}")
        
        # Get system status
        status = await orchestrator.get_system_status()
        logger.info("=== System Status ===")
        logger.info(f"Component health: {status['component_health']}")
        logger.info(f"Event queue size: {status['event_queue_size']}")
        logger.info(f"Active threats: {status['active_threats']}")
        
        await orchestrator.close()
        
    except Exception as e:
        logger.error(f"Integrated orchestrator demo failed: {e}")


async def demo_automated_response():
    """Demonstrate automated response capabilities"""
    logger.info("=== Demonstrating Automated Response ===")
    
    config = load_example_config()
    
    try:
        # Initialize response orchestrator
        response_orchestrator = AutomatedResponseOrchestrator(
            config['redis_url'],
            config['postgres_url'],
            config['response_config']
        )
        await response_orchestrator.initialize()
        
        # Create example threat context
        threat_context = ThreatContext(
            threat_id='demo_threat_001',
            threat_type='credential_stuffing',
            severity='high',
            confidence=0.85,
            affected_entities={'user_1', 'user_2', 'user_3'},
            source_ips={'192.168.100.50'},
            indicators=['high_failure_rate', 'multiple_users', 'same_ip'],
            first_seen=datetime.now() - timedelta(minutes=10),
            last_seen=datetime.now(),
            risk_score=85,
            related_events=['cred_stuff_001', 'cred_stuff_002', 'cred_stuff_003']
        )
        
        logger.info("Creating response plan for credential stuffing attack...")
        
        # Create response plan
        plan = await response_orchestrator.create_response_plan(threat_context)
        logger.info(f"Response plan created: {plan.plan_id}")
        logger.info(f"  - Threat type: {plan.threat_context.threat_type}")
        logger.info(f"  - Severity: {plan.threat_context.severity}")
        logger.info(f"  - Actions planned: {len(plan.actions)}")
        logger.info(f"  - Escalation level: {plan.escalation_level}")
        logger.info(f"  - Approval required: {plan.approval_required}")
        
        # List planned actions
        for action in plan.actions:
            logger.info(f"    Action: {action.action_type} (priority: {action.priority})")
            if action.requires_approval:
                logger.info(f"      ⚠️  Requires approval")
            else:
                logger.info(f"      ✅ Auto-approved")
        
        # Execute response plan (in demo mode, actions will likely fail due to mock endpoints)
        logger.info("Executing response plan...")
        success = await response_orchestrator.execute_response_plan(plan.plan_id)
        
        if success:
            logger.info("✅ Response plan executed successfully")
        else:
            logger.info("⚠️  Response plan execution had issues (expected in demo mode)")
        
        # Get plan status
        status = await response_orchestrator.get_response_status(plan.plan_id)
        if status:
            logger.info("=== Response Plan Status ===")
            logger.info(f"Plan status: {status['status']}")
            logger.info(f"Executed actions: {status['executed_actions']}/{status['total_actions']}")
            logger.info(f"Failed actions: {status['failed_actions']}")
            
            for action in status['actions']:
                status_emoji = {
                    'completed': '✅',
                    'failed': '❌',
                    'pending': '⏳',
                    'in_progress': '🔄',
                    'requires_approval': '⚠️'
                }.get(action['status'], '❓')
                
                logger.info(f"  {status_emoji} {action['action_type']}: {action['status']}")
                if action['error_message']:
                    logger.info(f"    Error: {action['error_message']}")
        
        await response_orchestrator.close()
        
    except Exception as e:
        logger.error(f"Automated response demo failed: {e}")


async def demo_log_file_processing():
    """Demonstrate log file processing capabilities"""
    logger.info("=== Demonstrating Log File Processing ===")
    
    # Create a sample log file
    sample_log_content = """
2024-01-15T10:30:00.123Z INFO security_audit SECURITY_EVENT: {"event_id":"log_001","timestamp":"2024-01-15T10:30:00.123Z","event_type":"authentication_failure","severity":"medium","source":"auth-service","client_id":"client123","ip_address":"192.168.1.100","description":"Failed login attempt","outcome":"failure","risk_score":60}
2024-01-15T10:30:05.456Z INFO security_audit SECURITY_EVENT: {"event_id":"log_002","timestamp":"2024-01-15T10:30:05.456Z","event_type":"authentication_failure","severity":"medium","source":"auth-service","client_id":"client123","ip_address":"192.168.1.100","description":"Failed login attempt","outcome":"failure","risk_score":65}
2024-01-15T10:30:10.789Z INFO security_audit SECURITY_EVENT: {"event_id":"log_003","timestamp":"2024-01-15T10:30:10.789Z","event_type":"authentication_success","severity":"high","source":"auth-service","client_id":"client123","ip_address":"192.168.1.100","description":"Successful login after failures","outcome":"success","risk_score":80}
""".strip()
    
    # Write sample log file
    import tempfile
    import os
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        f.write(sample_log_content)
        temp_log_file = f.name
    
    try:
        config = load_example_config()
        orchestrator = ThreatHuntingOrchestrator(config)
        
        await orchestrator.initialize()
        
        logger.info(f"Processing sample log file: {temp_log_file}")
        await orchestrator.process_log_file(temp_log_file)
        
        # Wait a moment for processing
        await asyncio.sleep(2)
        
        # Get system status
        status = await orchestrator.get_system_status()
        logger.info(f"Events in queue after log processing: {status['event_queue_size']}")
        
        await orchestrator.close()
        
    except Exception as e:
        logger.error(f"Log file processing demo failed: {e}")
    finally:
        # Clean up temp file
        if os.path.exists(temp_log_file):
            os.unlink(temp_log_file)


async def main():
    """Main demonstration function"""
    logger.info("🔍 Starting Threat Hunting Toolkit Demonstration")
    logger.info("=" * 60)
    
    try:
        # Demo 1: Individual Components
        await demo_individual_components()
        await asyncio.sleep(1)
        
        # Demo 2: Integrated Orchestrator
        await demo_integrated_orchestrator()
        await asyncio.sleep(1)
        
        # Demo 3: Automated Response
        await demo_automated_response()
        await asyncio.sleep(1)
        
        # Demo 4: Log File Processing
        await demo_log_file_processing()
        
        logger.info("=" * 60)
        logger.info("✅ All demonstrations completed successfully!")
        
    except KeyboardInterrupt:
        logger.info("Demo interrupted by user")
    except Exception as e:
        logger.error(f"Demo failed with error: {e}")
        raise
    
    logger.info("🎯 Threat Hunting Toolkit Demo Complete")


if __name__ == "__main__":
    print("""
    🔍 Threat Hunting Toolkit Demo
    =============================
    
    This demo will showcase the capabilities of the comprehensive threat hunting toolkit
    designed for the Rust Authentication Service.
    
    Prerequisites:
    - Redis server running on localhost:6379
    - PostgreSQL server with security database
    - Python dependencies installed (pip install -r requirements.txt)
    
    Note: Some features may show errors in demo mode due to mock endpoints.
    This is expected behavior for demonstration purposes.
    
    Starting demonstration...
    """)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Demo stopped by user. Thank you!")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        print("Please check the prerequisites and try again.")