#!/usr/bin/env python3
"""
Chaos Engineering Automation Script
Orchestrates chaos experiments with safety checks and reporting
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import yaml
import aiohttp
import prometheus_client
from kubernetes import client, config, watch
from kubernetes.client import ApiException

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/chaos-automation.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ChaosAutomationOrchestrator:
    """Orchestrates chaos experiments with comprehensive safety and monitoring"""
    
    def __init__(self):
        self.load_kubernetes_config()
        self.k8s_core_v1 = client.CoreV1Api()
        self.k8s_apps_v1 = client.AppsV1Api()
        self.k8s_custom = client.CustomObjectsApi()
        
        self.prometheus_url = os.getenv('PROMETHEUS_URL', 'http://prometheus:9090')
        self.alertmanager_url = os.getenv('ALERTMANAGER_URL', 'http://alertmanager:9093')
        self.slack_webhook = os.getenv('SLACK_WEBHOOK_URL')
        
        # Safety configuration
        self.safety_config = self.load_safety_config()
        
        # Experiment tracking
        self.active_experiments = {}
        self.experiment_history = []
        
    def load_kubernetes_config(self):
        """Load Kubernetes configuration"""
        try:
            if os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount'):
                config.load_incluster_config()
                logger.info("Loaded in-cluster Kubernetes configuration")
            else:
                config.load_kube_config()
                logger.info("Loaded local Kubernetes configuration")
        except Exception as e:
            logger.error(f"Failed to load Kubernetes configuration: {e}")
            raise
    
    def load_safety_config(self) -> Dict:
        """Load safety configuration from ConfigMap"""
        try:
            config_map = self.k8s_core_v1.read_namespaced_config_map(
                name='chaos-engineering-config',
                namespace='chaos-engineering'
            )
            safety_config = yaml.safe_load(config_map.data['safety-guardrails.yaml'])
            logger.info("Loaded safety configuration")
            return safety_config
        except Exception as e:
            logger.error(f"Failed to load safety configuration: {e}")
            # Return default safety config
            return {
                'safety': {
                    'max_concurrent_experiments': 3,
                    'max_experiment_duration': '30m',
                    'recovery_timeout': '5m',
                    'monitoring_required': True
                },
                'guardrails': {
                    'network': {
                        'max_packet_loss': 50,
                        'max_latency_ms': 5000
                    },
                    'pod': {
                        'max_kill_percentage': 50,
                        'min_healthy_replicas': 1
                    }
                }
            }
    
    async def run_automation_cycle(self):
        """Main automation cycle"""
        logger.info("Starting chaos automation cycle")
        
        try:
            # Check system health before running experiments
            if not await self.check_system_health():
                logger.warning("System health check failed, skipping experiments")
                return
            
            # Load scheduled experiments
            scheduled_experiments = await self.get_scheduled_experiments()
            
            # Execute experiments with safety checks
            for experiment in scheduled_experiments:
                if await self.should_execute_experiment(experiment):
                    await self.execute_experiment(experiment)
                    
            # Monitor active experiments
            await self.monitor_active_experiments()
            
            # Generate reports
            await self.generate_experiment_reports()
            
        except Exception as e:
            logger.error(f"Error in automation cycle: {e}")
            await self.send_alert(f"Chaos automation cycle failed: {e}")
    
    async def check_system_health(self) -> bool:
        """Check overall system health before running experiments"""
        logger.info("Checking system health")
        
        health_checks = [
            self.check_service_health(),
            self.check_resource_utilization(),
            self.check_alert_status(),
            self.check_previous_experiments()
        ]
        
        results = await asyncio.gather(*health_checks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Health check {i} failed: {result}")
                return False
            elif not result:
                logger.warning(f"Health check {i} failed")
                return False
                
        logger.info("System health check passed")
        return True
    
    async def check_service_health(self) -> bool:
        """Check if all critical services are healthy"""
        try:
            # Check deployment readiness
            namespaces = ['rust-security-dev', 'rust-security-staging']
            
            for namespace in namespaces:
                deployments = self.k8s_apps_v1.list_namespaced_deployment(namespace=namespace)
                
                for deployment in deployments.items:
                    if deployment.spec.replicas > 0:
                        ready_replicas = deployment.status.ready_replicas or 0
                        if ready_replicas < deployment.spec.replicas:
                            logger.warning(f"Deployment {deployment.metadata.name} not fully ready: {ready_replicas}/{deployment.spec.replicas}")
                            return False
            
            return True
            
        except Exception as e:
            logger.error(f"Service health check failed: {e}")
            return False
    
    async def check_resource_utilization(self) -> bool:
        """Check cluster resource utilization"""
        try:
            # Query Prometheus for resource metrics
            async with aiohttp.ClientSession() as session:
                queries = [
                    'avg(100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100))',  # CPU usage
                    'avg((1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100)'  # Memory usage
                ]
                
                for query in queries:
                    async with session.get(f'{self.prometheus_url}/api/v1/query', 
                                         params={'query': query}) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data['data']['result']:
                                value = float(data['data']['result'][0]['value'][1])
                                if value > 80:  # 80% threshold
                                    logger.warning(f"High resource utilization: {value}%")
                                    return False
                        else:
                            logger.error(f"Failed to query Prometheus: {resp.status}")
                            return False
                            
            return True
            
        except Exception as e:
            logger.error(f"Resource utilization check failed: {e}")
            return False
    
    async def check_alert_status(self) -> bool:
        """Check if there are any critical alerts"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'{self.alertmanager_url}/api/v1/alerts') as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        active_alerts = [alert for alert in data['data'] 
                                       if alert['status']['state'] == 'active' 
                                       and alert['labels'].get('severity') in ['critical', 'warning']]
                        
                        if active_alerts:
                            logger.warning(f"Active alerts found: {len(active_alerts)}")
                            return False
                    else:
                        logger.error(f"Failed to query Alertmanager: {resp.status}")
                        return False
                        
            return True
            
        except Exception as e:
            logger.error(f"Alert status check failed: {e}")
            return False
    
    async def check_previous_experiments(self) -> bool:
        """Check if previous experiments completed successfully"""
        try:
            # Check for failed experiments in the last hour
            one_hour_ago = datetime.utcnow() - timedelta(hours=1)
            
            recent_failures = [exp for exp in self.experiment_history 
                             if exp['end_time'] > one_hour_ago and exp['status'] == 'failed']
            
            if len(recent_failures) >= 3:  # Too many recent failures
                logger.warning(f"Too many recent experiment failures: {len(recent_failures)}")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Previous experiments check failed: {e}")
            return False
    
    async def get_scheduled_experiments(self) -> List[Dict]:
        """Get experiments scheduled for execution"""
        scheduled = []
        
        try:
            # Get all chaos experiments
            experiment_types = ['networkchaos', 'podchaos', 'stresschaos', 'iochaos', 'dnschaos', 'timechaos']
            
            for exp_type in experiment_types:
                try:
                    experiments = self.k8s_custom.list_namespaced_custom_object(
                        group='chaos-mesh.org',
                        version='v1alpha1',
                        namespace='chaos-engineering',
                        plural=exp_type
                    )
                    
                    for experiment in experiments['items']:
                        if self.is_experiment_scheduled(experiment):
                            scheduled.append({
                                'type': exp_type,
                                'name': experiment['metadata']['name'],
                                'spec': experiment['spec'],
                                'metadata': experiment['metadata']
                            })
                            
                except ApiException as e:
                    if e.status != 404:  # Ignore if resource type doesn't exist
                        logger.error(f"Failed to list {exp_type}: {e}")
                        
        except Exception as e:
            logger.error(f"Failed to get scheduled experiments: {e}")
        
        logger.info(f"Found {len(scheduled)} scheduled experiments")
        return scheduled
    
    def is_experiment_scheduled(self, experiment: Dict) -> bool:
        """Check if experiment should be executed now"""
        try:
            # Check if experiment has scheduler configuration
            scheduler = experiment.get('spec', {}).get('scheduler')
            if not scheduler:
                return False
                
            # Check automation label
            automation = experiment.get('metadata', {}).get('labels', {}).get('automation', 'disabled')
            if automation != 'enabled':
                return False
                
            # Simple cron-like scheduling (would use proper cron library in production)
            cron = scheduler.get('cron', '')
            if cron == '@weekly':
                return datetime.utcnow().weekday() == 0 and datetime.utcnow().hour == 2  # Monday 2 AM
            elif cron.startswith('0 '):  # Simple hourly check
                hour = int(cron.split(' ')[1])
                return datetime.utcnow().hour == hour
                
            return False
            
        except Exception as e:
            logger.error(f"Error checking experiment schedule: {e}")
            return False
    
    async def should_execute_experiment(self, experiment: Dict) -> bool:
        """Check if experiment should be executed based on safety rules"""
        try:
            # Check concurrent experiment limit
            if len(self.active_experiments) >= self.safety_config['safety']['max_concurrent_experiments']:
                logger.info(f"Concurrent experiment limit reached: {len(self.active_experiments)}")
                return False
            
            # Check namespace safety
            target_namespace = experiment['spec']['selector']['namespaces'][0]
            forbidden_namespaces = self.safety_config['safety'].get('forbidden_namespaces', [])
            if target_namespace in forbidden_namespaces:
                logger.warning(f"Experiment targets forbidden namespace: {target_namespace}")
                return False
            
            # Check experiment parameters against guardrails
            if not self.validate_experiment_parameters(experiment):
                return False
                
            # Check target service health
            if not await self.check_target_service_health(experiment):
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Error validating experiment execution: {e}")
            return False
    
    def validate_experiment_parameters(self, experiment: Dict) -> bool:
        """Validate experiment parameters against safety guardrails"""
        try:
            experiment_type = experiment['type']
            spec = experiment['spec']
            guardrails = self.safety_config.get('guardrails', {})
            
            if experiment_type == 'networkchaos':
                network_guardrails = guardrails.get('network', {})
                
                # Check packet loss
                if 'loss' in spec:
                    loss_percent = float(spec['loss']['loss'].rstrip('%'))
                    if loss_percent > network_guardrails.get('max_packet_loss', 50):
                        logger.warning(f"Packet loss exceeds safety limit: {loss_percent}%")
                        return False
                
                # Check latency
                if 'delay' in spec:
                    latency_ms = int(spec['delay']['latency'].rstrip('ms'))
                    if latency_ms > network_guardrails.get('max_latency_ms', 5000):
                        logger.warning(f"Latency exceeds safety limit: {latency_ms}ms")
                        return False
            
            elif experiment_type == 'podchaos':
                pod_guardrails = guardrails.get('pod', {})
                
                # Check kill percentage
                mode = spec.get('mode', 'one')
                if 'percent' in mode:
                    kill_percent = int(mode.split('-')[-1].rstrip('%'))
                    if kill_percent > pod_guardrails.get('max_kill_percentage', 50):
                        logger.warning(f"Kill percentage exceeds safety limit: {kill_percent}%")
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating experiment parameters: {e}")
            return False
    
    async def check_target_service_health(self, experiment: Dict) -> bool:
        """Check if target service is healthy enough for chaos testing"""
        try:
            target_namespace = experiment['spec']['selector']['namespaces'][0]
            label_selector = experiment['spec']['selector']['labelSelectors']
            
            # Convert label selector dict to string
            selector_string = ','.join([f"{k}={v}" for k, v in label_selector.items()])
            
            # Get target pods
            pods = self.k8s_core_v1.list_namespaced_pod(
                namespace=target_namespace,
                label_selector=selector_string
            )
            
            if not pods.items:
                logger.warning("No target pods found for experiment")
                return False
            
            # Check pod readiness
            ready_pods = sum(1 for pod in pods.items 
                           if pod.status.phase == 'Running' and 
                           all(condition.status == 'True' 
                               for condition in pod.status.conditions or []
                               if condition.type == 'Ready'))
            
            total_pods = len(pods.items)
            min_healthy = self.safety_config['guardrails']['pod']['min_healthy_replicas']
            
            if ready_pods < min_healthy:
                logger.warning(f"Insufficient healthy replicas: {ready_pods} < {min_healthy}")
                return False
                
            # Check if we have enough replicas for the experiment
            experiment_mode = experiment['spec'].get('mode', 'one')
            if experiment_mode.startswith('random-max-percent') or experiment_mode.startswith('fixed-percent'):
                # Calculate how many pods will be affected
                if 'percent' in experiment_mode:
                    percent = float(experiment_mode.split('-')[-1].rstrip('%'))
                    affected_pods = int(total_pods * percent / 100)
                    remaining_pods = total_pods - affected_pods
                    
                    if remaining_pods < min_healthy:
                        logger.warning(f"Experiment would leave insufficient replicas: {remaining_pods}")
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking target service health: {e}")
            return False
    
    async def execute_experiment(self, experiment: Dict):
        """Execute a chaos experiment"""
        experiment_name = experiment['name']
        experiment_type = experiment['type']
        
        try:
            logger.info(f"Executing experiment: {experiment_name} ({experiment_type})")
            
            # Record experiment start
            experiment_record = {
                'name': experiment_name,
                'type': experiment_type,
                'start_time': datetime.utcnow(),
                'status': 'running',
                'metadata': experiment['metadata']
            }
            self.active_experiments[experiment_name] = experiment_record
            
            # Create the experiment in Kubernetes
            created_experiment = self.k8s_custom.create_namespaced_custom_object(
                group='chaos-mesh.org',
                version='v1alpha1',
                namespace='chaos-engineering',
                plural=experiment_type,
                body={
                    'apiVersion': 'chaos-mesh.org/v1alpha1',
                    'kind': experiment_type.capitalize().replace('chaos', 'Chaos'),
                    'metadata': {
                        'name': f"{experiment_name}-{int(datetime.utcnow().timestamp())}",
                        'namespace': 'chaos-engineering',
                        'labels': experiment['metadata']['labels']
                    },
                    'spec': experiment['spec']
                }
            )
            
            logger.info(f"Experiment {experiment_name} started successfully")
            
            # Send notification
            await self.send_notification(f"🧪 Chaos experiment started: {experiment_name}")
            
            # Schedule monitoring
            asyncio.create_task(self.monitor_experiment(experiment_record))
            
        except Exception as e:
            logger.error(f"Failed to execute experiment {experiment_name}: {e}")
            if experiment_name in self.active_experiments:
                self.active_experiments[experiment_name]['status'] = 'failed'
                self.active_experiments[experiment_name]['error'] = str(e)
            await self.send_alert(f"Experiment {experiment_name} failed to start: {e}")
    
    async def monitor_experiment(self, experiment_record: Dict):
        """Monitor a running experiment"""
        experiment_name = experiment_record['name']
        
        try:
            duration = experiment_record.get('duration', '5m')
            duration_seconds = self.parse_duration(duration)
            
            # Monitor experiment progress
            start_time = experiment_record['start_time']
            
            while True:
                await asyncio.sleep(30)  # Check every 30 seconds
                
                # Check if experiment should be completed
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                if elapsed >= duration_seconds:
                    await self.complete_experiment(experiment_record)
                    break
                
                # Perform safety checks
                if not await self.perform_safety_checks(experiment_record):
                    logger.warning(f"Safety violation detected for experiment {experiment_name}")
                    await self.emergency_stop_experiment(experiment_record)
                    break
                
                # Collect metrics
                await self.collect_experiment_metrics(experiment_record)
                
        except Exception as e:
            logger.error(f"Error monitoring experiment {experiment_name}: {e}")
            await self.emergency_stop_experiment(experiment_record)
    
    async def perform_safety_checks(self, experiment_record: Dict) -> bool:
        """Perform safety checks during experiment execution"""
        try:
            # Check service availability
            if not await self.check_service_availability_during_experiment(experiment_record):
                return False
            
            # Check error rates
            if not await self.check_error_rates(experiment_record):
                return False
            
            # Check response times
            if not await self.check_response_times(experiment_record):
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error in safety checks: {e}")
            return False
    
    async def check_service_availability_during_experiment(self, experiment_record: Dict) -> bool:
        """Check service availability during experiment"""
        try:
            async with aiohttp.ClientSession() as session:
                # Query service availability from Prometheus
                query = f'avg(up{{job=~".*{experiment_record["name"]}.*"}})'
                
                async with session.get(f'{self.prometheus_url}/api/v1/query',
                                     params={'query': query}) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data['data']['result']:
                            availability = float(data['data']['result'][0]['value'][1])
                            if availability < 0.8:  # 80% availability threshold
                                logger.warning(f"Service availability below threshold: {availability}")
                                return False
                    
            return True
            
        except Exception as e:
            logger.error(f"Error checking service availability: {e}")
            return False
    
    async def check_error_rates(self, experiment_record: Dict) -> bool:
        """Check error rates during experiment"""
        try:
            async with aiohttp.ClientSession() as session:
                # Query error rate from Prometheus
                query = 'rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])'
                
                async with session.get(f'{self.prometheus_url}/api/v1/query',
                                     params={'query': query}) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data['data']['result']:
                            error_rate = float(data['data']['result'][0]['value'][1])
                            if error_rate > 0.1:  # 10% error rate threshold
                                logger.warning(f"Error rate above threshold: {error_rate}")
                                return False
                    
            return True
            
        except Exception as e:
            logger.error(f"Error checking error rates: {e}")
            return True  # Continue on monitoring failure
    
    async def check_response_times(self, experiment_record: Dict) -> bool:
        """Check response times during experiment"""
        try:
            async with aiohttp.ClientSession() as session:
                # Query response time from Prometheus
                query = 'histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))'
                
                async with session.get(f'{self.prometheus_url}/api/v1/query',
                                     params={'query': query}) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data['data']['result']:
                            response_time = float(data['data']['result'][0]['value'][1])
                            if response_time > 5.0:  # 5 second threshold
                                logger.warning(f"Response time above threshold: {response_time}s")
                                return False
                    
            return True
            
        except Exception as e:
            logger.error(f"Error checking response times: {e}")
            return True  # Continue on monitoring failure
    
    async def collect_experiment_metrics(self, experiment_record: Dict):
        """Collect metrics during experiment execution"""
        try:
            metrics = {}
            
            async with aiohttp.ClientSession() as session:
                # Collect various metrics
                queries = {
                    'cpu_usage': 'rate(container_cpu_usage_seconds_total[5m])',
                    'memory_usage': 'container_memory_usage_bytes',
                    'network_latency': 'histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))',
                    'error_rate': 'rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])'
                }
                
                for metric_name, query in queries.items():
                    async with session.get(f'{self.prometheus_url}/api/v1/query',
                                         params={'query': query}) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data['data']['result']:
                                metrics[metric_name] = data['data']['result']
            
            # Store metrics in experiment record
            if 'metrics' not in experiment_record:
                experiment_record['metrics'] = {}
            
            experiment_record['metrics'][datetime.utcnow().isoformat()] = metrics
            
        except Exception as e:
            logger.error(f"Error collecting experiment metrics: {e}")
    
    async def complete_experiment(self, experiment_record: Dict):
        """Complete an experiment successfully"""
        experiment_name = experiment_record['name']
        
        try:
            logger.info(f"Completing experiment: {experiment_name}")
            
            # Update experiment record
            experiment_record['end_time'] = datetime.utcnow()
            experiment_record['status'] = 'completed'
            experiment_record['duration'] = (experiment_record['end_time'] - experiment_record['start_time']).total_seconds()
            
            # Move to history
            self.experiment_history.append(experiment_record)
            if experiment_name in self.active_experiments:
                del self.active_experiments[experiment_name]
            
            # Send completion notification
            await self.send_notification(f"✅ Chaos experiment completed: {experiment_name}")
            
            logger.info(f"Experiment {experiment_name} completed successfully")
            
        except Exception as e:
            logger.error(f"Error completing experiment {experiment_name}: {e}")
    
    async def emergency_stop_experiment(self, experiment_record: Dict):
        """Emergency stop an experiment due to safety violation"""
        experiment_name = experiment_record['name']
        
        try:
            logger.error(f"Emergency stopping experiment: {experiment_name}")
            
            # Update experiment record
            experiment_record['end_time'] = datetime.utcnow()
            experiment_record['status'] = 'emergency_stopped'
            experiment_record['duration'] = (experiment_record['end_time'] - experiment_record['start_time']).total_seconds()
            
            # Try to delete the experiment resource
            try:
                self.k8s_custom.delete_namespaced_custom_object(
                    group='chaos-mesh.org',
                    version='v1alpha1',
                    namespace='chaos-engineering',
                    plural=experiment_record['type'],
                    name=experiment_name
                )
            except:
                pass  # Continue even if deletion fails
            
            # Move to history
            self.experiment_history.append(experiment_record)
            if experiment_name in self.active_experiments:
                del self.active_experiments[experiment_name]
            
            # Send emergency alert
            await self.send_alert(f"🚨 EMERGENCY: Chaos experiment stopped due to safety violation: {experiment_name}")
            
            logger.error(f"Experiment {experiment_name} emergency stopped")
            
        except Exception as e:
            logger.error(f"Error emergency stopping experiment {experiment_name}: {e}")
    
    async def monitor_active_experiments(self):
        """Monitor all active experiments"""
        for experiment_name, experiment_record in list(self.active_experiments.items()):
            try:
                # Check if experiment is still running in Kubernetes
                if not await self.is_experiment_still_running(experiment_record):
                    # Experiment completed externally
                    await self.complete_experiment(experiment_record)
                    
            except Exception as e:
                logger.error(f"Error monitoring experiment {experiment_name}: {e}")
    
    async def is_experiment_still_running(self, experiment_record: Dict) -> bool:
        """Check if experiment is still running in Kubernetes"""
        try:
            experiments = self.k8s_custom.list_namespaced_custom_object(
                group='chaos-mesh.org',
                version='v1alpha1',
                namespace='chaos-engineering',
                plural=experiment_record['type']
            )
            
            for exp in experiments['items']:
                if exp['metadata']['name'].startswith(experiment_record['name']):
                    return exp['status'].get('conditions', [{}])[-1].get('type') == 'Selected'
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking experiment status: {e}")
            return False
    
    async def generate_experiment_reports(self):
        """Generate reports for completed experiments"""
        try:
            # Generate daily report
            today = datetime.utcnow().date()
            daily_experiments = [exp for exp in self.experiment_history 
                               if exp.get('end_time', datetime.utcnow()).date() == today]
            
            if daily_experiments:
                report = self.create_daily_report(daily_experiments)
                await self.send_report(report)
                
        except Exception as e:
            logger.error(f"Error generating reports: {e}")
    
    def create_daily_report(self, experiments: List[Dict]) -> str:
        """Create daily experiment report"""
        total = len(experiments)
        completed = len([exp for exp in experiments if exp['status'] == 'completed'])
        failed = len([exp for exp in experiments if exp['status'] in ['failed', 'emergency_stopped']])
        
        report = f"""
# Daily Chaos Engineering Report - {datetime.utcnow().strftime('%Y-%m-%d')}

## Summary
- Total Experiments: {total}
- Completed Successfully: {completed}
- Failed/Stopped: {failed}
- Success Rate: {(completed/total*100) if total > 0 else 0:.1f}%

## Experiment Details
"""
        
        for exp in experiments:
            status_emoji = {'completed': '✅', 'failed': '❌', 'emergency_stopped': '🚨'}.get(exp['status'], '❓')
            report += f"- {status_emoji} {exp['name']} ({exp['type']}) - {exp.get('duration', 0):.1f}s\n"
        
        return report
    
    async def send_notification(self, message: str):
        """Send notification to configured channels"""
        try:
            if self.slack_webhook:
                async with aiohttp.ClientSession() as session:
                    await session.post(self.slack_webhook, json={'text': message})
                    
            logger.info(f"Notification sent: {message}")
            
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
    
    async def send_alert(self, message: str):
        """Send alert for critical issues"""
        try:
            # Send to Alertmanager
            alert_data = [{
                'labels': {
                    'alertname': 'ChaosAutomationAlert',
                    'severity': 'critical',
                    'service': 'chaos-automation'
                },
                'annotations': {
                    'summary': message,
                    'description': message
                },
                'startsAt': datetime.utcnow().isoformat() + 'Z'
            }]
            
            async with aiohttp.ClientSession() as session:
                await session.post(f'{self.alertmanager_url}/api/v1/alerts', json=alert_data)
            
            # Also send as notification
            await self.send_notification(f"🚨 ALERT: {message}")
            
            logger.error(f"Alert sent: {message}")
            
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
    
    async def send_report(self, report: str):
        """Send experiment report"""
        try:
            await self.send_notification(f"📊 Chaos Engineering Report:\n```{report}```")
        except Exception as e:
            logger.error(f"Error sending report: {e}")
    
    def parse_duration(self, duration: str) -> int:
        """Parse duration string to seconds"""
        if duration.endswith('s'):
            return int(duration[:-1])
        elif duration.endswith('m'):
            return int(duration[:-1]) * 60
        elif duration.endswith('h'):
            return int(duration[:-1]) * 3600
        else:
            return 300  # Default 5 minutes

async def main():
    """Main entry point"""
    orchestrator = ChaosAutomationOrchestrator()
    
    # Run automation cycle every 5 minutes
    while True:
        try:
            await orchestrator.run_automation_cycle()
            await asyncio.sleep(300)  # 5 minutes
        except KeyboardInterrupt:
            logger.info("Shutting down chaos automation")
            break
        except Exception as e:
            logger.error(f"Unexpected error in main loop: {e}")
            await asyncio.sleep(60)  # Wait 1 minute before retrying

if __name__ == "__main__":
    asyncio.run(main())
