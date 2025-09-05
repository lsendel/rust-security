#!/usr/bin/env python3
"""
Automated Threat Hunting System
Executes hunting queries and analyzes results for potential threats
"""

import asyncio
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path

import asyncpg
import aiohttp
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class HuntResult:
    """Represents a threat hunting result"""
    hunt_id: str
    hunt_name: str
    timestamp: datetime
    severity: str
    confidence: float
    findings: List[Dict[str, Any]]
    indicators: List[str]
    recommendations: List[str]
    false_positive_likelihood: float

@dataclass
class ThreatIndicator:
    """Represents a threat indicator"""
    indicator_type: str
    value: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    context: Dict[str, Any]

class ThreatHuntingEngine:
    """Main threat hunting engine"""
    
    def __init__(self, config_path: str = "config/hunting_config.yaml"):
        self.config = self._load_config(config_path)
        self.db_pool = None
        self.hunt_queries = self._load_hunt_queries()
        self.ml_models = {}
        self.threat_intel_cache = {}
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load hunting configuration"""
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def _load_hunt_queries(self) -> Dict[str, str]:
        """Load hunting queries from SQL files"""
        queries = {}
        hunt_dir = Path("security-platform/threat-hunting")
        
        # Load the main hunt queries file
        queries_file = hunt_dir / "hunt-queries.sql"
        if queries_file.exists():
            with open(queries_file, 'r') as f:
                content = f.read()
                
            # Parse queries by comments
            current_query = ""
            current_name = ""
            
            for line in content.split('\n'):
                if line.strip().startswith('-- Detect') or line.strip().startswith('-- Hunt'):
                    if current_query and current_name:
                        queries[current_name] = current_query.strip()
                    current_name = line.strip().replace('-- ', '').replace('Detect ', '').replace('Hunt for ', '')
                    current_query = ""
                elif line.strip() and not line.strip().startswith('--') and not line.strip().startswith('-- ='):
                    current_query += line + '\n'
            
            # Add the last query
            if current_query and current_name:
                queries[current_name] = current_query.strip()
        
        logger.info(f"Loaded {len(queries)} hunting queries")
        return queries
    
    async def initialize(self):
        """Initialize database connections and ML models"""
        # Initialize database pool
        self.db_pool = await asyncpg.create_pool(
            host=self.config['database']['host'],
            port=self.config['database']['port'],
            user=self.config['database']['user'],
            password=self.config['database']['password'],
            database=self.config['database']['name'],
            min_size=2,
            max_size=10
        )
        
        # Initialize ML models
        await self._initialize_ml_models()
        
        # Load threat intelligence
        await self._load_threat_intelligence()
        
        logger.info("Threat hunting engine initialized successfully")
    
    async def _initialize_ml_models(self):
        """Initialize machine learning models for anomaly detection"""
        # Isolation Forest for network traffic anomaly detection
        self.ml_models['network_anomaly'] = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        
        # Isolation Forest for process behavior anomaly detection
        self.ml_models['process_anomaly'] = IsolationForest(
            contamination=0.05,
            random_state=42
        )
        
        # Train models with historical data
        await self._train_models()
    
    async def _train_models(self):
        """Train ML models with historical data"""
        async with self.db_pool.acquire() as conn:
            # Train network anomaly model
            network_data = await conn.fetch("""
                SELECT 
                    bytes_sent,
                    bytes_received,
                    connection_duration,
                    destination_port,
                    EXTRACT(HOUR FROM timestamp) as hour
                FROM network_connections
                WHERE timestamp >= NOW() - INTERVAL '30 days'
                    AND connection_state = 'established'
                LIMIT 10000
            """)
            
            if network_data:
                df = pd.DataFrame(network_data)
                scaler = StandardScaler()
                scaled_data = scaler.fit_transform(df)
                self.ml_models['network_anomaly'].fit(scaled_data)
                self.ml_models['network_scaler'] = scaler
                logger.info("Network anomaly model trained")
            
            # Train process anomaly model
            process_data = await conn.fetch("""
                SELECT 
                    LENGTH(command_line) as cmdline_length,
                    CASE WHEN parent_process = 'explorer.exe' THEN 1 ELSE 0 END as from_explorer,
                    CASE WHEN user_name = 'SYSTEM' THEN 1 ELSE 0 END as system_user,
                    EXTRACT(HOUR FROM timestamp) as hour
                FROM process_events
                WHERE timestamp >= NOW() - INTERVAL '30 days'
                LIMIT 10000
            """)
            
            if process_data:
                df = pd.DataFrame(process_data)
                scaler = StandardScaler()
                scaled_data = scaler.fit_transform(df)
                self.ml_models['process_anomaly'].fit(scaled_data)
                self.ml_models['process_scaler'] = scaler
                logger.info("Process anomaly model trained")
    
    async def _load_threat_intelligence(self):
        """Load threat intelligence from various sources"""
        # Load from local database
        async with self.db_pool.acquire() as conn:
            threat_intel = await conn.fetch("""
                SELECT indicator, indicator_type, threat_level, confidence, context
                FROM threat_intelligence
                WHERE last_updated >= NOW() - INTERVAL '7 days'
            """)
            
            for row in threat_intel:
                self.threat_intel_cache[row['indicator']] = {
                    'type': row['indicator_type'],
                    'threat_level': row['threat_level'],
                    'confidence': row['confidence'],
                    'context': json.loads(row['context']) if row['context'] else {}
                }
        
        logger.info(f"Loaded {len(self.threat_intel_cache)} threat indicators")
    
    async def execute_hunt(self, hunt_name: str) -> Optional[HuntResult]:
        """Execute a specific hunting query"""
        if hunt_name not in self.hunt_queries:
            logger.error(f"Hunt query '{hunt_name}' not found")
            return None
        
        query = self.hunt_queries[hunt_name]
        start_time = time.time()
        
        try:
            async with self.db_pool.acquire() as conn:
                results = await conn.fetch(query)
            
            execution_time = time.time() - start_time
            logger.info(f"Hunt '{hunt_name}' executed in {execution_time:.2f}s, found {len(results)} results")
            
            if not results:
                return None
            
            # Analyze results
            hunt_result = await self._analyze_hunt_results(hunt_name, results)
            
            # Enrich with threat intelligence
            await self._enrich_with_threat_intel(hunt_result)
            
            # Apply ML analysis
            await self._apply_ml_analysis(hunt_result)
            
            return hunt_result
            
        except Exception as e:
            logger.error(f"Error executing hunt '{hunt_name}': {str(e)}")
            return None
    
    async def _analyze_hunt_results(self, hunt_name: str, results: List[Dict]) -> HuntResult:
        """Analyze hunting results and create structured output"""
        findings = [dict(row) for row in results]
        
        # Extract indicators
        indicators = set()
        for finding in findings:
            for key, value in finding.items():
                if key in ['source_ip', 'destination_ip', 'user_name', 'process_name', 'file_path']:
                    if value:
                        indicators.add(str(value))
        
        # Calculate severity and confidence
        severity, confidence = self._calculate_severity_confidence(hunt_name, findings)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(hunt_name, findings)
        
        # Calculate false positive likelihood
        fp_likelihood = self._calculate_false_positive_likelihood(hunt_name, findings)
        
        return HuntResult(
            hunt_id=f"hunt_{int(time.time())}",
            hunt_name=hunt_name,
            timestamp=datetime.utcnow(),
            severity=severity,
            confidence=confidence,
            findings=findings,
            indicators=list(indicators),
            recommendations=recommendations,
            false_positive_likelihood=fp_likelihood
        )
    
    def _calculate_severity_confidence(self, hunt_name: str, findings: List[Dict]) -> Tuple[str, float]:
        """Calculate severity and confidence scores"""
        # Base severity on hunt type
        severity_map = {
            'lateral movement': 'HIGH',
            'privilege escalation': 'CRITICAL',
            'persistence': 'HIGH',
            'data exfiltration': 'CRITICAL',
            'command and control': 'HIGH',
            'insider threat': 'MEDIUM',
            'apt': 'CRITICAL'
        }
        
        severity = 'MEDIUM'  # Default
        for key, sev in severity_map.items():
            if key in hunt_name.lower():
                severity = sev
                break
        
        # Calculate confidence based on number of findings and indicators
        base_confidence = min(0.9, len(findings) / 10.0 + 0.1)
        
        # Adjust confidence based on threat intel matches
        threat_intel_matches = 0
        for finding in findings:
            for key, value in finding.items():
                if str(value) in self.threat_intel_cache:
                    threat_intel_matches += 1
        
        confidence_boost = min(0.3, threat_intel_matches / len(findings))
        confidence = min(1.0, base_confidence + confidence_boost)
        
        return severity, confidence
    
    def _generate_recommendations(self, hunt_name: str, findings: List[Dict]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if 'lateral movement' in hunt_name.lower():
            recommendations.extend([
                "Isolate affected hosts from network",
                "Reset credentials for affected accounts",
                "Review and strengthen network segmentation",
                "Deploy additional monitoring on identified systems"
            ])
        
        elif 'privilege escalation' in hunt_name.lower():
            recommendations.extend([
                "Disable affected user accounts immediately",
                "Review sudo/admin group memberships",
                "Audit service configurations and permissions",
                "Implement privilege access management (PAM)"
            ])
        
        elif 'persistence' in hunt_name.lower():
            recommendations.extend([
                "Remove identified persistence mechanisms",
                "Scan for additional backdoors",
                "Review startup programs and scheduled tasks",
                "Implement application whitelisting"
            ])
        
        elif 'data exfiltration' in hunt_name.lower():
            recommendations.extend([
                "Block identified exfiltration channels",
                "Audit data access logs",
                "Implement data loss prevention (DLP)",
                "Review and classify sensitive data"
            ])
        
        elif 'command and control' in hunt_name.lower():
            recommendations.extend([
                "Block identified C2 domains/IPs",
                "Analyze network traffic patterns",
                "Deploy DNS filtering",
                "Review firewall rules and network monitoring"
            ])
        
        else:
            recommendations.extend([
                "Investigate identified anomalies",
                "Correlate with other security events",
                "Review system and application logs",
                "Consider escalating to incident response team"
            ])
        
        return recommendations
    
    def _calculate_false_positive_likelihood(self, hunt_name: str, findings: List[Dict]) -> float:
        """Calculate likelihood of false positives"""
        # Base false positive rates by hunt type
        fp_rates = {
            'lateral movement': 0.2,
            'privilege escalation': 0.1,
            'persistence': 0.15,
            'data exfiltration': 0.25,
            'command and control': 0.3,
            'insider threat': 0.4,
            'apt': 0.2
        }
        
        base_fp_rate = 0.3  # Default
        for key, rate in fp_rates.items():
            if key in hunt_name.lower():
                base_fp_rate = rate
                break
        
        # Adjust based on findings characteristics
        if len(findings) < 3:
            base_fp_rate += 0.2
        elif len(findings) > 20:
            base_fp_rate -= 0.1
        
        return max(0.0, min(1.0, base_fp_rate))
    
    async def _enrich_with_threat_intel(self, hunt_result: HuntResult):
        """Enrich hunting results with threat intelligence"""
        enriched_findings = []
        
        for finding in hunt_result.findings:
            enriched_finding = finding.copy()
            threat_intel_matches = []
            
            for key, value in finding.items():
                if str(value) in self.threat_intel_cache:
                    intel = self.threat_intel_cache[str(value)]
                    threat_intel_matches.append({
                        'indicator': str(value),
                        'type': intel['type'],
                        'threat_level': intel['threat_level'],
                        'confidence': intel['confidence'],
                        'context': intel['context']
                    })
            
            if threat_intel_matches:
                enriched_finding['threat_intel_matches'] = threat_intel_matches
                # Increase confidence if threat intel matches
                hunt_result.confidence = min(1.0, hunt_result.confidence + 0.1)
            
            enriched_findings.append(enriched_finding)
        
        hunt_result.findings = enriched_findings
    
    async def _apply_ml_analysis(self, hunt_result: HuntResult):
        """Apply machine learning analysis to hunting results"""
        if 'network' in hunt_result.hunt_name.lower():
            await self._analyze_network_anomalies(hunt_result)
        elif 'process' in hunt_result.hunt_name.lower():
            await self._analyze_process_anomalies(hunt_result)
    
    async def _analyze_network_anomalies(self, hunt_result: HuntResult):
        """Analyze network-related findings for anomalies"""
        if 'network_anomaly' not in self.ml_models or 'network_scaler' not in self.ml_models:
            return
        
        model = self.ml_models['network_anomaly']
        scaler = self.ml_models['network_scaler']
        
        for finding in hunt_result.findings:
            # Extract network features
            features = []
            try:
                features.append(finding.get('bytes_sent', 0))
                features.append(finding.get('bytes_received', 0))
                features.append(finding.get('connection_duration', 0))
                features.append(finding.get('destination_port', 0))
                features.append(finding.get('access_hour', 12))  # Default to noon
                
                if len(features) == 5:
                    scaled_features = scaler.transform([features])
                    anomaly_score = model.decision_function(scaled_features)[0]
                    is_anomaly = model.predict(scaled_features)[0] == -1
                    
                    finding['ml_anomaly_score'] = float(anomaly_score)
                    finding['ml_is_anomaly'] = bool(is_anomaly)
                    
                    if is_anomaly:
                        hunt_result.confidence = min(1.0, hunt_result.confidence + 0.15)
            
            except (KeyError, ValueError, TypeError) as e:
                logger.debug(f"Could not analyze network anomaly: {e}")
                continue
    
    async def _analyze_process_anomalies(self, hunt_result: HuntResult):
        """Analyze process-related findings for anomalies"""
        if 'process_anomaly' not in self.ml_models or 'process_scaler' not in self.ml_models:
            return
        
        model = self.ml_models['process_anomaly']
        scaler = self.ml_models['process_scaler']
        
        for finding in hunt_result.findings:
            # Extract process features
            features = []
            try:
                cmdline = finding.get('command_line', '')
                features.append(len(cmdline) if cmdline else 0)
                features.append(1 if finding.get('parent_process') == 'explorer.exe' else 0)
                features.append(1 if finding.get('user_name') == 'SYSTEM' else 0)
                features.append(finding.get('access_hour', 12))
                
                if len(features) == 4:
                    scaled_features = scaler.transform([features])
                    anomaly_score = model.decision_function(scaled_features)[0]
                    is_anomaly = model.predict(scaled_features)[0] == -1
                    
                    finding['ml_anomaly_score'] = float(anomaly_score)
                    finding['ml_is_anomaly'] = bool(is_anomaly)
                    
                    if is_anomaly:
                        hunt_result.confidence = min(1.0, hunt_result.confidence + 0.15)
            
            except (KeyError, ValueError, TypeError) as e:
                logger.debug(f"Could not analyze process anomaly: {e}")
                continue
    
    async def execute_all_hunts(self) -> List[HuntResult]:
        """Execute all hunting queries"""
        results = []
        
        for hunt_name in self.hunt_queries.keys():
            logger.info(f"Executing hunt: {hunt_name}")
            result = await self.execute_hunt(hunt_name)
            if result:
                results.append(result)
            
            # Small delay between hunts to avoid overwhelming the database
            await asyncio.sleep(1)
        
        return results
    
    async def generate_hunt_report(self, results: List[HuntResult]) -> Dict[str, Any]:
        """Generate comprehensive hunting report"""
        high_priority_findings = [r for r in results if r.severity in ['HIGH', 'CRITICAL']]
        medium_priority_findings = [r for r in results if r.severity == 'MEDIUM']
        
        total_findings = sum(len(r.findings) for r in results)
        unique_indicators = set()
        for result in results:
            unique_indicators.update(result.indicators)
        
        report = {
            'report_timestamp': datetime.utcnow().isoformat(),
            'summary': {
                'total_hunts_executed': len(results),
                'total_findings': total_findings,
                'high_priority_hunts': len(high_priority_findings),
                'medium_priority_hunts': len(medium_priority_findings),
                'unique_indicators': len(unique_indicators),
                'avg_confidence': np.mean([r.confidence for r in results]) if results else 0
            },
            'high_priority_results': [asdict(r) for r in high_priority_findings],
            'medium_priority_results': [asdict(r) for r in medium_priority_findings],
            'recommendations': {
                'immediate_actions': [],
                'short_term_actions': [],
                'long_term_improvements': []
            }
        }
        
        # Aggregate recommendations
        immediate_actions = set()
        short_term_actions = set()
        long_term_actions = set()
        
        for result in high_priority_findings:
            for rec in result.recommendations[:2]:  # First 2 are immediate
                immediate_actions.add(rec)
        
        for result in results:
            if len(result.recommendations) > 2:
                for rec in result.recommendations[2:4]:  # Next 2 are short-term
                    short_term_actions.add(rec)
        
        long_term_actions.update([
            "Implement continuous threat hunting program",
            "Enhance security monitoring and detection capabilities",
            "Conduct regular security awareness training",
            "Review and update incident response procedures"
        ])
        
        report['recommendations']['immediate_actions'] = list(immediate_actions)
        report['recommendations']['short_term_actions'] = list(short_term_actions)
        report['recommendations']['long_term_improvements'] = list(long_term_actions)
        
        return report
    
    async def save_results(self, results: List[HuntResult], output_path: str = "hunt_results"):
        """Save hunting results to files"""
        os.makedirs(output_path, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        # Save individual hunt results
        for result in results:
            filename = f"{output_path}/hunt_{result.hunt_name.replace(' ', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(asdict(result), f, indent=2, default=str)
        
        # Save summary report
        report = await self.generate_hunt_report(results)
        report_filename = f"{output_path}/hunt_report_{timestamp}.json"
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Hunt results saved to {output_path}")
        return report_filename

async def main():
    """Main execution function"""
    # Initialize hunting engine
    engine = ThreatHuntingEngine()
    await engine.initialize()
    
    # Execute all hunts
    logger.info("Starting automated threat hunting")
    results = await engine.execute_all_hunts()
    
    # Generate and save report
    report_file = await engine.save_results(results)
    
    # Print summary
    logger.info(f"Threat hunting completed. Found {len(results)} hunt results.")
    logger.info(f"Report saved to: {report_file}")
    
    # Print high-priority findings
    high_priority = [r for r in results if r.severity in ['HIGH', 'CRITICAL']]
    if high_priority:
        logger.warning(f"HIGH PRIORITY: Found {len(high_priority)} critical/high severity threats!")
        for result in high_priority:
            logger.warning(f"  - {result.hunt_name}: {len(result.findings)} findings (confidence: {result.confidence:.2f})")

if __name__ == "__main__":
    asyncio.run(main())