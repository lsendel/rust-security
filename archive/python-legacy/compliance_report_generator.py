#!/usr/bin/env python3
"""
Automated Compliance Report Generator for Rust Security Workspace

This script generates comprehensive compliance reports covering:
- SOC 2 Type II requirements
- ISO 27001 controls
- GDPR compliance
- Security audit findings
- Risk assessments
"""

import json
import os
import sys
import argparse
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import requests
import pandas as pd
from jinja2 import Template
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class SecurityMetric:
    """Security metric data structure"""
    name: str
    value: float
    threshold: float
    status: str  # 'pass', 'fail', 'warning'
    description: str
    timestamp: datetime

@dataclass
class ComplianceControl:
    """Compliance control assessment"""
    control_id: str
    framework: str  # 'SOC2', 'ISO27001', 'GDPR', etc.
    title: str
    description: str
    implementation_status: str  # 'implemented', 'partial', 'not_implemented'
    effectiveness: str  # 'effective', 'needs_improvement', 'ineffective'
    evidence: List[str]
    last_tested: datetime
    next_review: datetime
    risk_level: str  # 'low', 'medium', 'high', 'critical'

@dataclass
class SecurityIncident:
    """Security incident record"""
    incident_id: str
    severity: str
    category: str
    description: str
    detected_at: datetime
    resolved_at: Optional[datetime]
    impact: str
    root_cause: str
    remediation_actions: List[str]

class PrometheusClient:
    """Client for fetching metrics from Prometheus"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        
    def query(self, query: str, time: Optional[datetime] = None) -> Dict[str, Any]:
        """Execute a Prometheus query"""
        params = {'query': query}
        if time:
            params['time'] = time.isoformat()
            
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/query",
                params=params,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to query Prometheus: {e}")
            return {'status': 'error', 'data': {'result': []}}
    
    def query_range(self, query: str, start: datetime, end: datetime, step: str = '1h') -> Dict[str, Any]:
        """Execute a Prometheus range query"""
        params = {
            'query': query,
            'start': start.isoformat(),
            'end': end.isoformat(),
            'step': step
        }
        
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/query_range",
                params=params,
                timeout=60
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to query Prometheus range: {e}")
            return {'status': 'error', 'data': {'result': []}}

class ElasticsearchClient:
    """Client for fetching audit logs from Elasticsearch"""
    
    def __init__(self, base_url: str, username: str = None, password: str = None):
        self.base_url = base_url.rstrip('/')
        self.auth = (username, password) if username and password else None
    
    def search(self, index: str, query: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an Elasticsearch search"""
        try:
            response = requests.post(
                f"{self.base_url}/{index}/_search",
                json=query,
                auth=self.auth,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to search Elasticsearch: {e}")
            return {'hits': {'total': {'value': 0}, 'hits': []}}

class ComplianceReportGenerator:
    """Main compliance report generator"""
    
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.prometheus = PrometheusClient(self.config['prometheus']['url'])
        self.elasticsearch = ElasticsearchClient(
            self.config['elasticsearch']['url'],
            self.config['elasticsearch'].get('username'),
            self.config['elasticsearch'].get('password')
        )
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)
    
    def collect_security_metrics(self, start_time: datetime, end_time: datetime) -> List[SecurityMetric]:
        """Collect security metrics from Prometheus"""
        logger.info("Collecting security metrics...")
        
        metrics_config = self.config['metrics']
        metrics = []
        
        for metric_name, metric_config in metrics_config.items():
            query = metric_config['query']
            threshold = metric_config['threshold']
            description = metric_config['description']
            
            # Query current value
            result = self.prometheus.query(query)
            
            if result['status'] == 'success' and result['data']['result']:
                value = float(result['data']['result'][0]['value'][1])
                
                # Determine status based on threshold
                if 'operator' in metric_config:
                    operator = metric_config['operator']
                    if operator == 'lt':
                        status = 'pass' if value < threshold else 'fail'
                    elif operator == 'gt':
                        status = 'pass' if value > threshold else 'fail'
                    elif operator == 'eq':
                        status = 'pass' if value == threshold else 'fail'
                    else:
                        status = 'warning'
                else:
                    status = 'pass' if value <= threshold else 'fail'
                
                metrics.append(SecurityMetric(
                    name=metric_name,
                    value=value,
                    threshold=threshold,
                    status=status,
                    description=description,
                    timestamp=datetime.utcnow()
                ))
            else:
                logger.warning(f"No data found for metric: {metric_name}")
                metrics.append(SecurityMetric(
                    name=metric_name,
                    value=0.0,
                    threshold=threshold,
                    status='warning',
                    description=f"{description} (No data available)",
                    timestamp=datetime.utcnow()
                ))
        
        return metrics
    
    def assess_compliance_controls(self) -> List[ComplianceControl]:
        """Assess compliance controls implementation"""
        logger.info("Assessing compliance controls...")
        
        controls_config = self.config['compliance_controls']
        controls = []
        
        for control_id, control_config in controls_config.items():
            # Check implementation evidence
            evidence = []
            implementation_status = 'implemented'
            effectiveness = 'effective'
            
            # Verify control implementation through metrics/logs
            if 'verification_queries' in control_config:
                for query_name, query in control_config['verification_queries'].items():
                    result = self.prometheus.query(query)
                    if result['status'] == 'success' and result['data']['result']:
                        evidence.append(f"{query_name}: Verified")
                    else:
                        evidence.append(f"{query_name}: Not verified")
                        implementation_status = 'partial'
                        effectiveness = 'needs_improvement'
            
            controls.append(ComplianceControl(
                control_id=control_id,
                framework=control_config['framework'],
                title=control_config['title'],
                description=control_config['description'],
                implementation_status=implementation_status,
                effectiveness=effectiveness,
                evidence=evidence,
                last_tested=datetime.utcnow(),
                next_review=datetime.utcnow() + timedelta(days=90),
                risk_level=control_config.get('risk_level', 'medium')
            ))
        
        return controls
    
    def collect_security_incidents(self, start_time: datetime, end_time: datetime) -> List[SecurityIncident]:
        """Collect security incidents from audit logs"""
        logger.info("Collecting security incidents...")
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"log_type": "security_audit"}},
                        {"terms": {"severity": ["high", "critical"]}},
                        {"range": {"timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat()
                        }}}
                    ]
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": 1000
        }
        
        result = self.elasticsearch.search("security-audit-*", query)
        incidents = []
        
        for hit in result['hits']['hits']:
            source = hit['_source']
            
            incidents.append(SecurityIncident(
                incident_id=source.get('event_id', 'unknown'),
                severity=source.get('severity', 'unknown'),
                category=source.get('event_type', 'unknown'),
                description=source.get('description', 'No description'),
                detected_at=datetime.fromisoformat(source.get('timestamp', datetime.utcnow().isoformat())),
                resolved_at=None,  # Would need additional logic to determine resolution
                impact=source.get('impact', 'Unknown'),
                root_cause=source.get('root_cause', 'Under investigation'),
                remediation_actions=source.get('remediation_actions', [])
            ))
        
        return incidents
    
    def generate_soc2_report(self, metrics: List[SecurityMetric], controls: List[ComplianceControl], 
                           incidents: List[SecurityIncident]) -> Dict[str, Any]:
        """Generate SOC 2 Type II compliance report"""
        logger.info("Generating SOC 2 compliance report...")
        
        soc2_controls = [c for c in controls if c.framework == 'SOC2']
        
        # SOC 2 Trust Service Criteria assessment
        criteria_assessment = {
            'Security': {
                'implemented': len([c for c in soc2_controls if 'CC6' in c.control_id and c.implementation_status == 'implemented']),
                'total': len([c for c in soc2_controls if 'CC6' in c.control_id]),
                'effectiveness': 'effective' if all(c.effectiveness == 'effective' for c in soc2_controls if 'CC6' in c.control_id) else 'needs_improvement'
            },
            'Availability': {
                'implemented': len([c for c in soc2_controls if 'A1' in c.control_id and c.implementation_status == 'implemented']),
                'total': len([c for c in soc2_controls if 'A1' in c.control_id]),
                'effectiveness': 'effective' if all(c.effectiveness == 'effective' for c in soc2_controls if 'A1' in c.control_id) else 'needs_improvement'
            },
            'Processing_Integrity': {
                'implemented': len([c for c in soc2_controls if 'PI1' in c.control_id and c.implementation_status == 'implemented']),
                'total': len([c for c in soc2_controls if 'PI1' in c.control_id]),
                'effectiveness': 'effective' if all(c.effectiveness == 'effective' for c in soc2_controls if 'PI1' in c.control_id) else 'needs_improvement'
            },
            'Confidentiality': {
                'implemented': len([c for c in soc2_controls if 'C1' in c.control_id and c.implementation_status == 'implemented']),
                'total': len([c for c in soc2_controls if 'C1' in c.control_id]),
                'effectiveness': 'effective' if all(c.effectiveness == 'effective' for c in soc2_controls if 'C1' in c.control_id) else 'needs_improvement'
            }
        }
        
        return {
            'report_type': 'SOC 2 Type II',
            'period_start': (datetime.utcnow() - timedelta(days=365)).isoformat(),
            'period_end': datetime.utcnow().isoformat(),
            'criteria_assessment': criteria_assessment,
            'controls': [asdict(c) for c in soc2_controls],
            'security_incidents': [asdict(i) for i in incidents],
            'key_metrics': [asdict(m) for m in metrics if m.status in ['pass', 'fail']],
            'overall_assessment': 'Satisfactory' if all(
                criteria['effectiveness'] == 'effective' 
                for criteria in criteria_assessment.values()
            ) else 'Needs Improvement'
        }
    
    def generate_iso27001_report(self, metrics: List[SecurityMetric], controls: List[ComplianceControl]) -> Dict[str, Any]:
        """Generate ISO 27001 compliance report"""
        logger.info("Generating ISO 27001 compliance report...")
        
        iso_controls = [c for c in controls if c.framework == 'ISO27001']
        
        # ISO 27001 Annex A control categories
        control_categories = {
            'A.5': 'Information Security Policies',
            'A.6': 'Organization of Information Security',
            'A.7': 'Human Resource Security',
            'A.8': 'Asset Management',
            'A.9': 'Access Control',
            'A.10': 'Cryptography',
            'A.11': 'Physical and Environmental Security',
            'A.12': 'Operations Security',
            'A.13': 'Communications Security',
            'A.14': 'System Acquisition, Development and Maintenance',
            'A.15': 'Supplier Relationships',
            'A.16': 'Information Security Incident Management',
            'A.17': 'Information Security Aspects of Business Continuity Management',
            'A.18': 'Compliance'
        }
        
        category_assessment = {}
        for category_id, category_name in control_categories.items():
            category_controls = [c for c in iso_controls if c.control_id.startswith(category_id)]
            if category_controls:
                implemented = len([c for c in category_controls if c.implementation_status == 'implemented'])
                total = len(category_controls)
                category_assessment[category_id] = {
                    'name': category_name,
                    'implemented': implemented,
                    'total': total,
                    'percentage': (implemented / total * 100) if total > 0 else 0,
                    'status': 'compliant' if implemented == total else 'non_compliant'
                }
        
        return {
            'report_type': 'ISO 27001',
            'assessment_date': datetime.utcnow().isoformat(),
            'category_assessment': category_assessment,
            'controls': [asdict(c) for c in iso_controls],
            'overall_compliance': sum(cat['percentage'] for cat in category_assessment.values()) / len(category_assessment) if category_assessment else 0,
            'recommendations': self._generate_iso27001_recommendations(iso_controls)
        }
    
    def _generate_iso27001_recommendations(self, controls: List[ComplianceControl]) -> List[str]:
        """Generate recommendations for ISO 27001 compliance improvement"""
        recommendations = []
        
        partial_controls = [c for c in controls if c.implementation_status == 'partial']
        if partial_controls:
            recommendations.append(f"Complete implementation of {len(partial_controls)} partially implemented controls")
        
        ineffective_controls = [c for c in controls if c.effectiveness == 'ineffective']
        if ineffective_controls:
            recommendations.append(f"Improve effectiveness of {len(ineffective_controls)} controls")
        
        high_risk_controls = [c for c in controls if c.risk_level == 'high' and c.implementation_status != 'implemented']
        if high_risk_controls:
            recommendations.append(f"Prioritize implementation of {len(high_risk_controls)} high-risk controls")
        
        return recommendations
    
    def generate_executive_summary(self, reports: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of all compliance reports"""
        logger.info("Generating executive summary...")
        
        summary = {
            'report_date': datetime.utcnow().isoformat(),
            'reporting_period': f"{(datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%d')} to {datetime.utcnow().strftime('%Y-%m-%d')}",
            'overall_security_posture': 'Strong',
            'key_findings': [],
            'critical_issues': [],
            'recommendations': [],
            'compliance_status': {}
        }
        
        # Analyze SOC 2 compliance
        if 'soc2' in reports:
            soc2_report = reports['soc2']
            summary['compliance_status']['SOC2'] = soc2_report['overall_assessment']
            
            if soc2_report['overall_assessment'] != 'Satisfactory':
                summary['critical_issues'].append('SOC 2 compliance needs improvement')
        
        # Analyze ISO 27001 compliance
        if 'iso27001' in reports:
            iso_report = reports['iso27001']
            compliance_percentage = iso_report['overall_compliance']
            
            if compliance_percentage >= 95:
                summary['compliance_status']['ISO27001'] = 'Compliant'
            elif compliance_percentage >= 80:
                summary['compliance_status']['ISO27001'] = 'Mostly Compliant'
            else:
                summary['compliance_status']['ISO27001'] = 'Non-Compliant'
                summary['critical_issues'].append('ISO 27001 compliance below acceptable threshold')
        
        # Generate recommendations
        if summary['critical_issues']:
            summary['overall_security_posture'] = 'Needs Improvement'
            summary['recommendations'].extend([
                'Address critical compliance issues immediately',
                'Implement additional security controls',
                'Increase monitoring and alerting coverage'
            ])
        
        return summary
    
    def generate_html_report(self, reports: Dict[str, Any], output_path: str):
        """Generate HTML compliance report"""
        logger.info(f"Generating HTML report: {output_path}")
        
        template_str = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Compliance Report - {{ report_date }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .metric { background-color: #e9ecef; padding: 10px; margin: 5px 0; border-radius: 3px; }
        .pass { border-left: 5px solid #28a745; }
        .fail { border-left: 5px solid #dc3545; }
        .warning { border-left: 5px solid #ffc107; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; font-weight: bold; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Compliance Report</h1>
        <p><strong>Generated:</strong> {{ report_date }}</p>
        <p><strong>Reporting Period:</strong> {{ reporting_period }}</p>
        <p><strong>Overall Security Posture:</strong> {{ overall_security_posture }}</p>
    </div>
    
    {% if critical_issues %}
    <div class="section">
        <h2>Critical Issues</h2>
        <ul>
        {% for issue in critical_issues %}
            <li class="critical">{{ issue }}</li>
        {% endfor %}
        </ul>
    </div>
    {% endif %}
    
    <div class="section">
        <h2>Compliance Status</h2>
        <table>
            <tr><th>Framework</th><th>Status</th></tr>
            {% for framework, status in compliance_status.items() %}
            <tr>
                <td>{{ framework }}</td>
                <td class="{{ 'pass' if 'Compliant' in status or 'Satisfactory' in status else 'fail' }}">{{ status }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    {% if soc2 %}
    <div class="section">
        <h2>SOC 2 Type II Assessment</h2>
        <p><strong>Overall Assessment:</strong> {{ soc2.overall_assessment }}</p>
        <table>
            <tr><th>Trust Service Criteria</th><th>Implemented</th><th>Total</th><th>Effectiveness</th></tr>
            {% for criteria, assessment in soc2.criteria_assessment.items() %}
            <tr>
                <td>{{ criteria.replace('_', ' ') }}</td>
                <td>{{ assessment.implemented }}</td>
                <td>{{ assessment.total }}</td>
                <td class="{{ 'pass' if assessment.effectiveness == 'effective' else 'warning' }}">{{ assessment.effectiveness }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}
    
    {% if iso27001 %}
    <div class="section">
        <h2>ISO 27001 Assessment</h2>
        <p><strong>Overall Compliance:</strong> {{ "%.1f"|format(iso27001.overall_compliance) }}%</p>
        <table>
            <tr><th>Control Category</th><th>Name</th><th>Implemented</th><th>Total</th><th>Percentage</th><th>Status</th></tr>
            {% for category_id, assessment in iso27001.category_assessment.items() %}
            <tr>
                <td>{{ category_id }}</td>
                <td>{{ assessment.name }}</td>
                <td>{{ assessment.implemented }}</td>
                <td>{{ assessment.total }}</td>
                <td>{{ "%.1f"|format(assessment.percentage) }}%</td>
                <td class="{{ 'pass' if assessment.status == 'compliant' else 'fail' }}">{{ assessment.status }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
        {% for recommendation in recommendations %}
            <li>{{ recommendation }}</li>
        {% endfor %}
        </ul>
    </div>
    
    <div class="section">
        <h2>Report Generation Details</h2>
        <p>This report was automatically generated by the Rust Security Workspace compliance monitoring system.</p>
        <p>For questions or concerns, please contact the security team.</p>
    </div>
</body>
</html>
        """
        
        template = Template(template_str)
        html_content = template.render(**reports['executive_summary'], **reports)
        
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def generate_reports(self, output_dir: str):
        """Generate all compliance reports"""
        logger.info("Starting compliance report generation...")
        
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Define reporting period
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=30)
        
        # Collect data
        metrics = self.collect_security_metrics(start_time, end_time)
        controls = self.assess_compliance_controls()
        incidents = self.collect_security_incidents(start_time, end_time)
        
        # Generate reports
        reports = {}
        
        # SOC 2 Report
        reports['soc2'] = self.generate_soc2_report(metrics, controls, incidents)
        
        # ISO 27001 Report
        reports['iso27001'] = self.generate_iso27001_report(metrics, controls)
        
        # Executive Summary
        reports['executive_summary'] = self.generate_executive_summary(reports)
        
        # Save JSON reports
        for report_type, report_data in reports.items():
            json_path = os.path.join(output_dir, f"{report_type}_report.json")
            with open(json_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            logger.info(f"Generated {report_type} report: {json_path}")
        
        # Generate HTML report
        html_path = os.path.join(output_dir, "compliance_report.html")
        self.generate_html_report(reports, html_path)
        logger.info(f"Generated HTML report: {html_path}")
        
        logger.info("Compliance report generation completed successfully")
        return reports

def main():
    parser = argparse.ArgumentParser(description='Generate compliance reports for Rust Security Workspace')
    parser.add_argument('--config', required=True, help='Path to configuration file')
    parser.add_argument('--output', required=True, help='Output directory for reports')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        generator = ComplianceReportGenerator(args.config)
        reports = generator.generate_reports(args.output)
        
        print(f"✅ Compliance reports generated successfully in {args.output}")
        print(f"📊 Executive Summary: {reports['executive_summary']['overall_security_posture']}")
        
        if reports['executive_summary']['critical_issues']:
            print("⚠️  Critical Issues Found:")
            for issue in reports['executive_summary']['critical_issues']:
                print(f"   - {issue}")
        
    except Exception as e:
        logger.error(f"Failed to generate compliance reports: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
