"""
Visualization components for the Security Dashboard using Plotly
"""
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from models import RedTeamReport
from config import RISK_COLORS, POSTURE_COLORS, CHART_CONFIG


class SecurityCharts:
    """Creates various security-focused charts and visualizations"""
    
    def __init__(self, theme: str = "plotly_white"):
        self.theme = theme
        self.default_config = CHART_CONFIG
        
    def create_security_posture_gauge(self, report: RedTeamReport) -> go.Figure:
        """Create a gauge chart showing overall security posture"""
        posture = report.executive_summary.overall_security_posture
        
        # Convert posture to numeric value
        posture_values = {
            "Critical": 20,
            "Poor": 40,
            "Fair": 60,
            "Good": 80,
            "Excellent": 100
        }
        
        value = posture_values.get(posture, 50)
        color = POSTURE_COLORS.get(posture, "#ffc107")
        
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = value,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Security Posture"},
            delta = {'reference': 70},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': color},
                'steps': [
                    {'range': [0, 20], 'color': POSTURE_COLORS["Critical"]},
                    {'range': [20, 40], 'color': POSTURE_COLORS["Poor"]},
                    {'range': [40, 60], 'color': POSTURE_COLORS["Fair"]},
                    {'range': [60, 80], 'color': POSTURE_COLORS["Good"]},
                    {'range': [80, 100], 'color': POSTURE_COLORS["Excellent"]}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        
        fig.add_annotation(
            text=posture,
            x=0.5, y=0.15,
            showarrow=False,
            font=dict(size=16, color=color)
        )
        
        fig.update_layout(
            template=self.theme,
            height=400,
            title="Overall Security Posture"
        )
        
        return fig
    
    def create_findings_breakdown(self, report: RedTeamReport) -> go.Figure:
        """Create a pie chart showing findings by severity"""
        findings = report.get_findings_by_severity()
        
        # Filter out zero values
        non_zero_findings = {k: v for k, v in findings.items() if v > 0}
        
        if not non_zero_findings:
            # Create empty chart
            fig = go.Figure(go.Pie(
                labels=["No Findings"],
                values=[1],
                marker_colors=["#e9ecef"]
            ))
            fig.update_layout(
                title="Security Findings by Severity",
                template=self.theme,
                height=400
            )
            return fig
        
        colors = [RISK_COLORS[severity] for severity in non_zero_findings.keys()]
        
        fig = go.Figure(go.Pie(
            labels=list(non_zero_findings.keys()),
            values=list(non_zero_findings.values()),
            marker_colors=colors,
            textinfo='label+percent+value',
            textfont_size=12
        ))
        
        fig.update_layout(
            title="Security Findings by Severity",
            template=self.theme,
            height=400,
            showlegend=True
        )
        
        return fig
    
    def create_attack_success_metrics(self, report: RedTeamReport) -> go.Figure:
        """Create a bar chart showing attack scenario results"""
        scenarios = report.attack_scenarios
        
        if not scenarios:
            return self._create_empty_chart("No Attack Scenarios Available")
        
        scenario_names = [s.scenario_name for s in scenarios]
        success_rates = [s.success_rate * 100 for s in scenarios]
        detection_rates = [s.detection_rate * 100 for s in scenarios]
        
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            name='Attack Success Rate (%)',
            x=scenario_names,
            y=success_rates,
            marker_color='#dc3545',
            text=[f'{rate:.1f}%' for rate in success_rates],
            textposition='outside'
        ))
        
        fig.add_trace(go.Bar(
            name='Detection Rate (%)',
            x=scenario_names,
            y=detection_rates,
            marker_color='#28a745',
            text=[f'{rate:.1f}%' for rate in detection_rates],
            textposition='outside'
        ))
        
        fig.update_layout(
            title='Attack Scenario Performance',
            xaxis_title='Scenarios',
            yaxis_title='Percentage (%)',
            barmode='group',
            template=self.theme,
            height=500,
            xaxis_tickangle=-45
        )
        
        return fig
    
    def create_control_effectiveness_heatmap(self, report: RedTeamReport) -> go.Figure:
        """Create a heatmap showing control effectiveness"""
        controls = report.get_controls_by_category()
        
        if not controls:
            return self._create_empty_chart("No Control Data Available")
        
        control_names = list(controls.keys())
        effectiveness_scores = []
        
        for control_name, results in controls.items():
            total = results["passed"] + results["failed"]
            if total > 0:
                effectiveness = results["passed"] / total
            else:
                effectiveness = 0
            effectiveness_scores.append(effectiveness)
        
        # Create color scale based on effectiveness
        colors = []
        for score in effectiveness_scores:
            if score >= 0.8:
                colors.append('#28a745')  # Green
            elif score >= 0.6:
                colors.append('#ffc107')  # Yellow
            elif score >= 0.4:
                colors.append('#fd7e14')  # Orange
            else:
                colors.append('#dc3545')  # Red
        
        fig = go.Figure(go.Bar(
            x=control_names,
            y=effectiveness_scores,
            marker_color=colors,
            text=[f'{score:.1%}' for score in effectiveness_scores],
            textposition='outside'
        ))
        
        fig.update_layout(
            title='Security Control Effectiveness',
            xaxis_title='Security Controls',
            yaxis_title='Effectiveness Rate',
            template=self.theme,
            height=500,
            xaxis_tickangle=-45,
            yaxis=dict(range=[0, 1], tickformat='.1%')
        )
        
        return fig
    
    def create_timeline_chart(self, reports: List[RedTeamReport]) -> go.Figure:
        """Create a timeline chart showing security metrics over time"""
        if not reports:
            return self._create_empty_chart("No Historical Data Available")
        
        # Sort reports by date
        sorted_reports = sorted(reports, key=lambda r: r.exercise_metadata.datetime)
        
        dates = [r.exercise_metadata.datetime for r in sorted_reports]
        attack_success_rates = [r.executive_summary.attack_success_rate * 100 for r in sorted_reports]
        detection_rates = [r.executive_summary.detection_rate * 100 for r in sorted_reports]
        critical_findings = [r.executive_summary.critical_findings for r in sorted_reports]
        
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=('Security Metrics Over Time', 'Critical Findings Trend'),
            vertical_spacing=0.15
        )
        
        # Top subplot: Success and detection rates
        fig.add_trace(
            go.Scatter(
                x=dates,
                y=attack_success_rates,
                mode='lines+markers',
                name='Attack Success Rate (%)',
                line=dict(color='#dc3545', width=3),
                marker=dict(size=8)
            ),
            row=1, col=1
        )
        
        fig.add_trace(
            go.Scatter(
                x=dates,
                y=detection_rates,
                mode='lines+markers',
                name='Detection Rate (%)',
                line=dict(color='#28a745', width=3),
                marker=dict(size=8)
            ),
            row=1, col=1
        )
        
        # Bottom subplot: Critical findings
        fig.add_trace(
            go.Scatter(
                x=dates,
                y=critical_findings,
                mode='lines+markers',
                name='Critical Findings',
                line=dict(color='#fd7e14', width=3),
                marker=dict(size=8),
                fill='tonexty'
            ),
            row=2, col=1
        )
        
        fig.update_layout(
            template=self.theme,
            height=800,
            title='Security Metrics Timeline',
            showlegend=True
        )
        
        fig.update_xaxes(title_text="Date", row=2, col=1)
        fig.update_yaxes(title_text="Percentage (%)", row=1, col=1)
        fig.update_yaxes(title_text="Count", row=2, col=1)
        
        return fig
    
    def create_recommendations_priority_chart(self, report: RedTeamReport) -> go.Figure:
        """Create a chart showing recommendations by priority"""
        recommendations = report.recommendations
        
        if not recommendations:
            return self._create_empty_chart("No Recommendations Available")
        
        priority_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for rec in recommendations:
            if rec.priority in priority_counts:
                priority_counts[rec.priority] += 1
        
        # Filter out zero values
        non_zero_priorities = {k: v for k, v in priority_counts.items() if v > 0}
        
        colors = [RISK_COLORS[priority] for priority in non_zero_priorities.keys()]
        
        fig = go.Figure(go.Bar(
            x=list(non_zero_priorities.keys()),
            y=list(non_zero_priorities.values()),
            marker_color=colors,
            text=list(non_zero_priorities.values()),
            textposition='outside'
        ))
        
        fig.update_layout(
            title='Recommendations by Priority',
            xaxis_title='Priority Level',
            yaxis_title='Number of Recommendations',
            template=self.theme,
            height=400
        )
        
        return fig
    
    def create_security_metrics_radar(self, report: RedTeamReport) -> go.Figure:
        """Create a radar chart showing various security metrics"""
        metrics = report.security_metrics
        summary = report.executive_summary
        
        categories = [
            'Detection Accuracy',
            'Response Effectiveness', 
            'Attack Surface Coverage',
            'Control Pass Rate',
            'Detection Rate'
        ]
        
        values = [
            metrics.detection_accuracy * 100,
            summary.response_effectiveness * 100,
            metrics.attack_surface_coverage * 100,
            summary.control_pass_rate * 100,
            summary.detection_rate * 100
        ]
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatterpolar(
            r=values,
            theta=categories,
            fill='toself',
            name='Current Performance',
            line_color='#2E86AB',
            fillcolor='rgba(46, 134, 171, 0.3)'
        ))
        
        # Add target performance line
        target_values = [90, 85, 95, 80, 75]  # Target percentages
        fig.add_trace(go.Scatterpolar(
            r=target_values,
            theta=categories,
            fill='toself',
            name='Target Performance',
            line_color='#28a745',
            fillcolor='rgba(40, 167, 69, 0.1)',
            line_dash='dash'
        ))
        
        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 100]
                )
            ),
            showlegend=True,
            title="Security Metrics Performance",
            template=self.theme,
            height=500
        )
        
        return fig
    
    def create_attack_vector_distribution(self, report: RedTeamReport) -> go.Figure:
        """Create a chart showing distribution of attack vectors"""
        findings = report.detailed_findings
        
        if not findings:
            return self._create_empty_chart("No Attack Vector Data Available")
        
        # Extract attack vectors and count them
        vector_counts = {}
        for finding in findings:
            vector = finding.attack_vector
            vector_counts[vector] = vector_counts.get(vector, 0) + 1
        
        # Sort by count
        sorted_vectors = sorted(vector_counts.items(), key=lambda x: x[1], reverse=True)
        
        fig = go.Figure(go.Bar(
            x=[item[1] for item in sorted_vectors],
            y=[item[0] for item in sorted_vectors],
            orientation='h',
            marker_color='#A23B72',
            text=[str(count) for count in [item[1] for item in sorted_vectors]],
            textposition='outside'
        ))
        
        fig.update_layout(
            title='Attack Vector Distribution',
            xaxis_title='Number of Findings',
            yaxis_title='Attack Vector',
            template=self.theme,
            height=max(400, len(sorted_vectors) * 40)
        )
        
        return fig
    
    def _create_empty_chart(self, message: str) -> go.Figure:
        """Create an empty chart with a message"""
        fig = go.Figure()
        fig.add_annotation(
            text=message,
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(size=16, color="gray")
        )
        fig.update_layout(
            template=self.theme,
            height=400,
            xaxis=dict(visible=False),
            yaxis=dict(visible=False)
        )
        return fig


class TrendAnalyzer:
    """Analyzes trends across multiple reports"""
    
    def __init__(self, reports: List[RedTeamReport]):
        self.reports = sorted(reports, key=lambda r: r.exercise_metadata.datetime)
        
    def create_security_trend_dashboard(self) -> go.Figure:
        """Create a comprehensive trend dashboard"""
        if len(self.reports) < 2:
            return self._create_empty_trend_chart()
        
        dates = [r.exercise_metadata.datetime for r in self.reports]
        
        fig = make_subplots(
            rows=3, cols=2,
            subplot_titles=[
                'Attack Success Rate Trend',
                'Detection Rate Trend', 
                'Critical Findings Trend',
                'Control Effectiveness Trend',
                'Response Time Trend',
                'Security Posture Evolution'
            ],
            vertical_spacing=0.08,
            horizontal_spacing=0.1
        )
        
        # Attack Success Rate Trend
        success_rates = [r.executive_summary.attack_success_rate * 100 for r in self.reports]
        fig.add_trace(
            go.Scatter(x=dates, y=success_rates, mode='lines+markers',
                      name='Attack Success Rate', line=dict(color='#dc3545')),
            row=1, col=1
        )
        
        # Detection Rate Trend
        detection_rates = [r.executive_summary.detection_rate * 100 for r in self.reports]
        fig.add_trace(
            go.Scatter(x=dates, y=detection_rates, mode='lines+markers',
                      name='Detection Rate', line=dict(color='#28a745')),
            row=1, col=2
        )
        
        # Critical Findings Trend
        critical_findings = [r.executive_summary.critical_findings for r in self.reports]
        fig.add_trace(
            go.Scatter(x=dates, y=critical_findings, mode='lines+markers',
                      name='Critical Findings', line=dict(color='#fd7e14')),
            row=2, col=1
        )
        
        # Control Effectiveness Trend
        control_rates = [r.executive_summary.control_pass_rate * 100 for r in self.reports]
        fig.add_trace(
            go.Scatter(x=dates, y=control_rates, mode='lines+markers',
                      name='Control Pass Rate', line=dict(color='#6cb400')),
            row=2, col=2
        )
        
        # Response Time Trend
        response_times = [r.security_metrics.response_time_ms for r in self.reports]
        fig.add_trace(
            go.Scatter(x=dates, y=response_times, mode='lines+markers',
                      name='Response Time (ms)', line=dict(color='#17a2b8')),
            row=3, col=1
        )
        
        # Security Posture Evolution
        posture_mapping = {"Critical": 1, "Poor": 2, "Fair": 3, "Good": 4, "Excellent": 5}
        posture_scores = [posture_mapping.get(r.executive_summary.overall_security_posture, 3) 
                         for r in self.reports]
        fig.add_trace(
            go.Scatter(x=dates, y=posture_scores, mode='lines+markers',
                      name='Security Posture', line=dict(color='#A23B72')),
            row=3, col=2
        )
        
        fig.update_layout(
            height=1200,
            title='Security Trends Dashboard',
            template='plotly_white',
            showlegend=False
        )
        
        return fig
    
    def _create_empty_trend_chart(self) -> go.Figure:
        """Create empty trend chart"""
        fig = go.Figure()
        fig.add_annotation(
            text="Insufficient data for trend analysis<br>At least 2 reports required",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=16, color="gray")
        )
        fig.update_layout(
            template='plotly_white',
            height=400,
            xaxis=dict(visible=False),
            yaxis=dict(visible=False)
        )
        return fig