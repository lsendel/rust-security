# {{ report.framework | upper }} Compliance Report

**Organization:** {{ report.organization.name }}  
**Domain:** {{ report.organization.domain }}  
**Compliance Officer:** {{ report.organization.compliance_officer }}  
**Contact:** {{ report.organization.contact_email }}  
**Assessment Period:** {{ report.assessment_period_days }} days  
**Generated:** {{ generated_at }}  
**Classification:** {{ report.classification | upper }}

---

## Executive Summary

This compliance report provides an assessment of {{ report.organization.name }}'s adherence to {{ report.framework | upper }} requirements over the past {{ report.assessment_period_days }} days.

### Key Metrics

- **Total Controls Assessed:** {{ report.compliance_controls | length }}
- **Implemented Controls:** {{ report.compliance_controls | selectattr("implementation_status", "equalto", "Implemented") | list | length }}
- **Security Metrics Collected:** {{ report.security_metrics | length }}
- **Security Incidents:** {{ report.security_incidents | length }}

---

## Security Metrics

{% if report.security_metrics %}
{% for metric in report.security_metrics %}
### {{ metric.name | replace("_", " ") | title }}

- **Current Value:** {{ "%.2f" | format(metric.value) }}{% if metric.name | regex_match(".*rate.*") %}%{% endif %}
- **Threshold:** {{ metric.threshold }}
- **Status:** {{ metric.status | upper }}
- **Description:** {{ metric.description }}
- **Timestamp:** {{ metric.timestamp | date(format="%Y-%m-%d %H:%M:%S UTC") }}

{% endfor %}
{% else %}
No security metrics available.
{% endif %}

---

## Compliance Controls

{% if report.compliance_controls %}
{% for control in report.compliance_controls %}
### {{ control.control_id }}: {{ control.title }}

- **Framework:** {{ control.framework | upper }}
- **Implementation Status:** {{ control.implementation_status | replace("_", " ") | title }}
- **Effectiveness:** {{ control.effectiveness | replace("_", " ") | title }}
- **Risk Level:** {{ control.risk_level | upper }}
- **Last Tested:** {{ control.last_tested | date(format="%Y-%m-%d") }}
- **Next Review:** {{ control.next_review | date(format="%Y-%m-%d") }}
- **Assigned To:** {{ control.assigned_to | default("Unassigned") }}

**Description:** {{ control.description }}

{% if control.evidence %}
**Evidence:**
{% for evidence in control.evidence %}
- {{ evidence }}
{% endfor %}
{% endif %}

{% if control.remediation_plan %}
**Remediation Plan:** {{ control.remediation_plan }}
{% endif %}

---
{% endfor %}
{% else %}
No compliance controls defined for this framework.
{% endif %}

## Security Incidents

{% if report.security_incidents %}
{% for incident in report.security_incidents %}
### {{ incident.incident_id }}: {{ incident.title | default(incident.description) }}

- **Severity:** {{ incident.severity | upper }}
- **Category:** {{ incident.category | replace("_", " ") | title }}
- **Detected:** {{ incident.detected_at | date(format="%Y-%m-%d %H:%M:%S UTC") }}
- **Status:** {% if incident.resolved_at %}Resolved ({{ incident.resolved_at | date(format="%Y-%m-%d %H:%M:%S UTC") }}){% else %}Open{% endif %}
- **Impact:** {{ incident.impact }}

**Description:** {{ incident.description }}

{% if incident.root_cause %}
**Root Cause:** {{ incident.root_cause }}
{% endif %}

{% if incident.remediation_actions %}
**Remediation Actions:**
{% for action in incident.remediation_actions %}
- {{ action }}
{% endfor %}
{% endif %}

{% if incident.affected_systems %}
**Affected Systems:** {{ incident.affected_systems | join(", ") }}
{% endif %}

{% if incident.assigned_to %}
**Assigned To:** {{ incident.assigned_to }}
{% endif %}

{% if incident.lessons_learned %}
**Lessons Learned:** {{ incident.lessons_learned }}
{% endif %}

---
{% endfor %}
{% else %}
No security incidents reported during the assessment period.
{% endif %}

## Audit Summary

- **Total Events:** {{ report.audit_summary.total_events }}
- **Successful Events:** {{ report.audit_summary.successful_events }}
- **Failed Events:** {{ report.audit_summary.failed_events }}
- **Blocked Events:** {{ report.audit_summary.blocked_events }}
- **Unique Users:** {{ report.audit_summary.unique_users }}
- **Unique IP Addresses:** {{ report.audit_summary.unique_ips }}
- **Anomalous Activity Events:** {{ report.audit_summary.anomalous_activity }}

{% if report.audit_summary.top_actions %}
### Top Actions

{% for action, count in report.audit_summary.top_actions %}
- **{{ action }}:** {{ count }} occurrences
{% endfor %}
{% endif %}

---

## Recommendations

Based on this assessment, we recommend:

1. **Continue monitoring** security metrics to ensure they remain within acceptable thresholds
2. **Review and update** any controls with "Needs Improvement" effectiveness ratings
3. **Address any failed security metrics** by investigating root causes and implementing corrective actions
4. **Maintain regular testing** of all compliance controls as per their scheduled review dates
5. **Document and track** any remediation activities for incomplete controls

---

## Conclusion

This report provides a comprehensive view of {{ report.organization.name }}'s compliance posture with {{ report.framework | upper }} requirements. Regular assessment and continuous improvement of security controls and processes are essential for maintaining compliance and protecting the organization's assets.

---

*This report was generated automatically by the Rust Security Compliance Tools on {{ generated_at }}.*

**Classification: {{ report.classification | upper }}**