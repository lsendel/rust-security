# Compliance Management Runbook

## Overview

This runbook provides operational procedures for managing compliance with SOC 2, HIPAA, and PCI DSS requirements across the Rust Security Platform. It covers monitoring, reporting, audit preparation, and violation response procedures.

## Table of Contents

1. [Compliance Framework Overview](#compliance-framework-overview)
2. [Daily Operations](#daily-operations)
3. [Monitoring and Alerting](#monitoring-and-alerting)
4. [Audit Procedures](#audit-procedures)
5. [Violation Response](#violation-response)
6. [Reporting](#reporting)

## Compliance Framework Overview

### SOC 2 Type II Compliance
**Focus**: Trust Service Criteria (Security, Availability, Processing Integrity, Confidentiality, Privacy)

**Key Controls**:
- CC6.1: Logical and Physical Access Controls
- CC6.2: User Authentication and Authorization  
- CC6.3: System Access Monitoring
- A1.1: System Availability Management
- PI1.1: Data Processing Integrity
- C1.1: Data Confidentiality Protection
- P1.1: Privacy Notice Management

### HIPAA Compliance
**Focus**: Protected Health Information (PHI) security and privacy

**Key Safeguards**:
- Administrative: Security Officer, Workforce Training
- Physical: Facility Access Controls
- Technical: Access Control, Transmission Security

### PCI DSS Compliance  
**Focus**: Cardholder data protection

**Key Requirements**:
- Build and Maintain Secure Networks (Req 1-2)
- Protect Cardholder Data (Req 3-4)
- Maintain Vulnerability Management (Req 5-6)
- Implement Strong Access Control (Req 7-8)
- Regular Monitoring and Testing (Req 9-10)
- Maintain Information Security Policy (Req 11-12)

## Daily Operations

### Morning Compliance Check (8:00 AM)

```bash
#!/bin/bash
# Daily compliance status check

echo "=== Daily Compliance Check - $(date) ==="

# Check compliance dashboard
curl -s http://localhost:3000/compliance/dashboard | \
  jq '{
    overall_score: .overall_compliance_score,
    critical_violations: .critical_violations | length,
    frameworks: .framework_metrics | to_entries | map({
      framework: .key,
      score: .value.compliance_percentage,
      violations: .value.open_violations
    })
  }'

# Check for new violations
curl -s http://localhost:3000/compliance/violations?status=open&since=24h | \
  jq '.violations[] | select(.severity == "Critical" or .severity == "High")'

# Verify automated checks are running
curl -s http://localhost:3000/compliance/check-status | \
  jq '.last_check_times'

echo "=== Compliance Check Complete ==="
```

### Control Status Verification

```bash
#!/bin/bash
# Verify key controls are operational

check_control() {
    local framework=$1
    local control_id=$2
    local description=$3
    
    echo "Checking $framework $control_id: $description"
    
    status=$(curl -s "http://localhost:3000/compliance/controls/$framework/$control_id" | \
             jq -r '.status')
    
    if [ "$status" != "Compliant" ]; then
        echo "⚠️  WARNING: $framework $control_id is $status"
        return 1
    else
        echo "✅ $framework $control_id is compliant"
        return 0
    fi
}

# Check critical SOC 2 controls
check_control "SOC2" "CC6.1" "Access Controls"
check_control "SOC2" "CC6.2" "Authentication"
check_control "SOC2" "CC6.3" "Monitoring"

# Check critical HIPAA controls  
check_control "HIPAA" "164.312(a)(1)" "Access Control"
check_control "HIPAA" "164.312(e)(1)" "Transmission Security"

# Check critical PCI DSS controls
check_control "PCI_DSS" "3.4" "PAN Protection"
check_control "PCI_DSS" "4.1" "Transmission Encryption"
check_control "PCI_DSS" "8.2" "User Authentication"
```

## Monitoring and Alerting

### Compliance Metrics Dashboard

#### Key Performance Indicators
```bash
# Generate compliance KPI report
curl -s http://localhost:3000/compliance/metrics | \
  jq '{
    soc2: {
      score: .SOC2.compliance_percentage,
      violations: .SOC2.open_violations,
      critical: .SOC2.critical_violations,
      automated_checks: .SOC2.automated_checks_enabled
    },
    hipaa: {
      score: .HIPAA.compliance_percentage,
      violations: .HIPAA.open_violations,
      critical: .HIPAA.critical_violations,
      automated_checks: .HIPAA.automated_checks_enabled
    },
    pci_dss: {
      score: .PCI_DSS.compliance_percentage,
      violations: .PCI_DSS.open_violations,
      critical: .PCI_DSS.critical_violations,
      automated_checks: .PCI_DSS.automated_checks_enabled
    }
  }'
```

### Alert Thresholds

#### Critical Alerts (Immediate Response)
```yaml
Compliance Score Drop: >5% decrease in 24 hours
Critical Violations: Any new critical violations
Control Failure: Any required control marked as non-compliant
Audit Trail Gap: Missing logs for >1 hour
Data Breach Indicators: Potential PHI/PCI data exposure
```

#### Warning Alerts (4-hour Response)
```yaml
Compliance Score: Below 95% for any framework
High Violations: >3 new high-severity violations
Manual Reviews Overdue: >10 controls pending review
Evidence Collection: Missing evidence for upcoming audit
Automated Check Failures: >50% of checks failing
```

### Monitoring Commands

#### Real-time Compliance Status
```bash
# Watch compliance violations in real-time
watch -n 30 'curl -s http://localhost:3000/compliance/violations?status=open | \
  jq ".violations | group_by(.framework) | map({
    framework: .[0].framework,
    count: length,
    critical: map(select(.severity == \"Critical\")) | length,
    high: map(select(.severity == \"High\")) | length
  })"'
```

#### Audit Trail Monitoring
```bash
# Check audit trail completeness
curl -s http://localhost:3000/compliance/audit-trail/health | \
  jq '{
    events_last_hour: .events_count_1h,
    missing_periods: .missing_periods,
    integrity_check: .integrity_status
  }'

# Monitor critical security events
tail -f /var/log/auth-service/audit.log | \
  grep -E "(authentication_failure|data_access|privileged_operation)" | \
  while read line; do
    echo "$(date): $line"
  done
```

## Audit Procedures

### Pre-Audit Preparation

#### Evidence Collection (30 days before audit)
```bash
#!/bin/bash
# Automated evidence collection for compliance audit

AUDIT_DATE="2025-02-15"
EVIDENCE_DIR="/audit-evidence/$(date +%Y%m%d)"
mkdir -p "$EVIDENCE_DIR"

echo "=== Collecting Audit Evidence for $AUDIT_DATE ==="

# 1. Control Implementation Evidence
echo "Collecting control implementation evidence..."
curl -s http://localhost:3000/compliance/controls/evidence | \
  jq '.' > "$EVIDENCE_DIR/control-evidence.json"

# 2. Audit Logs (90 days)
echo "Collecting audit logs..."
curl -s "http://localhost:3000/compliance/audit-trail/export?days=90" | \
  jq '.' > "$EVIDENCE_DIR/audit-logs.json"

# 3. Security Monitoring Reports
echo "Collecting security monitoring reports..."
curl -s http://localhost:3000/security/reports/summary?days=90 | \
  jq '.' > "$EVIDENCE_DIR/security-reports.json"

# 4. Compliance Metrics History
echo "Collecting compliance metrics..."
curl -s http://localhost:3000/compliance/metrics/history?days=90 | \
  jq '.' > "$EVIDENCE_DIR/compliance-metrics.json"

# 5. Configuration Snapshots
echo "Collecting configuration evidence..."
curl -s http://localhost:3000/admin/config/export | \
  jq '.' > "$EVIDENCE_DIR/system-configuration.json"

# 6. User Access Reviews
echo "Collecting access review evidence..."
curl -s http://localhost:3000/admin/access-reviews/export | \
  jq '.' > "$EVIDENCE_DIR/access-reviews.json"

# 7. Incident Response Records
echo "Collecting incident response records..."
curl -s http://localhost:3000/incidents/export?days=90 | \
  jq '.' > "$EVIDENCE_DIR/incident-records.json"

# Create evidence package
cd "$EVIDENCE_DIR"
tar -czf "../audit-evidence-package-$(date +%Y%m%d).tar.gz" .
echo "Evidence package created: audit-evidence-package-$(date +%Y%m%d).tar.gz"
```

#### Control Testing Scripts
```bash
#!/bin/bash
# Automated control testing for audit preparation

test_soc2_cc6_1() {
    echo "Testing SOC 2 CC6.1 - Access Controls"
    
    # Test user authentication
    curl -X POST http://localhost:3000/api/v1/auth/login \
         -d '{"username":"testuser","password":"wrongpassword"}' \
         -H "Content-Type: application/json" | \
    jq '.error // empty' | grep -q "authentication failed"
    
    if [ $? -eq 0 ]; then
        echo "✅ Access control test passed - invalid credentials rejected"
    else
        echo "❌ Access control test failed - invalid credentials accepted"
    fi
}

test_hipaa_access_control() {
    echo "Testing HIPAA 164.312(a)(1) - Access Control"
    
    # Test unique user identification
    response=$(curl -s -X GET http://localhost:3000/api/v1/auth/me \
              -H "Authorization: Bearer invalid_token")
    
    echo "$response" | grep -q "Unauthorized"
    if [ $? -eq 0 ]; then
        echo "✅ HIPAA access control test passed - unauthorized access denied"
    else
        echo "❌ HIPAA access control test failed - unauthorized access allowed"
    fi
}

test_pci_encryption() {
    echo "Testing PCI DSS 4.1 - Transmission Encryption"
    
    # Test HTTPS enforcement
    http_response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health)
    
    if [ "$http_response" = "301" ] || [ "$http_response" = "302" ]; then
        echo "✅ PCI encryption test passed - HTTP redirected to HTTPS"
    elif [ "$http_response" = "200" ]; then
        echo "⚠️  PCI encryption warning - HTTP not redirected to HTTPS"
    else
        echo "❌ PCI encryption test failed - unexpected response: $http_response"
    fi
}

# Run all control tests
test_soc2_cc6_1
test_hipaa_access_control  
test_pci_encryption
```

### During Audit Support

#### Auditor Access Management
```bash
# Create temporary auditor account (with approval)
create_auditor_access() {
    local auditor_name=$1
    local audit_firm=$2
    local expiry_date=$3
    
    echo "Creating auditor access for $auditor_name from $audit_firm"
    
    # Generate temporary credentials
    auditor_id="auditor_$(date +%s)"
    temp_password=$(openssl rand -base64 32)
    
    # Create account with read-only audit permissions
    curl -X POST http://localhost:3000/admin/users/auditor \
         -H "Authorization: Bearer $ADMIN_TOKEN" \
         -d "{
           \"user_id\": \"$auditor_id\",
           \"name\": \"$auditor_name\",
           \"organization\": \"$audit_firm\",
           \"permissions\": [\"audit:read\", \"compliance:read\"],
           \"expires_at\": \"$expiry_date\",
           \"password\": \"$temp_password\"
         }"
    
    echo "Auditor credentials:"
    echo "Username: $auditor_id"
    echo "Password: $temp_password"
    echo "Expires: $expiry_date"
}

# Revoke auditor access
revoke_auditor_access() {
    local auditor_id=$1
    
    curl -X DELETE http://localhost:3000/admin/users/$auditor_id \
         -H "Authorization: Bearer $ADMIN_TOKEN"
    
    echo "Auditor access revoked for: $auditor_id"
}
```

## Violation Response

### Critical Violation Response (15-minute response time)

```bash
#!/bin/bash
# Critical compliance violation response

handle_critical_violation() {
    local violation_id=$1
    
    echo "=== CRITICAL COMPLIANCE VIOLATION RESPONSE ==="
    echo "Violation ID: $violation_id"
    echo "Timestamp: $(date)"
    
    # Get violation details
    violation=$(curl -s "http://localhost:3000/compliance/violations/$violation_id")
    framework=$(echo "$violation" | jq -r '.framework')
    control_id=$(echo "$violation" | jq -r '.control_id')
    severity=$(echo "$violation" | jq -r '.severity')
    
    echo "Framework: $framework"
    echo "Control: $control_id"  
    echo "Severity: $severity"
    
    # Immediate containment actions
    case "$framework" in
        "HIPAA")
            echo "Implementing HIPAA breach containment..."
            # Stop data access if PHI exposure suspected
            if [[ "$control_id" == *"312"* ]]; then
                echo "Potential PHI exposure - implementing containment"
                # Additional HIPAA-specific containment
            fi
            ;;
        "PCI_DSS")
            echo "Implementing PCI DSS incident response..."
            # Secure cardholder data environment
            if [[ "$control_id" == "3.4" ]] || [[ "$control_id" == "4.1" ]]; then
                echo "Cardholder data protection violation - securing environment"
                # Additional PCI-specific containment
            fi
            ;;
        "SOC2")
            echo "Implementing SOC 2 control remediation..."
            # Address trust service criteria violation
            ;;
    esac
    
    # Document response actions
    curl -X POST "http://localhost:3000/compliance/violations/$violation_id/response" \
         -H "Content-Type: application/json" \
         -d "{
           \"response_time\": $(date +%s),
           \"responder\": \"$(whoami)\",
           \"actions_taken\": \"Immediate containment implemented per runbook\",
           \"status\": \"in_progress\"
         }"
    
    # Notify compliance team
    echo "Critical compliance violation requires immediate attention: $violation_id" | \
         mail -s "CRITICAL: Compliance Violation - $framework $control_id" \
         compliance-team@company.com
    
    echo "=== RESPONSE ACTIONS INITIATED ==="
}

# Usage: handle_critical_violation <violation_id>
```

### Violation Investigation

```bash
#!/bin/bash
# Compliance violation investigation

investigate_violation() {
    local violation_id=$1
    local investigation_dir="/investigations/$violation_id"
    
    mkdir -p "$investigation_dir"
    
    echo "Starting investigation for violation: $violation_id"
    
    # Collect violation details
    curl -s "http://localhost:3000/compliance/violations/$violation_id" | \
         jq '.' > "$investigation_dir/violation-details.json"
    
    # Collect related audit events
    violation_time=$(jq -r '.detected_at' "$investigation_dir/violation-details.json")
    start_time=$((violation_time - 3600))  # 1 hour before
    end_time=$((violation_time + 1800))    # 30 minutes after
    
    curl -s "http://localhost:3000/compliance/audit-trail/query" \
         -d "{\"start_time\": $start_time, \"end_time\": $end_time}" | \
         jq '.' > "$investigation_dir/related-events.json"
    
    # Check system status at time of violation
    curl -s "http://localhost:3000/admin/system/status/historical" \
         -d "{\"timestamp\": $violation_time}" | \
         jq '.' > "$investigation_dir/system-status.json"
    
    # Analyze root cause
    python3 /scripts/violation-analyzer.py \
            --violation-file "$investigation_dir/violation-details.json" \
            --events-file "$investigation_dir/related-events.json" \
            --output "$investigation_dir/root-cause-analysis.json"
    
    echo "Investigation complete. Results in: $investigation_dir"
}
```

## Reporting

### Daily Compliance Report

```bash
#!/bin/bash
# Generate daily compliance summary report

generate_daily_report() {
    local report_date=$(date +%Y-%m-%d)
    local report_file="/reports/compliance-daily-$report_date.json"
    
    echo "Generating daily compliance report for $report_date"
    
    # Get compliance dashboard data
    dashboard=$(curl -s http://localhost:3000/compliance/dashboard)
    
    # Get new violations in last 24 hours
    violations=$(curl -s "http://localhost:3000/compliance/violations?since=24h")
    
    # Get resolved violations in last 24 hours  
    resolved=$(curl -s "http://localhost:3000/compliance/violations?status=resolved&since=24h")
    
    # Combine into daily report
    jq -n \
       --argjson dashboard "$dashboard" \
       --argjson violations "$violations" \
       --argjson resolved "$resolved" \
       --arg date "$report_date" \
    '{
      report_date: $date,
      overall_compliance: $dashboard.overall_compliance_score,
      framework_scores: $dashboard.framework_metrics | to_entries | map({
        framework: .key,
        score: .value.compliance_percentage,
        violations: .value.open_violations
      }),
      new_violations: $violations.violations | length,
      resolved_violations: $resolved.violations | length,
      critical_issues: [
        $violations.violations[] | select(.severity == "Critical")
      ],
      recommendations: $dashboard.recommendations
    }' > "$report_file"
    
    echo "Daily report generated: $report_file"
    
    # Email report to compliance team
    mail -s "Daily Compliance Report - $report_date" \
         -a "$report_file" \
         compliance-team@company.com < /dev/null
}
```

### Monthly Compliance Assessment

```bash
#!/bin/bash
# Generate monthly compliance assessment report

generate_monthly_report() {
    local month=$(date +%Y-%m)
    local report_file="/reports/compliance-monthly-$month.pdf"
    
    echo "Generating monthly compliance assessment for $month"
    
    # Collect 30-day data
    start_date=$(date -d "30 days ago" +%s)
    end_date=$(date +%s)
    
    # Generate comprehensive report
    curl -s http://localhost:3000/compliance/reports/monthly \
         -d "{\"start_date\": $start_date, \"end_date\": $end_date}" \
         -H "Content-Type: application/json" > "/tmp/monthly-data.json"
    
    # Generate PDF report using template
    python3 /scripts/generate-compliance-pdf.py \
            --data "/tmp/monthly-data.json" \
            --template "/templates/monthly-compliance-report.html" \
            --output "$report_file"
    
    echo "Monthly assessment generated: $report_file"
    
    # Distribute to stakeholders
    mail -s "Monthly Compliance Assessment - $month" \
         -a "$report_file" \
         compliance-team@company.com,management@company.com
}
```

### Audit Readiness Report

```bash
#!/bin/bash
# Generate audit readiness assessment

assess_audit_readiness() {
    local framework=$1
    local assessment_file="/reports/audit-readiness-$framework-$(date +%Y%m%d).json"
    
    echo "Assessing audit readiness for $framework"
    
    # Check control implementation status
    controls=$(curl -s "http://localhost:3000/compliance/controls/$framework/status")
    
    # Check evidence completeness
    evidence=$(curl -s "http://localhost:3000/compliance/evidence/$framework/completeness")
    
    # Check violation status
    violations=$(curl -s "http://localhost:3000/compliance/violations?framework=$framework&status=open")
    
    # Generate readiness score
    readiness_score=$(echo "$controls $evidence $violations" | \
                     python3 /scripts/calculate-audit-readiness.py)
    
    # Compile assessment
    jq -n \
       --argjson controls "$controls" \
       --argjson evidence "$evidence" \
       --argjson violations "$violations" \
       --arg framework "$framework" \
       --arg score "$readiness_score" \
    '{
      framework: $framework,
      assessment_date: now | strftime("%Y-%m-%d"),
      readiness_score: ($score | tonumber),
      control_status: $controls,
      evidence_completeness: $evidence,
      open_violations: $violations.violations | length,
      recommendations: [
        if ($score | tonumber) < 85 then
          "Address open violations before audit"
        else empty end,
        if $evidence.missing_evidence | length > 0 then
          "Collect missing evidence items"
        else empty end,
        if $controls.non_compliant | length > 0 then
          "Remediate non-compliant controls"
        else empty end
      ]
    }' > "$assessment_file"
    
    echo "Audit readiness assessment complete: $assessment_file"
    cat "$assessment_file" | jq '.readiness_score,.recommendations'
}

# Assess all frameworks
assess_audit_readiness "SOC2"
assess_audit_readiness "HIPAA"  
assess_audit_readiness "PCI_DSS"
```

## Emergency Procedures

### Compliance Emergency Response

#### Regulatory Notification Requirements
```bash
#!/bin/bash
# Handle regulatory notification requirements

trigger_regulatory_notification() {
    local incident_type=$1
    local severity=$2
    local affected_data=$3
    
    case "$incident_type" in
        "data_breach")
            if [[ "$affected_data" == *"PHI"* ]]; then
                echo "HIPAA breach notification required"
                # Generate HIPAA breach notification
                generate_hipaa_breach_notice
            fi
            
            if [[ "$affected_data" == *"cardholder"* ]]; then
                echo "PCI DSS breach notification required"  
                # Generate PCI DSS incident notification
                generate_pci_incident_notice
            fi
            ;;
        "system_compromise")
            echo "SOC 2 control failure - customer notification may be required"
            # Assess customer notification requirements
            ;;
    esac
}

generate_hipaa_breach_notice() {
    # HIPAA requires notification within 72 hours to HHS
    # and within 60 days to affected individuals
    
    echo "Generating HIPAA breach notification..."
    # Implementation would create proper HIPAA breach notice
}
```

---

**Document Version**: 1.0  
**Last Updated**: [Current Date]  
**Next Review**: [Date + 6 months]  
**Owner**: Compliance Team