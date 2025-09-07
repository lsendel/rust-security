//! Automated Compliance Assessment Tools
//!
//! This module provides comprehensive automated compliance assessment capabilities
//! for enterprise security frameworks including SOX, GDPR, HIPAA, PCI DSS, ISO 27001,
//! NIST Cybersecurity Framework, and OWASP ASVS Level 3.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn, debug};
use uuid::Uuid;

/// Compliance frameworks supported by the assessment engine
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ComplianceFramework {
    /// Sarbanes-Oxley Act compliance
    SOX,
    /// General Data Protection Regulation
    GDPR,
    /// Health Insurance Portability and Accountability Act
    HIPAA,
    /// Payment Card Industry Data Security Standard
    PCIDSS,
    /// International Organization for Standardization 27001
    ISO27001,
    /// NIST Cybersecurity Framework
    NISTCSF,
    /// OWASP Application Security Verification Standard Level 3
    OWASPASVS,
}

/// Compliance assessment severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssessmentSeverity {
    /// Critical compliance violations requiring immediate attention
    Critical,
    /// High-priority compliance issues
    High,
    /// Medium-priority compliance gaps
    Medium,
    /// Low-priority compliance recommendations
    Low,
    /// Informational compliance notes
    Info,
}

/// Compliance control categories for systematic assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ControlCategory {
    /// Access control and identity management
    AccessControl,
    /// Audit logging and monitoring
    AuditLogging,
    /// Cryptography and data protection
    Cryptography,
    /// Incident response and recovery
    IncidentResponse,
    /// Network security controls
    NetworkSecurity,
    /// Physical security measures
    PhysicalSecurity,
    /// Risk assessment and management
    RiskManagement,
    /// Security awareness and training
    SecurityTraining,
    /// System and information integrity
    SystemIntegrity,
    /// Configuration management
    ConfigurationManagement,
    /// Vulnerability management
    VulnerabilityManagement,
    /// Data loss prevention
    DataLossPrevention,
}

/// Individual compliance control definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    /// Unique control identifier
    pub id: String,
    /// Human-readable control name
    pub name: String,
    /// Detailed control description
    pub description: String,
    /// Control category
    pub category: ControlCategory,
    /// Applicable frameworks
    pub frameworks: HashSet<ComplianceFramework>,
    /// Control implementation status
    pub status: ControlStatus,
    /// Assessment severity if non-compliant
    pub severity: AssessmentSeverity,
    /// Implementation guidance
    pub guidance: Vec<String>,
    /// Related controls
    pub related_controls: Vec<String>,
    /// Last assessment timestamp
    pub last_assessed: DateTime<Utc>,
    /// Assessment score (0.0 to 1.0)
    pub score: f64,
    /// Assessment evidence
    pub evidence: Vec<AssessmentEvidence>,
}

/// Control implementation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlStatus {
    /// Control is fully implemented and compliant
    Implemented,
    /// Control is partially implemented
    PartiallyImplemented,
    /// Control is not implemented
    NotImplemented,
    /// Control is not applicable to current environment
    NotApplicable,
    /// Control implementation is pending
    Pending,
    /// Control requires remediation
    RequiresRemediation,
}

/// Evidence supporting control assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentEvidence {
    /// Evidence type
    pub evidence_type: EvidenceType,
    /// Evidence description
    pub description: String,
    /// Evidence source
    pub source: String,
    /// Evidence timestamp
    pub timestamp: DateTime<Utc>,
    /// Evidence weight in assessment (0.0 to 1.0)
    pub weight: f64,
    /// Evidence validation status
    pub validated: bool,
}

/// Types of assessment evidence
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceType {
    /// Automated system scan results
    AutomatedScan,
    /// Configuration audit results
    ConfigurationAudit,
    /// Log analysis findings
    LogAnalysis,
    /// Code review results
    CodeReview,
    /// Penetration testing results
    PenetrationTest,
    /// Documentation review
    DocumentationReview,
    /// Interview findings
    InterviewFindings,
    /// Observation evidence
    Observation,
}

/// Compliance assessment report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAssessmentReport {
    /// Report identifier
    pub id: Uuid,
    /// Assessment timestamp
    pub timestamp: DateTime<Utc>,
    /// Assessed frameworks
    pub frameworks: HashSet<ComplianceFramework>,
    /// Overall compliance score (0.0 to 1.0)
    pub overall_score: f64,
    /// Framework-specific scores
    pub framework_scores: HashMap<ComplianceFramework, f64>,
    /// Control assessments
    pub control_assessments: Vec<ComplianceControl>,
    /// Critical findings requiring immediate attention
    pub critical_findings: Vec<ComplianceFinding>,
    /// High-priority recommendations
    pub high_priority_recommendations: Vec<ComplianceRecommendation>,
    /// Remediation timeline
    pub remediation_timeline: Vec<RemediationAction>,
    /// Assessment metadata
    pub metadata: AssessmentMetadata,
}

/// Individual compliance finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    /// Finding identifier
    pub id: Uuid,
    /// Finding title
    pub title: String,
    /// Detailed finding description
    pub description: String,
    /// Affected control IDs
    pub affected_controls: Vec<String>,
    /// Finding severity
    pub severity: AssessmentSeverity,
    /// Applicable frameworks
    pub frameworks: HashSet<ComplianceFramework>,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Remediation effort estimate
    pub remediation_effort: RemediationEffort,
    /// Finding evidence
    pub evidence: Vec<AssessmentEvidence>,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
}

/// Compliance recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRecommendation {
    /// Recommendation identifier
    pub id: Uuid,
    /// Recommendation title
    pub title: String,
    /// Detailed recommendation description
    pub description: String,
    /// Priority level
    pub priority: AssessmentSeverity,
    /// Expected benefit
    pub expected_benefit: String,
    /// Implementation effort
    pub implementation_effort: RemediationEffort,
    /// Cost estimate
    pub cost_estimate: CostEstimate,
    /// Timeline estimate
    pub timeline_estimate: TimelineEstimate,
}

/// Remediation action item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAction {
    /// Action identifier
    pub id: Uuid,
    /// Action title
    pub title: String,
    /// Detailed action description
    pub description: String,
    /// Responsible party
    pub responsible_party: String,
    /// Due date
    pub due_date: DateTime<Utc>,
    /// Action status
    pub status: ActionStatus,
    /// Dependencies
    pub dependencies: Vec<Uuid>,
    /// Estimated effort
    pub effort: RemediationEffort,
}

/// Risk level classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Very high risk requiring immediate action
    VeryHigh,
    /// High risk requiring prompt action
    High,
    /// Medium risk requiring planned action
    Medium,
    /// Low risk for future consideration
    Low,
    /// Very low risk, minimal concern
    VeryLow,
}

/// Remediation effort estimates
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemediationEffort {
    /// Minimal effort (< 1 day)
    Minimal,
    /// Low effort (1-3 days)
    Low,
    /// Medium effort (1-2 weeks)
    Medium,
    /// High effort (2-4 weeks)
    High,
    /// Very high effort (> 1 month)
    VeryHigh,
}

/// Cost estimate ranges
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CostEstimate {
    /// Minimal cost (< $1,000)
    Minimal,
    /// Low cost ($1,000 - $5,000)
    Low,
    /// Medium cost ($5,000 - $25,000)
    Medium,
    /// High cost ($25,000 - $100,000)
    High,
    /// Very high cost (> $100,000)
    VeryHigh,
}

/// Timeline estimate ranges
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimelineEstimate {
    /// Immediate (within 1 week)
    Immediate,
    /// Short term (1-4 weeks)
    ShortTerm,
    /// Medium term (1-3 months)
    MediumTerm,
    /// Long term (3-12 months)
    LongTerm,
    /// Strategic (> 12 months)
    Strategic,
}

/// Remediation action status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionStatus {
    /// Action not yet started
    NotStarted,
    /// Action in progress
    InProgress,
    /// Action completed successfully
    Completed,
    /// Action blocked by dependencies
    Blocked,
    /// Action cancelled or no longer needed
    Cancelled,
    /// Action requires review
    UnderReview,
}

/// Assessment metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentMetadata {
    /// Assessment version
    pub version: String,
    /// Assessor information
    pub assessor: String,
    /// Assessment scope
    pub scope: String,
    /// Assessment methodology
    pub methodology: String,
    /// Tools used for assessment
    pub tools_used: Vec<String>,
    /// Assessment duration
    pub duration_hours: f64,
    /// Next assessment due date
    pub next_assessment_due: DateTime<Utc>,
}

/// Main automated compliance assessment engine
pub struct ComplianceAssessmentEngine {
    /// Control registry
    controls: Arc<RwLock<HashMap<String, ComplianceControl>>>,
    /// Assessment history
    assessment_history: Arc<RwLock<VecDeque<ComplianceAssessmentReport>>>,
    /// Assessment configuration
    config: Arc<ComplianceAssessmentConfig>,
    /// Framework mappings
    framework_mappings: Arc<RwLock<HashMap<ComplianceFramework, Vec<String>>>>,
    /// Evidence collectors
    evidence_collectors: Arc<RwLock<HashMap<EvidenceType, Box<dyn EvidenceCollector + Send + Sync>>>>,
    /// Assessment scheduler
    scheduler: Arc<RwLock<AssessmentScheduler>>,
}

/// Compliance assessment configuration
#[derive(Debug, Clone)]
pub struct ComplianceAssessmentConfig {
    /// Enabled frameworks
    pub enabled_frameworks: HashSet<ComplianceFramework>,
    /// Assessment frequency in days
    pub assessment_frequency_days: u32,
    /// Automated assessment enabled
    pub automated_assessment_enabled: bool,
    /// Evidence collection enabled
    pub evidence_collection_enabled: bool,
    /// Report retention days
    pub report_retention_days: u32,
    /// Critical finding alert threshold
    pub critical_finding_threshold: u32,
    /// Minimum control score for compliance
    pub minimum_control_score: f64,
}

/// Evidence collector trait for automated evidence gathering
#[async_trait::async_trait]
pub trait EvidenceCollector: Send + Sync {
    /// Collect evidence for the specified control
    async fn collect_evidence(&self, control: &ComplianceControl) -> Result<Vec<AssessmentEvidence>>;
    
    /// Validate existing evidence
    async fn validate_evidence(&self, evidence: &AssessmentEvidence) -> Result<bool>;
}

/// Assessment scheduler for automated assessments
#[derive(Debug)]
pub struct AssessmentScheduler {
    /// Last assessment timestamp
    pub last_assessment: DateTime<Utc>,
    /// Next assessment due
    pub next_assessment_due: DateTime<Utc>,
    /// Scheduled assessments
    pub scheduled_assessments: VecDeque<ScheduledAssessment>,
    /// Assessment intervals by framework
    pub framework_intervals: HashMap<ComplianceFramework, Duration>,
}

/// Scheduled assessment entry
#[derive(Debug, Clone)]
pub struct ScheduledAssessment {
    /// Assessment ID
    pub id: Uuid,
    /// Frameworks to assess
    pub frameworks: HashSet<ComplianceFramework>,
    /// Scheduled time
    pub scheduled_time: DateTime<Utc>,
    /// Assessment scope
    pub scope: String,
    /// Assessment type
    pub assessment_type: AssessmentType,
}

/// Types of automated assessments
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssessmentType {
    /// Full comprehensive assessment
    Full,
    /// Delta assessment for changes only
    Delta,
    /// Focused assessment on specific controls
    Focused,
    /// Continuous monitoring assessment
    Continuous,
}

impl ComplianceAssessmentEngine {
    /// Create new compliance assessment engine
    pub async fn new(config: ComplianceAssessmentConfig) -> Result<Self> {
        let controls = Arc::new(RwLock::new(HashMap::new()));
        let assessment_history = Arc::new(RwLock::new(VecDeque::new()));
        let framework_mappings = Arc::new(RwLock::new(HashMap::new()));
        let evidence_collectors = Arc::new(RwLock::new(HashMap::new()));
        
        let scheduler = Arc::new(RwLock::new(AssessmentScheduler {
            last_assessment: Utc::now() - Duration::days(365), // Force initial assessment
            next_assessment_due: Utc::now(),
            scheduled_assessments: VecDeque::new(),
            framework_intervals: Self::default_framework_intervals(),
        }));

        let engine = Self {
            controls,
            assessment_history,
            config: Arc::new(config),
            framework_mappings,
            evidence_collectors,
            scheduler,
        };

        // Initialize default controls
        engine.initialize_default_controls().await?;
        
        // Initialize framework mappings
        engine.initialize_framework_mappings().await?;

        Ok(engine)
    }

    /// Get default assessment intervals for each framework
    fn default_framework_intervals() -> HashMap<ComplianceFramework, Duration> {
        let mut intervals = HashMap::new();
        intervals.insert(ComplianceFramework::SOX, Duration::days(90)); // Quarterly
        intervals.insert(ComplianceFramework::GDPR, Duration::days(180)); // Semi-annually
        intervals.insert(ComplianceFramework::HIPAA, Duration::days(365)); // Annually
        intervals.insert(ComplianceFramework::PCIDSS, Duration::days(365)); // Annually
        intervals.insert(ComplianceFramework::ISO27001, Duration::days(180)); // Semi-annually
        intervals.insert(ComplianceFramework::NISTCSF, Duration::days(90)); // Quarterly
        intervals.insert(ComplianceFramework::OWASPASVS, Duration::days(30)); // Monthly
        intervals
    }

    /// Initialize default compliance controls
    async fn initialize_default_controls(&self) -> Result<()> {
        let mut controls = self.controls.write().await;
        
        // Access Control Controls
        controls.insert("AC-001".to_string(), ComplianceControl {
            id: "AC-001".to_string(),
            name: "Multi-Factor Authentication".to_string(),
            description: "Implement multi-factor authentication for all user accounts with administrative privileges".to_string(),
            category: ControlCategory::AccessControl,
            frameworks: [ComplianceFramework::SOX, ComplianceFramework::NISTCSF, ComplianceFramework::OWASPASVS].into(),
            status: ControlStatus::RequiresRemediation,
            severity: AssessmentSeverity::High,
            guidance: vec![
                "Implement TOTP-based MFA for all admin accounts".to_string(),
                "Consider hardware tokens for high-privilege accounts".to_string(),
                "Establish MFA bypass procedures for emergency access".to_string(),
            ],
            related_controls: vec!["AC-002".to_string(), "AC-003".to_string()],
            last_assessed: Utc::now() - Duration::days(30),
            score: 0.6,
            evidence: Vec::new(),
        });

        controls.insert("AC-002".to_string(), ComplianceControl {
            id: "AC-002".to_string(),
            name: "Role-Based Access Control".to_string(),
            description: "Implement comprehensive role-based access control with principle of least privilege".to_string(),
            category: ControlCategory::AccessControl,
            frameworks: [ComplianceFramework::SOX, ComplianceFramework::GDPR, ComplianceFramework::NISTCSF].into(),
            status: ControlStatus::PartiallyImplemented,
            severity: AssessmentSeverity::Medium,
            guidance: vec![
                "Define clear role hierarchies and permissions".to_string(),
                "Implement automated provisioning and deprovisioning".to_string(),
                "Conduct regular access reviews".to_string(),
            ],
            related_controls: vec!["AC-001".to_string(), "AC-003".to_string()],
            last_assessed: Utc::now() - Duration::days(15),
            score: 0.75,
            evidence: Vec::new(),
        });

        // Cryptography Controls
        controls.insert("CR-001".to_string(), ComplianceControl {
            id: "CR-001".to_string(),
            name: "Post-Quantum Cryptography".to_string(),
            description: "Implement post-quantum cryptographic algorithms for future-proof security".to_string(),
            category: ControlCategory::Cryptography,
            frameworks: [ComplianceFramework::NISTCSF, ComplianceFramework::OWASPASVS].into(),
            status: ControlStatus::Implemented,
            severity: AssessmentSeverity::High,
            guidance: vec![
                "Deploy CRYSTALS-Dilithium for digital signatures".to_string(),
                "Implement CRYSTALS-Kyber for key encapsulation".to_string(),
                "Maintain hybrid classical/post-quantum approach".to_string(),
            ],
            related_controls: vec!["CR-002".to_string()],
            last_assessed: Utc::now() - Duration::days(7),
            score: 0.95,
            evidence: Vec::new(),
        });

        // Audit Logging Controls
        controls.insert("AU-001".to_string(), ComplianceControl {
            id: "AU-001".to_string(),
            name: "Immutable Audit Logging".to_string(),
            description: "Implement immutable audit logging with cryptographic integrity verification".to_string(),
            category: ControlCategory::AuditLogging,
            frameworks: [ComplianceFramework::SOX, ComplianceFramework::GDPR, ComplianceFramework::HIPAA].into(),
            status: ControlStatus::Implemented,
            severity: AssessmentSeverity::Critical,
            guidance: vec![
                "Deploy hash chain-based audit logging".to_string(),
                "Implement digital signatures for non-repudiation".to_string(),
                "Establish automated integrity verification".to_string(),
            ],
            related_controls: vec!["AU-002".to_string()],
            last_assessed: Utc::now() - Duration::days(1),
            score: 0.90,
            evidence: Vec::new(),
        });

        // Security Monitoring Controls
        controls.insert("SM-001".to_string(), ComplianceControl {
            id: "SM-001".to_string(),
            name: "SIEM Integration".to_string(),
            description: "Implement comprehensive SIEM integration for security event monitoring".to_string(),
            category: ControlCategory::SystemIntegrity,
            frameworks: [ComplianceFramework::NISTCSF, ComplianceFramework::ISO27001].into(),
            status: ControlStatus::Implemented,
            severity: AssessmentSeverity::High,
            guidance: vec![
                "Integrate with major SIEM platforms".to_string(),
                "Implement real-time threat detection".to_string(),
                "Establish automated response workflows".to_string(),
            ],
            related_controls: vec!["SM-002".to_string()],
            last_assessed: Utc::now() - Duration::days(3),
            score: 0.88,
            evidence: Vec::new(),
        });

        info!("Initialized {} default compliance controls", controls.len());
        Ok(())
    }

    /// Initialize framework control mappings
    async fn initialize_framework_mappings(&self) -> Result<()> {
        let mut mappings = self.framework_mappings.write().await;
        
        mappings.insert(ComplianceFramework::SOX, vec![
            "AC-001".to_string(), "AC-002".to_string(), "AU-001".to_string(),
        ]);
        
        mappings.insert(ComplianceFramework::GDPR, vec![
            "AC-002".to_string(), "AU-001".to_string(), "CR-001".to_string(),
        ]);
        
        mappings.insert(ComplianceFramework::NISTCSF, vec![
            "AC-001".to_string(), "AC-002".to_string(), "CR-001".to_string(), "SM-001".to_string(),
        ]);
        
        mappings.insert(ComplianceFramework::OWASPASVS, vec![
            "AC-001".to_string(), "CR-001".to_string(),
        ]);

        info!("Initialized framework control mappings for {} frameworks", mappings.len());
        Ok(())
    }

    /// Perform comprehensive compliance assessment
    pub async fn perform_assessment(
        &self,
        frameworks: HashSet<ComplianceFramework>,
        assessment_type: AssessmentType,
    ) -> Result<ComplianceAssessmentReport> {
        info!("Starting compliance assessment for frameworks: {:?}", frameworks);
        
        let assessment_id = Uuid::new_v4();
        let timestamp = Utc::now();
        
        // Collect applicable controls
        let applicable_controls = self.get_applicable_controls(&frameworks).await?;
        
        // Assess each control
        let mut control_assessments = Vec::new();
        let mut critical_findings = Vec::new();
        let mut high_priority_recommendations = Vec::new();
        
        for control in applicable_controls {
            let assessed_control = self.assess_control(&control, &assessment_type).await?;
            
            // Check for critical findings
            if assessed_control.severity == AssessmentSeverity::Critical && 
               assessed_control.status != ControlStatus::Implemented {
                critical_findings.push(ComplianceFinding {
                    id: Uuid::new_v4(),
                    title: format!("Critical Control Not Implemented: {}", assessed_control.name),
                    description: format!("Control {} ({}) is not properly implemented", 
                                       assessed_control.id, assessed_control.name),
                    affected_controls: vec![assessed_control.id.clone()],
                    severity: AssessmentSeverity::Critical,
                    frameworks: assessed_control.frameworks.clone(),
                    risk_level: RiskLevel::VeryHigh,
                    remediation_effort: RemediationEffort::High,
                    evidence: assessed_control.evidence.clone(),
                    recommended_actions: assessed_control.guidance.clone(),
                });
            }
            
            // Generate high-priority recommendations
            if assessed_control.score < self.config.minimum_control_score {
                high_priority_recommendations.push(ComplianceRecommendation {
                    id: Uuid::new_v4(),
                    title: format!("Improve Control Implementation: {}", assessed_control.name),
                    description: format!("Control {} requires improvement to meet compliance standards", 
                                       assessed_control.name),
                    priority: AssessmentSeverity::High,
                    expected_benefit: "Enhanced security posture and regulatory compliance".to_string(),
                    implementation_effort: RemediationEffort::Medium,
                    cost_estimate: CostEstimate::Medium,
                    timeline_estimate: TimelineEstimate::ShortTerm,
                });
            }
            
            control_assessments.push(assessed_control);
        }
        
        // Calculate framework-specific scores
        let framework_scores = self.calculate_framework_scores(&frameworks, &control_assessments).await?;
        
        // Calculate overall score
        let overall_score = framework_scores.values().sum::<f64>() / framework_scores.len() as f64;
        
        // Generate remediation timeline
        let remediation_timeline = self.generate_remediation_timeline(&critical_findings, &high_priority_recommendations).await?;
        
        let report = ComplianceAssessmentReport {
            id: assessment_id,
            timestamp,
            frameworks,
            overall_score,
            framework_scores,
            control_assessments,
            critical_findings,
            high_priority_recommendations,
            remediation_timeline,
            metadata: AssessmentMetadata {
                version: "1.0.0".to_string(),
                assessor: "Automated Compliance Assessment Engine".to_string(),
                scope: "Full enterprise security platform assessment".to_string(),
                methodology: "NIST SP 800-53 based automated assessment".to_string(),
                tools_used: vec![
                    "Automated Control Assessment".to_string(),
                    "Evidence Collection Engine".to_string(),
                    "Risk Analysis Framework".to_string(),
                ],
                duration_hours: 2.5,
                next_assessment_due: timestamp + Duration::days(self.config.assessment_frequency_days as i64),
            },
        };
        
        // Store assessment report
        self.assessment_history.write().await.push_back(report.clone());
        
        info!("Compliance assessment completed. Overall score: {:.2}", overall_score);
        Ok(report)
    }

    /// Get controls applicable to specified frameworks
    async fn get_applicable_controls(&self, frameworks: &HashSet<ComplianceFramework>) -> Result<Vec<ComplianceControl>> {
        let controls = self.controls.read().await;
        let mut applicable_controls = Vec::new();
        
        for control in controls.values() {
            if control.frameworks.intersection(frameworks).count() > 0 {
                applicable_controls.push(control.clone());
            }
        }
        
        Ok(applicable_controls)
    }

    /// Assess individual control
    async fn assess_control(&self, control: &ComplianceControl, _assessment_type: &AssessmentType) -> Result<ComplianceControl> {
        let mut assessed_control = control.clone();
        
        // Collect evidence if enabled
        if self.config.evidence_collection_enabled {
            assessed_control.evidence = self.collect_control_evidence(control).await?;
        }
        
        // Calculate control score based on implementation status and evidence
        assessed_control.score = self.calculate_control_score(control, &assessed_control.evidence).await?;
        
        // Update assessment timestamp
        assessed_control.last_assessed = Utc::now();
        
        // Determine control status based on score and evidence
        assessed_control.status = self.determine_control_status(&assessed_control).await?;
        
        debug!("Assessed control {}: score={:.2}, status={:?}", 
               assessed_control.id, assessed_control.score, assessed_control.status);
        
        Ok(assessed_control)
    }

    /// Collect evidence for a control
    async fn collect_control_evidence(&self, control: &ComplianceControl) -> Result<Vec<AssessmentEvidence>> {
        let mut evidence = Vec::new();
        
        // Simulate evidence collection based on control category
        match control.category {
            ControlCategory::AccessControl => {
                evidence.push(AssessmentEvidence {
                    evidence_type: EvidenceType::ConfigurationAudit,
                    description: "User access configuration review".to_string(),
                    source: "Identity Management System".to_string(),
                    timestamp: Utc::now(),
                    weight: 0.8,
                    validated: true,
                });
            }
            ControlCategory::AuditLogging => {
                evidence.push(AssessmentEvidence {
                    evidence_type: EvidenceType::LogAnalysis,
                    description: "Audit log integrity verification".to_string(),
                    source: "Audit Logging System".to_string(),
                    timestamp: Utc::now(),
                    weight: 0.9,
                    validated: true,
                });
            }
            ControlCategory::Cryptography => {
                evidence.push(AssessmentEvidence {
                    evidence_type: EvidenceType::AutomatedScan,
                    description: "Cryptographic algorithm assessment".to_string(),
                    source: "Security Scanner".to_string(),
                    timestamp: Utc::now(),
                    weight: 0.85,
                    validated: true,
                });
            }
            _ => {
                evidence.push(AssessmentEvidence {
                    evidence_type: EvidenceType::AutomatedScan,
                    description: "General security control assessment".to_string(),
                    source: "Compliance Scanner".to_string(),
                    timestamp: Utc::now(),
                    weight: 0.7,
                    validated: true,
                });
            }
        }
        
        Ok(evidence)
    }

    /// Calculate control score based on implementation and evidence
    async fn calculate_control_score(&self, control: &ComplianceControl, evidence: &[AssessmentEvidence]) -> Result<f64> {
        let mut score = match control.status {
            ControlStatus::Implemented => 0.9,
            ControlStatus::PartiallyImplemented => 0.6,
            ControlStatus::NotImplemented => 0.2,
            ControlStatus::NotApplicable => 1.0,
            ControlStatus::Pending => 0.3,
            ControlStatus::RequiresRemediation => 0.4,
        };
        
        // Adjust score based on evidence quality and validation
        if !evidence.is_empty() {
            let evidence_score: f64 = evidence.iter()
                .filter(|e| e.validated)
                .map(|e| e.weight)
                .sum::<f64>() / evidence.len() as f64;
            
            score = (score + evidence_score) / 2.0;
        }
        
        // Apply severity penalty for critical controls
        if control.severity == AssessmentSeverity::Critical && score < 0.8 {
            score *= 0.8; // Penalty for critical control gaps
        }
        
        Ok(score.min(1.0).max(0.0))
    }

    /// Determine control status based on assessment
    async fn determine_control_status(&self, control: &ComplianceControl) -> Result<ControlStatus> {
        let status = if control.score >= 0.9 {
            ControlStatus::Implemented
        } else if control.score >= 0.7 {
            ControlStatus::PartiallyImplemented
        } else if control.score >= 0.4 {
            ControlStatus::RequiresRemediation
        } else {
            ControlStatus::NotImplemented
        };
        
        Ok(status)
    }

    /// Calculate framework-specific compliance scores
    async fn calculate_framework_scores(
        &self,
        frameworks: &HashSet<ComplianceFramework>,
        control_assessments: &[ComplianceControl],
    ) -> Result<HashMap<ComplianceFramework, f64>> {
        let mut framework_scores = HashMap::new();
        let mappings = self.framework_mappings.read().await;
        
        for framework in frameworks {
            if let Some(control_ids) = mappings.get(framework) {
                let applicable_assessments: Vec<_> = control_assessments.iter()
                    .filter(|c| control_ids.contains(&c.id))
                    .collect();
                
                if !applicable_assessments.is_empty() {
                    let total_score: f64 = applicable_assessments.iter().map(|c| c.score).sum();
                    let average_score = total_score / applicable_assessments.len() as f64;
                    framework_scores.insert(framework.clone(), average_score);
                } else {
                    framework_scores.insert(framework.clone(), 0.0);
                }
            }
        }
        
        Ok(framework_scores)
    }

    /// Generate remediation timeline
    async fn generate_remediation_timeline(
        &self,
        critical_findings: &[ComplianceFinding],
        recommendations: &[ComplianceRecommendation],
    ) -> Result<Vec<RemediationAction>> {
        let mut actions = Vec::new();
        
        // Create actions for critical findings (immediate priority)
        for finding in critical_findings {
            actions.push(RemediationAction {
                id: Uuid::new_v4(),
                title: format!("Remediate Critical Finding: {}", finding.title),
                description: finding.description.clone(),
                responsible_party: "Security Team".to_string(),
                due_date: Utc::now() + Duration::days(7), // 1 week for critical
                status: ActionStatus::NotStarted,
                dependencies: Vec::new(),
                effort: finding.remediation_effort.clone(),
            });
        }
        
        // Create actions for high-priority recommendations
        for recommendation in recommendations {
            let due_date = match recommendation.timeline_estimate {
                TimelineEstimate::Immediate => Utc::now() + Duration::days(7),
                TimelineEstimate::ShortTerm => Utc::now() + Duration::days(30),
                TimelineEstimate::MediumTerm => Utc::now() + Duration::days(90),
                TimelineEstimate::LongTerm => Utc::now() + Duration::days(365),
                TimelineEstimate::Strategic => Utc::now() + Duration::days(730),
            };
            
            actions.push(RemediationAction {
                id: Uuid::new_v4(),
                title: recommendation.title.clone(),
                description: recommendation.description.clone(),
                responsible_party: "Compliance Team".to_string(),
                due_date,
                status: ActionStatus::NotStarted,
                dependencies: Vec::new(),
                effort: recommendation.implementation_effort.clone(),
            });
        }
        
        Ok(actions)
    }

    /// Start automated assessment scheduler
    pub async fn start_automated_assessment(&self) -> Result<()> {
        if !self.config.automated_assessment_enabled {
            return Ok(());
        }
        
        let config = Arc::clone(&self.config);
        let engine = self.clone_for_scheduler();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // Check hourly
            
            loop {
                interval.tick().await;
                
                let should_assess = {
                    let scheduler = engine.scheduler.read().await;
                    Utc::now() >= scheduler.next_assessment_due
                };
                
                if should_assess {
                    info!("Starting scheduled compliance assessment");
                    
                    match engine.perform_assessment(config.enabled_frameworks.clone(), AssessmentType::Full).await {
                        Ok(report) => {
                            info!("Scheduled assessment completed. Overall score: {:.2}", report.overall_score);
                            
                            // Update next assessment due date
                            let mut scheduler = engine.scheduler.write().await;
                            scheduler.last_assessment = Utc::now();
                            scheduler.next_assessment_due = Utc::now() + 
                                Duration::days(config.assessment_frequency_days as i64);
                        }
                        Err(e) => {
                            error!("Scheduled assessment failed: {}", e);
                        }
                    }
                }
            }
        });
        
        info!("Automated compliance assessment scheduler started");
        Ok(())
    }

    /// Clone engine for scheduler use (simplified for async context)
    fn clone_for_scheduler(&self) -> Self {
        Self {
            controls: Arc::clone(&self.controls),
            assessment_history: Arc::clone(&self.assessment_history),
            config: Arc::clone(&self.config),
            framework_mappings: Arc::clone(&self.framework_mappings),
            evidence_collectors: Arc::clone(&self.evidence_collectors),
            scheduler: Arc::clone(&self.scheduler),
        }
    }

    /// Get latest assessment report
    pub async fn get_latest_assessment(&self) -> Option<ComplianceAssessmentReport> {
        self.assessment_history.read().await.back().cloned()
    }

    /// Get assessment history
    pub async fn get_assessment_history(&self) -> Vec<ComplianceAssessmentReport> {
        self.assessment_history.read().await.iter().cloned().collect()
    }

    /// Add custom control
    pub async fn add_control(&self, control: ComplianceControl) -> Result<()> {
        self.controls.write().await.insert(control.id.clone(), control);
        Ok(())
    }

    /// Update control status
    pub async fn update_control_status(&self, control_id: &str, status: ControlStatus) -> Result<()> {
        if let Some(control) = self.controls.write().await.get_mut(control_id) {
            control.status = status;
            control.last_assessed = Utc::now();
            Ok(())
        } else {
            Err(anyhow!("Control {} not found", control_id))
        }
    }
}

impl Default for ComplianceAssessmentConfig {
    fn default() -> Self {
        Self {
            enabled_frameworks: [
                ComplianceFramework::SOX,
                ComplianceFramework::NISTCSF,
                ComplianceFramework::OWASPASVS,
            ].into(),
            assessment_frequency_days: 30,
            automated_assessment_enabled: true,
            evidence_collection_enabled: true,
            report_retention_days: 2555, // 7 years
            critical_finding_threshold: 5,
            minimum_control_score: 0.8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_compliance_assessment_engine_creation() {
        let config = ComplianceAssessmentConfig::default();
        let engine = ComplianceAssessmentEngine::new(config).await.unwrap();
        
        let controls = engine.controls.read().await;
        assert!(!controls.is_empty());
        assert!(controls.contains_key("AC-001"));
        assert!(controls.contains_key("CR-001"));
    }

    #[tokio::test]
    async fn test_framework_assessment() {
        let config = ComplianceAssessmentConfig::default();
        let engine = ComplianceAssessmentEngine::new(config).await.unwrap();
        
        let frameworks = [ComplianceFramework::NISTCSF].into();
        let report = engine.perform_assessment(frameworks, AssessmentType::Full).await.unwrap();
        
        assert!(!report.control_assessments.is_empty());
        assert!(report.framework_scores.contains_key(&ComplianceFramework::NISTCSF));
        assert!(report.overall_score >= 0.0 && report.overall_score <= 1.0);
    }

    #[tokio::test]
    async fn test_control_score_calculation() {
        let config = ComplianceAssessmentConfig::default();
        let engine = ComplianceAssessmentEngine::new(config).await.unwrap();
        
        let control = ComplianceControl {
            id: "TEST-001".to_string(),
            name: "Test Control".to_string(),
            description: "Test control description".to_string(),
            category: ControlCategory::AccessControl,
            frameworks: [ComplianceFramework::NISTCSF].into(),
            status: ControlStatus::Implemented,
            severity: AssessmentSeverity::High,
            guidance: Vec::new(),
            related_controls: Vec::new(),
            last_assessed: Utc::now(),
            score: 0.0,
            evidence: Vec::new(),
        };
        
        let evidence = vec![AssessmentEvidence {
            evidence_type: EvidenceType::AutomatedScan,
            description: "Test evidence".to_string(),
            source: "Test source".to_string(),
            timestamp: Utc::now(),
            weight: 0.8,
            validated: true,
        }];
        
        let score = engine.calculate_control_score(&control, &evidence).await.unwrap();
        assert!(score >= 0.0 && score <= 1.0);
        assert!(score > 0.8); // Should be high for implemented control with good evidence
    }

    #[tokio::test]
    async fn test_remediation_timeline_generation() {
        let config = ComplianceAssessmentConfig::default();
        let engine = ComplianceAssessmentEngine::new(config).await.unwrap();
        
        let critical_finding = ComplianceFinding {
            id: Uuid::new_v4(),
            title: "Test Critical Finding".to_string(),
            description: "Test description".to_string(),
            affected_controls: vec!["AC-001".to_string()],
            severity: AssessmentSeverity::Critical,
            frameworks: [ComplianceFramework::NISTCSF].into(),
            risk_level: RiskLevel::VeryHigh,
            remediation_effort: RemediationEffort::High,
            evidence: Vec::new(),
            recommended_actions: Vec::new(),
        };
        
        let recommendation = ComplianceRecommendation {
            id: Uuid::new_v4(),
            title: "Test Recommendation".to_string(),
            description: "Test recommendation description".to_string(),
            priority: AssessmentSeverity::High,
            expected_benefit: "Test benefit".to_string(),
            implementation_effort: RemediationEffort::Medium,
            cost_estimate: CostEstimate::Low,
            timeline_estimate: TimelineEstimate::ShortTerm,
        };
        
        let timeline = engine.generate_remediation_timeline(&[critical_finding], &[recommendation]).await.unwrap();
        assert_eq!(timeline.len(), 2);
        assert!(timeline[0].due_date < timeline[1].due_date); // Critical should be due first
    }

    #[test]
    fn test_compliance_framework_enum() {
        let framework = ComplianceFramework::SOX;
        assert_eq!(format!("{:?}", framework), "SOX");
        
        let frameworks: HashSet<ComplianceFramework> = [
            ComplianceFramework::GDPR,
            ComplianceFramework::HIPAA,
        ].into();
        assert_eq!(frameworks.len(), 2);
    }

    #[test]
    fn test_assessment_severity_ordering() {
        assert!(AssessmentSeverity::Critical > AssessmentSeverity::High);
        assert!(AssessmentSeverity::High > AssessmentSeverity::Medium);
        assert!(AssessmentSeverity::Medium > AssessmentSeverity::Low);
        assert!(AssessmentSeverity::Low > AssessmentSeverity::Info);
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::VeryHigh > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
        assert!(RiskLevel::Low > RiskLevel::VeryLow);
    }
}