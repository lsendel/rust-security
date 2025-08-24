//! SOAR case template system
//!
//! This module provides case template management including automation rules,
//! assignment policies, and escalation procedures.

pub mod automation;
pub mod assignment;
pub mod escalation;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::security_monitoring::AlertSeverity;
use crate::soar::case_types::{CasePhase, CasePriority};

pub use automation::*;
pub use assignment::*;
pub use escalation::*;

/// Base case template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseTemplate {
    /// Template ID
    pub id: String,

    /// Template name
    pub name: String,

    /// Template description
    pub description: String,

    /// Template version
    pub version: String,

    /// Template category
    pub category: String,

    /// Default case title pattern
    pub title_pattern: String,

    /// Default case description template
    pub description_template: String,

    /// Default severity
    pub default_severity: AlertSeverity,

    /// Default priority
    pub default_priority: CasePriority,

    /// Default tags
    pub default_tags: Vec<String>,

    /// Required custom fields
    pub required_fields: Vec<TemplateField>,

    /// Optional custom fields
    pub optional_fields: Vec<TemplateField>,

    /// Template metadata
    pub metadata: HashMap<String, serde_json::Value>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,

    /// Template creator
    pub created_by: String,

    /// Template status
    pub status: TemplateStatus,
}

/// Enhanced case template with automation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedCaseTemplate {
    /// Base template
    pub base_template: CaseTemplate,

    /// Automation rules
    pub automation_rules: Vec<CaseAutomationRule>,

    /// Assignment rules
    pub assignment_rules: Vec<AssignmentRule>,

    /// Escalation policies
    pub escalation_policies: Vec<CaseEscalationPolicy>,

    /// Communication templates
    pub communication_templates: Vec<CommunicationTemplate>,

    /// Quality assurance checklist
    pub qa_checklist: Vec<QualityCheckItem>,
}

/// Template field definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateField {
    /// Field name
    pub name: String,

    /// Field display name
    pub display_name: String,

    /// Field description
    pub description: String,

    /// Field type
    pub field_type: FieldType,

    /// Default value
    pub default_value: Option<serde_json::Value>,

    /// Validation rules
    pub validation: Vec<ValidationRule>,

    /// Field options (for select/multi-select)
    pub options: Vec<FieldOption>,
}

/// Field types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldType {
    /// Text input
    Text,
    /// Number input
    Number,
    /// Boolean checkbox
    Boolean,
    /// Date picker
    Date,
    /// DateTime picker
    DateTime,
    /// Single select dropdown
    Select,
    /// Multi-select dropdown
    MultiSelect,
    /// Long text area
    TextArea,
    /// File upload
    File,
    /// JSON object
    Json,
}

/// Field validation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    /// Rule type
    pub rule_type: ValidationType,

    /// Rule value
    pub value: serde_json::Value,

    /// Error message
    pub error_message: String,
}

/// Validation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationType {
    /// Required field
    Required,
    /// Minimum length
    MinLength,
    /// Maximum length
    MaxLength,
    /// Regular expression pattern
    Pattern,
    /// Minimum value
    MinValue,
    /// Maximum value
    MaxValue,
    /// Custom validation
    Custom(String),
}

/// Field option for select fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldOption {
    /// Option value
    pub value: String,

    /// Option display label
    pub label: String,

    /// Option description
    pub description: Option<String>,
}

/// Template status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemplateStatus {
    /// Draft template
    Draft,
    /// Active template
    Active,
    /// Deprecated template
    Deprecated,
    /// Archived template
    Archived,
}

/// Communication template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationTemplate {
    /// Template ID
    pub id: String,

    /// Template name
    pub name: String,

    /// Template type
    pub template_type: CommunicationTemplateType,

    /// Subject template
    pub subject: String,

    /// Body template
    pub body: String,

    /// Template variables
    pub variables: Vec<String>,

    /// Recipient rules
    pub recipient_rules: Vec<RecipientRule>,

    /// Delivery channels
    pub channels: Vec<NotificationChannel>,
}

/// Communication template types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommunicationTemplateType {
    /// Case assignment notification
    CaseAssignment,
    /// Status update notification
    StatusUpdate,
    /// Escalation notification
    Escalation,
    /// Evidence collection request
    EvidenceRequest,
    /// Case closure notification
    CaseClosure,
    /// Custom template
    Custom(String),
}

/// Recipient rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientRule {
    /// Rule ID
    pub id: String,

    /// Recipient type
    pub recipient_type: RecipientType,

    /// Recipient identifier
    pub recipient_id: String,

    /// Conditions for sending
    pub conditions: Vec<String>,
}

/// Recipient types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecipientType {
    /// Individual user
    User,
    /// Team
    Team,
    /// Role
    Role,
    /// Case assignee
    CaseAssignee,
    /// Case reporter
    CaseReporter,
    /// Stakeholder group
    StakeholderGroup,
    /// Custom recipient
    Custom(String),
}

/// Notification channels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationChannel {
    /// Email notification
    Email,
    /// Slack notification
    Slack,
    /// Microsoft Teams
    Teams,
    /// SMS notification
    Sms,
    /// In-app notification
    InApp,
    /// Webhook
    Webhook,
    /// Custom channel
    Custom(String),
}

/// Quality check item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityCheckItem {
    /// Check ID
    pub id: String,

    /// Check name
    pub name: String,

    /// Check description
    pub description: String,

    /// Check type
    pub check_type: QualityCheckType,

    /// When to perform this check
    pub trigger_phase: CasePhase,

    /// Whether check is mandatory
    pub mandatory: bool,

    /// Check criteria
    pub criteria: Vec<QualityCriterion>,

    /// Check weight (for scoring)
    pub weight: f64,
}

/// Quality check types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QualityCheckType {
    /// Automated check
    Automated,
    /// Manual check
    Manual,
    /// Hybrid check
    Hybrid,
}

/// Quality criterion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityCriterion {
    /// Criterion ID
    pub id: String,

    /// Criterion description
    pub description: String,

    /// Expected value or condition
    pub expected: serde_json::Value,

    /// Actual value (filled during check)
    pub actual: Option<serde_json::Value>,

    /// Check result
    pub passed: Option<bool>,

    /// Check notes
    pub notes: Option<String>,
}

/// Template manager
pub struct TemplateManager {
    /// Active templates
    templates: HashMap<String, EnhancedCaseTemplate>,

    /// Template cache
    cache: HashMap<String, CaseTemplate>,
}

impl TemplateManager {
    /// Create new template manager
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
            cache: HashMap::new(),
        }
    }

    /// Load template by ID
    pub fn get_template(&self, template_id: &str) -> Option<&EnhancedCaseTemplate> {
        self.templates.get(template_id)
    }

    /// Add template
    pub fn add_template(&mut self, template: EnhancedCaseTemplate) {
        let id = template.base_template.id.clone();
        self.templates.insert(id.clone(), template);
        // Update cache
        if let Some(template) = self.templates.get(&id) {
            self.cache.insert(id, template.base_template.clone());
        }
    }

    /// Remove template
    pub fn remove_template(&mut self, template_id: &str) -> Option<EnhancedCaseTemplate> {
        self.cache.remove(template_id);
        self.templates.remove(template_id)
    }

    /// List all templates
    pub fn list_templates(&self) -> Vec<&CaseTemplate> {
        self.cache.values().collect()
    }

    /// Find templates by category
    pub fn find_by_category(&self, category: &str) -> Vec<&EnhancedCaseTemplate> {
        self.templates
            .values()
            .filter(|t| t.base_template.category == category)
            .collect()
    }
}

impl Default for TemplateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_template_manager() {
        let mut manager = TemplateManager::new();

        let template = EnhancedCaseTemplate {
            base_template: CaseTemplate {
                id: Uuid::new_v4().to_string(),
                name: "Test Template".to_string(),
                description: "Test".to_string(),
                version: "1.0".to_string(),
                category: "security".to_string(),
                title_pattern: "Security Incident: {title}".to_string(),
                description_template: "Incident: {description}".to_string(),
                default_severity: AlertSeverity::Medium,
                default_priority: CasePriority::Medium,
                default_tags: vec!["security".to_string()],
                required_fields: vec![],
                optional_fields: vec![],
                metadata: HashMap::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                created_by: "system".to_string(),
                status: TemplateStatus::Active,
            },
            automation_rules: vec![],
            assignment_rules: vec![],
            escalation_policies: vec![],
            communication_templates: vec![],
            qa_checklist: vec![],
        };

        let template_id = template.base_template.id.clone();
        manager.add_template(template);

        assert!(manager.get_template(&template_id).is_some());
        assert_eq!(manager.list_templates().len(), 1);
    }
}
