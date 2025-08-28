//! Case assignment rules and policies
//!
//! This module handles automated case assignment based on various criteria
//! including skills, workload, availability, and escalation paths.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::security_monitoring::AlertSeverity;
use crate::soar::case_types::{CasePriority, SecurityCase};

/// Assignment rule for automatic case assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignmentRule {
    /// Rule ID
    pub id: String,

    /// Rule name
    pub name: String,

    /// Rule description
    pub description: String,

    /// Rule priority (higher = evaluated first)
    pub priority: u32,

    /// Rule status
    pub enabled: bool,

    /// Assignment conditions
    pub conditions: Vec<AssignmentCondition>,

    /// Assignment target
    pub target: AssignmentTarget,

    /// Assignment strategy
    pub strategy: AssignmentStrategy,

    /// Rule metadata
    pub metadata: HashMap<String, serde_json::Value>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// Assignment condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignmentCondition {
    /// Condition ID
    pub id: String,

    /// Field to evaluate
    pub field: String,

    /// Condition operator
    pub operator: String,

    /// Expected value
    pub value: serde_json::Value,

    /// Condition weight
    pub weight: f64,
}

/// Assignment target types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssignmentTarget {
    /// Assign to specific user
    User {
        /// User ID
        user_id: String,
    },
    /// Assign to team
    Team {
        /// Team ID
        team_id: String,
        /// Team assignment strategy
        strategy: TeamAssignmentStrategy,
    },
    /// Assign based on skills
    SkillBased {
        /// Required skills
        required_skills: Vec<String>,
        /// Minimum skill level
        min_skill_level: u32,
        /// Skill matching strategy
        matching_strategy: SkillMatchingStrategy,
    },
    /// Assign based on workload
    WorkloadBased {
        /// Maximum case load
        max_case_load: u32,
        /// Workload calculation method
        calculation_method: WorkloadCalculationMethod,
    },
    /// Round-robin assignment
    RoundRobin {
        /// Candidate users/teams
        candidates: Vec<String>,
    },
    /// Custom assignment logic
    Custom(String),
}

/// Team assignment strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TeamAssignmentStrategy {
    /// Assign to team lead
    TeamLead,
    /// Assign to least busy member
    LeastBusy,
    /// Assign to most skilled member
    MostSkilled,
    /// Round-robin within team
    RoundRobin,
    /// Random assignment
    Random,
}

/// Skill matching strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SkillMatchingStrategy {
    /// All skills must match
    AllSkills,
    /// Any skill must match
    AnySkill,
    /// Best skill match
    BestMatch,
    /// Weighted skill matching
    Weighted,
}

/// Workload calculation methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkloadCalculationMethod {
    /// Simple case count
    CaseCount,
    /// Weighted by severity
    SeverityWeighted,
    /// Weighted by priority
    PriorityWeighted,
    /// Time-based calculation
    TimeBased,
    /// Custom calculation
    Custom(String),
}

/// Assignment strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssignmentStrategy {
    /// Immediate assignment
    Immediate,
    /// Delayed assignment
    Delayed {
        /// Delay in seconds
        delay_seconds: u64,
    },
    /// Conditional assignment
    Conditional {
        /// Additional conditions
        conditions: Vec<AssignmentCondition>,
    },
    /// Escalation-based assignment
    Escalation {
        /// Escalation levels
        levels: Vec<EscalationLevel>,
    },
}

/// Escalation level for assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationLevel {
    /// Level number
    pub level: u32,

    /// Time threshold (seconds)
    pub time_threshold_seconds: u64,

    /// Assignment target for this level
    pub target: AssignmentTarget,

    /// Notification settings
    pub notifications: Vec<String>,
}

/// User profile for assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    /// User ID
    pub user_id: String,

    /// User name
    pub name: String,

    /// User email
    pub email: String,

    /// User skills
    pub skills: Vec<UserSkill>,

    /// Current workload
    pub current_workload: WorkloadInfo,

    /// Availability status
    pub availability: AvailabilityStatus,

    /// Assignment preferences
    pub preferences: AssignmentPreferences,

    /// Performance metrics
    pub performance: PerformanceMetrics,
}

/// User skill
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSkill {
    /// Skill name
    pub skill: String,

    /// Skill level (1-10)
    pub level: u32,

    /// Skill certification
    pub certified: bool,

    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
}

/// Workload information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadInfo {
    /// Current active cases
    pub active_cases: u32,

    /// Total case load score
    pub load_score: f64,

    /// Average case resolution time
    pub avg_resolution_time_hours: f64,

    /// Cases resolved this week
    pub cases_resolved_week: u32,

    /// Workload trend
    pub trend: WorkloadTrend,
}

/// Workload trend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkloadTrend {
    /// Increasing workload
    Increasing,
    /// Stable workload
    Stable,
    /// Decreasing workload
    Decreasing,
}

/// Availability status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AvailabilityStatus {
    /// Available for assignment
    Available,
    /// Busy but can take urgent cases
    Busy,
    /// Out of office
    OutOfOffice,
    /// On vacation
    OnVacation,
    /// In training
    InTraining,
    /// Custom status
    Custom(String),
}

/// Assignment preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignmentPreferences {
    /// Preferred case types
    pub preferred_case_types: Vec<String>,

    /// Maximum concurrent cases
    pub max_concurrent_cases: u32,

    /// Preferred severity levels
    pub preferred_severities: Vec<AlertSeverity>,

    /// Working hours
    pub working_hours: WorkingHours,

    /// Notification preferences
    pub notification_preferences: NotificationPreferences,
}

/// Working hours configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingHours {
    /// Timezone
    pub timezone: String,

    /// Working days (0 = Sunday, 6 = Saturday)
    pub working_days: Vec<u8>,

    /// Start time (24-hour format)
    pub start_time: String,

    /// End time (24-hour format)
    pub end_time: String,
}

/// Notification preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationPreferences {
    /// Email notifications enabled
    pub email_enabled: bool,

    /// Slack notifications enabled
    pub slack_enabled: bool,

    /// SMS notifications enabled
    pub sms_enabled: bool,

    /// Notification frequency
    pub frequency: NotificationFrequency,
}

/// Notification frequency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationFrequency {
    /// Immediate notifications
    Immediate,
    /// Batched notifications
    Batched {
        /// Batch interval in minutes
        interval_minutes: u32,
    },
    /// Digest notifications
    Digest {
        /// Digest frequency
        frequency: DigestFrequency,
    },
}

/// Digest frequency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DigestFrequency {
    /// Hourly digest
    Hourly,
    /// Daily digest
    Daily,
    /// Weekly digest
    Weekly,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Average case resolution time (hours)
    pub avg_resolution_time: f64,

    /// Case resolution rate
    pub resolution_rate: f64,

    /// Customer satisfaction score
    pub satisfaction_score: f64,

    /// SLA compliance rate
    pub sla_compliance_rate: f64,

    /// Quality score
    pub quality_score: f64,

    /// Last updated
    pub last_updated: DateTime<Utc>,
}

/// Assignment engine
pub struct AssignmentEngine {
    /// Assignment rules
    rules: Vec<AssignmentRule>,

    /// User profiles
    user_profiles: HashMap<String, UserProfile>,

    /// Team configurations
    team_configs: HashMap<String, TeamConfig>,

    /// Assignment history
    assignment_history: Vec<AssignmentRecord>,
}

/// Team configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamConfig {
    /// Team ID
    pub team_id: String,

    /// Team name
    pub name: String,

    /// Team members
    pub members: Vec<String>,

    /// Team lead
    pub team_lead: String,

    /// Team skills
    pub team_skills: Vec<String>,

    /// Team capacity
    pub capacity: TeamCapacity,

    /// Team schedule
    pub schedule: TeamSchedule,
}

/// Team capacity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamCapacity {
    /// Maximum concurrent cases
    pub max_concurrent_cases: u32,

    /// Current active cases
    pub current_active_cases: u32,

    /// Capacity utilization percentage
    pub utilization_percentage: f64,

    /// Available capacity
    pub available_capacity: u32,
}

/// Team schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamSchedule {
    /// Timezone
    pub timezone: String,

    /// Coverage hours
    pub coverage_hours: CoverageHours,

    /// On-call rotation
    pub on_call_rotation: Vec<OnCallEntry>,
}

/// Coverage hours
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageHours {
    /// 24/7 coverage
    pub full_coverage: bool,

    /// Business hours only
    pub business_hours_only: bool,

    /// Custom schedule
    pub custom_schedule: Option<Vec<ScheduleEntry>>,
}

/// Schedule entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleEntry {
    /// Day of week (0 = Sunday)
    pub day_of_week: u8,

    /// Start time
    pub start_time: String,

    /// End time
    pub end_time: String,

    /// Assigned members
    pub assigned_members: Vec<String>,
}

/// On-call entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnCallEntry {
    /// User ID
    pub user_id: String,

    /// Start time
    pub start_time: DateTime<Utc>,

    /// End time
    pub end_time: DateTime<Utc>,

    /// Primary or backup
    pub role: OnCallRole,
}

/// On-call role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OnCallRole {
    /// Primary on-call
    Primary,
    /// Backup on-call
    Backup,
    /// Escalation contact
    Escalation,
}

/// Assignment record
#[derive(Debug, Clone)]
pub struct AssignmentRecord {
    /// Assignment ID
    pub id: String,

    /// Case ID
    pub case_id: String,

    /// Assigned user/team
    pub assignee: String,

    /// Assignment rule used
    pub rule_id: Option<String>,

    /// Assignment timestamp
    pub assigned_at: DateTime<Utc>,

    /// Assignment reason
    pub reason: String,

    /// Assignment score
    pub score: f64,
}

/// Assignment result
#[derive(Debug, Clone)]
pub struct AssignmentResult {
    /// Assigned user/team ID
    pub assignee: String,

    /// Assignment confidence score
    pub confidence_score: f64,

    /// Assignment reason
    pub reason: String,

    /// Rule that triggered assignment
    pub rule_id: Option<String>,

    /// Alternative assignments
    pub alternatives: Vec<AlternativeAssignment>,
}

/// Alternative assignment option
#[derive(Debug, Clone)]
pub struct AlternativeAssignment {
    /// Alternative assignee
    pub assignee: String,

    /// Assignment score
    pub score: f64,

    /// Reason for alternative
    pub reason: String,
}

impl AssignmentEngine {
    /// Create new assignment engine
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            user_profiles: HashMap::new(),
            team_configs: HashMap::new(),
            assignment_history: Vec::new(),
        }
    }

    /// Add assignment rule
    pub fn add_rule(&mut self, rule: AssignmentRule) {
        // Insert in priority order
        let insert_pos = self
            .rules
            .iter()
            .position(|r| r.priority < rule.priority)
            .unwrap_or(self.rules.len());
        
        self.rules.insert(insert_pos, rule);
    }

    /// Add user profile
    pub fn add_user_profile(&mut self, profile: UserProfile) {
        self.user_profiles.insert(profile.user_id.clone(), profile);
    }

    /// Add team configuration
    pub fn add_team_config(&mut self, config: TeamConfig) {
        self.team_configs.insert(config.team_id.clone(), config);
    }

    /// Find best assignment for a case
    pub fn find_assignment(&self, case: &SecurityCase) -> Option<AssignmentResult> {
        // Evaluate assignment rules
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if self.evaluate_assignment_conditions(&rule.conditions, case) {
                if let Some(result) = self.execute_assignment_target(&rule.target, case) {
                    return Some(AssignmentResult {
                        assignee: operation_result.assignee,
                        confidence_score: operation_result.confidence_score,
                        reason: format!("Assigned by rule: {}", rule.name),
                        rule_id: Some(rule.id.clone()),
                        alternatives: operation_result.alternatives,
                    });
                }
            }
        }

        // Fallback to default assignment logic
        self.default_assignment(case)
    }

    /// Evaluate assignment conditions
    fn evaluate_assignment_conditions(&self, conditions: &[AssignmentCondition], case: &SecurityCase) -> bool {
        for condition in conditions {
            if !self.evaluate_assignment_condition(condition, case) {
                return false;
            }
        }
        true
    }

    /// Evaluate single assignment condition
    fn evaluate_assignment_condition(&self, condition: &AssignmentCondition, case: &SecurityCase) -> bool {
        // Extract field value from case
        let actual_value = match condition.field.as_str() {
            "severity" => serde_json::to_value(&case.severity).unwrap_or(serde_json::Value::Null),
            "status" => serde_json::to_value(&case.status).unwrap_or(serde_json::Value::Null),
            "age_hours" => serde_json::Value::Number(
                serde_json::Number::from_f64(case.age_hours()).unwrap_or(serde_json::Number::from(0))
            ),
            "tags" => serde_json::to_value(&case.tags).unwrap_or(serde_json::Value::Null),
            _ => {
                // Check custom fields
                case.custom_fields.get(&condition.field).cloned().unwrap_or(serde_json::Value::Null)
            }
        };

        // Simple equality check for now
        actual_value == condition.value
    }

    /// Execute assignment target
    fn execute_assignment_target(&self, target: &AssignmentTarget, case: &SecurityCase) -> Option<AssignmentResult> {
        match target {
            AssignmentTarget::User { user_id } => {
                if let Some(profile) = self.user_profiles.get(user_id) {
                    if self.is_user_available(profile) {
                        Some(AssignmentResult {
                            assignee: user_id.clone(),
                            confidence_score: 0.9,
                            reason: "Direct user assignment".to_string(),
                            rule_id: None,
                            alternatives: vec![],
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            AssignmentTarget::Team { team_id, strategy } => {
                self.assign_to_team(team_id, strategy, case)
            }
            AssignmentTarget::SkillBased { required_skills, min_skill_level, matching_strategy } => {
                self.assign_by_skills(required_skills, *min_skill_level, matching_strategy, case)
            }
            AssignmentTarget::WorkloadBased { max_case_load, calculation_method } => {
                self.assign_by_workload(*max_case_load, calculation_method, case)
            }
            AssignmentTarget::RoundRobin { candidates } => {
                self.assign_round_robin(candidates, case)
            }
            AssignmentTarget::Custom(_) => {
                // TODO: Implement custom assignment logic
                None
            }
        }
    }

    /// Check if user is available for assignment
    fn is_user_available(&self, profile: &UserProfile) -> bool {
        matches!(profile.availability, AvailabilityStatus::Available | AvailabilityStatus::Busy)
            && profile.current_workload.active_cases < profile.preferences.max_concurrent_cases
    }

    /// Assign to team
    fn assign_to_team(&self, team_id: &str, strategy: &TeamAssignmentStrategy, _case: &SecurityCase) -> Option<AssignmentResult> {
        if let Some(team) = self.team_configs.get(team_id) {
            match strategy {
                TeamAssignmentStrategy::TeamLead => {
                    Some(AssignmentResult {
                        assignee: team.team_lead.clone(),
                        confidence_score: 0.8,
                        reason: "Assigned to team lead".to_string(),
                        rule_id: None,
                        alternatives: vec![],
                    })
                }
                TeamAssignmentStrategy::LeastBusy => {
                    self.find_least_busy_team_member(&team.members)
                }
                _ => {
                    // TODO: Implement other team assignment strategies
                    None
                }
            }
        } else {
            None
        }
    }

    /// Find least busy team member
    fn find_least_busy_team_member(&self, members: &[String]) -> Option<AssignmentResult> {
        let mut best_member = None;
        let mut lowest_workload = f64::MAX;

        for member_id in members {
            if let Some(profile) = self.user_profiles.get(member_id) {
                if self.is_user_available(profile) {
                    let workload = profile.current_workload.load_score;
                    if workload < lowest_workload {
                        lowest_workload = workload;
                        best_member = Some(member_id.clone());
                    }
                }
            }
        }

        best_member.map(|assignee| AssignmentResult {
            assignee,
            confidence_score: 0.85,
            reason: "Assigned to least busy team member".to_string(),
            rule_id: None,
            alternatives: vec![],
        })
    }

    /// Assign by skills
    fn assign_by_skills(&self, _required_skills: &[String], _min_skill_level: u32, _matching_strategy: &SkillMatchingStrategy, _case: &SecurityCase) -> Option<AssignmentResult> {
        // TODO: Implement skill-based assignment
        None
    }

    /// Assign by workload
    fn assign_by_workload(&self, _max_case_load: u32, _calculation_method: &WorkloadCalculationMethod, _case: &SecurityCase) -> Option<AssignmentResult> {
        // TODO: Implement workload-based assignment
        None
    }

    /// Round-robin assignment
    fn assign_round_robin(&self, _candidates: &[String], _case: &SecurityCase) -> Option<AssignmentResult> {
        // TODO: Implement round-robin assignment
        None
    }

    /// Default assignment logic
    fn default_assignment(&self, _case: &SecurityCase) -> Option<AssignmentResult> {
        // Find any available user
        for (user_id, profile) in &self.user_profiles {
            if self.is_user_available(profile) {
                return Some(AssignmentResult {
                    assignee: user_id.clone(),
                    confidence_score: 0.5,
                    reason: "Default assignment to available user".to_string(),
                    rule_id: None,
                    alternatives: vec![],
                });
            }
        }
        None
    }
}

impl Default for AssignmentEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soar::case_types::*;
    use uuid::Uuid;

    #[test]
    fn test_assignment_engine() {
        let mut engine = AssignmentEngine::new();

        // Add a user profile
        let profile = UserProfile {
            user_id: "analyst1".to_string(),
            name: "Analyst One".to_string(),
            email: "analyst1@example.com".to_string(),
            skills: vec![],
            current_workload: WorkloadInfo {
                active_cases: 2,
                load_score: 0.4,
                avg_resolution_time_hours: 4.5,
                cases_resolved_week: 8,
                trend: WorkloadTrend::Stable,
            },
            availability: AvailabilityStatus::Available,
            preferences: AssignmentPreferences {
                preferred_case_types: vec![],
                max_concurrent_cases: 5,
                preferred_severities: vec![],
                working_hours: WorkingHours {
                    timezone: "UTC".to_string(),
                    working_days: vec![1, 2, 3, 4, 5],
                    start_time: "09:00".to_string(),
                    end_time: "17:00".to_string(),
                },
                notification_preferences: NotificationPreferences {
                    email_enabled: true,
                    slack_enabled: true,
                    sms_enabled: false,
                    frequency: NotificationFrequency::Immediate,
                },
            },
            performance: PerformanceMetrics {
                avg_resolution_time: 4.2,
                resolution_rate: 0.95,
                satisfaction_score: 4.3,
                sla_compliance_rate: 0.98,
                quality_score: 4.1,
                last_updated: Utc::now(),
            },
        };

        engine.add_user_profile(profile);

        // Create a test case
        let case = SecurityCase::new(
            "Test Case".to_string(),
            "Test Description".to_string(),
            AlertSeverity::Medium,
            vec![],
        );

        // Test assignment
        let result = engine.find_assignment(&case);
        assert!(operation_result.is_some());
        
        let assignment = operation_result.unwrap();
        assert_eq!(assignment.assignee, "analyst1");
    }
}
