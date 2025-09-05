//! Social Engineering Attack Simulation Framework
//!
//! Comprehensive social engineering attack simulation framework for defensive testing.
//! This module provides sophisticated attack scenarios designed to test organizational
//! security awareness and technical controls in an ethical, controlled manner.

pub mod email;
pub mod voice;
pub mod physical;
pub mod pretexting;
pub mod intelligence;
pub mod templates;
pub mod targets;
pub mod payloads;

use crate::attack_framework::{AttackSession, RedTeamFramework};
use crate::reporting::RedTeamReporter;
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

pub use email::*;
pub use voice::*;
pub use physical::*;
pub use pretexting::*;
pub use intelligence::*;

/// Configuration for social engineering attack scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialEngineeringConfig {
    /// Target company name
    pub company_name: String,
    
    /// Target domain
    pub domain: String,
    
    /// Target email addresses
    pub target_emails: Vec<String>,
    
    /// LinkedIn company ID for reconnaissance
    pub linkedin_company_id: Option<String>,
    
    /// Target phone numbers
    pub phone_numbers: Vec<String>,
    
    /// Physical locations
    pub physical_locations: Vec<String>,
    
    /// Known technologies used by target
    pub known_technologies: Vec<String>,
    
    /// Available breach databases for intelligence
    pub breach_databases: Vec<String>,
    
    /// Attack intensity level
    pub intensity: AttackIntensity,
    
    /// Campaign duration
    pub campaign_duration: Duration,
    
    /// Maximum concurrent attacks
    pub max_concurrent_attacks: usize,
}

/// Attack intensity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackIntensity {
    /// Low intensity - basic attacks, minimal detection risk
    Low,
    /// Medium intensity - moderate sophistication
    Medium,
    /// High intensity - advanced persistent threat simulation
    High,
    /// Custom intensity with specific parameters
    Custom {
        attack_frequency: Duration,
        sophistication_level: u8,
        evasion_techniques: bool,
    },
}

/// Social engineering campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialEngineeringCampaign {
    /// Campaign ID
    pub id: String,
    
    /// Campaign name
    pub name: String,
    
    /// Campaign description
    pub description: String,
    
    /// Attack vectors to use
    pub attack_vectors: Vec<AttackVectorType>,
    
    /// Target profiles
    pub targets: Vec<Target>,
    
    /// Campaign timeline
    pub timeline: CampaignTimeline,
    
    /// Success metrics
    pub success_metrics: SuccessMetrics,
    
    /// Campaign status
    pub status: CampaignStatus,
    
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// Attack vector types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackVectorType {
    /// Email-based attacks
    Email(EmailAttackType),
    /// Voice-based attacks
    Voice(VoiceAttackType),
    /// Physical attacks
    Physical(PhysicalAttackType),
    /// Digital pretexting
    Pretexting(PretextingAttackType),
    /// Intelligence gathering
    Intelligence(IntelligenceType),
}

/// Email attack types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmailAttackType {
    /// Generic phishing
    Phishing,
    /// Spear phishing
    SpearPhishing,
    /// Business Email Compromise
    BusinessEmailCompromise,
    /// Whaling (executive targeting)
    Whaling,
    /// Clone phishing
    ClonePhishing,
}

/// Voice attack types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VoiceAttackType {
    /// Voice phishing (vishing)
    Vishing,
    /// Caller ID spoofing
    CallerIdSpoofing,
    /// IVR system attacks
    IvrAttacks,
    /// Support channel manipulation
    SupportChannelManipulation,
}

/// Physical attack types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PhysicalAttackType {
    /// Badge cloning/authentication
    BadgeAuthentication,
    /// Tailgating
    Tailgating,
    /// Physical device access
    PhysicalDeviceAccess,
    /// RFID vulnerabilities
    RfidVulnerabilities,
    /// Visitor management bypass
    VisitorManagementBypass,
}

/// Pretexting attack types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PretextingAttackType {
    /// API pretexting
    ApiPretexting,
    /// Support pretexting
    SupportPretexting,
    /// Credential recovery
    CredentialRecovery,
    /// Administrative pretexting
    AdministrativePretexting,
}

/// Intelligence gathering types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntelligenceType {
    /// Open Source Intelligence
    Osint,
    /// Breach database analysis
    BreachDataAnalysis,
    /// Social media reconnaissance
    SocialMediaRecon,
    /// Technical reconnaissance
    TechnicalRecon,
}

/// Target profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// Target ID
    pub id: String,
    
    /// Target name
    pub name: String,
    
    /// Email address
    pub email: Option<String>,
    
    /// Phone number
    pub phone: Option<String>,
    
    /// Job title/role
    pub role: Option<String>,
    
    /// Department
    pub department: Option<String>,
    
    /// Social media profiles
    pub social_profiles: HashMap<String, String>,
    
    /// Known interests/hobbies
    pub interests: Vec<String>,
    
    /// Technical knowledge level
    pub technical_level: TechnicalLevel,
    
    /// Previous attack history
    pub attack_history: Vec<AttackResult>,
}

/// Technical knowledge level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TechnicalLevel {
    /// Non-technical user
    Beginner,
    /// Some technical knowledge
    Intermediate,
    /// Advanced technical knowledge
    Advanced,
    /// Security-aware expert
    Expert,
}

/// Campaign timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignTimeline {
    /// Campaign start time
    pub start_time: DateTime<Utc>,
    
    /// Campaign end time
    pub end_time: DateTime<Utc>,
    
    /// Attack phases
    pub phases: Vec<AttackPhase>,
    
    /// Milestone events
    pub milestones: Vec<CampaignMilestone>,
}

/// Attack phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPhase {
    /// Phase name
    pub name: String,
    
    /// Phase description
    pub description: String,
    
    /// Phase start time
    pub start_time: DateTime<Utc>,
    
    /// Phase duration
    pub duration: Duration,
    
    /// Attack vectors in this phase
    pub attack_vectors: Vec<AttackVectorType>,
    
    /// Success criteria
    pub success_criteria: Vec<String>,
}

/// Campaign milestone
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignMilestone {
    /// Milestone name
    pub name: String,
    
    /// Milestone description
    pub description: String,
    
    /// Target date
    pub target_date: DateTime<Utc>,
    
    /// Completion status
    pub completed: bool,
    
    /// Completion date
    pub completed_date: Option<DateTime<Utc>>,
}

/// Success metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessMetrics {
    /// Target success rate
    pub target_success_rate: f64,
    
    /// Actual success rate
    pub actual_success_rate: f64,
    
    /// Detection rate
    pub detection_rate: f64,
    
    /// Response time metrics
    pub response_times: HashMap<String, Duration>,
    
    /// User awareness scores
    pub awareness_scores: HashMap<String, f64>,
    
    /// Technical control effectiveness
    pub control_effectiveness: HashMap<String, f64>,
}

/// Campaign status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CampaignStatus {
    /// Campaign is being planned
    Planning,
    /// Campaign is ready to start
    Ready,
    /// Campaign is running
    Running,
    /// Campaign is paused
    Paused,
    /// Campaign completed successfully
    Completed,
    /// Campaign was cancelled
    Cancelled,
    /// Campaign failed
    Failed,
}

/// Attack result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    /// Attack ID
    pub attack_id: String,
    
    /// Attack type
    pub attack_type: AttackVectorType,
    
    /// Target ID
    pub target_id: String,
    
    /// Attack timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Attack success
    pub success: bool,
    
    /// Detection status
    pub detected: bool,
    
    /// Response time
    pub response_time: Option<Duration>,
    
    /// Attack details
    pub details: AttackDetails,
    
    /// Lessons learned
    pub lessons_learned: Vec<String>,
}

/// Attack details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackDetails {
    /// Attack method used
    pub method: String,
    
    /// Payload information
    pub payload: Option<String>,
    
    /// Delivery mechanism
    pub delivery_mechanism: String,
    
    /// Evasion techniques used
    pub evasion_techniques: Vec<String>,
    
    /// Detection signatures triggered
    pub detection_signatures: Vec<String>,
    
    /// User response
    pub user_response: Option<String>,
    
    /// Technical response
    pub technical_response: Option<String>,
}

/// Attack vector trait
#[async_trait]
pub trait AttackVector {
    /// Prepare the attack vector
    async fn prepare(&mut self, targets: &[Target]) -> Result<()>;
    
    /// Execute the attack against a target
    async fn execute(&self, target: &Target) -> Result<AttackResult>;
    
    /// Clean up after attack execution
    async fn cleanup(&self) -> Result<()>;
    
    /// Get detection signatures for this attack
    fn get_detection_signatures(&self) -> Vec<DetectionSignature>;
    
    /// Get attack metadata
    fn get_metadata(&self) -> AttackMetadata;
}

/// Detection signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignature {
    /// Signature name
    pub name: String,
    
    /// Signature type
    pub signature_type: SignatureType,
    
    /// Pattern to detect
    pub pattern: String,
    
    /// Confidence level
    pub confidence: f64,
    
    /// False positive rate
    pub false_positive_rate: f64,
}

/// Signature types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureType {
    /// Email header signature
    EmailHeader,
    /// Email content signature
    EmailContent,
    /// URL pattern
    UrlPattern,
    /// Phone number pattern
    PhonePattern,
    /// Behavioral signature
    Behavioral,
    /// Network signature
    Network,
}

/// Attack metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMetadata {
    /// Attack name
    pub name: String,
    
    /// Attack description
    pub description: String,
    
    /// Difficulty level
    pub difficulty: DifficultyLevel,
    
    /// Required resources
    pub required_resources: Vec<String>,
    
    /// Estimated duration
    pub estimated_duration: Duration,
    
    /// Success probability
    pub success_probability: f64,
    
    /// Detection probability
    pub detection_probability: f64,
}

/// Difficulty levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DifficultyLevel {
    /// Easy to execute
    Easy,
    /// Moderate difficulty
    Moderate,
    /// Difficult to execute
    Difficult,
    /// Expert level required
    Expert,
}

/// Social engineering orchestrator
pub struct SocialEngineeringOrchestrator {
    /// Configuration
    config: SocialEngineeringConfig,
    
    /// Active campaigns
    campaigns: HashMap<String, SocialEngineeringCampaign>,
    
    /// Attack vector registry
    attack_vectors: HashMap<AttackVectorType, Box<dyn AttackVector + Send + Sync>>,
    
    /// Target database
    targets: HashMap<String, Target>,
    
    /// Results database
    results: Vec<AttackResult>,
}

impl SocialEngineeringOrchestrator {
    /// Create new orchestrator
    pub fn new(config: SocialEngineeringConfig) -> Self {
        Self {
            config,
            campaigns: HashMap::new(),
            attack_vectors: HashMap::new(),
            targets: HashMap::new(),
            results: Vec::new(),
        }
    }
    
    /// Register an attack vector
    pub fn register_attack_vector(
        &mut self,
        attack_type: AttackVectorType,
        attack_vector: Box<dyn AttackVector + Send + Sync>,
    ) {
        self.attack_vectors.insert(attack_type, attack_vector);
    }
    
    /// Create a new campaign
    pub fn create_campaign(&mut self, campaign: SocialEngineeringCampaign) -> Result<String> {
        let campaign_id = campaign.id.clone();
        self.campaigns.insert(campaign_id.clone(), campaign);
        Ok(campaign_id)
    }
    
    /// Execute a campaign
    pub async fn execute_campaign(&mut self, campaign_id: &str) -> Result<Vec<AttackResult>> {
        let campaign = self.campaigns.get_mut(campaign_id)
            .ok_or_else(|| anyhow::anyhow!("Campaign not found: {}", campaign_id))?;
        
        campaign.status = CampaignStatus::Running;
        let mut results = Vec::new();
        
        for attack_vector_type in &campaign.attack_vectors.clone() {
            if let Some(attack_vector) = self.attack_vectors.get(attack_vector_type) {
                for target in &campaign.targets {
                    match attack_vector.execute(target).await {
                        Ok(result) => {
                            results.push(result.clone());
                            self.results.push(result);
                        }
                        Err(e) => {
                            tracing::warn!("Attack failed: {}", e);
                        }
                    }
                }
            }
        }
        
        campaign.status = CampaignStatus::Completed;
        Ok(results)
    }
    
    /// Get campaign results
    pub fn get_campaign_results(&self, campaign_id: &str) -> Vec<&AttackResult> {
        self.results
            .iter()
            .filter(|result| {
                // Filter results by campaign (would need campaign_id in AttackResult)
                true // Simplified for now
            })
            .collect()
    }
    
    /// Generate campaign report
    pub fn generate_report(&self, campaign_id: &str) -> Result<CampaignReport> {
        let campaign = self.campaigns.get(campaign_id)
            .ok_or_else(|| anyhow::anyhow!("Campaign not found: {}", campaign_id))?;
        
        let results = self.get_campaign_results(campaign_id);
        
        Ok(CampaignReport {
            campaign_id: campaign_id.to_string(),
            campaign_name: campaign.name.clone(),
            total_attacks: results.len(),
            successful_attacks: results.iter().filter(|r| r.success).count(),
            detected_attacks: results.iter().filter(|r| r.detected).count(),
            success_rate: results.iter().filter(|r| r.success).count() as f64 / results.len() as f64,
            detection_rate: results.iter().filter(|r| r.detected).count() as f64 / results.len() as f64,
            recommendations: self.generate_recommendations(&results),
            generated_at: Utc::now(),
        })
    }
    
    /// Generate security recommendations
    fn generate_recommendations(&self, results: &[&AttackResult]) -> Vec<SecurityRecommendation> {
        let mut recommendations = Vec::new();
        
        // Analyze results and generate recommendations
        let success_rate = results.iter().filter(|r| r.success).count() as f64 / results.len() as f64;
        let detection_rate = results.iter().filter(|r| r.detected).count() as f64 / results.len() as f64;
        
        if success_rate > 0.3 {
            recommendations.push(SecurityRecommendation {
                category: "User Training".to_string(),
                priority: RecommendationPriority::High,
                description: "High success rate indicates need for enhanced security awareness training".to_string(),
                implementation_steps: vec![
                    "Conduct phishing simulation training".to_string(),
                    "Implement regular security awareness sessions".to_string(),
                    "Create security incident response procedures".to_string(),
                ],
            });
        }
        
        if detection_rate < 0.5 {
            recommendations.push(SecurityRecommendation {
                category: "Technical Controls".to_string(),
                priority: RecommendationPriority::High,
                description: "Low detection rate indicates need for improved security controls".to_string(),
                implementation_steps: vec![
                    "Enhance email security filtering".to_string(),
                    "Implement behavioral analysis".to_string(),
                    "Deploy advanced threat detection".to_string(),
                ],
            });
        }
        
        recommendations
    }
}

/// Campaign report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignReport {
    /// Campaign ID
    pub campaign_id: String,
    
    /// Campaign name
    pub campaign_name: String,
    
    /// Total number of attacks
    pub total_attacks: usize,
    
    /// Number of successful attacks
    pub successful_attacks: usize,
    
    /// Number of detected attacks
    pub detected_attacks: usize,
    
    /// Overall success rate
    pub success_rate: f64,
    
    /// Overall detection rate
    pub detection_rate: f64,
    
    /// Security recommendations
    pub recommendations: Vec<SecurityRecommendation>,
    
    /// Report generation timestamp
    pub generated_at: DateTime<Utc>,
}

/// Security recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRecommendation {
    /// Recommendation category
    pub category: String,
    
    /// Priority level
    pub priority: RecommendationPriority,
    
    /// Recommendation description
    pub description: String,
    
    /// Implementation steps
    pub implementation_steps: Vec<String>,
}

/// Recommendation priority
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationPriority {
    /// Low priority
    Low,
    /// Medium priority
    Medium,
    /// High priority
    High,
    /// Critical priority
    Critical,
}

impl Default for SocialEngineeringConfig {
    fn default() -> Self {
        Self {
            company_name: "Acme Corp".to_string(),
            domain: "acme-corp.com".to_string(),
            target_emails: vec![
                "admin@acme-corp.com".to_string(),
                "support@acme-corp.com".to_string(),
                "hr@acme-corp.com".to_string(),
            ],
            linkedin_company_id: None,
            phone_numbers: vec!["+1-555-0123".to_string()],
            physical_locations: vec!["San Francisco, CA".to_string()],
            known_technologies: vec![
                "OAuth 2.0".to_string(),
                "Rust".to_string(),
                "PostgreSQL".to_string(),
            ],
            breach_databases: vec![],
            intensity: AttackIntensity::Medium,
            campaign_duration: Duration::from_secs(3600), // 1 hour
            max_concurrent_attacks: 5,
        }
    }
}

/// Main entry point for social engineering scenarios
pub async fn run_social_engineering_scenarios(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
) -> Result<()> {
    tracing::info!("🔐 Starting Enhanced Social Engineering Simulation Scenarios");

    let config = SocialEngineeringConfig::default();
    let mut orchestrator = SocialEngineeringOrchestrator::new(config);

    // Register attack vectors
    // orchestrator.register_attack_vector(
    //     AttackVectorType::Email(EmailAttackType::Phishing),
    //     Box::new(PhishingAttack::new()),
    // );

    // Create and execute campaigns based on intensity
    let campaign = create_campaign_for_intensity(intensity)?;
    let campaign_id = orchestrator.create_campaign(campaign)?;
    
    let results = orchestrator.execute_campaign(&campaign_id).await?;
    let report = orchestrator.generate_report(&campaign_id)?;
    
    // Report results
    reporter.add_section("Social Engineering Campaign Results".to_string());
    reporter.add_finding(format!(
        "Campaign '{}' completed with {} attacks, {:.1}% success rate, {:.1}% detection rate",
        report.campaign_name,
        report.total_attacks,
        report.success_rate * 100.0,
        report.detection_rate * 100.0
    ));

    for recommendation in &report.recommendations {
        reporter.add_recommendation(format!(
            "[{}] {}: {}",
            match recommendation.priority {
                RecommendationPriority::Critical => "CRITICAL",
                RecommendationPriority::High => "HIGH",
                RecommendationPriority::Medium => "MEDIUM",
                RecommendationPriority::Low => "LOW",
            },
            recommendation.category,
            recommendation.description
        ));
    }

    Ok(())
}

/// Create campaign based on intensity level
fn create_campaign_for_intensity(intensity: &str) -> Result<SocialEngineeringCampaign> {
    let attack_vectors = match intensity {
        "low" => vec![
            AttackVectorType::Email(EmailAttackType::Phishing),
        ],
        "medium" => vec![
            AttackVectorType::Email(EmailAttackType::Phishing),
            AttackVectorType::Email(EmailAttackType::SpearPhishing),
            AttackVectorType::Voice(VoiceAttackType::Vishing),
        ],
        "high" => vec![
            AttackVectorType::Email(EmailAttackType::Phishing),
            AttackVectorType::Email(EmailAttackType::SpearPhishing),
            AttackVectorType::Email(EmailAttackType::BusinessEmailCompromise),
            AttackVectorType::Voice(VoiceAttackType::Vishing),
            AttackVectorType::Voice(VoiceAttackType::CallerIdSpoofing),
            AttackVectorType::Physical(PhysicalAttackType::Tailgating),
            AttackVectorType::Pretexting(PretextingAttackType::SupportPretexting),
        ],
        _ => return Err(anyhow::anyhow!("Invalid intensity level: {}", intensity)),
    };

    Ok(SocialEngineeringCampaign {
        id: Uuid::new_v4().to_string(),
        name: format!("Social Engineering Campaign - {} Intensity", intensity.to_uppercase()),
        description: format!("Comprehensive social engineering test with {} intensity level", intensity),
        attack_vectors,
        targets: vec![], // Would be populated with actual targets
        timeline: CampaignTimeline {
            start_time: Utc::now(),
            end_time: Utc::now() + chrono::Duration::hours(1),
            phases: vec![],
            milestones: vec![],
        },
        success_metrics: SuccessMetrics {
            target_success_rate: 0.1, // 10% target success rate
            actual_success_rate: 0.0,
            detection_rate: 0.0,
            response_times: HashMap::new(),
            awareness_scores: HashMap::new(),
            control_effectiveness: HashMap::new(),
        },
        status: CampaignStatus::Ready,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_social_engineering_config_default() {
        let config = SocialEngineeringConfig::default();
        assert_eq!(config.company_name, "Acme Corp");
        assert_eq!(config.domain, "acme-corp.com");
        assert!(!config.target_emails.is_empty());
    }

    #[test]
    fn test_campaign_creation() {
        let campaign = create_campaign_for_intensity("medium").unwrap();
        assert_eq!(campaign.attack_vectors.len(), 3);
        assert_eq!(campaign.status, CampaignStatus::Ready);
    }

    #[test]
    fn test_orchestrator_creation() {
        let config = SocialEngineeringConfig::default();
        let orchestrator = SocialEngineeringOrchestrator::new(config);
        assert_eq!(orchestrator.campaigns.len(), 0);
        assert_eq!(orchestrator.results.len(), 0);
    }
}
