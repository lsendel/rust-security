//! Email-Based Social Engineering Attacks
//!
//! This module contains sophisticated email-based social engineering attack simulations
//! including phishing, spear phishing, and business email compromise scenarios.

pub mod phishing;
pub mod spear_phishing;
pub mod bec;

use crate::attack_framework::{AttackSession, RedTeamFramework};
use crate::reporting::RedTeamReporter;
use crate::scenarios::social_engineering::{
    AttackResult, AttackVector, AttackDetails, AttackMetadata, DetectionSignature,
    SignatureType, DifficultyLevel, Target, TechnicalLevel,
};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand::{thread_rng, Rng};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub use phishing::*;
pub use spear_phishing::*;
pub use bec::*;

/// Email attack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAttackConfig {
    /// SMTP server configuration
    pub smtp_config: SmtpConfig,
    
    /// Email templates
    pub templates: Vec<EmailTemplate>,
    
    /// Sender profiles
    pub sender_profiles: Vec<SenderProfile>,
    
    /// Domain reputation settings
    pub domain_reputation: DomainReputationConfig,
    
    /// Tracking configuration
    pub tracking_config: TrackingConfig,
}

/// SMTP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    /// SMTP server host
    pub host: String,
    
    /// SMTP server port
    pub port: u16,
    
    /// Use TLS encryption
    pub use_tls: bool,
    
    /// Authentication username
    pub username: Option<String>,
    
    /// Authentication password
    pub password: Option<String>,
    
    /// Connection timeout
    pub timeout: Duration,
}

/// Email template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailTemplate {
    /// Template ID
    pub id: String,
    
    /// Template name
    pub name: String,
    
    /// Template category
    pub category: EmailTemplateCategory,
    
    /// Subject line template
    pub subject: String,
    
    /// HTML body template
    pub html_body: String,
    
    /// Plain text body template
    pub text_body: String,
    
    /// Template variables
    pub variables: Vec<String>,
    
    /// Sophistication level
    pub sophistication: SophisticationLevel,
    
    /// Success rate estimate
    pub estimated_success_rate: f64,
}

/// Email template categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmailTemplateCategory {
    /// Generic phishing
    GenericPhishing,
    /// Credential harvesting
    CredentialHarvesting,
    /// Malware delivery
    MalwareDelivery,
    /// Business email compromise
    BusinessEmailCompromise,
    /// Invoice fraud
    InvoiceFraud,
    /// IT support impersonation
    ItSupportImpersonation,
    /// Executive impersonation
    ExecutiveImpersonation,
    /// Vendor impersonation
    VendorImpersonation,
}

/// Sophistication levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SophisticationLevel {
    /// Basic template with obvious indicators
    Basic,
    /// Moderate sophistication with some evasion
    Moderate,
    /// Advanced template with sophisticated evasion
    Advanced,
    /// Expert-level template with advanced techniques
    Expert,
}

/// Sender profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderProfile {
    /// Profile ID
    pub id: String,
    
    /// Display name
    pub display_name: String,
    
    /// Email address
    pub email_address: String,
    
    /// Reply-to address
    pub reply_to: Option<String>,
    
    /// Organization
    pub organization: Option<String>,
    
    /// Job title
    pub job_title: Option<String>,
    
    /// Profile credibility score
    pub credibility_score: f64,
    
    /// Profile type
    pub profile_type: SenderProfileType,
}

/// Sender profile types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SenderProfileType {
    /// Internal employee impersonation
    InternalEmployee,
    /// External vendor
    ExternalVendor,
    /// IT support
    ItSupport,
    /// Executive/C-level
    Executive,
    /// HR representative
    HumanResources,
    /// Finance/accounting
    Finance,
    /// Customer support
    CustomerSupport,
    /// Generic external contact
    Generic,
}

/// Domain reputation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReputationConfig {
    /// Use legitimate domains
    pub use_legitimate_domains: bool,
    
    /// Use typosquatting domains
    pub use_typosquatting: bool,
    
    /// Use subdomain spoofing
    pub use_subdomain_spoofing: bool,
    
    /// Domain age simulation
    pub simulate_domain_age: bool,
    
    /// SSL certificate configuration
    pub ssl_config: SslConfig,
}

/// SSL certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslConfig {
    /// Use valid SSL certificates
    pub use_valid_ssl: bool,
    
    /// Certificate authority
    pub certificate_authority: Option<String>,
    
    /// Certificate validation level
    pub validation_level: CertificateValidationLevel,
}

/// Certificate validation levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CertificateValidationLevel {
    /// Domain validated
    DomainValidated,
    /// Organization validated
    OrganizationValidated,
    /// Extended validation
    ExtendedValidation,
}

/// Tracking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingConfig {
    /// Enable email open tracking
    pub track_opens: bool,
    
    /// Enable link click tracking
    pub track_clicks: bool,
    
    /// Enable attachment download tracking
    pub track_downloads: bool,
    
    /// Enable geolocation tracking
    pub track_geolocation: bool,
    
    /// Tracking pixel configuration
    pub pixel_config: TrackingPixelConfig,
}

/// Tracking pixel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingPixelConfig {
    /// Pixel URL
    pub pixel_url: String,
    
    /// Pixel size
    pub pixel_size: (u32, u32),
    
    /// Pixel transparency
    pub transparency: f64,
    
    /// Embed in HTML
    pub embed_in_html: bool,
}

/// Email attack result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAttackResult {
    /// Base attack result
    pub base_result: AttackResult,
    
    /// Email-specific metrics
    pub email_metrics: EmailMetrics,
    
    /// Delivery status
    pub delivery_status: DeliveryStatus,
    
    /// User interaction
    pub user_interaction: UserInteraction,
}

/// Email metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMetrics {
    /// Email sent timestamp
    pub sent_at: DateTime<Utc>,
    
    /// Email delivered timestamp
    pub delivered_at: Option<DateTime<Utc>>,
    
    /// Email opened timestamp
    pub opened_at: Option<DateTime<Utc>>,
    
    /// Links clicked
    pub links_clicked: Vec<LinkClick>,
    
    /// Attachments downloaded
    pub attachments_downloaded: Vec<AttachmentDownload>,
    
    /// Email forwarded
    pub forwarded: bool,
    
    /// Email reported as spam
    pub reported_as_spam: bool,
}

/// Link click information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkClick {
    /// Link URL
    pub url: String,
    
    /// Click timestamp
    pub clicked_at: DateTime<Utc>,
    
    /// User agent
    pub user_agent: Option<String>,
    
    /// IP address
    pub ip_address: Option<String>,
    
    /// Geolocation
    pub geolocation: Option<String>,
}

/// Attachment download information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentDownload {
    /// Attachment filename
    pub filename: String,
    
    /// Download timestamp
    pub downloaded_at: DateTime<Utc>,
    
    /// File size
    pub file_size: u64,
    
    /// Download completed
    pub completed: bool,
}

/// Delivery status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// Email delivered successfully
    Delivered,
    /// Email bounced
    Bounced,
    /// Email marked as spam
    Spam,
    /// Email blocked by security controls
    Blocked,
    /// Delivery pending
    Pending,
    /// Delivery failed
    Failed,
}

/// User interaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInteraction {
    /// User opened the email
    pub opened: bool,
    
    /// User clicked links
    pub clicked_links: bool,
    
    /// User downloaded attachments
    pub downloaded_attachments: bool,
    
    /// User entered credentials
    pub entered_credentials: bool,
    
    /// User reported the email
    pub reported_email: bool,
    
    /// User forwarded the email
    pub forwarded_email: bool,
    
    /// Time to first interaction
    pub time_to_first_interaction: Option<Duration>,
}

/// Generic email attack implementation
pub struct EmailAttack {
    /// Attack configuration
    config: EmailAttackConfig,
    
    /// Current template
    template: Option<EmailTemplate>,
    
    /// Current sender profile
    sender_profile: Option<SenderProfile>,
    
    /// Attack session
    session: Option<AttackSession>,
}

impl EmailAttack {
    /// Create new email attack
    pub fn new(config: EmailAttackConfig) -> Self {
        Self {
            config,
            template: None,
            sender_profile: None,
            session: None,
        }
    }
    
    /// Select template based on target profile
    pub fn select_template(&mut self, target: &Target) -> Result<()> {
        let suitable_templates: Vec<_> = self.config.templates
            .iter()
            .filter(|template| self.is_template_suitable(template, target))
            .collect();
        
        if suitable_templates.is_empty() {
            return Err(anyhow::anyhow!("No suitable templates found for target"));
        }
        
        let mut rng = thread_rng();
        let selected_template = suitable_templates[rng.gen_range(0..suitable_templates.len())];
        self.template = Some(selected_template.clone());
        
        Ok(())
    }
    
    /// Check if template is suitable for target
    fn is_template_suitable(&self, template: &EmailTemplate, target: &Target) -> bool {
        match target.technical_level {
            TechnicalLevel::Beginner => {
                matches!(template.sophistication, SophisticationLevel::Basic | SophisticationLevel::Moderate)
            }
            TechnicalLevel::Intermediate => {
                matches!(template.sophistication, SophisticationLevel::Moderate | SophisticationLevel::Advanced)
            }
            TechnicalLevel::Advanced => {
                matches!(template.sophistication, SophisticationLevel::Advanced | SophisticationLevel::Expert)
            }
            TechnicalLevel::Expert => {
                matches!(template.sophistication, SophisticationLevel::Expert)
            }
        }
    }
    
    /// Select sender profile
    pub fn select_sender_profile(&mut self, target: &Target) -> Result<()> {
        let suitable_profiles: Vec<_> = self.config.sender_profiles
            .iter()
            .filter(|profile| self.is_profile_suitable(profile, target))
            .collect();
        
        if suitable_profiles.is_empty() {
            return Err(anyhow::anyhow!("No suitable sender profiles found"));
        }
        
        let mut rng = thread_rng();
        let selected_profile = suitable_profiles[rng.gen_range(0..suitable_profiles.len())];
        self.sender_profile = Some(selected_profile.clone());
        
        Ok(())
    }
    
    /// Check if sender profile is suitable for target
    fn is_profile_suitable(&self, profile: &SenderProfile, target: &Target) -> bool {
        // Logic to determine if sender profile matches target's likely contacts
        match &target.department {
            Some(dept) if dept == "IT" => {
                matches!(profile.profile_type, SenderProfileType::ItSupport | SenderProfileType::InternalEmployee)
            }
            Some(dept) if dept == "Finance" => {
                matches!(profile.profile_type, SenderProfileType::Finance | SenderProfileType::ExternalVendor)
            }
            Some(dept) if dept == "HR" => {
                matches!(profile.profile_type, SenderProfileType::HumanResources | SenderProfileType::InternalEmployee)
            }
            _ => true, // Generic profiles work for any department
        }
    }
    
    /// Generate personalized email content
    pub fn generate_email_content(&self, target: &Target) -> Result<(String, String, String)> {
        let template = self.template.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No template selected"))?;
        
        let sender_profile = self.sender_profile.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No sender profile selected"))?;
        
        // Replace template variables with target-specific information
        let mut subject = template.subject.clone();
        let mut html_body = template.html_body.clone();
        let mut text_body = template.text_body.clone();
        
        // Common replacements
        let replacements = vec![
            ("{target_name}", target.name.as_str()),
            ("{target_email}", target.email.as_deref().unwrap_or("user")),
            ("{sender_name}", sender_profile.display_name.as_str()),
            ("{sender_email}", sender_profile.email_address.as_str()),
            ("{organization}", sender_profile.organization.as_deref().unwrap_or("Organization")),
            ("{job_title}", sender_profile.job_title.as_deref().unwrap_or("Representative")),
            ("{department}", target.department.as_deref().unwrap_or("Department")),
            ("{current_date}", &Utc::now().format("%Y-%m-%d").to_string()),
            ("{current_time}", &Utc::now().format("%H:%M").to_string()),
        ];
        
        for (placeholder, replacement) in replacements {
            subject = subject.replace(placeholder, replacement);
            html_body = html_body.replace(placeholder, replacement);
            text_body = text_body.replace(placeholder, replacement);
        }
        
        // Add tracking pixels if enabled
        if self.config.tracking_config.track_opens {
            let tracking_pixel = self.generate_tracking_pixel(target)?;
            html_body.push_str(&tracking_pixel);
        }
        
        Ok((subject, html_body, text_body))
    }
    
    /// Generate tracking pixel HTML
    fn generate_tracking_pixel(&self, target: &Target) -> Result<String> {
        let pixel_config = &self.config.tracking_config.pixel_config;
        let tracking_id = Uuid::new_v4().to_string();
        
        Ok(format!(
            r#"<img src="{}?id={}&target={}" width="{}" height="{}" style="opacity: {};" />"#,
            pixel_config.pixel_url,
            tracking_id,
            target.id,
            pixel_config.pixel_size.0,
            pixel_config.pixel_size.1,
            pixel_config.transparency
        ))
    }
    
    /// Send email to target
    pub async fn send_email(&self, target: &Target) -> Result<EmailAttackResult> {
        let (subject, html_body, text_body) = self.generate_email_content(target)?;
        
        // Simulate email sending (in real implementation, would use SMTP)
        let sent_at = Utc::now();
        
        // Simulate delivery delay
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Simulate delivery status based on target's technical level
        let delivery_status = self.simulate_delivery_status(target);
        
        let delivered_at = if matches!(delivery_status, DeliveryStatus::Delivered) {
            Some(sent_at + chrono::Duration::seconds(5))
        } else {
            None
        };
        
        // Simulate user interaction
        let user_interaction = self.simulate_user_interaction(target).await;
        
        let email_metrics = EmailMetrics {
            sent_at,
            delivered_at,
            opened_at: if user_interaction.opened {
                Some(sent_at + chrono::Duration::minutes(5))
            } else {
                None
            },
            links_clicked: if user_interaction.clicked_links {
                vec![LinkClick {
                    url: "https://malicious-site.com/login".to_string(),
                    clicked_at: sent_at + chrono::Duration::minutes(10),
                    user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string()),
                    ip_address: Some("192.168.1.100".to_string()),
                    geolocation: Some("San Francisco, CA".to_string()),
                }]
            } else {
                vec![]
            },
            attachments_downloaded: vec![],
            forwarded: user_interaction.forwarded_email,
            reported_as_spam: user_interaction.reported_email,
        };
        
        let base_result = AttackResult {
            attack_id: Uuid::new_v4().to_string(),
            attack_type: crate::scenarios::social_engineering::AttackVectorType::Email(
                crate::scenarios::social_engineering::EmailAttackType::Phishing
            ),
            target_id: target.id.clone(),
            timestamp: sent_at,
            success: user_interaction.entered_credentials || user_interaction.clicked_links,
            detected: user_interaction.reported_email,
            response_time: user_interaction.time_to_first_interaction,
            details: AttackDetails {
                method: "Email Phishing".to_string(),
                payload: Some(subject.clone()),
                delivery_mechanism: "SMTP".to_string(),
                evasion_techniques: vec!["Template personalization".to_string()],
                detection_signatures: vec![],
                user_response: if user_interaction.reported_email {
                    Some("Reported as spam".to_string())
                } else {
                    None
                },
                technical_response: None,
            },
            lessons_learned: vec![
                "User interaction patterns vary by technical level".to_string(),
                "Personalization increases success rates".to_string(),
            ],
        };
        
        Ok(EmailAttackResult {
            base_result,
            email_metrics,
            delivery_status,
            user_interaction,
        })
    }
    
    /// Simulate delivery status based on target profile
    fn simulate_delivery_status(&self, target: &Target) -> DeliveryStatus {
        let mut rng = thread_rng();
        
        match target.technical_level {
            TechnicalLevel::Expert => {
                // Security experts more likely to have advanced filtering
                if rng.gen_bool(0.3) {
                    DeliveryStatus::Blocked
                } else if rng.gen_bool(0.2) {
                    DeliveryStatus::Spam
                } else {
                    DeliveryStatus::Delivered
                }
            }
            TechnicalLevel::Advanced => {
                if rng.gen_bool(0.1) {
                    DeliveryStatus::Blocked
                } else if rng.gen_bool(0.15) {
                    DeliveryStatus::Spam
                } else {
                    DeliveryStatus::Delivered
                }
            }
            _ => {
                if rng.gen_bool(0.05) {
                    DeliveryStatus::Spam
                } else {
                    DeliveryStatus::Delivered
                }
            }
        }
    }
    
    /// Simulate user interaction based on target profile
    async fn simulate_user_interaction(&self, target: &Target) -> UserInteraction {
        let mut rng = thread_rng();
        
        // Base probabilities based on technical level
        let (open_prob, click_prob, cred_prob, report_prob) = match target.technical_level {
            TechnicalLevel::Beginner => (0.8, 0.4, 0.2, 0.05),
            TechnicalLevel::Intermediate => (0.6, 0.2, 0.1, 0.15),
            TechnicalLevel::Advanced => (0.4, 0.1, 0.05, 0.3),
            TechnicalLevel::Expert => (0.2, 0.05, 0.01, 0.6),
        };
        
        let opened = rng.gen_bool(open_prob);
        let clicked_links = opened && rng.gen_bool(click_prob);
        let entered_credentials = clicked_links && rng.gen_bool(cred_prob);
        let reported_email = rng.gen_bool(report_prob);
        
        let time_to_first_interaction = if opened {
            Some(Duration::from_secs(rng.gen_range(60..3600))) // 1 minute to 1 hour
        } else {
            None
        };
        
        UserInteraction {
            opened,
            clicked_links,
            downloaded_attachments: false,
            entered_credentials,
            reported_email,
            forwarded_email: opened && rng.gen_bool(0.05), // 5% chance of forwarding
            time_to_first_interaction,
        }
    }
}

#[async_trait]
impl AttackVector for EmailAttack {
    async fn prepare(&mut self, targets: &[Target]) -> Result<()> {
        info!("Preparing email attack for {} targets", targets.len());
        
        // Initialize attack session
        // self.session = Some(attack_session);
        
        Ok(())
    }
    
    async fn execute(&self, target: &Target) -> Result<AttackResult> {
        info!("Executing email attack against target: {}", target.name);
        
        let _result = self.send_email(target).await?;
        Ok(result.base_result)
    }
    
    async fn cleanup(&self) -> Result<()> {
        info!("Cleaning up email attack resources");
        Ok(())
    }
    
    fn get_detection_signatures(&self) -> Vec<DetectionSignature> {
        vec![
            DetectionSignature {
                name: "Suspicious sender domain".to_string(),
                signature_type: SignatureType::EmailHeader,
                pattern: r"@[a-z0-9-]+\.(tk|ml|ga|cf)$".to_string(),
                confidence: 0.8,
                false_positive_rate: 0.1,
            },
            DetectionSignature {
                name: "Phishing keywords".to_string(),
                signature_type: SignatureType::EmailContent,
                pattern: r"(?i)(urgent|verify|suspend|click here|act now)".to_string(),
                confidence: 0.6,
                false_positive_rate: 0.2,
            },
            DetectionSignature {
                name: "Suspicious URLs".to_string(),
                signature_type: SignatureType::UrlPattern,
                pattern: r"https?://[a-z0-9-]+\.(tk|ml|ga|cf)/".to_string(),
                confidence: 0.9,
                false_positive_rate: 0.05,
            },
        ]
    }
    
    fn get_metadata(&self) -> AttackMetadata {
        AttackMetadata {
            name: "Email Phishing Attack".to_string(),
            description: "Generic email-based phishing attack simulation".to_string(),
            difficulty: DifficultyLevel::Easy,
            required_resources: vec![
                "SMTP server access".to_string(),
                "Email templates".to_string(),
                "Target email addresses".to_string(),
            ],
            estimated_duration: Duration::from_secs(300), // 5 minutes
            success_probability: 0.3,
            detection_probability: 0.4,
        }
    }
}

impl Default for EmailAttackConfig {
    fn default() -> Self {
        Self {
            smtp_config: SmtpConfig {
                host: "localhost".to_string(),
                port: 587,
                use_tls: true,
                username: None,
                password: None,
                timeout: Duration::from_secs(30),
            },
            templates: vec![
                EmailTemplate {
                    id: "generic_phishing".to_string(),
                    name: "Generic Phishing".to_string(),
                    category: EmailTemplateCategory::GenericPhishing,
                    subject: "Urgent: Verify your account - {target_name}".to_string(),
                    html_body: r#"
                        <html>
                        <body>
                            <p>Dear {target_name},</p>
                            <p>We have detected suspicious activity on your account. Please verify your identity immediately.</p>
                            <p><a href="https://verification-site.com/verify?user={target_email}">Click here to verify</a></p>
                            <p>Best regards,<br>{sender_name}</p>
                        </body>
                        </html>
                    "#.to_string(),
                    text_body: "Dear {target_name}, Please verify your account at: https://verification-site.com/verify?user={target_email}".to_string(),
                    variables: vec!["target_name".to_string(), "target_email".to_string(), "sender_name".to_string()],
                    sophistication: SophisticationLevel::Basic,
                    estimated_success_rate: 0.2,
                },
            ],
            sender_profiles: vec![
                SenderProfile {
                    id: "it_support".to_string(),
                    display_name: "IT Support".to_string(),
                    email_address: "support@company.com".to_string(),
                    reply_to: None,
                    organization: Some("IT Department".to_string()),
                    job_title: Some("IT Support Specialist".to_string()),
                    credibility_score: 0.8,
                    profile_type: SenderProfileType::ItSupport,
                },
            ],
            domain_reputation: DomainReputationConfig {
                use_legitimate_domains: false,
                use_typosquatting: true,
                use_subdomain_spoofing: true,
                simulate_domain_age: true,
                ssl_config: SslConfig {
                    use_valid_ssl: false,
                    certificate_authority: None,
                    validation_level: CertificateValidationLevel::DomainValidated,
                },
            },
            tracking_config: TrackingConfig {
                track_opens: true,
                track_clicks: true,
                track_downloads: true,
                track_geolocation: false,
                pixel_config: TrackingPixelConfig {
                    pixel_url: "https://tracking.example.com/pixel.gif".to_string(),
                    pixel_size: (1, 1),
                    transparency: 0.0,
                    embed_in_html: true,
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_attack_config_default() {
        let config = EmailAttackConfig::default();
        assert_eq!(config.smtp_config.host, "localhost");
        assert_eq!(config.templates.len(), 1);
        assert_eq!(config.sender_profiles.len(), 1);
    }

    #[test]
    fn test_template_suitability() {
        let config = EmailAttackConfig::default();
        let attack = EmailAttack::new(config);
        
        let template = EmailTemplate {
            id: "test".to_string(),
            name: "Test".to_string(),
            category: EmailTemplateCategory::GenericPhishing,
            subject: "Test".to_string(),
            html_body: "Test".to_string(),
            text_body: "Test".to_string(),
            variables: vec![],
            sophistication: SophisticationLevel::Basic,
            estimated_success_rate: 0.5,
        };
        
        let target = Target {
            id: "test_target".to_string(),
            name: "Test User".to_string(),
            email: Some("test@example.com".to_string()),
            phone: None,
            role: None,
            department: None,
            social_profiles: HashMap::new(),
            interests: vec![],
            technical_level: TechnicalLevel::Beginner,
            attack_history: vec![],
        };
        
        assert!(attack.is_template_suitable(&template, &target));
    }

    #[tokio::test]
    async fn test_user_interaction_simulation() {
        let config = EmailAttackConfig::default();
        let attack = EmailAttack::new(config);
        
        let target = Target {
            id: "test_target".to_string(),
            name: "Test User".to_string(),
            email: Some("test@example.com".to_string()),
            phone: None,
            role: None,
            department: None,
            social_profiles: HashMap::new(),
            interests: vec![],
            technical_level: TechnicalLevel::Expert,
            attack_history: vec![],
        };
        
        let interaction = attack.simulate_user_interaction(&target).await;
        
        // Expert users should have low interaction rates
        // This is probabilistic, so we can't assert exact values
        // but we can check the structure is correct
        assert!(interaction.time_to_first_interaction.is_some() || !interaction.opened);
    }
}
