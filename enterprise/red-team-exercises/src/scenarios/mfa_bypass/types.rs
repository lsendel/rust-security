use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

/// MFA bypass attack result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaBypassResult {
    pub attack_type: MfaAttackType,
    pub success: bool,
    pub bypass_method: Option<String>,
    pub time_taken: std::time::Duration,
    pub attempts_made: u32,
    pub error_messages: Vec<String>,
    pub vulnerability_details: Option<VulnerabilityDetails>,
}

/// Types of MFA attacks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaAttackType {
    TotpReplay,
    TotpBruteForce,
    BackupCodeEnumeration,
    TimeWindowExploitation,
    HeaderManipulation,
    OtpInterception,
    StateConfusion,
    WebAuthnBypass,
    BiometricBypass,
    PushNotificationBypass,
    HardwareTokenEmulation,
    VoiceRecognitionBypass,
}

/// Vulnerability details discovered during attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityDetails {
    pub vulnerability_type: VulnerabilityType,
    pub severity: SeverityLevel,
    pub description: String,
    pub proof_of_concept: String,
    pub remediation_steps: Vec<String>,
    pub cve_references: Vec<String>,
}

/// Types of vulnerabilities that can be discovered
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnerabilityType {
    WeakTimeWindow,
    InsecureBackupCodes,
    ReplayVulnerability,
    StateManipulation,
    BiometricSpoofing,
    TokenEmulation,
    HeaderInjection,
    RateLimitBypass,
}

/// Severity levels for vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// TOTP attack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpAttackConfig {
    pub time_window_seconds: u64,
    pub max_attempts: u32,
    pub brute_force_patterns: Vec<String>,
    pub replay_window_seconds: u64,
}

/// Backup code attack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupCodeConfig {
    pub code_length: usize,
    pub code_patterns: Vec<String>,
    pub enumeration_delay_ms: u64,
    pub max_enumeration_attempts: u32,
}

/// Biometric attack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricAttackConfig {
    pub spoofing_techniques: Vec<SpoofingTechnique>,
    pub bypass_methods: Vec<BiometricBypassMethod>,
    pub template_injection_payloads: Vec<String>,
}

/// Biometric spoofing techniques
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpoofingTechnique {
    FingerprintSilicone,
    FacePhotoAttack,
    VoiceRecording,
    IrisPhotoAttack,
    GaitImitation,
}

/// Biometric bypass methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BiometricBypassMethod {
    TemplateInjection,
    SensorSpoofing,
    AlgorithmConfusion,
    FallbackExploitation,
    LivenessDetectionBypass,
}

/// WebAuthn attack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAttackConfig {
    pub credential_stuffing_payloads: Vec<String>,
    pub attestation_bypass_methods: Vec<String>,
    pub resident_key_enumeration: bool,
    pub user_verification_bypass: bool,
}

/// Push notification attack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushNotificationConfig {
    pub notification_flooding: bool,
    pub approval_fatigue_count: u32,
    pub timing_attack_intervals: Vec<u64>,
    pub device_registration_bypass: bool,
}

/// Attack execution context
#[derive(Debug, Clone)]
pub struct AttackContext {
    pub target_url: String,
    pub session_cookies: HashMap<String, String>,
    pub csrf_tokens: HashMap<String, String>,
    pub user_agent: String,
    pub attack_intensity: AttackIntensity,
    pub start_time: SystemTime,
}

/// Attack intensity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackIntensity {
    Low,      // Minimal, stealthy attacks
    Medium,   // Moderate attack patterns
    High,     // Aggressive attack patterns
    Extreme,  // Maximum intensity attacks
}

/// MFA bypass attack statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStatistics {
    pub total_attacks: u32,
    pub successful_bypasses: u32,
    pub failed_attempts: u32,
    pub vulnerabilities_found: u32,
    pub average_attack_time: std::time::Duration,
    pub attack_success_rate: f64,
}

/// OTP interception result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpInterceptionResult {
    pub interception_method: InterceptionMethod,
    pub intercepted_codes: Vec<String>,
    pub success_rate: f64,
    pub detection_evasion: bool,
}

/// Methods for OTP interception
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterceptionMethod {
    SmsInterception,
    EmailInterception,
    NetworkSniffing,
    SocialEngineering,
    SimSwapping,
    ManInTheMiddle,
}

/// Hardware token emulation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEmulationResult {
    pub token_type: HardwareTokenType,
    pub emulation_success: bool,
    pub cloned_credentials: Vec<String>,
    pub bypass_techniques_used: Vec<String>,
}

/// Types of hardware tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HardwareTokenType {
    YubiKey,
    RSASecurID,
    GoogleTitan,
    FidoU2F,
    SmartCard,
    CustomToken,
}

impl Default for TotpAttackConfig {
    fn default() -> Self {
        Self {
            time_window_seconds: 30,
            max_attempts: 1000,
            brute_force_patterns: vec![
                "000000".to_string(),
                "123456".to_string(),
                "111111".to_string(),
                "000001".to_string(),
            ],
            replay_window_seconds: 90,
        }
    }
}

impl Default for BackupCodeConfig {
    fn default() -> Self {
        Self {
            code_length: 8,
            code_patterns: vec![
                "12345678".to_string(),
                "00000000".to_string(),
                "11111111".to_string(),
                "87654321".to_string(),
            ],
            enumeration_delay_ms: 100,
            max_enumeration_attempts: 10000,
        }
    }
}

impl Default for BiometricAttackConfig {
    fn default() -> Self {
        Self {
            spoofing_techniques: vec![
                SpoofingTechnique::FingerprintSilicone,
                SpoofingTechnique::FacePhotoAttack,
                SpoofingTechnique::VoiceRecording,
            ],
            bypass_methods: vec![
                BiometricBypassMethod::TemplateInjection,
                BiometricBypassMethod::SensorSpoofing,
                BiometricBypassMethod::FallbackExploitation,
            ],
            template_injection_payloads: vec![
                "fake_template_data".to_string(),
                "spoofed_biometric".to_string(),
            ],
        }
    }
}

impl AttackIntensity {
    pub fn get_delay_ms(&self) -> u64 {
        match self {
            AttackIntensity::Low => 2000,
            AttackIntensity::Medium => 1000,
            AttackIntensity::High => 500,
            AttackIntensity::Extreme => 100,
        }
    }

    pub fn get_max_attempts(&self) -> u32 {
        match self {
            AttackIntensity::Low => 100,
            AttackIntensity::Medium => 500,
            AttackIntensity::High => 2000,
            AttackIntensity::Extreme => 10000,
        }
    }
}

impl MfaBypassResult {
    pub fn new(attack_type: MfaAttackType) -> Self {
        Self {
            attack_type,
            success: false,
            bypass_method: None,
            time_taken: std::time::Duration::from_secs(0),
            attempts_made: 0,
            error_messages: Vec::new(),
            vulnerability_details: None,
        }
    }

    pub fn with_success(mut self, success: bool, method: Option<String>) -> Self {
        self.success = success;
        self.bypass_method = method;
        self
    }

    pub fn with_vulnerability(mut self, vulnerability: VulnerabilityDetails) -> Self {
        self.vulnerability_details = Some(vulnerability);
        self
    }
}
