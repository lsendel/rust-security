use crate::scenarios::mfa_bypass::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main configuration for MFA bypass attack scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaBypassConfig {
    pub totp_config: TotpAttackConfig,
    pub backup_code_config: BackupCodeConfig,
    pub biometric_config: BiometricAttackConfig,
    pub webauthn_config: WebAuthnAttackConfig,
    pub push_notification_config: PushNotificationConfig,
    pub general_settings: GeneralAttackSettings,
}

/// General attack settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralAttackSettings {
    pub max_concurrent_attacks: u32,
    pub attack_timeout_seconds: u64,
    pub stealth_mode: bool,
    pub evasion_techniques: Vec<EvasionTechnique>,
    pub user_agent_rotation: bool,
    pub proxy_rotation: bool,
    pub rate_limiting_evasion: bool,
}

/// Evasion techniques to avoid detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvasionTechnique {
    RandomDelays,
    UserAgentRotation,
    ProxyRotation,
    HeaderRandomization,
    TimingVariation,
    RequestObfuscation,
    TrafficMimicry,
}

impl Default for MfaBypassConfig {
    fn default() -> Self {
        Self {
            totp_config: TotpAttackConfig::default(),
            backup_code_config: BackupCodeConfig::default(),
            biometric_config: BiometricAttackConfig::default(),
            webauthn_config: WebAuthnAttackConfig::default(),
            push_notification_config: PushNotificationConfig::default(),
            general_settings: GeneralAttackSettings::default(),
        }
    }
}

impl Default for WebAuthnAttackConfig {
    fn default() -> Self {
        Self {
            credential_stuffing_payloads: vec![
                "common_credential_1".to_string(),
                "common_credential_2".to_string(),
            ],
            attestation_bypass_methods: vec![
                "none_attestation".to_string(),
                "self_attestation".to_string(),
            ],
            resident_key_enumeration: true,
            user_verification_bypass: true,
        }
    }
}

impl Default for PushNotificationConfig {
    fn default() -> Self {
        Self {
            notification_flooding: true,
            approval_fatigue_count: 20,
            timing_attack_intervals: vec![1000, 2000, 5000, 10000],
            device_registration_bypass: true,
        }
    }
}

impl Default for GeneralAttackSettings {
    fn default() -> Self {
        Self {
            max_concurrent_attacks: 5,
            attack_timeout_seconds: 300,
            stealth_mode: false,
            evasion_techniques: vec![
                EvasionTechnique::RandomDelays,
                EvasionTechnique::UserAgentRotation,
                EvasionTechnique::TimingVariation,
            ],
            user_agent_rotation: true,
            proxy_rotation: false,
            rate_limiting_evasion: true,
        }
    }
}

impl MfaBypassConfig {
    /// Create a new configuration with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure for stealth mode (low detection risk)
    pub fn stealth_mode() -> Self {
        let mut config = Self::default();
        config.general_settings.stealth_mode = true;
        config.general_settings.max_concurrent_attacks = 1;
        config.general_settings.evasion_techniques = vec![
            EvasionTechnique::RandomDelays,
            EvasionTechnique::UserAgentRotation,
            EvasionTechnique::ProxyRotation,
            EvasionTechnique::TimingVariation,
            EvasionTechnique::TrafficMimicry,
        ];
        
        // Reduce attack intensity for stealth
        config.totp_config.max_attempts = 50;
        config.backup_code_config.max_enumeration_attempts = 100;
        config.backup_code_config.enumeration_delay_ms = 5000;
        
        config
    }

    /// Configure for aggressive testing (high intensity)
    pub fn aggressive_mode() -> Self {
        let mut config = Self::default();
        config.general_settings.stealth_mode = false;
        config.general_settings.max_concurrent_attacks = 10;
        config.general_settings.attack_timeout_seconds = 600;
        
        // Increase attack intensity
        config.totp_config.max_attempts = 10000;
        config.backup_code_config.max_enumeration_attempts = 50000;
        config.backup_code_config.enumeration_delay_ms = 10;
        config.push_notification_config.approval_fatigue_count = 100;
        
        config
    }

    /// Configure for compliance testing (controlled environment)
    pub fn compliance_mode() -> Self {
        let mut config = Self::default();
        config.general_settings.stealth_mode = true;
        config.general_settings.max_concurrent_attacks = 2;
        
        // Moderate attack parameters for compliance testing
        config.totp_config.max_attempts = 500;
        config.backup_code_config.max_enumeration_attempts = 1000;
        config.push_notification_config.approval_fatigue_count = 10;
        
        config
    }

    /// Validate configuration settings
    pub fn validate(&self) -> Result<(), String> {
        if self.general_settings.max_concurrent_attacks == 0 {
            return Err("Max concurrent attacks must be greater than 0".to_string());
        }

        if self.general_settings.attack_timeout_seconds == 0 {
            return Err("Attack timeout must be greater than 0".to_string());
        }

        if self.totp_config.max_attempts == 0 {
            return Err("TOTP max attempts must be greater than 0".to_string());
        }

        if self.backup_code_config.max_enumeration_attempts == 0 {
            return Err("Backup code max attempts must be greater than 0".to_string());
        }

        if self.backup_code_config.code_length == 0 {
            return Err("Backup code length must be greater than 0".to_string());
        }

        Ok(())
    }

    /// Get attack patterns for specific intensity level
    pub fn get_attack_patterns(&self, intensity: &AttackIntensity) -> HashMap<String, Vec<String>> {
        let mut patterns = HashMap::new();

        // TOTP patterns based on intensity
        let totp_patterns = match intensity {
            AttackIntensity::Low => vec!["000000".to_string(), "123456".to_string()],
            AttackIntensity::Medium => vec![
                "000000".to_string(), "123456".to_string(), "111111".to_string(), "000001".to_string()
            ],
            AttackIntensity::High => {
                let mut high_patterns = self.totp_config.brute_force_patterns.clone();
                high_patterns.extend(vec![
                    "999999".to_string(), "654321".to_string(), "888888".to_string()
                ]);
                high_patterns
            },
            AttackIntensity::Extreme => {
                let mut extreme_patterns = self.totp_config.brute_force_patterns.clone();
                // Add comprehensive pattern set for extreme mode
                for i in 0..1000 {
                    extreme_patterns.push(format!("{:06}", i));
                }
                extreme_patterns
            }
        };

        patterns.insert("totp".to_string(), totp_patterns);

        // Backup code patterns
        let backup_patterns = match intensity {
            AttackIntensity::Low => vec!["12345678".to_string()],
            AttackIntensity::Medium => self.backup_code_config.code_patterns.clone(),
            AttackIntensity::High | AttackIntensity::Extreme => {
                let mut high_patterns = self.backup_code_config.code_patterns.clone();
                high_patterns.extend(vec![
                    "00000000".to_string(), "11111111".to_string(), "99999999".to_string()
                ]);
                high_patterns
            }
        };

        patterns.insert("backup_codes".to_string(), backup_patterns);
        patterns
    }

    /// Get evasion delay based on stealth mode
    pub fn get_evasion_delay(&self) -> u64 {
        if self.general_settings.stealth_mode {
            rand::random::<u64>() % 5000 + 1000 // 1-6 seconds
        } else {
            rand::random::<u64>() % 1000 + 100  // 100ms-1.1s
        }
    }

    /// Update configuration at runtime
    pub fn update_totp_config(&mut self, config: TotpAttackConfig) {
        self.totp_config = config;
    }

    pub fn update_backup_code_config(&mut self, config: BackupCodeConfig) {
        self.backup_code_config = config;
    }

    pub fn enable_stealth_mode(&mut self) {
        self.general_settings.stealth_mode = true;
        self.general_settings.max_concurrent_attacks = 1;
        self.totp_config.max_attempts = 100;
        self.backup_code_config.enumeration_delay_ms = 3000;
    }

    pub fn disable_stealth_mode(&mut self) {
        self.general_settings.stealth_mode = false;
        self.general_settings.max_concurrent_attacks = 5;
        self.totp_config.max_attempts = 1000;
        self.backup_code_config.enumeration_delay_ms = 100;
    }
}
