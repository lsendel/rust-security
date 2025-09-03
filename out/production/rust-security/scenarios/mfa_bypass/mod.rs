pub mod types;
pub mod config;
pub mod totp;
pub mod backup_codes;
pub mod biometric;
pub mod webauthn;
pub mod push_notification;
pub mod coordinator;

pub use types::*;
pub use config::MfaBypassConfig;
pub use coordinator::MfaBypassCoordinator;

// Re-export key attack engines
pub use totp::TotpAttackEngine;

/// Main entry point for MFA bypass scenarios
pub async fn run_mfa_scenarios(
    framework: &mut crate::attack_framework::RedTeamFramework,
    reporter: &mut crate::reporting::RedTeamReporter,
    intensity: &str,
) -> anyhow::Result<()> {
    let attack_intensity = match intensity {
        "low" => AttackIntensity::Low,
        "medium" => AttackIntensity::Medium,
        "high" => AttackIntensity::High,
        "extreme" => AttackIntensity::Extreme,
        _ => AttackIntensity::Medium,
    };

    let config = match intensity {
        "low" => MfaBypassConfig::stealth_mode(),
        "high" | "extreme" => MfaBypassConfig::aggressive_mode(),
        _ => MfaBypassConfig::default(),
    };

    let mut coordinator = MfaBypassCoordinator::new(config);
    coordinator.run_all_scenarios(framework, reporter, attack_intensity).await
}
