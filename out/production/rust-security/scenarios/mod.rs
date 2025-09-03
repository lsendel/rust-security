//! Attack Scenarios Module
//!
//! Contains realistic attack scenarios that test the implemented security measures

use crate::attack_framework::RedTeamFramework;
use crate::reporting::RedTeamReporter;
use anyhow::Result;

pub mod authentication;
pub mod idor_attacks;
pub mod mfa_bypass;
pub mod oauth_manipulation;
pub mod rate_limit_bypass;
pub mod session_attacks;
pub mod social_engineering;
pub mod token_manipulation;

// Re-export scenario functions
pub use authentication::run_authentication_scenarios;
pub use idor_attacks::run_idor_scenarios;
pub use mfa_bypass::run_mfa_scenarios;
pub use oauth_manipulation::run_oauth_scenarios;
pub use rate_limit_bypass::run_rate_limit_scenarios;
pub use session_attacks::run_session_scenarios;
pub use social_engineering::run_social_engineering_scenarios;
pub use token_manipulation::run_token_scenarios;
