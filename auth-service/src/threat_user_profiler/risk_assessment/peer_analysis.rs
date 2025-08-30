use crate::threat_user_profiler::types::{EnhancedUserBehaviorProfile, RiskFactor};
#[derive(Clone)]
pub struct PeerComparisonAnalyzer;
impl Default for PeerComparisonAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerComparisonAnalyzer {
    #[must_use] pub const fn new() -> Self {
        Self
    }
    pub async fn assess_peer_risks(
        &self,
        _profile: &EnhancedUserBehaviorProfile,
        _peers: &[EnhancedUserBehaviorProfile],
    ) -> Result<Vec<RiskFactor>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }
}
