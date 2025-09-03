//! Mock implementation of `HealthChecker` for testing

use crate::health_check::HealthChecker;

/// Mock health checker for testing
pub struct MockHealthChecker(HealthChecker);

impl MockHealthChecker {
    /// Create a new mock health checker
    #[must_use]
    pub fn new() -> Self {
        Self(HealthChecker::new())
    }
}

impl Default for MockHealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl From<MockHealthChecker> for HealthChecker {
    fn from(mock: MockHealthChecker) -> Self {
        mock.0
    }
}
