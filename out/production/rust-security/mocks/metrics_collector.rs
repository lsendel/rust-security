//! Mock implementation of `MetricsCollector` for testing

use crate::infrastructure::monitoring::MetricsCollector;

/// Mock metrics collector for testing
pub struct MockMetricsCollector(MetricsCollector);

impl MockMetricsCollector {
    /// Create a new mock metrics collector
    #[must_use]
    pub fn new() -> Self {
        // Create a real MetricsCollector for testing
        let collector =
            MetricsCollector::new().expect("Failed to create metrics collector for testing");
        Self(collector)
    }
}

impl Default for MockMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl From<MockMetricsCollector> for MetricsCollector {
    fn from(mock: MockMetricsCollector) -> Self {
        mock.0
    }
}
