pub struct StatisticalAnalyzer;

impl Default for StatisticalAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl StatisticalAnalyzer {
    #[must_use] pub const fn new() -> Self {
        Self
    }
}
