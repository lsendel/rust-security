pub struct BehavioralForecaster;
pub struct ForecastEngine;

impl Default for BehavioralForecaster {
    fn default() -> Self {
        Self::new()
    }
}

impl BehavioralForecaster {
    #[must_use] pub const fn new() -> Self {
        Self
    }
}

impl Default for ForecastEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ForecastEngine {
    #[must_use] pub const fn new() -> Self {
        Self
    }
}
