pub mod config;
pub mod features;
pub mod ml_models;
pub mod profiler;
pub mod risk_assessment;
pub mod time_series;
pub mod types;

pub use config::*;
pub use profiler::AdvancedUserBehaviorProfiler;
pub use types::*;

// Re-export key components for easy access
pub use features::BehavioralFeatureExtractor;
pub use ml_models::MLModelManager;
pub use risk_assessment::RiskAssessmentEngine;
pub use time_series::{BehavioralForecaster, TimeSeriesAnalyzer};
