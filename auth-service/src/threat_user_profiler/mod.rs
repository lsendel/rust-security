pub mod types;
pub mod config;
pub mod time_series;
pub mod features;
pub mod risk_assessment;
pub mod ml_models;
pub mod profiler;

pub use types::*;
pub use config::*;
pub use profiler::AdvancedUserBehaviorProfiler;

// Re-export key components for easy access
pub use time_series::{TimeSeriesAnalyzer, BehavioralForecaster};
pub use features::BehavioralFeatureExtractor;
pub use risk_assessment::RiskAssessmentEngine;
pub use ml_models::MLModelManager;
