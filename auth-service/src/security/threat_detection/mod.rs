//! Threat Detection Module
//!
//! This module provides comprehensive threat detection capabilities
//! including AI-based analysis, behavioral monitoring, and attack pattern recognition.

pub mod ai_threat_detection;
pub mod ai_threat_detection_advanced;
pub mod ml_threat_models;
pub mod threat_adapter;
pub mod threat_attack_patterns;
pub mod threat_behavioral_analyzer;
pub mod threat_hunting_orchestrator;
pub mod threat_processor;
pub mod threat_response_orchestrator;
pub mod threat_types;

// Re-export main types for easy access
pub use ai_threat_detection::AiThreatDetector;
pub use threat_attack_patterns::AttackPatternDetector;
pub use threat_types::*;
