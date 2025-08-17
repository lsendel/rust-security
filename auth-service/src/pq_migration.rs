//! # Post-Quantum Migration and Performance Assessment
//! 
//! This module provides tools for migrating from classical to post-quantum cryptography,
//! performance benchmarking, compliance reporting, and rollback procedures.
//! 
//! ## Migration Features
//! - Phased migration strategies
//! - Performance impact assessment  
//! - Compatibility testing
//! - Rollback and recovery procedures
//! - Compliance reporting for NIST standards
//! - Real-time migration monitoring

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::post_quantum_crypto::{
    SecurityLevel, PQAlgorithm, MigrationMode, get_pq_manager, 
    PQFeatures, MigrationStatus
};
use crate::pq_key_management::{get_pq_key_manager, KeyOperation};
use crate::security_logging::{SecurityLogger, SecurityEvent, SecurityEventType, SecuritySeverity};

/// Migration phase configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPhase {
    pub phase_id: String,
    pub name: String,
    pub description: String,
    pub start_date: Option<u64>,
    pub target_completion: Option<u64>,
    pub prerequisites: Vec<String>,
    pub actions: Vec<MigrationAction>,
    pub rollback_plan: Vec<RollbackAction>,
    pub success_criteria: Vec<SuccessCriteria>,
    pub risk_assessment: RiskAssessment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationAction {
    pub action_id: String,
    pub action_type: ActionType,
    pub description: String,
    pub estimated_duration: Duration,
    pub impact_level: ImpactLevel,
    pub automation_level: AutomationLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    /// Deploy post-quantum algorithms alongside classical
    DeployHybrid,
    /// Update key generation to use post-quantum algorithms
    UpdateKeyGeneration,
    /// Migrate existing tokens to hybrid format
    MigrateTokens,
    /// Update client applications
    UpdateClients,
    /// Monitor performance and compatibility
    MonitorPerformance,
    /// Deprecate classical algorithms
    DeprecateClassical,
    /// Full cutover to post-quantum only
    PostQuantumCutover,
    /// Compliance validation
    ComplianceValidation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImpactLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutomationLevel {
    Manual,
    SemiAutomated,
    FullyAutomated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackAction {
    pub trigger: RollbackTrigger,
    pub procedure: String,
    pub estimated_time: Duration,
    pub data_preservation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RollbackTrigger {
    PerformanceDegradation(f64), // Percentage threshold
    CompatibilityIssue,
    SecurityIncident,
    ClientFailures(u64), // Number of failures
    ManualTrigger,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessCriteria {
    pub metric: String,
    pub target_value: f64,
    pub measurement_method: String,
    pub validation_period: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub overall_risk: RiskLevel,
    pub performance_risk: RiskLevel,
    pub compatibility_risk: RiskLevel,
    pub security_risk: RiskLevel,
    pub mitigation_strategies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Performance benchmark results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceBenchmark {
    pub timestamp: u64,
    pub algorithm: String,
    pub security_level: SecurityLevel,
    pub operation_type: String,
    pub sample_size: usize,
    pub metrics: PerformanceMetrics,
    pub system_info: SystemInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub avg_duration_ms: f64,
    pub min_duration_ms: f64,
    pub max_duration_ms: f64,
    pub p50_duration_ms: f64,
    pub p95_duration_ms: f64,
    pub p99_duration_ms: f64,
    pub throughput_ops_per_sec: f64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub error_rate_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub cpu_cores: usize,
    pub memory_gb: f64,
    pub os: String,
    pub architecture: String,
    pub rust_version: String,
}

/// Migration manager for coordinating the transition
pub struct MigrationManager {
    phases: RwLock<Vec<MigrationPhase>>,
    current_phase: RwLock<Option<String>>,
    performance_history: RwLock<Vec<PerformanceBenchmark>>,
    compatibility_status: RwLock<CompatibilityStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityStatus {
    pub classical_support: bool,
    pub hybrid_support: bool,
    pub post_quantum_support: bool,
    pub client_compatibility: HashMap<String, ClientCompatibility>,
    pub feature_matrix: PQFeatures,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCompatibility {
    pub client_id: String,
    pub supports_hybrid: bool,
    pub supports_post_quantum: bool,
    pub last_updated: u64,
    pub issues: Vec<String>,
}

impl MigrationManager {
    pub fn new() -> Self {
        Self {
            phases: RwLock::new(Self::default_migration_phases()),
            current_phase: RwLock::new(None),
            performance_history: RwLock::new(Vec::new()),
            compatibility_status: RwLock::new(CompatibilityStatus::default()),
        }
    }

    /// Get default migration phases for NIST post-quantum transition
    fn default_migration_phases() -> Vec<MigrationPhase> {
        vec![
            MigrationPhase {
                phase_id: "phase-1".to_string(),
                name: "Assessment and Planning".to_string(),
                description: "Inventory current cryptographic implementations and plan migration".to_string(),
                start_date: None,
                target_completion: None,
                prerequisites: vec![],
                actions: vec![
                    MigrationAction {
                        action_id: "inventory".to_string(),
                        action_type: ActionType::ComplianceValidation,
                        description: "Inventory all cryptographic implementations".to_string(),
                        estimated_duration: Duration::from_secs(7 * 24 * 3600), // 1 week
                        impact_level: ImpactLevel::Low,
                        automation_level: AutomationLevel::SemiAutomated,
                    },
                    MigrationAction {
                        action_id: "risk-assessment".to_string(),
                        action_type: ActionType::ComplianceValidation,
                        description: "Assess risks and create migration timeline".to_string(),
                        estimated_duration: Duration::from_secs(3 * 24 * 3600), // 3 days
                        impact_level: ImpactLevel::Medium,
                        automation_level: AutomationLevel::Manual,
                    },
                ],
                rollback_plan: vec![],
                success_criteria: vec![
                    SuccessCriteria {
                        metric: "inventory_completeness".to_string(),
                        target_value: 100.0,
                        measurement_method: "Manual review".to_string(),
                        validation_period: Duration::from_secs(24 * 3600),
                    },
                ],
                risk_assessment: RiskAssessment {
                    overall_risk: RiskLevel::Low,
                    performance_risk: RiskLevel::Low,
                    compatibility_risk: RiskLevel::Low,
                    security_risk: RiskLevel::Low,
                    mitigation_strategies: vec!["Thorough documentation".to_string()],
                },
            },
            MigrationPhase {
                phase_id: "phase-2".to_string(),
                name: "Hybrid Deployment".to_string(),
                description: "Deploy hybrid classical/post-quantum algorithms".to_string(),
                start_date: None,
                target_completion: None,
                prerequisites: vec!["phase-1".to_string()],
                actions: vec![
                    MigrationAction {
                        action_id: "deploy-hybrid".to_string(),
                        action_type: ActionType::DeployHybrid,
                        description: "Deploy hybrid cryptographic algorithms".to_string(),
                        estimated_duration: Duration::from_secs(14 * 24 * 3600), // 2 weeks
                        impact_level: ImpactLevel::Medium,
                        automation_level: AutomationLevel::FullyAutomated,
                    },
                    MigrationAction {
                        action_id: "performance-monitoring".to_string(),
                        action_type: ActionType::MonitorPerformance,
                        description: "Monitor performance impact of hybrid algorithms".to_string(),
                        estimated_duration: Duration::from_secs(30 * 24 * 3600), // 30 days
                        impact_level: ImpactLevel::Low,
                        automation_level: AutomationLevel::FullyAutomated,
                    },
                ],
                rollback_plan: vec![
                    RollbackAction {
                        trigger: RollbackTrigger::PerformanceDegradation(20.0),
                        procedure: "Disable hybrid algorithms and fallback to classical".to_string(),
                        estimated_time: Duration::from_secs(3600), // 1 hour
                        data_preservation: true,
                    },
                ],
                success_criteria: vec![
                    SuccessCriteria {
                        metric: "performance_degradation".to_string(),
                        target_value: 15.0, // Max 15% performance degradation
                        measurement_method: "Automated benchmarking".to_string(),
                        validation_period: Duration::from_secs(7 * 24 * 3600),
                    },
                ],
                risk_assessment: RiskAssessment {
                    overall_risk: RiskLevel::Medium,
                    performance_risk: RiskLevel::Medium,
                    compatibility_risk: RiskLevel::Medium,
                    security_risk: RiskLevel::Low,
                    mitigation_strategies: vec![
                        "Gradual rollout".to_string(),
                        "Real-time monitoring".to_string(),
                        "Automated rollback".to_string(),
                    ],
                },
            },
            MigrationPhase {
                phase_id: "phase-3".to_string(),
                name: "Client Migration".to_string(),
                description: "Update client applications to support post-quantum algorithms".to_string(),
                start_date: None,
                target_completion: None,
                prerequisites: vec!["phase-2".to_string()],
                actions: vec![
                    MigrationAction {
                        action_id: "client-updates".to_string(),
                        action_type: ActionType::UpdateClients,
                        description: "Update client applications for post-quantum support".to_string(),
                        estimated_duration: Duration::from_secs(60 * 24 * 3600), // 2 months
                        impact_level: ImpactLevel::High,
                        automation_level: AutomationLevel::Manual,
                    },
                ],
                rollback_plan: vec![
                    RollbackAction {
                        trigger: RollbackTrigger::ClientFailures(1000),
                        procedure: "Maintain classical algorithm support".to_string(),
                        estimated_time: Duration::from_secs(24 * 3600), // 24 hours
                        data_preservation: true,
                    },
                ],
                success_criteria: vec![
                    SuccessCriteria {
                        metric: "client_compatibility".to_string(),
                        target_value: 95.0, // 95% client compatibility
                        measurement_method: "Automated testing and monitoring".to_string(),
                        validation_period: Duration::from_secs(14 * 24 * 3600),
                    },
                ],
                risk_assessment: RiskAssessment {
                    overall_risk: RiskLevel::High,
                    performance_risk: RiskLevel::Medium,
                    compatibility_risk: RiskLevel::High,
                    security_risk: RiskLevel::Low,
                    mitigation_strategies: vec![
                        "Staged client rollout".to_string(),
                        "Backward compatibility".to_string(),
                        "Extensive testing".to_string(),
                    ],
                },
            },
            MigrationPhase {
                phase_id: "phase-4".to_string(),
                name: "Post-Quantum Transition".to_string(),
                description: "Transition to post-quantum only algorithms".to_string(),
                start_date: None,
                target_completion: None,
                prerequisites: vec!["phase-3".to_string()],
                actions: vec![
                    MigrationAction {
                        action_id: "deprecate-classical".to_string(),
                        action_type: ActionType::DeprecateClassical,
                        description: "Deprecate classical cryptographic algorithms".to_string(),
                        estimated_duration: Duration::from_secs(30 * 24 * 3600), // 30 days
                        impact_level: ImpactLevel::High,
                        automation_level: AutomationLevel::SemiAutomated,
                    },
                    MigrationAction {
                        action_id: "pq-cutover".to_string(),
                        action_type: ActionType::PostQuantumCutover,
                        description: "Complete cutover to post-quantum only".to_string(),
                        estimated_duration: Duration::from_secs(7 * 24 * 3600), // 7 days
                        impact_level: ImpactLevel::Critical,
                        automation_level: AutomationLevel::Manual,
                    },
                ],
                rollback_plan: vec![
                    RollbackAction {
                        trigger: RollbackTrigger::SecurityIncident,
                        procedure: "Re-enable hybrid algorithms immediately".to_string(),
                        estimated_time: Duration::from_secs(1800), // 30 minutes
                        data_preservation: true,
                    },
                ],
                success_criteria: vec![
                    SuccessCriteria {
                        metric: "post_quantum_adoption".to_string(),
                        target_value: 100.0,
                        measurement_method: "System configuration audit".to_string(),
                        validation_period: Duration::from_secs(30 * 24 * 3600),
                    },
                ],
                risk_assessment: RiskAssessment {
                    overall_risk: RiskLevel::Critical,
                    performance_risk: RiskLevel::Medium,
                    compatibility_risk: RiskLevel::High,
                    security_risk: RiskLevel::Medium,
                    mitigation_strategies: vec![
                        "Extensive testing".to_string(),
                        "Emergency rollback plan".to_string(),
                        "24/7 monitoring".to_string(),
                    ],
                },
            },
        ]
    }

    /// Start a migration phase
    pub async fn start_phase(&self, phase_id: &str) -> Result<()> {
        let mut phases = self.phases.write().await;
        let phase = phases.iter_mut()
            .find(|p| p.phase_id == phase_id)
            .ok_or_else(|| anyhow!("Phase not found: {}", phase_id))?;

        // Check prerequisites
        for prereq in &phase.prerequisites {
            // In a real implementation, you'd check if prerequisites are completed
            info!("Checking prerequisite: {}", prereq);
        }

        phase.start_date = Some(current_timestamp());
        
        let mut current_phase = self.current_phase.write().await;
        *current_phase = Some(phase_id.to_string());

        info!("Started migration phase: {} - {}", phase_id, phase.name);

        // Log phase start
        SecurityLogger::log_event(&SecurityEvent::new(
            SecurityEventType::SystemEvent,
            SecuritySeverity::Medium,
            "pq-migration".to_string(),
            format!("Migration phase started: {}", phase.name),
        )
        .with_detail("phase_id".to_string(), phase_id.to_string())
        .with_detail("risk_level".to_string(), format!("{:?}", phase.risk_assessment.overall_risk))
        .with_outcome("started".to_string()));

        Ok(())
    }

    /// Run performance benchmarks
    pub async fn run_performance_benchmark(&self, algorithm: PQAlgorithm, iterations: usize) -> Result<PerformanceBenchmark> {
        info!("Running performance benchmark for {:?} with {} iterations", algorithm, iterations);

        let start_time = Instant::now();
        let mut durations = Vec::new();
        let mut errors = 0;

        let manager = get_pq_manager();
        let key_manager = get_pq_key_manager();

        // Generate test data
        let test_data = b"This is test data for performance benchmarking of post-quantum cryptographic algorithms";

        // Benchmark signing operations
        for i in 0..iterations {
            let operation_start = Instant::now();
            
            match manager.sign(test_data, None).await {
                Ok(_signature) => {
                    let duration = operation_start.elapsed();
                    durations.push(duration.as_millis() as f64);
                    
                    // Record operation in key manager
                    if let Some(kid) = manager.current_signing_key_id().await {
                        let _ = key_manager.record_operation(&kid, KeyOperation::Sign, duration.as_millis() as u64).await;
                    }
                }
                Err(e) => {
                    errors += 1;
                    error!("Benchmark iteration {} failed: {}", i, e);
                    
                    if let Some(kid) = manager.current_signing_key_id().await {
                        let _ = key_manager.record_operation(&kid, KeyOperation::Error, 0).await;
                    }
                }
            }
        }

        let total_duration = start_time.elapsed();

        // Calculate metrics
        durations.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let metrics = PerformanceMetrics {
            avg_duration_ms: durations.iter().sum::<f64>() / durations.len() as f64,
            min_duration_ms: durations.first().copied().unwrap_or(0.0),
            max_duration_ms: durations.last().copied().unwrap_or(0.0),
            p50_duration_ms: percentile(&durations, 50.0),
            p95_duration_ms: percentile(&durations, 95.0),
            p99_duration_ms: percentile(&durations, 99.0),
            throughput_ops_per_sec: (iterations - errors) as f64 / total_duration.as_secs_f64(),
            memory_usage_mb: get_memory_usage_mb(),
            cpu_usage_percent: get_cpu_usage_percent(),
            error_rate_percent: (errors as f64 / iterations as f64) * 100.0,
        };

        let benchmark = PerformanceBenchmark {
            timestamp: current_timestamp(),
            algorithm: format!("{:?}", algorithm),
            security_level: SecurityLevel::Level3, // Default for benchmark
            operation_type: "sign".to_string(),
            sample_size: iterations,
            metrics,
            system_info: get_system_info(),
        };

        // Store benchmark result
        let mut history = self.performance_history.write().await;
        history.push(benchmark.clone());

        // Keep only last 1000 benchmarks
        while history.len() > 1000 {
            history.remove(0);
        }

        info!("Benchmark completed: avg={:.2}ms, throughput={:.2} ops/sec, errors={}",
            benchmark.metrics.avg_duration_ms,
            benchmark.metrics.throughput_ops_per_sec,
            errors
        );

        // Log benchmark completion
        SecurityLogger::log_event(&SecurityEvent::new(
            SecurityEventType::SystemEvent,
            SecuritySeverity::Low,
            "pq-migration".to_string(),
            "Performance benchmark completed".to_string(),
        )
        .with_detail("algorithm".to_string(), benchmark.algorithm.clone())
        .with_detail("iterations".to_string(), iterations)
        .with_detail("avg_duration_ms".to_string(), benchmark.metrics.avg_duration_ms)
        .with_detail("throughput_ops_per_sec".to_string(), benchmark.metrics.throughput_ops_per_sec)
        .with_detail("error_rate_percent".to_string(), benchmark.metrics.error_rate_percent)
        .with_outcome("completed".to_string()));

        Ok(benchmark)
    }

    /// Generate migration compliance report
    pub async fn generate_compliance_report(&self) -> ComplianceReport {
        let migration_status = get_pq_manager().migration_status();
        let current_phase = self.current_phase.read().await;
        let phases = self.phases.read().await;
        let performance_history = self.performance_history.read().await;
        let compatibility = self.compatibility_status.read().await;

        let completed_phases = phases.iter()
            .filter(|p| p.start_date.is_some())
            .count();

        let nist_compliance = NISTCompliance {
            fips_203_ml_kem: migration_status.features_available.kyber,
            fips_204_ml_dsa: migration_status.features_available.dilithium,
            sp_800_208_stateful_hash: false, // Not implemented in this module
            hybrid_support: migration_status.features_available.hybrid,
            migration_timeline_documented: true,
            risk_assessment_completed: completed_phases > 0,
            performance_benchmarks_available: !performance_history.is_empty(),
        };

        ComplianceReport {
            timestamp: current_timestamp(),
            migration_status: migration_status.mode.clone(),
            current_phase: current_phase.clone(),
            phase_completion: PhaseCompletion {
                total_phases: phases.len(),
                completed_phases,
                current_phase_progress: 0.0, // Would need more detailed tracking
            },
            nist_compliance,
            performance_summary: if performance_history.is_empty() {
                None
            } else {
                Some(PerformanceSummary {
                    total_benchmarks: performance_history.len(),
                    latest_benchmark_date: performance_history.last().map(|b| b.timestamp),
                    avg_performance_degradation: calculate_performance_degradation(&performance_history),
                })
            },
            compatibility_status: compatibility.clone(),
            recommendations: generate_recommendations(&migration_status, &phases, &performance_history),
        }
    }

    /// Check if rollback is needed
    pub async fn check_rollback_triggers(&self) -> Vec<RollbackTrigger> {
        let mut triggers = Vec::new();
        let performance_history = self.performance_history.read().await;
        
        // Check performance degradation
        if let Some(degradation) = calculate_performance_degradation(&performance_history) {
            if degradation > 25.0 { // 25% degradation threshold
                triggers.push(RollbackTrigger::PerformanceDegradation(degradation));
            }
        }

        // Check compatibility issues
        let compatibility = self.compatibility_status.read().await;
        let failed_clients = compatibility.client_compatibility.values()
            .filter(|c| !c.supports_hybrid && !c.supports_post_quantum)
            .count();

        if failed_clients > 100 {
            triggers.push(RollbackTrigger::ClientFailures(failed_clients as u64));
        }

        triggers
    }

    /// Execute rollback procedure
    pub async fn execute_rollback(&self, trigger: RollbackTrigger) -> Result<()> {
        warn!("Executing rollback due to trigger: {:?}", trigger);

        // Log rollback initiation
        SecurityLogger::log_event(&SecurityEvent::new(
            SecurityEventType::SystemEvent,
            SecuritySeverity::Critical,
            "pq-migration".to_string(),
            "Migration rollback initiated".to_string(),
        )
        .with_detail("trigger".to_string(), format!("{:?}", trigger))
        .with_outcome("initiated".to_string()));

        // Implementation would depend on the current migration state
        // For now, we'll just log the action
        match trigger {
            RollbackTrigger::PerformanceDegradation(percentage) => {
                info!("Rollback: Performance degradation {}% exceeded threshold", percentage);
                // Would disable post-quantum algorithms and fallback to classical
            }
            RollbackTrigger::ClientFailures(count) => {
                info!("Rollback: {} client failures exceeded threshold", count);
                // Would re-enable full backward compatibility
            }
            RollbackTrigger::SecurityIncident => {
                error!("Rollback: Security incident detected");
                // Would immediately disable post-quantum and revert to known-good state
            }
            _ => {
                info!("Rollback: Manual or compatibility trigger");
            }
        }

        Ok(())
    }

    /// Get migration timeline
    pub async fn get_migration_timeline(&self) -> MigrationTimeline {
        let phases = self.phases.read().await;
        let current_phase = self.current_phase.read().await;

        MigrationTimeline {
            phases: phases.clone(),
            current_phase: current_phase.clone(),
            estimated_completion: phases.iter()
                .filter_map(|p| p.target_completion)
                .max(),
            total_estimated_duration: phases.iter()
                .map(|p| p.actions.iter()
                    .map(|a| a.estimated_duration.as_secs())
                    .sum::<u64>())
                .sum(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub timestamp: u64,
    pub migration_status: MigrationMode,
    pub current_phase: Option<String>,
    pub phase_completion: PhaseCompletion,
    pub nist_compliance: NISTCompliance,
    pub performance_summary: Option<PerformanceSummary>,
    pub compatibility_status: CompatibilityStatus,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhaseCompletion {
    pub total_phases: usize,
    pub completed_phases: usize,
    pub current_phase_progress: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NISTCompliance {
    pub fips_203_ml_kem: bool,    // CRYSTALS-Kyber support
    pub fips_204_ml_dsa: bool,    // CRYSTALS-Dilithium support
    pub sp_800_208_stateful_hash: bool, // Stateful hash-based signatures
    pub hybrid_support: bool,
    pub migration_timeline_documented: bool,
    pub risk_assessment_completed: bool,
    pub performance_benchmarks_available: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub total_benchmarks: usize,
    pub latest_benchmark_date: Option<u64>,
    pub avg_performance_degradation: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationTimeline {
    pub phases: Vec<MigrationPhase>,
    pub current_phase: Option<String>,
    pub estimated_completion: Option<u64>,
    pub total_estimated_duration: u64,
}

impl Default for CompatibilityStatus {
    fn default() -> Self {
        Self {
            classical_support: true,
            hybrid_support: cfg!(feature = "hybrid-crypto"),
            post_quantum_support: cfg!(feature = "post-quantum"),
            client_compatibility: HashMap::new(),
            feature_matrix: PQFeatures {
                dilithium: cfg!(feature = "post-quantum"),
                kyber: cfg!(feature = "post-quantum"),
                hybrid: cfg!(feature = "hybrid-crypto"),
            },
        }
    }
}

/// Helper functions
fn percentile(sorted_data: &[f64], percentile: f64) -> f64 {
    if sorted_data.is_empty() {
        return 0.0;
    }
    let index = (percentile / 100.0 * (sorted_data.len() - 1) as f64).round() as usize;
    sorted_data.get(index).copied().unwrap_or(0.0)
}

fn get_memory_usage_mb() -> f64 {
    // Placeholder - in production, would use system metrics
    0.0
}

fn get_cpu_usage_percent() -> f64 {
    // Placeholder - in production, would use system metrics
    0.0
}

fn get_system_info() -> SystemInfo {
    SystemInfo {
        cpu_cores: num_cpus::get(),
        memory_gb: 0.0, // Would get from system
        os: std::env::consts::OS.to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        rust_version: env!("CARGO_PKG_RUST_VERSION").to_string(),
    }
}

fn calculate_performance_degradation(history: &[PerformanceBenchmark]) -> Option<f64> {
    if history.len() < 2 {
        return None;
    }
    
    let baseline = history.first()?.metrics.avg_duration_ms;
    let current = history.last()?.metrics.avg_duration_ms;
    
    Some(((current - baseline) / baseline) * 100.0)
}

fn generate_recommendations(
    status: &MigrationStatus,
    phases: &[MigrationPhase],
    performance_history: &[PerformanceBenchmark],
) -> Vec<String> {
    let mut recommendations = Vec::new();

    if !status.post_quantum_enabled {
        recommendations.push("Enable post-quantum cryptography features".to_string());
    }

    if !status.hybrid_enabled && status.post_quantum_enabled {
        recommendations.push("Enable hybrid cryptography for smoother migration".to_string());
    }

    if performance_history.is_empty() {
        recommendations.push("Run performance benchmarks to assess impact".to_string());
    }

    if phases.iter().all(|p| p.start_date.is_none()) {
        recommendations.push("Begin migration planning and start Phase 1".to_string());
    }

    recommendations
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Global migration manager
static MIGRATION_MANAGER: once_cell::sync::Lazy<MigrationManager> = 
    once_cell::sync::Lazy::new(|| MigrationManager::new());

/// Get the global migration manager
pub fn get_migration_manager() -> &'static MigrationManager {
    &MIGRATION_MANAGER
}

/// Initialize migration management
pub async fn initialize_migration_management() -> Result<()> {
    info!("Migration management initialized");
    Ok(())
}

/// Convenience function to run a performance benchmark
pub async fn run_benchmark(algorithm: PQAlgorithm, iterations: usize) -> Result<PerformanceBenchmark> {
    get_migration_manager().run_performance_benchmark(algorithm, iterations).await
}

/// Generate a compliance report
pub async fn generate_compliance_report() -> ComplianceReport {
    get_migration_manager().generate_compliance_report().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_phases_default() {
        let phases = MigrationManager::default_migration_phases();
        assert_eq!(phases.len(), 4);
        assert_eq!(phases[0].phase_id, "phase-1");
        assert_eq!(phases[0].name, "Assessment and Planning");
    }

    #[test]
    fn test_risk_levels() {
        let risk = RiskLevel::Medium;
        assert_eq!(format!("{:?}", risk), "Medium");
    }

    #[test]
    fn test_percentile_calculation() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(percentile(&data, 50.0), 3.0);
        assert_eq!(percentile(&data, 95.0), 5.0);
    }

    #[tokio::test]
    async fn test_migration_manager_creation() {
        let manager = MigrationManager::new();
        let timeline = manager.get_migration_timeline().await;
        assert_eq!(timeline.phases.len(), 4);
    }

    #[test]
    fn test_compatibility_status_default() {
        let status = CompatibilityStatus::default();
        assert!(status.classical_support);
        // Other fields depend on compile-time features
    }
}
