//! Quality Gates Module for Automated Quality Assurance
//!
//! This module provides comprehensive quality gate functionality including:
//! - CI/CD pipeline integration and quality enforcement
//! - Automated quality checks and validation
//! - Quality metrics collection and reporting
//! - Quality gate rules and thresholds
//! - Quality dashboard and monitoring
//! - Automated validation workflows

pub mod checks;
pub mod dashboard;
pub mod enforcement;
pub mod metrics;
pub mod pipeline;
pub mod reporting;

// Re-export main quality gate types
pub use checks::{CheckResult, CheckType, QualityCheck};
pub use dashboard::{DashboardConfig, QualityDashboard, QualityStatus};
pub use enforcement::{EnforcementResult, GatePolicy, QualityGate};
pub use metrics::{MetricThreshold, QualityMetricsCollector, QualityScore};
pub use pipeline::{PipelineResult, PipelineStage, QualityPipeline};
pub use reporting::{QualityReport, ReportFormat, ReportGenerator};

/// Quality gate configuration
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct QualityGateConfig {
    /// Enable quality gates
    pub enabled: bool,
    /// Fail build on quality gate failures
    pub fail_on_failure: bool,
    /// Quality thresholds
    pub thresholds: QualityThresholds,
    /// Required checks
    pub required_checks: Vec<String>,
    /// Optional checks
    pub optional_checks: Vec<String>,
    /// Quality gate policies
    pub policies: Vec<GatePolicy>,
    /// CI/CD integration settings
    pub ci_cd_config: CiCdConfig,
    /// Reporting configuration
    pub reporting_config: ReportingConfig,
}

/// Quality thresholds
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct QualityThresholds {
    pub min_test_coverage: f64,
    pub max_security_issues: usize,
    pub max_performance_issues: usize,
    pub max_maintainability_issues: usize,
    pub min_code_quality_score: f64,
    pub max_build_warnings: usize,
    pub max_build_errors: usize,
}

/// CI/CD configuration
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CiCdConfig {
    pub supported_platforms: Vec<String>,
    pub timeout_minutes: u64,
    pub retry_attempts: u32,
    pub parallel_execution: bool,
    pub cache_enabled: bool,
}

/// Reporting configuration
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ReportingConfig {
    pub generate_reports: bool,
    pub report_formats: Vec<String>,
    pub publish_reports: bool,
    pub notification_channels: Vec<String>,
    pub dashboard_enabled: bool,
}

/// Quality gate orchestrator
pub struct QualityGateOrchestrator {
    config: QualityGateConfig,
    pipeline: QualityPipeline,
    checks: Vec<Box<dyn QualityCheck>>,
    metrics_collector: QualityMetricsCollector,
    dashboard: QualityDashboard,
    enforcement: QualityGate,
}

impl QualityGateOrchestrator {
    /// Create new quality gate orchestrator
    pub fn new(config: QualityGateConfig) -> Self {
        Self {
            pipeline: QualityPipeline::new(),
            checks: Vec::new(),
            metrics_collector: QualityMetricsCollector::new(),
            dashboard: QualityDashboard::new(DashboardConfig::default()),
            enforcement: QualityGate::new(config.policies.clone()),
            config,
        }
    }

    /// Add quality check
    pub fn add_check(&mut self, check: Box<dyn QualityCheck>) {
        self.checks.push(check);
    }

    /// Execute all quality gates
    pub async fn execute_quality_gates(
        &self,
        context: &QualityContext,
    ) -> Result<QualityGateResult, QualityError> {
        let start_time = std::time::Instant::now();

        // Initialize pipeline
        self.pipeline.initialize(context).await?;

        // Execute all checks
        let mut check_results = Vec::new();
        for check in &self.checks {
            let result = check.execute(context).await?;
            check_results.push(result);
        }

        // Collect metrics
        let metrics = self
            .metrics_collector
            .collect_metrics(&check_results)
            .await?;

        // Evaluate against thresholds
        let threshold_evaluation = self.evaluate_thresholds(&metrics)?;

        // Apply enforcement policies
        let enforcement_result = self
            .enforcement
            .enforce(&check_results, &metrics, context)
            .await?;

        // Generate final result
        // Safe casting to prevent potential truncation
        let execution_time_ms = start_time.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let overall_status = self.determine_overall_status(
            &check_results,
            &threshold_evaluation,
            &enforcement_result,
        );

        let result = QualityGateResult {
            status: overall_status,
            check_results,
            metrics,
            threshold_evaluation,
            enforcement_result,
            execution_time_ms,
            timestamp: chrono::Utc::now(),
            recommendations: self.generate_recommendations(&check_results, &metrics),
        };

        // Update dashboard
        self.dashboard.update(&result).await?;

        // Generate report if configured
        if self.config.reporting_config.generate_reports {
            self.generate_report(&result).await?;
        }

        Ok(result)
    }

    /// Evaluate metrics against thresholds
    fn evaluate_thresholds(
        &self,
        metrics: &QualityScore,
    ) -> Result<ThresholdEvaluation, QualityError> {
        let mut violations = Vec::new();

        if metrics.test_coverage < self.config.thresholds.min_test_coverage {
            violations.push(ThresholdViolation {
                metric: "test_coverage".to_string(),
                actual_value: metrics.test_coverage,
                threshold_value: self.config.thresholds.min_test_coverage,
                severity: ViolationSeverity::High,
            });
        }

        if metrics.security_issues > self.config.thresholds.max_security_issues {
            violations.push(ThresholdViolation {
                metric: "security_issues".to_string(),
                actual_value: metrics.security_issues as f64,
                threshold_value: self.config.thresholds.max_security_issues as f64,
                severity: ViolationSeverity::Critical,
            });
        }

        if metrics.performance_issues > self.config.thresholds.max_performance_issues {
            violations.push(ThresholdViolation {
                metric: "performance_issues".to_string(),
                actual_value: metrics.performance_issues as f64,
                threshold_value: self.config.thresholds.max_performance_issues as f64,
                severity: ViolationSeverity::Medium,
            });
        }

        if metrics.maintainability_issues > self.config.thresholds.max_maintainability_issues {
            violations.push(ThresholdViolation {
                metric: "maintainability_issues".to_string(),
                actual_value: metrics.maintainability_issues as f64,
                threshold_value: self.config.thresholds.max_maintainability_issues as f64,
                severity: ViolationSeverity::Medium,
            });
        }

        if metrics.code_quality_score < self.config.thresholds.min_code_quality_score {
            violations.push(ThresholdViolation {
                metric: "code_quality_score".to_string(),
                actual_value: metrics.code_quality_score,
                threshold_value: self.config.thresholds.min_code_quality_score,
                severity: ViolationSeverity::High,
            });
        }

        Ok(ThresholdEvaluation {
            passed: violations.is_empty(),
            violations,
        })
    }

    /// Determine overall status
    fn determine_overall_status(
        &self,
        check_results: &[CheckResult],
        threshold_evaluation: &ThresholdEvaluation,
        enforcement_result: &EnforcementResult,
    ) -> QualityStatus {
        // Check for critical violations
        if threshold_evaluation
            .violations
            .iter()
            .any(|v| matches!(v.severity, ViolationSeverity::Critical))
        {
            return QualityStatus::Failed;
        }

        // Check enforcement result
        if !enforcement_result.allowed {
            return QualityStatus::Blocked;
        }

        // Check if any required checks failed
        let required_checks_passed = check_results
            .iter()
            .filter(|r| {
                self.config
                    .required_checks
                    .contains(&r.check_type.to_string())
            })
            .all(|r| matches!(r.status, CheckStatus::Passed));

        if !required_checks_passed {
            return QualityStatus::Failed;
        }

        // Check for high severity issues
        let has_high_issues = check_results.iter().any(|r| {
            r.issues.iter().any(|issue| {
                matches!(
                    issue.severity,
                    IssueSeverity::High | IssueSeverity::Critical
                )
            })
        });

        if has_high_issues {
            return QualityStatus::Warning;
        }

        QualityStatus::Passed
    }

    /// Generate recommendations
    fn generate_recommendations(
        &self,
        check_results: &[CheckResult],
        metrics: &QualityScore,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if metrics.test_coverage < 80.0 {
            recommendations.push("Increase test coverage by adding more unit tests".to_string());
        }

        if metrics.security_issues > 0 {
            recommendations.push("Address security issues identified in the checks".to_string());
        }

        if metrics.code_quality_score < 7.0 {
            recommendations
                .push("Improve code quality by following established patterns".to_string());
        }

        if metrics.performance_issues > 0 {
            recommendations
                .push("Optimize performance bottlenecks identified in profiling".to_string());
        }

        let failed_checks: Vec<_> = check_results
            .iter()
            .filter(|r| !matches!(r.status, CheckStatus::Passed))
            .collect();

        if !failed_checks.is_empty() {
            recommendations.push(format!(
                "Fix issues in {} failed checks",
                failed_checks.len()
            ));
        }

        recommendations
    }

    /// Generate quality report
    async fn generate_report(&self, result: &QualityGateResult) -> Result<(), QualityError> {
        let report_generator = ReportGenerator::new();

        for format in &self.config.reporting_config.report_formats {
            let report = report_generator.generate_report(result, format)?;

            // In a real implementation, this would save or publish the report
            println!("Generated {} report", format);
        }

        Ok(())
    }

    /// Get quality dashboard
    pub fn get_dashboard(&self) -> &QualityDashboard {
        &self.dashboard
    }

    /// Get current configuration
    pub fn get_config(&self) -> &QualityGateConfig {
        &self.config
    }

    /// Update configuration
    pub fn update_config(&mut self, config: QualityGateConfig) -> Result<(), QualityError> {
        self.config = config;
        Ok(())
    }
}

/// Quality context
#[derive(Debug, Clone)]
pub struct QualityContext {
    pub repository: String,
    pub branch: String,
    pub commit_hash: String,
    pub author: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub environment: QualityEnvironment,
    pub triggered_by: TriggerSource,
}

/// Quality environment
#[derive(Debug, Clone, PartialEq)]
pub enum QualityEnvironment {
    Local,
    CI,
    CD,
    Development,
    Staging,
    Production,
}

/// Trigger source
#[derive(Debug, Clone, PartialEq)]
pub enum TriggerSource {
    Manual,
    PreCommit,
    Push,
    PullRequest,
    Scheduled,
    Deployment,
}

/// Quality gate result
#[derive(Debug, Clone)]
pub struct QualityGateResult {
    pub status: QualityStatus,
    pub check_results: Vec<CheckResult>,
    pub metrics: QualityScore,
    pub threshold_evaluation: ThresholdEvaluation,
    pub enforcement_result: EnforcementResult,
    pub execution_time_ms: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub recommendations: Vec<String>,
}

/// Quality status
#[derive(Debug, Clone, PartialEq)]
pub enum QualityStatus {
    Passed,
    Warning,
    Failed,
    Blocked,
}

/// Threshold evaluation
#[derive(Debug, Clone)]
pub struct ThresholdEvaluation {
    pub passed: bool,
    pub violations: Vec<ThresholdViolation>,
}

/// Threshold violation
#[derive(Debug, Clone)]
pub struct ThresholdViolation {
    pub metric: String,
    pub actual_value: f64,
    pub threshold_value: f64,
    pub severity: ViolationSeverity,
}

/// Violation severity
#[derive(Debug, Clone, PartialEq)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Enforcement result
#[derive(Debug, Clone)]
pub struct EnforcementResult {
    pub allowed: bool,
    pub reason: Option<String>,
    pub applied_policies: Vec<String>,
}

/// Quality error
#[derive(Debug, thiserror::Error)]
pub enum QualityError {
    #[error("Quality gate execution failed: {message}")]
    ExecutionFailed { message: String },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    #[error("Check execution failed: {message}")]
    CheckFailed { message: String },

    #[error("Metrics collection failed: {message}")]
    MetricsFailed { message: String },

    #[error("Enforcement failed: {message}")]
    EnforcementFailed { message: String },

    #[error("Reporting failed: {message}")]
    ReportingFailed { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quality_gate_config_defaults() {
        let config = QualityGateConfig {
            enabled: true,
            fail_on_failure: true,
            thresholds: QualityThresholds {
                min_test_coverage: 80.0,
                max_security_issues: 0,
                max_performance_issues: 5,
                max_maintainability_issues: 10,
                min_code_quality_score: 7.0,
                max_build_warnings: 0,
                max_build_errors: 0,
            },
            required_checks: vec!["security".to_string(), "tests".to_string()],
            optional_checks: vec!["performance".to_string()],
            policies: vec![],
            ci_cd_config: CiCdConfig {
                supported_platforms: vec!["github".to_string(), "gitlab".to_string()],
                timeout_minutes: 30,
                retry_attempts: 2,
                parallel_execution: true,
                cache_enabled: true,
            },
            reporting_config: ReportingConfig {
                generate_reports: true,
                report_formats: vec!["json".to_string(), "html".to_string()],
                publish_reports: true,
                notification_channels: vec!["slack".to_string()],
                dashboard_enabled: true,
            },
        };

        assert!(config.enabled);
        assert!(config.fail_on_failure);
        assert_eq!(config.thresholds.min_test_coverage, 80.0);
        assert!(config.ci_cd_config.parallel_execution);
    }

    #[test]
    fn test_quality_context_creation() {
        let context = QualityContext {
            repository: "my-repo".to_string(),
            branch: "main".to_string(),
            commit_hash: "abc123".to_string(),
            author: "test@example.com".to_string(),
            timestamp: chrono::Utc::now(),
            environment: QualityEnvironment::CI,
            triggered_by: TriggerSource::Push,
        };

        assert_eq!(context.repository, "my-repo");
        assert_eq!(context.branch, "main");
        assert_eq!(context.commit_hash, "abc123");
    }

    #[test]
    fn test_threshold_evaluation() {
        let config = QualityGateConfig {
            enabled: true,
            fail_on_failure: true,
            thresholds: QualityThresholds {
                min_test_coverage: 80.0,
                max_security_issues: 0,
                max_performance_issues: 5,
                max_maintainability_issues: 10,
                min_code_quality_score: 7.0,
                max_build_warnings: 0,
                max_build_errors: 0,
            },
            required_checks: vec![],
            optional_checks: vec![],
            policies: vec![],
            ci_cd_config: CiCdConfig::default(),
            reporting_config: ReportingConfig::default(),
        };

        let orchestrator = QualityGateOrchestrator::new(config);

        // Test with good metrics
        let good_metrics = QualityScore {
            test_coverage: 85.0,
            security_issues: 0,
            performance_issues: 3,
            maintainability_issues: 5,
            code_quality_score: 8.0,
            build_warnings: 0,
            build_errors: 0,
        };

        let evaluation = orchestrator.evaluate_thresholds(&good_metrics).unwrap();
        assert!(evaluation.passed);
        assert!(evaluation.violations.is_empty());

        // Test with poor metrics
        let poor_metrics = QualityScore {
            test_coverage: 50.0,
            security_issues: 2,
            performance_issues: 10,
            maintainability_issues: 20,
            code_quality_score: 4.0,
            build_warnings: 5,
            build_errors: 1,
        };

        let evaluation = orchestrator.evaluate_thresholds(&poor_metrics).unwrap();
        assert!(!evaluation.passed);
        assert!(!evaluation.violations.is_empty());
    }

    #[test]
    fn test_overall_status_determination() {
        let config = QualityGateConfig::default();
        let orchestrator = QualityGateOrchestrator::new(config);

        // Test with all passing
        let check_results = vec![CheckResult {
            check_type: CheckType::Security,
            status: CheckStatus::Passed,
            issues: vec![],
            execution_time_ms: 100,
            timestamp: chrono::Utc::now(),
        }];

        let threshold_evaluation = ThresholdEvaluation {
            passed: true,
            violations: vec![],
        };

        let enforcement_result = EnforcementResult {
            allowed: true,
            reason: None,
            applied_policies: vec![],
        };

        let status = orchestrator.determine_overall_status(
            &check_results,
            &threshold_evaluation,
            &enforcement_result,
        );
        assert!(matches!(status, QualityStatus::Passed));
    }
}
