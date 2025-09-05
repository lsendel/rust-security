use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

/// Chaos Engineering Orchestrator for Rust Security Platform
/// Provides comprehensive fault injection and resilience testing
#[derive(Debug, Clone)]
pub struct ChaosOrchestrator {
    config: Arc<ChaosConfig>,
    experiments: Arc<RwLock<HashMap<String, ChaosExperiment>>>,
    safety_manager: Arc<SafetyManager>,
    metrics_collector: Arc<Mutex<MetricsCollector>>,
    notification_service: Arc<NotificationService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosConfig {
    pub safety_guardrails: SafetyGuardrails,
    pub allowed_namespaces: Vec<String>,
    pub forbidden_namespaces: Vec<String>,
    pub max_concurrent_experiments: usize,
    pub default_timeout: Duration,
    pub monitoring_enabled: bool,
    pub auto_recovery: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyGuardrails {
    pub max_packet_loss_percent: f64,
    pub max_latency_ms: u64,
    pub max_memory_stress_percent: f64,
    pub max_cpu_stress_percent: f64,
    pub min_healthy_replicas: usize,
    pub max_experiment_duration_minutes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosExperiment {
    pub id: String,
    pub name: String,
    pub experiment_type: ExperimentType,
    pub target: ExperimentTarget,
    pub parameters: ExperimentParameters,
    pub duration: Duration,
    pub status: ExperimentStatus,
    pub start_time: Option<chrono::DateTime<Utc>>,
    pub end_time: Option<chrono::DateTime<Utc>>,
    pub safety_checks: Vec<SafetyCheck>,
    pub metrics: ExperimentMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExperimentType {
    PodKill,
    PodFailure,
    NetworkPartition,
    NetworkLatency,
    NetworkPacketLoss,
    DnsFailure,
    IoDelay,
    IoError,
    MemoryStress,
    CpuStress,
    DiskFull,
    SystemdFailure,
    JvmException,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentTarget {
    pub namespace: String,
    pub selector: HashMap<String, String>,
    pub mode: TargetMode,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetMode {
    One,
    All,
    Fixed(usize),
    RandomMaxPercent(f64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentParameters {
    // Network chaos parameters
    pub latency_ms: Option<u64>,
    pub packet_loss_percent: Option<f64>,
    pub bandwidth_limit: Option<String>,
    pub network_partition_direction: Option<String>,

    // Pod chaos parameters
    pub grace_period_seconds: Option<u64>,
    pub force_kill: Option<bool>,

    // Stress testing parameters
    pub memory_size: Option<String>,
    pub cpu_load_percent: Option<f64>,
    pub workers: Option<usize>,

    // IO chaos parameters
    pub delay_ms: Option<u64>,
    pub error_percent: Option<f64>,
    pub volume_path: Option<String>,

    // DNS chaos parameters
    pub dns_domain_patterns: Option<Vec<String>>,
    pub dns_server: Option<String>,

    // Custom parameters
    pub custom: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExperimentStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
    SafetyViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyCheck {
    pub name: String,
    pub description: String,
    pub check_type: SafetyCheckType,
    pub threshold: f64,
    pub current_value: Option<f64>,
    pub status: SafetyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SafetyCheckType {
    ServiceAvailability,
    ResponseTime,
    ErrorRate,
    ResourceUtilization,
    ReplicaCount,
    NetworkConnectivity,
    DataConsistency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SafetyStatus {
    Passing,
    Warning,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentMetrics {
    pub service_availability: HashMap<String, f64>,
    pub response_times_p95: HashMap<String, f64>,
    pub error_rates: HashMap<String, f64>,
    pub resource_utilization: HashMap<String, f64>,
    pub network_metrics: NetworkMetrics,
    pub recovery_time_seconds: Option<f64>,
    pub blast_radius: BlastRadiusMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub latency_p95_ms: f64,
    pub packet_loss_percent: f64,
    pub throughput_mbps: f64,
    pub connection_errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusMetrics {
    pub affected_services: Vec<String>,
    pub affected_pods: usize,
    pub affected_nodes: usize,
    pub downstream_impact: HashMap<String, f64>,
}

#[derive(Debug)]
pub struct SafetyManager {
    config: ChaosConfig,
}

#[derive(Debug)]
pub struct MetricsCollector {
    experiments: HashMap<String, ExperimentMetrics>,
}

#[derive(Debug)]
pub struct NotificationService {
    webhook_url: Option<String>,
    slack_webhook: Option<String>,
    email_enabled: bool,
}

impl ChaosOrchestrator {
    pub async fn new(config: ChaosConfig) -> Result<Self> {
        let safety_manager = Arc::new(SafetyManager::new(config.clone()));
        let metrics_collector = Arc::new(Mutex::new(MetricsCollector::new()));
        let notification_service = Arc::new(NotificationService::new().await?);

        Ok(Self {
            config: Arc::new(config),
            experiments: Arc::new(RwLock::new(HashMap::new())),
            safety_manager,
            metrics_collector,
            notification_service,
        })
    }

    /// Schedule a new chaos experiment with safety validation
    pub async fn schedule_experiment(&self, experiment: ChaosExperiment) -> Result<String> {
        // Validate experiment against safety guardrails
        self.safety_manager.validate_experiment(&experiment).await?;

        // Check concurrent experiment limits
        let current_experiments = self.experiments.read().await;
        let running_count = current_experiments
            .values()
            .filter(|e| matches!(e.status, ExperimentStatus::Running))
            .count();

        if running_count >= self.config.max_concurrent_experiments {
            return Err(anyhow::anyhow!(
                "Maximum concurrent experiments limit reached: {}",
                self.config.max_concurrent_experiments
            ));
        }

        drop(current_experiments);

        // Store experiment
        let mut experiments = self.experiments.write().await;
        experiments.insert(experiment.id.clone(), experiment.clone());
        drop(experiments);

        info!(
            experiment_id = %experiment.id,
            experiment_type = ?experiment.experiment_type,
            target_namespace = %experiment.target.namespace,
            "Chaos experiment scheduled"
        );

        // Send notification
        self.notification_service.send_experiment_notification(&experiment, "scheduled").await?;

        Ok(experiment.id)
    }

    /// Execute a scheduled chaos experiment
    pub async fn execute_experiment(&self, experiment_id: &str) -> Result<()> {
        let mut experiments = self.experiments.write().await;
        let experiment = experiments.get_mut(experiment_id).context("Experiment not found")?;

        experiment.status = ExperimentStatus::Running;
        experiment.start_time = Some(Utc::now());

        let experiment_clone = experiment.clone();
        drop(experiments);

        info!(
            experiment_id = %experiment_id,
            experiment_type = ?experiment_clone.experiment_type,
            "Starting chaos experiment execution"
        );

        // Execute the actual chaos experiment
        match self.execute_experiment_by_type(&experiment_clone).await {
            Ok(_) => {
                self.update_experiment_status(experiment_id, ExperimentStatus::Running).await?;

                // Start monitoring and safety checks
                self.start_experiment_monitoring(experiment_id).await?;
            }
            Err(e) => {
                error!(
                    experiment_id = %experiment_id,
                    error = %e,
                    "Failed to execute chaos experiment"
                );

                self.update_experiment_status(experiment_id, ExperimentStatus::Failed).await?;

                return Err(e);
            }
        }

        Ok(())
    }

    /// Execute experiment based on type
    async fn execute_experiment_by_type(&self, experiment: &ChaosExperiment) -> Result<()> {
        match experiment.experiment_type {
            ExperimentType::PodKill => self.execute_pod_kill(experiment).await,
            ExperimentType::NetworkLatency => self.execute_network_latency(experiment).await,
            ExperimentType::NetworkPacketLoss => self.execute_network_packet_loss(experiment).await,
            ExperimentType::MemoryStress => self.execute_memory_stress(experiment).await,
            ExperimentType::CpuStress => self.execute_cpu_stress(experiment).await,
            ExperimentType::DnsFailure => self.execute_dns_failure(experiment).await,
            ExperimentType::IoDelay => self.execute_io_delay(experiment).await,
            _ => Err(anyhow::anyhow!("Experiment type not implemented yet")),
        }
    }

    async fn execute_pod_kill(&self, experiment: &ChaosExperiment) -> Result<()> {
        let manifest = self.generate_pod_kill_manifest(experiment)?;
        self.apply_kubernetes_manifest(&manifest).await
    }

    async fn execute_network_latency(&self, experiment: &ChaosExperiment) -> Result<()> {
        let manifest = self.generate_network_latency_manifest(experiment)?;
        self.apply_kubernetes_manifest(&manifest).await
    }

    async fn execute_network_packet_loss(&self, experiment: &ChaosExperiment) -> Result<()> {
        let manifest = self.generate_network_packet_loss_manifest(experiment)?;
        self.apply_kubernetes_manifest(&manifest).await
    }

    async fn execute_memory_stress(&self, experiment: &ChaosExperiment) -> Result<()> {
        let manifest = self.generate_memory_stress_manifest(experiment)?;
        self.apply_kubernetes_manifest(&manifest).await
    }

    async fn execute_cpu_stress(&self, experiment: &ChaosExperiment) -> Result<()> {
        let manifest = self.generate_cpu_stress_manifest(experiment)?;
        self.apply_kubernetes_manifest(&manifest).await
    }

    async fn execute_dns_failure(&self, experiment: &ChaosExperiment) -> Result<()> {
        let manifest = self.generate_dns_failure_manifest(experiment)?;
        self.apply_kubernetes_manifest(&manifest).await
    }

    async fn execute_io_delay(&self, experiment: &ChaosExperiment) -> Result<()> {
        let manifest = self.generate_io_delay_manifest(experiment)?;
        self.apply_kubernetes_manifest(&manifest).await
    }

    /// Start continuous monitoring for safety checks
    async fn start_experiment_monitoring(&self, experiment_id: &str) -> Result<()> {
        let experiments = self.experiments.clone();
        let safety_manager = self.safety_manager.clone();
        let metrics_collector = self.metrics_collector.clone();
        let notification_service = self.notification_service.clone();
        let experiment_id = experiment_id.to_string();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

            loop {
                interval.tick().await;

                // Check if experiment is still running
                let experiments_guard = experiments.read().await;
                let experiment = match experiments_guard.get(&experiment_id) {
                    Some(exp) if matches!(exp.status, ExperimentStatus::Running) => exp.clone(),
                    _ => break, // Experiment completed or not found
                };
                drop(experiments_guard);

                // Perform safety checks
                match safety_manager.perform_safety_checks(&experiment).await {
                    Ok(checks) => {
                        let has_violations =
                            checks.iter().any(|c| matches!(c.status, SafetyStatus::Critical));

                        if has_violations {
                            warn!(
                                experiment_id = %experiment_id,
                                "Safety violation detected, stopping experiment"
                            );

                            // Update experiment status
                            let mut experiments_guard = experiments.write().await;
                            if let Some(exp) = experiments_guard.get_mut(&experiment_id) {
                                exp.status = ExperimentStatus::SafetyViolation;
                                exp.end_time = Some(Utc::now());
                            }
                            drop(experiments_guard);

                            // Send emergency notification
                            let _ = notification_service
                                .send_safety_violation_alert(&experiment_id, &checks)
                                .await;

                            break;
                        }
                    }
                    Err(e) => {
                        error!(
                            experiment_id = %experiment_id,
                            error = %e,
                            "Failed to perform safety checks"
                        );
                    }
                }

                // Collect metrics
                let mut collector = metrics_collector.lock().await;
                let _ = collector.collect_experiment_metrics(&experiment).await;
            }
        });

        Ok(())
    }

    /// Stop a running chaos experiment
    pub async fn stop_experiment(&self, experiment_id: &str) -> Result<()> {
        self.update_experiment_status(experiment_id, ExperimentStatus::Cancelled).await?;

        // Clean up Kubernetes resources
        self.cleanup_experiment_resources(experiment_id).await?;

        info!(experiment_id = %experiment_id, "Chaos experiment stopped");

        Ok(())
    }

    async fn update_experiment_status(
        &self,
        experiment_id: &str,
        status: ExperimentStatus,
    ) -> Result<()> {
        let mut experiments = self.experiments.write().await;
        if let Some(experiment) = experiments.get_mut(experiment_id) {
            experiment.status = status;
            if matches!(
                experiment.status,
                ExperimentStatus::Completed
                    | ExperimentStatus::Failed
                    | ExperimentStatus::Cancelled
                    | ExperimentStatus::SafetyViolation
            ) {
                experiment.end_time = Some(Utc::now());
            }
        }
        Ok(())
    }

    async fn apply_kubernetes_manifest(&self, manifest: &str) -> Result<()> {
        // In a real implementation, this would use the Kubernetes API
        info!("Applying Kubernetes manifest: {}", manifest);
        Ok(())
    }

    async fn cleanup_experiment_resources(&self, experiment_id: &str) -> Result<()> {
        // In a real implementation, this would clean up Chaos Mesh resources
        info!("Cleaning up resources for experiment: {}", experiment_id);
        Ok(())
    }

    fn generate_pod_kill_manifest(&self, experiment: &ChaosExperiment) -> Result<String> {
        let selector_json = serde_json::to_string(&experiment.target.selector)?;

        Ok(format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: PodChaos
metadata:
  name: {}
  namespace: chaos-engineering
spec:
  action: pod-kill
  mode: {}
  selector:
    namespaces:
      - {}
    labelSelectors: {}
  duration: {}s
"#,
            experiment.id,
            match experiment.target.mode {
                TargetMode::One => "one".to_string(),
                TargetMode::All => "all".to_string(),
                TargetMode::Fixed(n) => format!("fixed-{}", n),
                TargetMode::RandomMaxPercent(p) => format!("random-max-percent-{}", p as i32),
            },
            experiment.target.namespace,
            selector_json,
            experiment.duration.num_seconds()
        ))
    }

    fn generate_network_latency_manifest(&self, experiment: &ChaosExperiment) -> Result<String> {
        let latency = experiment.parameters.latency_ms.unwrap_or(100);

        Ok(format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: {}
  namespace: chaos-engineering
spec:
  action: delay
  mode: {}
  selector:
    namespaces:
      - {}
    labelSelectors: {}
  delay:
    latency: {}ms
  duration: {}s
"#,
            experiment.id,
            "one", // Simplified for example
            experiment.target.namespace,
            serde_json::to_string(&experiment.target.selector)?,
            latency,
            experiment.duration.num_seconds()
        ))
    }

    fn generate_network_packet_loss_manifest(
        &self,
        experiment: &ChaosExperiment,
    ) -> Result<String> {
        let loss_percent = experiment.parameters.packet_loss_percent.unwrap_or(10.0);

        Ok(format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: {}
  namespace: chaos-engineering
spec:
  action: loss
  mode: one
  selector:
    namespaces:
      - {}
    labelSelectors: {}
  loss:
    loss: {}%
  duration: {}s
"#,
            experiment.id,
            experiment.target.namespace,
            serde_json::to_string(&experiment.target.selector)?,
            loss_percent,
            experiment.duration.num_seconds()
        ))
    }

    fn generate_memory_stress_manifest(&self, experiment: &ChaosExperiment) -> Result<String> {
        let memory_size =
            experiment.parameters.memory_size.as_ref().unwrap_or(&"256MB".to_string());

        Ok(format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: StressChaos
metadata:
  name: {}
  namespace: chaos-engineering
spec:
  mode: one
  selector:
    namespaces:
      - {}
    labelSelectors: {}
  stressors:
    memory:
      size: {}
  duration: {}s
"#,
            experiment.id,
            experiment.target.namespace,
            serde_json::to_string(&experiment.target.selector)?,
            memory_size,
            experiment.duration.num_seconds()
        ))
    }

    fn generate_cpu_stress_manifest(&self, experiment: &ChaosExperiment) -> Result<String> {
        let cpu_load = experiment.parameters.cpu_load_percent.unwrap_or(80.0);

        Ok(format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: StressChaos
metadata:
  name: {}
  namespace: chaos-engineering
spec:
  mode: one
  selector:
    namespaces:
      - {}
    labelSelectors: {}
  stressors:
    cpu:
      workers: 1
      load: {}
  duration: {}s
"#,
            experiment.id,
            experiment.target.namespace,
            serde_json::to_string(&experiment.target.selector)?,
            cpu_load as i32,
            experiment.duration.num_seconds()
        ))
    }

    fn generate_dns_failure_manifest(&self, experiment: &ChaosExperiment) -> Result<String> {
        let patterns =
            experiment.parameters.dns_domain_patterns.as_ref().unwrap_or(&vec![".*".to_string()]);

        Ok(format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: DNSChaos
metadata:
  name: {}
  namespace: chaos-engineering
spec:
  action: error
  mode: one
  selector:
    namespaces:
      - {}
    labelSelectors: {}
  patterns:
{}
  duration: {}s
"#,
            experiment.id,
            experiment.target.namespace,
            serde_json::to_string(&experiment.target.selector)?,
            patterns.iter().map(|p| format!("    - {}", p)).collect::<Vec<_>>().join("\n"),
            experiment.duration.num_seconds()
        ))
    }

    fn generate_io_delay_manifest(&self, experiment: &ChaosExperiment) -> Result<String> {
        let delay = experiment.parameters.delay_ms.unwrap_or(100);

        Ok(format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: IOChaos
metadata:
  name: {}
  namespace: chaos-engineering
spec:
  action: delay
  mode: one
  selector:
    namespaces:
      - {}
    labelSelectors: {}
  delay: {}ms
  duration: {}s
"#,
            experiment.id,
            experiment.target.namespace,
            serde_json::to_string(&experiment.target.selector)?,
            delay,
            experiment.duration.num_seconds()
        ))
    }
}

impl SafetyManager {
    pub fn new(config: ChaosConfig) -> Self {
        Self { config }
    }

    pub async fn validate_experiment(&self, experiment: &ChaosExperiment) -> Result<()> {
        // Check forbidden namespaces
        if self.config.forbidden_namespaces.contains(&experiment.target.namespace) {
            return Err(anyhow::anyhow!(
                "Experiment targeting forbidden namespace: {}",
                experiment.target.namespace
            ));
        }

        // Check allowed namespaces
        if !self.config.allowed_namespaces.is_empty()
            && !self.config.allowed_namespaces.contains(&experiment.target.namespace)
        {
            return Err(anyhow::anyhow!(
                "Experiment targeting non-allowed namespace: {}",
                experiment.target.namespace
            ));
        }

        // Validate experiment duration
        let max_duration =
            Duration::minutes(self.config.safety_guardrails.max_experiment_duration_minutes as i64);
        if experiment.duration > max_duration {
            return Err(anyhow::anyhow!(
                "Experiment duration exceeds maximum allowed: {} > {}",
                experiment.duration.num_minutes(),
                max_duration.num_minutes()
            ));
        }

        // Validate experiment parameters against safety guardrails
        self.validate_experiment_parameters(experiment)?;

        Ok(())
    }

    fn validate_experiment_parameters(&self, experiment: &ChaosExperiment) -> Result<()> {
        let guardrails = &self.config.safety_guardrails;

        // Validate network parameters
        if let Some(packet_loss) = experiment.parameters.packet_loss_percent {
            if packet_loss > guardrails.max_packet_loss_percent {
                return Err(anyhow::anyhow!(
                    "Packet loss percentage exceeds safety limit: {}% > {}%",
                    packet_loss,
                    guardrails.max_packet_loss_percent
                ));
            }
        }

        if let Some(latency) = experiment.parameters.latency_ms {
            if latency > guardrails.max_latency_ms {
                return Err(anyhow::anyhow!(
                    "Latency exceeds safety limit: {}ms > {}ms",
                    latency,
                    guardrails.max_latency_ms
                ));
            }
        }

        // Validate stress testing parameters
        if let Some(cpu_load) = experiment.parameters.cpu_load_percent {
            if cpu_load > guardrails.max_cpu_stress_percent {
                return Err(anyhow::anyhow!(
                    "CPU stress exceeds safety limit: {}% > {}%",
                    cpu_load,
                    guardrails.max_cpu_stress_percent
                ));
            }
        }

        Ok(())
    }

    pub async fn perform_safety_checks(
        &self,
        experiment: &ChaosExperiment,
    ) -> Result<Vec<SafetyCheck>> {
        let mut checks = Vec::new();

        // Service availability check
        let availability = self.check_service_availability(experiment).await?;
        checks.push(SafetyCheck {
            name: "service_availability".to_string(),
            description: "Ensures service remains available during chaos".to_string(),
            check_type: SafetyCheckType::ServiceAvailability,
            threshold: 90.0, // 90% availability required
            current_value: Some(availability),
            status: if availability >= 90.0 {
                SafetyStatus::Passing
            } else if availability >= 70.0 {
                SafetyStatus::Warning
            } else {
                SafetyStatus::Critical
            },
        });

        // Response time check
        let response_time = self.check_response_time(experiment).await?;
        checks.push(SafetyCheck {
            name: "response_time".to_string(),
            description: "Monitors service response time degradation".to_string(),
            check_type: SafetyCheckType::ResponseTime,
            threshold: 5000.0, // 5 seconds max
            current_value: Some(response_time),
            status: if response_time <= 2000.0 {
                SafetyStatus::Passing
            } else if response_time <= 5000.0 {
                SafetyStatus::Warning
            } else {
                SafetyStatus::Critical
            },
        });

        // Error rate check
        let error_rate = self.check_error_rate(experiment).await?;
        checks.push(SafetyCheck {
            name: "error_rate".to_string(),
            description: "Monitors service error rate increase".to_string(),
            check_type: SafetyCheckType::ErrorRate,
            threshold: 10.0, // 10% error rate max
            current_value: Some(error_rate),
            status: if error_rate <= 5.0 {
                SafetyStatus::Passing
            } else if error_rate <= 10.0 {
                SafetyStatus::Warning
            } else {
                SafetyStatus::Critical
            },
        });

        Ok(checks)
    }

    async fn check_service_availability(&self, experiment: &ChaosExperiment) -> Result<f64> {
        // In a real implementation, this would query monitoring systems
        // For now, simulate availability check
        Ok(95.0)
    }

    async fn check_response_time(&self, experiment: &ChaosExperiment) -> Result<f64> {
        // In a real implementation, this would query monitoring systems
        Ok(1500.0) // 1.5 seconds
    }

    async fn check_error_rate(&self, experiment: &ChaosExperiment) -> Result<f64> {
        // In a real implementation, this would query monitoring systems
        Ok(3.0) // 3% error rate
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self { experiments: HashMap::new() }
    }

    pub async fn collect_experiment_metrics(&mut self, experiment: &ChaosExperiment) -> Result<()> {
        let metrics = ExperimentMetrics {
            service_availability: self.collect_availability_metrics(experiment).await?,
            response_times_p95: self.collect_response_time_metrics(experiment).await?,
            error_rates: self.collect_error_rate_metrics(experiment).await?,
            resource_utilization: self.collect_resource_metrics(experiment).await?,
            network_metrics: self.collect_network_metrics(experiment).await?,
            recovery_time_seconds: None, // Will be calculated when experiment ends
            blast_radius: self.calculate_blast_radius(experiment).await?,
        };

        self.experiments.insert(experiment.id.clone(), metrics);
        Ok(())
    }

    async fn collect_availability_metrics(
        &self,
        experiment: &ChaosExperiment,
    ) -> Result<HashMap<String, f64>> {
        // Simulate metrics collection
        let mut metrics = HashMap::new();
        metrics.insert("auth-service".to_string(), 95.0);
        metrics.insert("policy-service".to_string(), 98.0);
        Ok(metrics)
    }

    async fn collect_response_time_metrics(
        &self,
        experiment: &ChaosExperiment,
    ) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        metrics.insert("auth-service".to_string(), 1200.0);
        metrics.insert("policy-service".to_string(), 800.0);
        Ok(metrics)
    }

    async fn collect_error_rate_metrics(
        &self,
        experiment: &ChaosExperiment,
    ) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        metrics.insert("auth-service".to_string(), 3.5);
        metrics.insert("policy-service".to_string(), 1.2);
        Ok(metrics)
    }

    async fn collect_resource_metrics(
        &self,
        experiment: &ChaosExperiment,
    ) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        metrics.insert("cpu_usage".to_string(), 65.0);
        metrics.insert("memory_usage".to_string(), 72.0);
        Ok(metrics)
    }

    async fn collect_network_metrics(
        &self,
        experiment: &ChaosExperiment,
    ) -> Result<NetworkMetrics> {
        Ok(NetworkMetrics {
            latency_p95_ms: 150.0,
            packet_loss_percent: 0.1,
            throughput_mbps: 950.0,
            connection_errors: 2,
        })
    }

    async fn calculate_blast_radius(
        &self,
        experiment: &ChaosExperiment,
    ) -> Result<BlastRadiusMetrics> {
        Ok(BlastRadiusMetrics {
            affected_services: vec!["auth-service".to_string(), "policy-service".to_string()],
            affected_pods: 3,
            affected_nodes: 1,
            downstream_impact: HashMap::new(),
        })
    }
}

impl NotificationService {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            webhook_url: std::env::var("CHAOS_WEBHOOK_URL").ok(),
            slack_webhook: std::env::var("SLACK_WEBHOOK_URL").ok(),
            email_enabled: true,
        })
    }

    pub async fn send_experiment_notification(
        &self,
        experiment: &ChaosExperiment,
        event: &str,
    ) -> Result<()> {
        info!(
            experiment_id = %experiment.id,
            event = %event,
            "Sending experiment notification"
        );

        // In a real implementation, this would send actual notifications
        Ok(())
    }

    pub async fn send_safety_violation_alert(
        &self,
        experiment_id: &str,
        checks: &[SafetyCheck],
    ) -> Result<()> {
        error!(
            experiment_id = %experiment_id,
            violations = checks.len(),
            "Safety violation detected - sending alert"
        );

        // In a real implementation, this would send urgent alerts
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_chaos_orchestrator_creation() {
        let config = ChaosConfig {
            safety_guardrails: SafetyGuardrails {
                max_packet_loss_percent: 50.0,
                max_latency_ms: 5000,
                max_memory_stress_percent: 80.0,
                max_cpu_stress_percent: 80.0,
                min_healthy_replicas: 1,
                max_experiment_duration_minutes: 30,
            },
            allowed_namespaces: vec!["test".to_string()],
            forbidden_namespaces: vec!["production".to_string()],
            max_concurrent_experiments: 3,
            default_timeout: Duration::minutes(10),
            monitoring_enabled: true,
            auto_recovery: true,
        };

        let orchestrator = ChaosOrchestrator::new(config).await;
        assert!(orchestrator.is_ok());
    }

    #[tokio::test]
    async fn test_experiment_validation() {
        let config = ChaosConfig {
            safety_guardrails: SafetyGuardrails {
                max_packet_loss_percent: 50.0,
                max_latency_ms: 5000,
                max_memory_stress_percent: 80.0,
                max_cpu_stress_percent: 80.0,
                min_healthy_replicas: 1,
                max_experiment_duration_minutes: 30,
            },
            allowed_namespaces: vec!["test".to_string()],
            forbidden_namespaces: vec!["production".to_string()],
            max_concurrent_experiments: 3,
            default_timeout: Duration::minutes(10),
            monitoring_enabled: true,
            auto_recovery: true,
        };

        let safety_manager = SafetyManager::new(config);

        let valid_experiment = ChaosExperiment {
            id: "test-exp-1".to_string(),
            name: "Test Pod Kill".to_string(),
            experiment_type: ExperimentType::PodKill,
            target: ExperimentTarget {
                namespace: "test".to_string(),
                selector: HashMap::new(),
                mode: TargetMode::One,
                value: None,
            },
            parameters: ExperimentParameters {
                latency_ms: None,
                packet_loss_percent: None,
                bandwidth_limit: None,
                network_partition_direction: None,
                grace_period_seconds: Some(30),
                force_kill: Some(false),
                memory_size: None,
                cpu_load_percent: None,
                workers: None,
                delay_ms: None,
                error_percent: None,
                volume_path: None,
                dns_domain_patterns: None,
                dns_server: None,
                custom: HashMap::new(),
            },
            duration: Duration::minutes(5),
            status: ExperimentStatus::Pending,
            start_time: None,
            end_time: None,
            safety_checks: Vec::new(),
            metrics: ExperimentMetrics {
                service_availability: HashMap::new(),
                response_times_p95: HashMap::new(),
                error_rates: HashMap::new(),
                resource_utilization: HashMap::new(),
                network_metrics: NetworkMetrics {
                    latency_p95_ms: 0.0,
                    packet_loss_percent: 0.0,
                    throughput_mbps: 0.0,
                    connection_errors: 0,
                },
                recovery_time_seconds: None,
                blast_radius: BlastRadiusMetrics {
                    affected_services: Vec::new(),
                    affected_pods: 0,
                    affected_nodes: 0,
                    downstream_impact: HashMap::new(),
                },
            },
        };

        let _result = safety_manager.validate_experiment(&valid_experiment).await;
        assert!(result.is_ok());
    }
}
