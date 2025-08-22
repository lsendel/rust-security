//! Compliance Report Generator
//!
//! A Rust-based replacement for the Python compliance_report_generator.py
//! Generates comprehensive compliance reports for SOC 2, ISO 27001, GDPR, and other frameworks

use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::{Arg, Command};
use compliance_tools::{
    prometheus_client::PrometheusClient,
    reporting::{AuditSummary, ComplianceReportData, ReportRenderer},
    *,
};
use std::path::PathBuf;
use tracing::{error, info, warn};

// Unused dependencies (required by workspace but not used in this binary)
use calamine as _;
use common as _;
use config as _;
use csv as _;
use dotenvy as _;
use fastrand as _;
use handlebars as _;
use moka as _;
use prometheus as _;
use pulldown_cmark as _;
use regex as _;
use reqwest as _;
use serde as _;
use sha2 as _;
use tempfile as _;
use tera as _;
use thiserror as _;
use url as _;
use uuid as _;
use walkdir as _;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let matches = Command::new("compliance-report-generator")
        .about("Generate comprehensive compliance reports")
        .version("1.0.0")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("config/compliance.yaml"),
        )
        .arg(
            Arg::new("framework")
                .short('f')
                .long("framework")
                .value_name("FRAMEWORK")
                .help("Compliance framework to report on")
                .value_parser(["soc2", "iso27001", "gdpr", "nist", "pci", "hipaa"])
                .default_value("soc2"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file path")
                .default_value("reports/compliance-report.html"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .help("Report format")
                .value_parser(["html", "pdf", "json", "csv", "excel", "markdown"])
                .default_value("html"),
        )
        .arg(
            Arg::new("period-days")
                .long("period-days")
                .value_name("DAYS")
                .help("Assessment period in days")
                .value_parser(clap::value_parser!(u32))
                .default_value("30"),
        )
        .arg(
            Arg::new("include-recommendations")
                .long("include-recommendations")
                .help("Include remediation recommendations")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let config_path = matches.get_one::<String>("config").unwrap();
    let framework = matches.get_one::<String>("framework").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();
    let format = matches.get_one::<String>("format").unwrap();
    let period_days = matches.get_one::<u32>("period-days").unwrap();
    let include_recommendations = matches.get_flag("include-recommendations");

    info!("Starting compliance report generation");
    info!(
        "Framework: {}, Output: {}, Format: {}",
        framework, output_path, format
    );

    // Load configuration
    let config = load_compliance_config(config_path).await?;

    // Create compliance reporter
    let mut reporter = ComplianceReporter::new(config).await?;

    // Parse framework
    let compliance_framework = parse_framework(framework)?;

    // Parse format
    let report_format = parse_format(format)?;

    // Generate report
    let report_config = ReportGenerationConfig {
        framework: compliance_framework,
        assessment_period_days: *period_days,
        _include_recommendations: include_recommendations,
        output_format: report_format,
        output_path: PathBuf::from(output_path),
        classification: ClassificationLevel::Internal,
    };

    match reporter.generate_report(report_config).await {
        Ok(report_metadata) => {
            info!("✅ Compliance report generated successfully");
            info!(
                "📊 Controls assessed: {}",
                report_metadata.controls_assessed
            );
            info!("⚠️  Issues found: {}", report_metadata.issues_found);
            info!(
                "📈 Compliance score: {:.1}%",
                report_metadata.compliance_score
            );
            info!("📄 Report saved to: {}", output_path);

            if report_metadata.issues_found > 0 {
                warn!(
                    "⚠️  {} compliance issues require attention",
                    report_metadata.issues_found
                );
            }
        }
        Err(e) => {
            error!("❌ Failed to generate compliance report: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn load_compliance_config(config_path: &str) -> Result<ComplianceConfig> {
    info!("Loading compliance configuration from: {}", config_path);

    let config_content = tokio::fs::read_to_string(config_path).await?;

    // Try YAML first, then JSON
    if config_path.ends_with(".yaml") || config_path.ends_with(".yml") {
        let config: ComplianceConfig = serde_yaml::from_str(&config_content)?;
        Ok(config)
    } else {
        let config: ComplianceConfig = serde_json::from_str(&config_content)?;
        Ok(config)
    }
}

fn parse_framework(framework: &str) -> Result<ComplianceFramework> {
    match framework.to_lowercase().as_str() {
        "soc2" => Ok(ComplianceFramework::Soc2),
        "iso27001" => Ok(ComplianceFramework::Iso27001),
        "gdpr" => Ok(ComplianceFramework::Gdpr),
        "nist" => Ok(ComplianceFramework::Nist),
        "pci" => Ok(ComplianceFramework::Pci),
        "hipaa" => Ok(ComplianceFramework::Hipaa),
        custom => Ok(ComplianceFramework::Custom(custom.to_string())),
    }
}

fn parse_format(format: &str) -> Result<ReportFormat> {
    match format.to_lowercase().as_str() {
        "html" => Ok(ReportFormat::Html),
        "pdf" => Ok(ReportFormat::Pdf),
        "json" => Ok(ReportFormat::Json),
        "csv" => Ok(ReportFormat::Csv),
        "excel" => Ok(ReportFormat::Excel),
        "markdown" => Ok(ReportFormat::Markdown),
        _ => Err(anyhow::anyhow!("Unsupported format: {}", format)),
    }
}

/// Configuration for report generation
#[derive(Debug, Clone)]
struct ReportGenerationConfig {
    framework: ComplianceFramework,
    assessment_period_days: u32,
    _include_recommendations: bool,
    output_format: ReportFormat,
    output_path: PathBuf,
    classification: ClassificationLevel,
}

/// Report generation metadata
#[derive(Debug)]
struct ReportMetadata {
    controls_assessed: u32,
    issues_found: u32,
    compliance_score: f64,
    _generation_time: DateTime<Utc>,
}

/// Main compliance reporter
struct ComplianceReporter {
    config: ComplianceConfig,
    metrics_collector: MetricsCollector,
    _prometheus_client: Option<PrometheusClient>,
}

impl ComplianceReporter {
    async fn new(config: ComplianceConfig) -> Result<Self> {
        let prometheus_client = config
            .data_sources
            .prometheus_url
            .as_ref()
            .map(|url| PrometheusClient::new(url.clone()));

        let metrics_collector = MetricsCollector::new(&config).await?;

        Ok(Self {
            config,
            metrics_collector,
            _prometheus_client: prometheus_client,
        })
    }

    async fn generate_report(&mut self, config: ReportGenerationConfig) -> Result<ReportMetadata> {
        info!(
            "Generating compliance report for framework: {:?}",
            config.framework
        );

        // Collect metrics and data
        let security_metrics = self.collect_security_metrics().await?;
        let compliance_controls = self.assess_compliance_controls(&config.framework).await?;
        let security_incidents = self
            .collect_security_incidents(config.assessment_period_days)
            .await?;
        let audit_logs = self
            .analyze_audit_logs(config.assessment_period_days)
            .await?;

        // Generate report
        let report_data = ComplianceReportData {
            framework: config.framework.clone(),
            assessment_period_days: config.assessment_period_days,
            organization: self.config.organization.clone(),
            security_metrics,
            compliance_controls: compliance_controls.clone(),
            security_incidents,
            audit_summary: audit_logs,
            generation_time: Utc::now(),
            classification: config.classification.clone(),
        };

        // Calculate metadata
        let controls_assessed = compliance_controls.len() as u32;
        let issues_found = compliance_controls
            .iter()
            .filter(|c| {
                c.implementation_status != ImplementationStatus::Implemented
                    || c.effectiveness != EffectivenessLevel::Effective
            })
            .count() as u32;

        let compliance_score = if controls_assessed > 0 {
            ((controls_assessed - issues_found) as f64 / controls_assessed as f64) * 100.0
        } else {
            0.0
        };

        // Generate output
        self.render_report(&report_data, &config).await?;

        Ok(ReportMetadata {
            controls_assessed,
            issues_found,
            compliance_score,
            _generation_time: Utc::now(),
        })
    }

    async fn collect_security_metrics(&self) -> Result<Vec<SecurityMetric>> {
        info!("Collecting security metrics");
        self.metrics_collector
            .collect_all_metrics()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to collect metrics: {}", e))
    }

    async fn assess_compliance_controls(
        &self,
        framework: &ComplianceFramework,
    ) -> Result<Vec<ComplianceControl>> {
        info!(
            "Assessing compliance controls for framework: {:?}",
            framework
        );

        // This would typically load control definitions and assess them
        // For now, return example controls
        let controls = match framework {
            ComplianceFramework::Soc2 => self.get_soc2_controls().await?,
            ComplianceFramework::Iso27001 => self.get_iso27001_controls().await?,
            ComplianceFramework::Gdpr => self.get_gdpr_controls().await?,
            _ => Vec::new(),
        };

        Ok(controls)
    }

    async fn collect_security_incidents(&self, period_days: u32) -> Result<Vec<SecurityIncident>> {
        info!(
            "Collecting security incidents for the last {} days",
            period_days
        );
        // Implementation would collect from incident management system
        Ok(Vec::new())
    }

    async fn analyze_audit_logs(&self, period_days: u32) -> Result<AuditSummary> {
        info!("Analyzing audit logs for the last {} days", period_days);
        // Implementation would analyze audit logs
        Ok(AuditSummary::default())
    }

    async fn get_soc2_controls(&self) -> Result<Vec<ComplianceControl>> {
        // SOC 2 control examples
        Ok(vec![
            ComplianceControl {
                control_id: "CC6.1".to_string(),
                framework: ComplianceFramework::Soc2,
                title: "Logical and Physical Access Controls".to_string(),
                description: "Implements logical and physical access controls".to_string(),
                implementation_status: ImplementationStatus::Implemented,
                effectiveness: EffectivenessLevel::Effective,
                evidence: vec![
                    "Access control policies".to_string(),
                    "IAM configurations".to_string(),
                ],
                last_tested: Utc::now(),
                next_review: Utc::now() + chrono::Duration::days(90),
                risk_level: RiskLevel::Low,
                assigned_to: Some("Security Team".to_string()),
                remediation_plan: None,
            },
            ComplianceControl {
                control_id: "CC6.2".to_string(),
                framework: ComplianceFramework::Soc2,
                title: "Multi-Factor Authentication".to_string(),
                description: "Requires multi-factor authentication for privileged access"
                    .to_string(),
                implementation_status: ImplementationStatus::Implemented,
                effectiveness: EffectivenessLevel::Effective,
                evidence: vec![
                    "MFA policies".to_string(),
                    "Authentication logs".to_string(),
                ],
                last_tested: Utc::now(),
                next_review: Utc::now() + chrono::Duration::days(90),
                risk_level: RiskLevel::Low,
                assigned_to: Some("Identity Team".to_string()),
                remediation_plan: None,
            },
        ])
    }

    async fn get_iso27001_controls(&self) -> Result<Vec<ComplianceControl>> {
        // ISO 27001 control examples
        Ok(vec![ComplianceControl {
            control_id: "A.9.1.1".to_string(),
            framework: ComplianceFramework::Iso27001,
            title: "Access Control Policy".to_string(),
            description: "Establish, document and review access control policy".to_string(),
            implementation_status: ImplementationStatus::Implemented,
            effectiveness: EffectivenessLevel::Effective,
            evidence: vec!["Access control policy document".to_string()],
            last_tested: Utc::now(),
            next_review: Utc::now() + chrono::Duration::days(365),
            risk_level: RiskLevel::Medium,
            assigned_to: Some("CISO".to_string()),
            remediation_plan: None,
        }])
    }

    async fn get_gdpr_controls(&self) -> Result<Vec<ComplianceControl>> {
        // GDPR control examples
        Ok(vec![ComplianceControl {
            control_id: "Art.32".to_string(),
            framework: ComplianceFramework::Gdpr,
            title: "Security of Processing".to_string(),
            description: "Implement appropriate technical and organizational measures".to_string(),
            implementation_status: ImplementationStatus::Implemented,
            effectiveness: EffectivenessLevel::Effective,
            evidence: vec![
                "Encryption policies".to_string(),
                "Access controls".to_string(),
            ],
            last_tested: Utc::now(),
            next_review: Utc::now() + chrono::Duration::days(180),
            risk_level: RiskLevel::High,
            assigned_to: Some("DPO".to_string()),
            remediation_plan: None,
        }])
    }

    async fn render_report(
        &self,
        data: &ComplianceReportData,
        config: &ReportGenerationConfig,
    ) -> Result<()> {
        info!("Rendering report in format: {:?}", config.output_format);

        let reporter = ReportRenderer::new();

        match config.output_format {
            ReportFormat::Html => {
                reporter.render_html(data, &config.output_path).await?;
            }
            ReportFormat::Json => {
                reporter.render_json(data, &config.output_path).await?;
            }
            ReportFormat::Csv => {
                reporter.render_csv(data, &config.output_path).await?;
            }
            ReportFormat::Markdown => {
                reporter.render_markdown(data, &config.output_path).await?;
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unsupported format: {:?}",
                    config.output_format
                ));
            }
        }

        Ok(())
    }
}
