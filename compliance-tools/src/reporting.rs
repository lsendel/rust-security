//! Report generation and rendering

use crate::{
    ClassificationLevel, ComplianceControl, ComplianceError, ComplianceFramework, ComplianceResult,
    OrganizationInfo, SecurityIncident, SecurityMetric,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::path::Path;
use tera::{Context, Tera};
use tokio::fs;

/// Report renderer for generating compliance reports in various formats
pub struct ReportRenderer {
    template_engine: Tera,
}

impl ReportRenderer {
    /// Create a new report renderer
    ///
    /// # Panics
    /// Panics if embedded templates cannot be loaded into the template engine.
    #[must_use]
    pub fn new() -> Self {
        let mut tera = Tera::new("templates/**/*").unwrap_or_else(|_| Tera::new("").unwrap());

        // Add built-in templates
        tera.add_raw_template(
            "compliance_report.html",
            include_str!("../templates/compliance_report.html"),
        )
        .expect("Failed to add HTML template");

        tera.add_raw_template(
            "compliance_report.md",
            include_str!("../templates/compliance_report.md"),
        )
        .expect("Failed to add Markdown template");

        Self {
            template_engine: tera,
        }
    }

    /// Render HTML report
    ///
    /// # Errors
    /// Returns an error if rendering or writing the file fails.
    pub async fn render_html(
        &self,
        data: &ComplianceReportData,
        output_path: &Path,
    ) -> ComplianceResult<()> {
        let mut context = Context::new();
        context.insert("report", data);
        context.insert(
            "generated_at",
            &Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );

        let html = self
            .template_engine
            .render("compliance_report.html", &context)
            .map_err(|e| ComplianceError::Template(e.to_string()))?;

        fs::write(output_path, html).await?;
        Ok(())
    }

    /// Render JSON report
    ///
    /// # Errors
    /// Returns an error if serialization or writing the file fails.
    pub async fn render_json(
        &self,
        data: &ComplianceReportData,
        output_path: &Path,
    ) -> ComplianceResult<()> {
        let json = serde_json::to_string_pretty(data)?;
        fs::write(output_path, json).await?;
        Ok(())
    }

    /// Render CSV report
    ///
    /// # Errors
    /// Returns an error if writing the file fails.
    pub async fn render_csv(
        &self,
        data: &ComplianceReportData,
        output_path: &Path,
    ) -> ComplianceResult<()> {
        let mut csv_content = String::new();

        // Controls CSV
        csv_content.push_str("Control ID,Framework,Title,Implementation Status,Effectiveness,Risk Level,Last Tested\n");
        for control in &data.compliance_controls {
            use std::fmt::Write as _;
            let _ = writeln!(
                csv_content,
                "{},{:?},{},{:?},{:?},{:?},{}",
                control.control_id,
                control.framework,
                control.title.replace(',', ";"),
                control.implementation_status,
                control.effectiveness,
                control.risk_level,
                control.last_tested.format("%Y-%m-%d")
            );
        }

        csv_content.push_str("\n\nSecurity Metrics\n");
        csv_content.push_str("Metric Name,Value,Threshold,Status,Description\n");
        for metric in &data.security_metrics {
            use std::fmt::Write as _;
            let _ = writeln!(
                csv_content,
                "{},{},{},{:?},{}",
                metric.name,
                metric.value,
                metric.threshold,
                metric.status,
                metric.description.replace(',', ";")
            );
        }

        fs::write(output_path, csv_content).await?;
        Ok(())
    }

    /// Render Markdown report
    ///
    /// # Errors
    /// Returns an error if rendering or writing the file fails.
    pub async fn render_markdown(
        &self,
        data: &ComplianceReportData,
        output_path: &Path,
    ) -> ComplianceResult<()> {
        let mut context = Context::new();
        context.insert("report", data);
        context.insert(
            "generated_at",
            &Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );

        let markdown = self
            .template_engine
            .render("compliance_report.md", &context)
            .map_err(|e| ComplianceError::Template(e.to_string()))?;

        fs::write(output_path, markdown).await?;
        Ok(())
    }
}

/// Complete compliance report data
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceReportData {
    pub framework: ComplianceFramework,
    pub assessment_period_days: u32,
    pub organization: OrganizationInfo,
    pub security_metrics: Vec<SecurityMetric>,
    pub compliance_controls: Vec<ComplianceControl>,
    pub security_incidents: Vec<SecurityIncident>,
    pub audit_summary: AuditSummary,
    pub generation_time: DateTime<Utc>,
    pub classification: ClassificationLevel,
}

/// Audit summary for reports
#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditSummary {
    pub total_events: u64,
    pub successful_events: u64,
    pub failed_events: u64,
    pub blocked_events: u64,
    pub unique_users: u64,
    pub unique_ips: u64,
    pub top_actions: Vec<(String, u64)>,
    pub anomalous_activity: u64,
}

impl Default for ReportRenderer {
    fn default() -> Self {
        Self::new()
    }
}
