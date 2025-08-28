//! Template utilities

use crate::{ComplianceError, ComplianceResult};

/// Template manager for report generation
pub struct TemplateManager;

impl TemplateManager {
    /// Load template from file
    pub async fn load_template(path: &str) -> ComplianceResult<String> {
        tokio::fs::read_to_string(path)
            .await
            .map_err(|e| ComplianceError::Template(format!("Failed to load template {path}: {e}")))
    }

    /// Get default HTML template
    #[must_use]
    pub const fn get_default_html_template() -> &'static str {
        include_str!("../templates/compliance_report.html")
    }

    /// Get default Markdown template
    #[must_use]
    pub const fn get_default_markdown_template() -> &'static str {
        include_str!("../templates/compliance_report.md")
    }
}
