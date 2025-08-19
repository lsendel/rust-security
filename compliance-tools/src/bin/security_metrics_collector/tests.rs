//! Unit tests for the security metrics collector

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;
    use tokio_test;

    #[tokio::test]
    async fn test_metrics_collection_json_output() {
        // Create a temporary config file
        let mut config_file = NamedTempFile::new().unwrap();
        let config_content = r#"
organization:
  name: "Test Org"
  domain: "test.com"
  contact_email: "test@test.com"
  compliance_officer: "Test Officer"
  assessment_period_days: 30

frameworks: []

report_settings:
  output_formats: ["json"]
  include_charts: false
  include_recommendations: false
  classification_level: "internal"
  retention_days: 30

data_sources:
  audit_log_paths: []
  prometheus_url: ~
  elasticsearch_url: ~
  redis_url: ~
  custom_apis: {}

notifications:
  slack_webhook: ~
  email_recipients: []
  teams_webhook: ~
  custom_webhooks: []
"#;
        write!(config_file, "{}", config_content).unwrap();

        // Test JSON output format
        let result = collect_metrics_json(config_file.path().to_str().unwrap()).await;
        assert!(result.is_ok());
        
        let json_str = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.is_object());
        assert!(parsed.get("metrics").is_some());
        assert!(parsed.get("timestamp").is_some());
    }

    #[tokio::test]
    async fn test_metrics_collection_prometheus_output() {
        let mut config_file = NamedTempFile::new().unwrap();
        let config_content = r#"
organization:
  name: "Test Org"
  domain: "test.com"
  contact_email: "test@test.com"
  compliance_officer: "Test Officer"
  assessment_period_days: 30
frameworks: []
report_settings:
  output_formats: ["json"]
  include_charts: false
  include_recommendations: false
  classification_level: "internal"
  retention_days: 30
data_sources:
  audit_log_paths: []
notifications:
  slack_webhook: ~
  email_recipients: []
  teams_webhook: ~
  custom_webhooks: []
"#;
        write!(config_file, "{}", config_content).unwrap();

        let result = collect_metrics_prometheus(config_file.path().to_str().unwrap()).await;
        assert!(result.is_ok());
        
        let prometheus_output = result.unwrap();
        assert!(prometheus_output.contains("# HELP"));
        assert!(prometheus_output.contains("# TYPE"));
    }

    #[tokio::test]
    async fn test_metrics_collection_csv_output() {
        let mut config_file = NamedTempFile::new().unwrap();
        let config_content = r#"
organization:
  name: "Test Org"
  domain: "test.com"
  contact_email: "test@test.com"
  compliance_officer: "Test Officer"
  assessment_period_days: 30
frameworks: []
report_settings:
  output_formats: ["json"]
  include_charts: false
  include_recommendations: false
  classification_level: "internal"
  retention_days: 30
data_sources:
  audit_log_paths: []
notifications:
  slack_webhook: ~
  email_recipients: []
  teams_webhook: ~
  custom_webhooks: []
"#;
        write!(config_file, "{}", config_content).unwrap();

        let result = collect_metrics_csv(config_file.path().to_str().unwrap()).await;
        assert!(result.is_ok());
        
        let csv_output = result.unwrap();
        assert!(csv_output.contains("metric_name,value,threshold,status,description"));
    }

    #[test]
    fn test_config_parsing() {
        let yaml_content = r#"
organization:
  name: "Test Org"
  domain: "test.com"
  contact_email: "test@test.com"
  compliance_officer: "Test Officer"
  assessment_period_days: 30
frameworks: []
report_settings:
  output_formats: ["json"]
  include_charts: false
  include_recommendations: false
  classification_level: "internal"
  retention_days: 30
data_sources:
  audit_log_paths: []
notifications:
  slack_webhook: ~
  email_recipients: []
  teams_webhook: ~
  custom_webhooks: []
"#;
        
        let config: compliance_tools::ComplianceConfig = serde_yaml::from_str(yaml_content).unwrap();
        assert_eq!(config.organization.name, "Test Org");
        assert_eq!(config.organization.domain, "test.com");
        assert_eq!(config.organization.assessment_period_days, 30);
    }
}