//! Threat Feed Validator
//!
//! A Rust-based replacement for the Python validate_threat_feeds.py
//! Validates threat intelligence feeds configuration and accessibility

use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::{Arg, Command};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{error, info, warn};
use url::Url;

// Unused dependencies (required by workspace but not used in this binary)
use calamine as _;
use common as _;
use compliance_tools as _;
use config as _;
use csv as _;
use dotenvy as _;
use fastrand as _;
use handlebars as _;
use moka as _;
use prometheus as _;
use pulldown_cmark as _;
use regex as _;
use sha2 as _;
use tempfile as _;
use tera as _;
use thiserror as _;
use uuid as _;
use walkdir as _;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let matches = Command::new("threat-feed-validator")
        .about("Validate threat intelligence feeds")
        .version("1.0.0")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Threat feeds configuration file")
                .default_value("config/threat-intelligence/enhanced_feeds.yaml"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output validation report file")
                .default_value("reports/threat-feed-validation.json"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .value_name("SECONDS")
                .help("Request timeout in seconds")
                .value_parser(clap::value_parser!(u64))
                .default_value("30"),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .help("Output format")
                .value_parser(["json", "yaml", "table"])
                .default_value("table"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let config_path = matches.get_one::<String>("config").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();
    let timeout_secs = matches.get_one::<u64>("timeout").unwrap();
    let format = matches.get_one::<String>("format").unwrap();
    let verbose = matches.get_flag("verbose");

    info!("Starting threat feed validation");
    info!(
        "Config: {}, Output: {}, Timeout: {}s",
        config_path, output_path, timeout_secs
    );

    // Load feeds configuration
    let feeds_config = load_feeds_config(config_path).await?;
    info!(
        "Loaded {} threat feeds from configuration",
        feeds_config.feeds.len()
    );

    // Create validator
    let validator = ThreatFeedValidator::new(*timeout_secs);

    // Validate all feeds
    let validation_results = validator.validate_all_feeds(&feeds_config).await?;

    // Generate report
    let report = ValidationReport {
        timestamp: Utc::now(),
        total_feeds: feeds_config.feeds.len() as u32,
        successful_feeds: validation_results
            .iter()
            .filter(|r| r.status == ValidationStatus::Success)
            .count() as u32,
        failed_feeds: validation_results
            .iter()
            .filter(|r| r.status == ValidationStatus::Failed)
            .count() as u32,
        feeds: validation_results,
    };

    // Output results
    match format.as_str() {
        "json" => {
            output_json_report(&report, output_path).await?;
        }
        "yaml" => {
            output_yaml_report(&report, output_path).await?;
        }
        "table" => {
            output_table_report(&report, verbose);
        }
        _ => {
            return Err(anyhow::anyhow!("Unsupported format: {}", format));
        }
    }

    // Print summary
    let success_rate = (report.successful_feeds as f64 / report.total_feeds as f64) * 100.0;

    if report.failed_feeds == 0 {
        info!(
            "✅ All {} threat feeds validated successfully ({:.1}%)",
            report.total_feeds, success_rate
        );
    } else {
        warn!(
            "⚠️  {}/{} threat feeds failed validation ({:.1}% success rate)",
            report.failed_feeds, report.total_feeds, success_rate
        );

        // Show failed feeds
        for feed in &report.feeds {
            if feed.status == ValidationStatus::Failed {
                error!("❌ {}: {}", feed.feed_name, feed.errors.join(", "));
            }
        }
    }

    if report.failed_feeds > 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// Load threat feeds configuration from file
async fn load_feeds_config(config_path: &str) -> Result<ThreatFeedsConfig> {
    let config_paths = vec![
        config_path.to_string(),
        "config/threat-intelligence/enhanced_feeds.yaml".to_string(),
        "config/threat-intelligence/config.yaml".to_string(),
    ];

    for path in config_paths {
        if Path::new(&path).exists() {
            info!("Loading config from: {}", path);
            let content = tokio::fs::read_to_string(&path).await?;

            let config: ThreatFeedsConfig = if path.ends_with(".yaml") || path.ends_with(".yml") {
                serde_yaml::from_str(&content)?
            } else {
                serde_json::from_str(&content)?
            };

            return Ok(config);
        }
    }

    Err(anyhow::anyhow!("No valid threat feeds configuration found"))
}

/// Output JSON report
async fn output_json_report(report: &ValidationReport, output_path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    tokio::fs::write(output_path, json).await?;
    info!("📄 JSON report saved to: {}", output_path);
    Ok(())
}

/// Output YAML report
async fn output_yaml_report(report: &ValidationReport, output_path: &str) -> Result<()> {
    let yaml = serde_yaml::to_string(report)?;
    tokio::fs::write(output_path, yaml).await?;
    info!("📄 YAML report saved to: {}", output_path);
    Ok(())
}

/// Output table report to console
fn output_table_report(report: &ValidationReport, verbose: bool) {
    println!("\n🔍 Threat Feed Validation Report");
    println!("═══════════════════════════════════════");
    println!("📊 Total Feeds: {}", report.total_feeds);
    println!("✅ Successful: {}", report.successful_feeds);
    println!("❌ Failed: {}", report.failed_feeds);
    println!(
        "📅 Generated: {}",
        report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    );

    println!("\n📋 Feed Details:");
    println!(
        "┌─────────────────────────────────────┬──────────┬──────────────┬─────────────────────┐"
    );
    println!(
        "│ Feed Name                           │ Status   │ Response Time│ Content Size        │"
    );
    println!(
        "├─────────────────────────────────────┼──────────┼──────────────┼─────────────────────┤"
    );

    for feed in &report.feeds {
        let status_icon = match feed.status {
            ValidationStatus::Success => "✅",
            ValidationStatus::Failed => "❌",
            ValidationStatus::Warning => "⚠️ ",
            ValidationStatus::Skipped => "⏭️ ",
        };

        let response_time = if feed.response_time_ms > 0 {
            format!("{}ms", feed.response_time_ms)
        } else {
            "N/A".to_string()
        };

        let content_size = if feed.content_size > 0 {
            format_bytes(feed.content_size)
        } else {
            "N/A".to_string()
        };

        println!(
            "│ {:<35} │ {} {:<6} │ {:<12} │ {:<19} │",
            truncate_string(&feed.feed_name, 35),
            status_icon,
            format!("{:?}", feed.status),
            response_time,
            content_size
        );

        if verbose && !feed.errors.is_empty() {
            for error in &feed.errors {
                println!("│   └─ ❌ {:<86} │", truncate_string(error, 86));
            }
        }
    }

    println!(
        "└─────────────────────────────────────┴──────────┴──────────────┴─────────────────────┘"
    );
}

/// Format bytes in human readable format
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Truncate string to specified length
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Threat feeds configuration structure
#[derive(Debug, Deserialize)]
struct ThreatFeedsConfig {
    feeds: HashMap<String, ThreatFeedConfig>,
}

/// Individual threat feed configuration
#[derive(Debug, Deserialize)]
struct ThreatFeedConfig {
    enabled: Option<bool>,
    url: Option<String>,
    api_key: Option<String>,
    headers: Option<HashMap<String, String>>,
    _feed_type: Option<String>,
    _description: Option<String>,
    _confidence_threshold: Option<f64>,
    _update_interval: Option<String>,
}

/// Threat feed validator
struct ThreatFeedValidator {
    client: Client,
    timeout_duration: Duration,
}

impl ThreatFeedValidator {
    fn new(timeout_secs: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent("RustSecurity-ThreatFeedValidator/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            timeout_duration: Duration::from_secs(timeout_secs),
        }
    }

    async fn validate_all_feeds(
        &self,
        config: &ThreatFeedsConfig,
    ) -> Result<Vec<FeedValidationResult>> {
        let mut results = Vec::new();

        for (feed_name, feed_config) in &config.feeds {
            let result = self.validate_feed(feed_name, feed_config).await;
            results.push(result);
        }

        Ok(results)
    }

    async fn validate_feed(
        &self,
        feed_name: &str,
        config: &ThreatFeedConfig,
    ) -> FeedValidationResult {
        let mut result = FeedValidationResult {
            feed_name: feed_name.to_string(),
            url: config.url.clone().unwrap_or_else(|| "N/A".to_string()),
            enabled: config.enabled.unwrap_or(false),
            status: ValidationStatus::Skipped,
            response_time_ms: 0,
            content_size: 0,
            content_preview: String::new(),
            errors: Vec::new(),
            timestamp: Utc::now(),
        };

        // Skip disabled feeds
        if !result.enabled {
            result.status = ValidationStatus::Skipped;
            result.errors.push("Feed is disabled".to_string());
            return result;
        }

        // Validate URL
        let url = match &config.url {
            Some(url_str) => match Url::parse(url_str) {
                Ok(url) => url,
                Err(e) => {
                    result.status = ValidationStatus::Failed;
                    result.errors.push(format!("Invalid URL: {}", e));
                    return result;
                }
            },
            None => {
                result.status = ValidationStatus::Failed;
                result.errors.push("No URL configured".to_string());
                return result;
            }
        };

        // Validate URL scheme
        if !matches!(url.scheme(), "http" | "https") {
            result.status = ValidationStatus::Failed;
            result
                .errors
                .push(format!("Unsupported URL scheme: {}", url.scheme()));
            return result;
        }

        // Test connectivity
        let start_time = Instant::now();

        match self.test_feed_connectivity(&url, config).await {
            Ok(response_info) => {
                result.response_time_ms = start_time.elapsed().as_millis() as u64;
                result.content_size = response_info.content_size;
                result.content_preview = response_info.content_preview;
                result.status = ValidationStatus::Success;

                // Add warnings for slow responses
                if result.response_time_ms > 10000 {
                    result.status = ValidationStatus::Warning;
                    result.errors.push("Slow response time (>10s)".to_string());
                }

                // Add warnings for small content
                if result.content_size < 100 {
                    if result.status == ValidationStatus::Success {
                        result.status = ValidationStatus::Warning;
                    }
                    result
                        .errors
                        .push("Small content size (<100 bytes)".to_string());
                }
            }
            Err(e) => {
                result.response_time_ms = start_time.elapsed().as_millis() as u64;
                result.status = ValidationStatus::Failed;
                result
                    .errors
                    .push(format!("Connectivity test failed: {}", e));
            }
        }

        result
    }

    async fn test_feed_connectivity(
        &self,
        url: &Url,
        config: &ThreatFeedConfig,
    ) -> Result<ResponseInfo> {
        let mut request = self.client.get(url.as_str());

        // Add API key if configured
        if let Some(api_key) = &config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        // Add custom headers
        if let Some(headers) = &config.headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        // Send request with timeout
        let response = timeout(self.timeout_duration, request.send()).await??;

        // Check status code
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("HTTP error: {}", response.status()));
        }

        // Get content length
        let _content_size = response.content_length().unwrap_or(0);

        // Read a preview of the content
        let content_bytes = response.bytes().await?;
        let actual_size = content_bytes.len() as u64;

        let content_preview = if content_bytes.len() > 200 {
            String::from_utf8_lossy(&content_bytes[..200]).to_string()
        } else {
            String::from_utf8_lossy(&content_bytes).to_string()
        };

        Ok(ResponseInfo {
            content_size: actual_size,
            content_preview,
        })
    }
}

/// Response information from feed test
struct ResponseInfo {
    content_size: u64,
    content_preview: String,
}

/// Validation status for feeds
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ValidationStatus {
    Success,
    Failed,
    Warning,
    Skipped,
}

/// Individual feed validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FeedValidationResult {
    feed_name: String,
    url: String,
    enabled: bool,
    status: ValidationStatus,
    response_time_ms: u64,
    content_size: u64,
    content_preview: String,
    errors: Vec<String>,
    timestamp: DateTime<Utc>,
}

/// Complete validation report
#[derive(Debug, Serialize, Deserialize)]
struct ValidationReport {
    timestamp: DateTime<Utc>,
    total_feeds: u32,
    successful_feeds: u32,
    failed_feeds: u32,
    feeds: Vec<FeedValidationResult>,
}
