use chrono::Utc;
use clap::{Arg, Command};
use compliance_tools::{ComplianceError, MetricStatus, Result, SecurityMetric};
use std::collections::HashMap;
use tracing::{debug, info};

// Unused dependencies (required by workspace but not used in this binary)
use anyhow as _;
use calamine as _;
use common as _;
use config as _;
use csv as _;
use dotenvy as _;
use handlebars as _;
use moka as _;
#[cfg(feature = "prometheus-metrics")]
use prometheus as _;
use pulldown_cmark as _;
use regex as _;
use reqwest as _;
use serde as _;
use serde_yaml as _;
use sha2 as _;
use tempfile as _;
use tera as _;
use thiserror as _;
use tracing_subscriber as _;
use url as _;
use uuid as _;
use walkdir as _;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("security-metrics-collector")
        .version("1.0.0")
        .about("Collects and reports security metrics")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FORMAT")
                .help("Output format (json, prometheus, csv)")
                .default_value("json"),
        )
        .arg(
            Arg::new("interval")
                .short('i')
                .long("interval")
                .value_name("SECONDS")
                .help("Collection interval in seconds")
                .default_value("60"),
        )
        .get_matches();

    let output_format = matches.get_one::<String>("output").unwrap();
    let interval: u64 = matches
        .get_one::<String>("interval")
        .unwrap()
        .parse()
        .map_err(|_| ComplianceError::Configuration("Invalid interval value".to_string()))?;

    info!("🔍 Security Metrics Collector v1.0.0");
    info!("📊 Output format: {output_format}");
    info!("⏱️  Collection interval: {interval}s");

    let collector = MetricsCollector::new();

    loop {
        debug!("🚀 Collecting security metrics...");
        let metrics = collector.collect_metrics();

        match output_format.as_str() {
            "json" => output_json(&metrics)?,
            "prometheus" => output_prometheus(&metrics),
            "csv" => output_csv(&metrics),
            _ => {
                return Err(ComplianceError::Configuration(
                    "Invalid output format".to_string(),
                ))
            }
        }

        info!("✅ Collected {} metrics", metrics.len());
        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
    }
}

struct MetricsCollector {
    tags: HashMap<String, String>,
}

impl MetricsCollector {
    fn new() -> Self {
        let mut tags = HashMap::new();
        tags.insert(
            "collector".to_string(),
            "security-metrics-collector".to_string(),
        );
        tags.insert("version".to_string(), "1.0.0".to_string());
        Self { tags }
    }

    fn collect_metrics(&self) -> Vec<SecurityMetric> {
        let now = Utc::now();
        let mut metrics = Vec::with_capacity(5);

        let auth_requests = Self::get_auth_requests_count();
        metrics.push(SecurityMetric {
            name: "auth_requests_total".to_string(),
            value: auth_requests,
            threshold: 1000.0,
            status: MetricStatus::Pass,
            description: "Total authentication requests in the last hour".to_string(),
            timestamp: now,
            tags: self.tags.clone(),
        });

        let auth_failures = Self::get_auth_failures_count();
        metrics.push(SecurityMetric {
            name: "auth_failures_total".to_string(),
            value: auth_failures,
            threshold: 100.0,
            status: Self::evaluate_threshold(auth_failures, 100.0),
            description: "Failed authentication attempts in the last hour".to_string(),
            timestamp: now,
            tags: self.tags.clone(),
        });

        let active_sessions = Self::get_active_sessions_count();
        metrics.push(SecurityMetric {
            name: "active_sessions".to_string(),
            value: active_sessions,
            threshold: 10000.0,
            status: MetricStatus::Pass,
            description: "Currently active user sessions".to_string(),
            timestamp: now,
            tags: self.tags.clone(),
        });

        let rate_limit_hits = Self::get_rate_limit_hits();
        metrics.push(SecurityMetric {
            name: "rate_limit_hits_total".to_string(),
            value: rate_limit_hits,
            threshold: 500.0,
            status: Self::evaluate_threshold(rate_limit_hits, 500.0),
            description: "Rate limit violations in the last hour".to_string(),
            timestamp: now,
            tags: self.tags.clone(),
        });

        let security_incidents = Self::get_security_incidents();
        metrics.push(SecurityMetric {
            name: "security_incidents_total".to_string(),
            value: security_incidents,
            threshold: 10.0,
            status: Self::evaluate_threshold(security_incidents, 10.0),
            description: "Security incidents detected in the last hour".to_string(),
            timestamp: now,
            tags: self.tags.clone(),
        });

        metrics
    }

    fn evaluate_threshold(value: f64, threshold: f64) -> MetricStatus {
        if value > threshold {
            MetricStatus::Fail
        } else if value > threshold * 0.8 {
            MetricStatus::Warning
        } else {
            MetricStatus::Pass
        }
    }

    fn get_auth_requests_count() -> f64 {
        fastrand::f64() * 1200.0
    }

    fn get_auth_failures_count() -> f64 {
        fastrand::f64() * 150.0
    }

    fn get_active_sessions_count() -> f64 {
        fastrand::f64() * 8000.0
    }

    fn get_rate_limit_hits() -> f64 {
        fastrand::f64() * 600.0
    }

    fn get_security_incidents() -> f64 {
        fastrand::f64() * 15.0
    }
}

#[allow(clippy::print_stdout)]
fn output_json(metrics: &[SecurityMetric]) -> Result<()> {
    let json = serde_json::to_string_pretty(metrics).map_err(ComplianceError::Serialization)?;
    println!("{json}");
    Ok(())
}

#[allow(clippy::print_stdout)]
fn output_prometheus(metrics: &[SecurityMetric]) {
    for metric in metrics {
        println!("# HELP {} {}", metric.name, metric.description);
        println!("# TYPE {} gauge", metric.name);

        let mut labels = Vec::new();
        for (key, value) in &metric.tags {
            labels.push(format!("{key}=\"{value}\""));
        }
        labels.push(format!("status=\"{:?}\"", metric.status));

        println!(
            "{}{{{} {} {}",
            metric.name,
            labels.join(","),
            metric.value,
            metric.timestamp.timestamp()
        );
    }
}

#[allow(clippy::print_stdout)]
fn output_csv(metrics: &[SecurityMetric]) {
    println!("name,value,threshold,status,description,timestamp");
    for metric in metrics {
        println!(
            "{},{},{},{:?},{},{}",
            metric.name,
            metric.value,
            metric.threshold,
            metric.status,
            metric.description.replace(',', ";"),
            metric.timestamp.format("%Y-%m-%d %H:%M:%S")
        );
    }
}
