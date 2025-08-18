//! Performance Impact Monitor Tool

use super::{RedTeamTool, ToolConfig, ToolResult};
use anyhow::Result;
use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{info, warn};

pub struct PerformanceMonitor {
    client: Client,
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .danger_accept_invalid_certs(true)
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    async fn measure_baseline_performance(&self, target: &str) -> Result<PerformanceBaseline> {
        info!("📊 Measuring baseline performance");

        let mut response_times = Vec::new();
        let mut error_count = 0;

        // Take 10 baseline measurements
        for _ in 0..10 {
            let start = Instant::now();

            let result = self.client.get(&format!("{}/health", target)).send().await;

            let duration = start.elapsed();

            match result {
                Ok(response) => {
                    if response.status().is_success() {
                        response_times.push(duration.as_millis() as u64);
                    } else {
                        error_count += 1;
                    }
                }
                Err(_) => {
                    error_count += 1;
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let avg_response_time = if response_times.is_empty() {
            0
        } else {
            response_times.iter().sum::<u64>() / response_times.len() as u64
        };

        let min_response_time = response_times.iter().min().copied().unwrap_or(0);
        let max_response_time = response_times.iter().max().copied().unwrap_or(0);

        Ok(PerformanceBaseline {
            avg_response_time,
            min_response_time,
            max_response_time,
            error_rate: error_count as f64 / 10.0,
            sample_size: response_times.len(),
        })
    }

    async fn measure_under_attack(
        &self,
        target: &str,
        config: &ToolConfig,
    ) -> Result<PerformanceMetrics> {
        info!("⚡ Measuring performance under attack");

        let concurrent_attacks = config.concurrent_threads;
        let duration = Duration::from_secs(config.duration_seconds.min(60)); // Cap at 1 minute

        let start_time = Instant::now();
        let mut handles = Vec::new();

        // Launch concurrent attack threads
        for i in 0..concurrent_attacks {
            let client = self.client.clone();
            let target = target.to_string();
            let thread_duration = duration;

            let handle = tokio::spawn(async move {
                let mut thread_metrics = ThreadMetrics::new(i);
                let thread_start = Instant::now();

                while thread_start.elapsed() < thread_duration {
                    let request_start = Instant::now();

                    // Simulate various attack requests
                    let endpoints = vec![
                        "/health",
                        "/oauth/token",
                        "/oauth/introspect",
                        "/admin/keys/rotation/status",
                    ];

                    let endpoint = endpoints[i as usize % endpoints.len()];
                    let result = client
                        .get(&format!("{}{}", target, endpoint))
                        .header("X-Attack-Thread", i.to_string())
                        .send()
                        .await;

                    let request_duration = request_start.elapsed();
                    thread_metrics.record_request(request_duration, result.is_ok());

                    tokio::time::sleep(Duration::from_millis(50)).await;
                }

                thread_metrics
            });

            handles.push(handle);
        }

        // Also measure legitimate traffic performance during attack
        let legit_client = self.client.clone();
        let legit_target = target.to_string();
        let legit_duration = duration;

        let legit_handle = tokio::spawn(async move {
            let mut legit_metrics = Vec::new();
            let legit_start = Instant::now();

            while legit_start.elapsed() < legit_duration {
                let request_start = Instant::now();

                let result = legit_client
                    .get(&format!("{}/health", legit_target))
                    .header("X-Legitimate-Request", "true")
                    .send()
                    .await;

                let request_duration = request_start.elapsed();
                legit_metrics.push((request_duration.as_millis() as u64, result.is_ok()));

                tokio::time::sleep(Duration::from_millis(1000)).await; // Slower rate for legit traffic
            }

            legit_metrics
        });

        // Collect results
        let mut all_thread_metrics = Vec::new();
        for handle in handles {
            if let Ok(metrics) = handle.await {
                all_thread_metrics.push(metrics);
            }
        }

        let legit_traffic_metrics = legit_handle.await.unwrap_or_default();

        let total_duration = start_time.elapsed();

        Ok(PerformanceMetrics {
            thread_metrics: all_thread_metrics,
            legitimate_traffic: legit_traffic_metrics,
            total_duration,
            concurrent_threads: concurrent_attacks,
        })
    }

    fn analyze_performance_impact(
        &self,
        baseline: &PerformanceBaseline,
        under_attack: &PerformanceMetrics,
    ) -> PerformanceAnalysis {
        // Calculate aggregate metrics from all threads
        let mut all_response_times = Vec::new();
        let mut total_requests = 0;
        let mut total_errors = 0;

        for thread in &under_attack.thread_metrics {
            all_response_times.extend(&thread.response_times);
            total_requests += thread.total_requests();
            total_errors += thread.error_count();
        }

        let avg_attack_response_time = if all_response_times.is_empty() {
            0
        } else {
            all_response_times.iter().sum::<u64>() / all_response_times.len() as u64
        };

        let error_rate_under_attack =
            if total_requests > 0 { total_errors as f64 / total_requests as f64 } else { 0.0 };

        // Calculate legitimate traffic impact
        let legit_response_times: Vec<u64> = under_attack
            .legitimate_traffic
            .iter()
            .filter(|(_, success)| *success)
            .map(|(time, _)| *time)
            .collect();

        let avg_legit_response_time = if legit_response_times.is_empty() {
            baseline.avg_response_time
        } else {
            legit_response_times.iter().sum::<u64>() / legit_response_times.len() as u64
        };

        let legit_error_count =
            under_attack.legitimate_traffic.iter().filter(|(_, success)| !*success).count();

        let legit_error_rate = if !under_attack.legitimate_traffic.is_empty() {
            legit_error_count as f64 / under_attack.legitimate_traffic.len() as f64
        } else {
            0.0
        };

        // Calculate performance degradation
        let response_time_degradation = if baseline.avg_response_time > 0 {
            (avg_legit_response_time as f64 - baseline.avg_response_time as f64)
                / baseline.avg_response_time as f64
        } else {
            0.0
        };

        let error_rate_increase = legit_error_rate - baseline.error_rate;

        // Calculate requests per second
        let requests_per_second = if under_attack.total_duration.as_secs() > 0 {
            total_requests as f64 / under_attack.total_duration.as_secs() as f64
        } else {
            0.0
        };

        PerformanceAnalysis {
            baseline_avg_response_time: baseline.avg_response_time,
            attack_avg_response_time: avg_attack_response_time,
            legit_avg_response_time: avg_legit_response_time,
            response_time_degradation,
            baseline_error_rate: baseline.error_rate,
            attack_error_rate: error_rate_under_attack,
            legit_error_rate,
            error_rate_increase,
            requests_per_second,
            total_requests,
            service_available: error_rate_increase < 0.5, // Service considered available if error rate increase < 50%
        }
    }
}

impl RedTeamTool for PerformanceMonitor {
    fn name(&self) -> &str {
        "performance_monitor"
    }

    fn description(&self) -> &str {
        "Monitors performance impact of security attacks on the target service"
    }

    async fn execute(&self, target: &str, config: &ToolConfig) -> Result<ToolResult> {
        // Step 1: Measure baseline performance
        let baseline = self.measure_baseline_performance(target).await?;

        // Step 2: Measure performance under attack
        let under_attack = self.measure_under_attack(target, config).await?;

        // Step 3: Analyze the impact
        let analysis = self.analyze_performance_impact(&baseline, &under_attack);

        // Prepare metrics
        let mut metrics = HashMap::new();
        metrics.insert(
            "baseline_response_time_ms".to_string(),
            analysis.baseline_avg_response_time as f64,
        );
        metrics.insert(
            "attack_response_time_ms".to_string(),
            analysis.attack_avg_response_time as f64,
        );
        metrics
            .insert("legit_response_time_ms".to_string(), analysis.legit_avg_response_time as f64);
        metrics.insert("response_time_degradation".to_string(), analysis.response_time_degradation);
        metrics.insert("error_rate_increase".to_string(), analysis.error_rate_increase);
        metrics.insert("requests_per_second".to_string(), analysis.requests_per_second);
        metrics.insert(
            "service_available".to_string(),
            if analysis.service_available { 1.0 } else { 0.0 },
        );

        // Generate findings
        let mut findings = Vec::new();

        if analysis.response_time_degradation > 0.5 {
            findings.push(format!(
                "Significant performance degradation: {:.1}% increase in response time",
                analysis.response_time_degradation * 100.0
            ));
        }

        if analysis.error_rate_increase > 0.2 {
            findings.push(format!(
                "High error rate increase: {:.1}% during attack",
                analysis.error_rate_increase * 100.0
            ));
        }

        if !analysis.service_available {
            findings.push("Service availability compromised during attack".to_string());
        }

        if analysis.requests_per_second > 100.0 {
            findings.push(format!(
                "High attack rate achieved: {:.1} requests/second",
                analysis.requests_per_second
            ));
        }

        // Success if service remained available and degradation was minimal
        let success = analysis.service_available
            && analysis.response_time_degradation < 1.0
            && analysis.error_rate_increase < 0.3;

        let raw_data = json!({
            "baseline": {
                "avg_response_time": baseline.avg_response_time,
                "min_response_time": baseline.min_response_time,
                "max_response_time": baseline.max_response_time,
                "error_rate": baseline.error_rate,
                "sample_size": baseline.sample_size
            },
            "under_attack": {
                "total_requests": analysis.total_requests,
                "requests_per_second": analysis.requests_per_second,
                "concurrent_threads": under_attack.concurrent_threads,
                "duration_seconds": under_attack.total_duration.as_secs(),
                "attack_error_rate": analysis.attack_error_rate
            },
            "analysis": {
                "response_time_degradation": analysis.response_time_degradation,
                "error_rate_increase": analysis.error_rate_increase,
                "service_available": analysis.service_available,
                "baseline_avg_response_time": analysis.baseline_avg_response_time,
                "legit_avg_response_time": analysis.legit_avg_response_time
            }
        });

        Ok(ToolResult { tool_name: self.name().to_string(), success, metrics, findings, raw_data })
    }
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct PerformanceBaseline {
    avg_response_time: u64,
    min_response_time: u64,
    max_response_time: u64,
    error_rate: f64,
    sample_size: usize,
}

#[derive(Debug)]
struct PerformanceMetrics {
    thread_metrics: Vec<ThreadMetrics>,
    legitimate_traffic: Vec<(u64, bool)>, // (response_time_ms, success)
    total_duration: Duration,
    concurrent_threads: u32,
}

#[derive(Debug)]
struct ThreadMetrics {
    thread_id: u32,
    response_times: Vec<u64>,
    errors: usize,
}

impl ThreadMetrics {
    fn new(thread_id: u32) -> Self {
        Self { thread_id, response_times: Vec::new(), errors: 0 }
    }

    fn record_request(&mut self, duration: Duration, success: bool) {
        self.response_times.push(duration.as_millis() as u64);
        if !success {
            self.errors += 1;
        }
    }

    fn total_requests(&self) -> usize {
        self.response_times.len()
    }

    fn error_count(&self) -> usize {
        self.errors
    }
}

#[derive(Debug)]
struct PerformanceAnalysis {
    baseline_avg_response_time: u64,
    attack_avg_response_time: u64,
    legit_avg_response_time: u64,
    response_time_degradation: f64,
    baseline_error_rate: f64,
    attack_error_rate: f64,
    legit_error_rate: f64,
    error_rate_increase: f64,
    requests_per_second: f64,
    total_requests: usize,
    service_available: bool,
}
