//! Prometheus client for collecting security metrics

use crate::{ComplianceError, ComplianceResult, MetricStatus, SecurityMetric};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, info};

/// Prometheus query client
pub struct PrometheusClient {
    base_url: String,
    client: Client,
}

impl PrometheusClient {
    #[must_use]
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Execute a Prometheus query
    pub async fn query(
        &self,
        query: &str,
        time: Option<DateTime<Utc>>,
    ) -> ComplianceResult<PrometheusResponse> {
        let url = format!("{}/api/v1/query", self.base_url);
        let mut params = vec![("query", query.to_string())];

        if let Some(time) = time {
            params.push(("time", time.timestamp().to_string()));
        }

        debug!("Executing Prometheus query: {}", query);

        let response = self.client.get(&url).query(&params).send().await?;

        if !response.status().is_success() {
            return Err(ComplianceError::DataCollection(format!(
                "Prometheus query failed with status: {}",
                response.status()
            )));
        }

        let prometheus_response: PrometheusResponse = response.json().await?;

        if prometheus_response.status != "success" {
            return Err(ComplianceError::DataCollection(format!(
                "Prometheus query error: {:?}",
                prometheus_response.error
            )));
        }

        Ok(prometheus_response)
    }

    /// Execute a range query
    pub async fn query_range(
        &self,
        query: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        step: &str,
    ) -> ComplianceResult<PrometheusResponse> {
        let url = format!("{}/api/v1/query_range", self.base_url);
        let params = vec![
            ("query", query.to_string()),
            ("start", start.timestamp().to_string()),
            ("end", end.timestamp().to_string()),
            ("step", step.to_string()),
        ];

        debug!(
            "Executing Prometheus range query: {} ({}s to {}s)",
            query,
            start.timestamp(),
            end.timestamp()
        );

        let response = self.client.get(&url).query(&params).send().await?;

        if !response.status().is_success() {
            return Err(ComplianceError::DataCollection(format!(
                "Prometheus range query failed with status: {}",
                response.status()
            )));
        }

        let prometheus_response: PrometheusResponse = response.json().await?;

        if prometheus_response.status != "success" {
            return Err(ComplianceError::DataCollection(format!(
                "Prometheus range query error: {:?}",
                prometheus_response.error
            )));
        }

        Ok(prometheus_response)
    }

    /// Collect security metrics from Prometheus
    pub async fn collect_security_metrics(&self) -> ComplianceResult<Vec<SecurityMetric>> {
        let mut metrics = Vec::new();
        let now = Utc::now();

        // Define security metrics to collect
        let metric_queries = vec![
            (
                "authentication_success_rate",
                r"rate(auth_service_authentication_success_total[5m]) / (rate(auth_service_authentication_success_total[5m]) + rate(auth_service_authentication_failure_total[5m])) * 100",
                95.0,
                "Authentication success rate percentage",
            ),
            (
                "failed_login_attempts",
                "increase(auth_service_authentication_failure_total[1h])",
                100.0,
                "Failed login attempts in the last hour",
            ),
            (
                "active_sessions",
                "auth_service_active_sessions",
                1000.0,
                "Number of currently active sessions",
            ),
            (
                "token_validation_errors",
                "increase(auth_service_token_validation_errors_total[1h])",
                50.0,
                "Token validation errors in the last hour",
            ),
            (
                "rate_limit_hits",
                "increase(auth_service_rate_limit_exceeded_total[1h])",
                200.0,
                "Rate limit violations in the last hour",
            ),
            (
                "mfa_success_rate",
                r"rate(auth_service_mfa_success_total[5m]) / (rate(auth_service_mfa_success_total[5m]) + rate(auth_service_mfa_failure_total[5m])) * 100",
                98.0,
                "MFA success rate percentage",
            ),
            (
                "threat_detections",
                "increase(threat_hunting_patterns_detected_total[1h])",
                10.0,
                "Threat patterns detected in the last hour",
            ),
            (
                "security_alerts",
                "threat_hunting_active_threats",
                5.0,
                "Currently active security threats",
            ),
        ];

        for (name, query, threshold, description) in metric_queries {
            match self.query(query, Some(now)).await {
                Ok(response) => {
                    if let Some(result) = response.data.result.first() {
                        if let Some(value_str) = result.value.get(1).and_then(|v| v.as_str()) {
                            if let Ok(value) = value_str.parse::<f64>() {
                                let status = if name.contains("rate") {
                                    // For rates, higher is better
                                    if value >= threshold {
                                        MetricStatus::Pass
                                    } else {
                                        MetricStatus::Fail
                                    }
                                } else {
                                    // For counts, lower is better
                                    if value <= threshold {
                                        MetricStatus::Pass
                                    } else {
                                        MetricStatus::Fail
                                    }
                                };

                                metrics.push(SecurityMetric {
                                    name: name.to_string(),
                                    value,
                                    threshold,
                                    status,
                                    description: description.to_string(),
                                    timestamp: now,
                                    tags: HashMap::new(),
                                });
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to collect metric {}: {}", name, e);
                    // Add a metric with unknown status
                    metrics.push(SecurityMetric {
                        name: name.to_string(),
                        value: 0.0,
                        threshold,
                        status: MetricStatus::Unknown,
                        description: format!("{description} (collection failed: {e})"),
                        timestamp: now,
                        tags: HashMap::new(),
                    });
                }
            }
        }

        info!(
            "Collected {} security metrics from Prometheus",
            metrics.len()
        );
        Ok(metrics)
    }

    /// Get available metrics from Prometheus
    pub async fn get_available_metrics(&self) -> ComplianceResult<Vec<String>> {
        let response = self
            .client
            .get(format!("{}/api/v1/label/__name__/values", self.base_url))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ComplianceError::DataCollection(format!(
                "Failed to get metrics list: {}",
                response.status()
            )));
        }

        let prometheus_response: PrometheusResponse = response.json().await?;

        if prometheus_response.status != "success" {
            return Err(ComplianceError::DataCollection(format!(
                "Prometheus metrics list error: {:?}",
                prometheus_response.error
            )));
        }

        let metrics = prometheus_response
            .data
            .result
            .into_iter()
            .filter_map(|result| {
                result
                    .value
                    .first()?
                    .as_str()
                    .map(std::string::ToString::to_string)
            })
            .collect();

        Ok(metrics)
    }

    /// Check if Prometheus is healthy
    pub async fn health_check(&self) -> ComplianceResult<bool> {
        let response = self
            .client
            .get(format!("{}/api/v1/query", self.base_url))
            .query(&[("query", "up")])
            .send()
            .await?;

        Ok(response.status().is_success())
    }
}

/// Prometheus API response structure
#[derive(Debug, Deserialize)]
pub struct PrometheusResponse {
    pub status: String,
    pub data: PrometheusData,
    pub error: Option<String>,
    #[serde(rename = "errorType")]
    pub error_type: Option<String>,
}

/// Prometheus response data
#[derive(Debug, Deserialize)]
pub struct PrometheusData {
    #[serde(rename = "resultType")]
    pub result_type: String,
    pub result: Vec<PrometheusResult>,
}

/// Individual Prometheus result
#[derive(Debug, Deserialize)]
pub struct PrometheusResult {
    pub metric: HashMap<String, String>,
    pub value: Vec<serde_json::Value>,
    pub values: Option<Vec<Vec<serde_json::Value>>>,
}

#[cfg(test)]
mod tests {
    // Tests temporarily disabled due to wiremock dependency removal
    // TODO: Re-enable tests when wiremock is added back or use alternative mocking

    /*
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_prometheus_query() {
        let mock_server = MockServer::start().await;

        let mock_response = serde_json::json!({
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"__name__": "test_metric"},
                        "value": [1640995200, "42.0"]
                    }
                ]
            }
        });

        Mock::given(method("GET"))
            .and(path("/api/v1/query"))
            .and(query_param("query", "test_metric"))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_response))
            .mount(&mock_server)
            .await;

        let client = PrometheusClient::new(mock_server.uri());
        let _result = client.query("test_metric", None).await.unwrap();

        assert_eq!(result.status, "success");
        assert_eq!(result.data.result.len(), 1);
    }

    #[tokio::test]
    async fn test_collect_security_metrics() {
        let mock_server = MockServer::start().await;

        // Mock authentication success rate query
        let auth_success_response = serde_json::json!({
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {},
                        "value": [1640995200, "98.5"]
                    }
                ]
            }
        });

        Mock::given(method("GET"))
            .and(path("/api/v1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(auth_success_response))
            .mount(&mock_server)
            .await;

        let client = PrometheusClient::new(mock_server.uri());
        let metrics = client.collect_security_metrics().await.unwrap();

        assert!(!metrics.is_empty());
    }
    */
}
