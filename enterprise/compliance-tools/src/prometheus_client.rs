//! Prometheus client for collecting security metrics

use crate::{ComplianceError, ComplianceResult, MetricStatus, SecurityMetric};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, info};

/// Prometheus query client
pub struct PrometheusClient {
    base_url: String,
    client: Client,
}

impl PrometheusClient {
    /// Create a new Prometheus client
    ///
    /// # Panics
    /// Panics if the underlying HTTP client cannot be constructed.
    #[must_use]
    pub fn new(base_url: &str) -> Self {
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
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or the response indicates an error.
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
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or the response indicates an error.
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
    ///
    /// # Errors
    /// Returns an error when any of the collection HTTP requests fail or return an error response.
    pub async fn collect_security_metrics(&self) -> ComplianceResult<Vec<SecurityMetric>> {
        let now = Utc::now();
        let defs = Self::metric_definitions();
        let mut metrics = Vec::with_capacity(defs.len());
        for def in &defs {
            let metric = self.fetch_metric(now, def).await;
            metrics.push(metric);
        }

        info!(
            "Collected {} security metrics from Prometheus",
            metrics.len()
        );
        Ok(metrics)
    }

    fn metric_definitions() -> Vec<MetricDef<'static>> {
        vec![
            MetricDef::new(
                "authentication_success_rate",
                r"rate(auth_service_authentication_success_total[5m]) / (rate(auth_service_authentication_success_total[5m]) + rate(auth_service_authentication_failure_total[5m])) * 100",
                95.0,
                true,
                "Authentication success rate percentage",
            ),
            MetricDef::new(
                "failed_login_attempts",
                "increase(auth_service_authentication_failure_total[1h])",
                100.0,
                false,
                "Failed login attempts in the last hour",
            ),
            MetricDef::new(
                "active_sessions",
                "auth_service_active_sessions",
                1000.0,
                false,
                "Number of currently active sessions",
            ),
            MetricDef::new(
                "token_validation_errors",
                "increase(auth_service_token_validation_errors_total[1h])",
                50.0,
                false,
                "Token validation errors in the last hour",
            ),
            MetricDef::new(
                "rate_limit_hits",
                "increase(auth_service_rate_limit_exceeded_total[1h])",
                200.0,
                false,
                "Rate limit violations in the last hour",
            ),
            MetricDef::new(
                "mfa_success_rate",
                r"rate(auth_service_mfa_success_total[5m]) / (rate(auth_service_mfa_success_total[5m]) + rate(auth_service_mfa_failure_total[5m])) * 100",
                98.0,
                true,
                "MFA success rate percentage",
            ),
            MetricDef::new(
                "threat_detections",
                "increase(threat_hunting_patterns_detected_total[1h])",
                10.0,
                false,
                "Threat patterns detected in the last hour",
            ),
            MetricDef::new(
                "security_alerts",
                "threat_hunting_active_threats",
                5.0,
                false,
                "Currently active security threats",
            ),
        ]
    }

    async fn fetch_metric(&self, now: DateTime<Utc>, def: &MetricDef<'_>) -> SecurityMetric {
        match self.query(def.query, Some(now)).await {
            Ok(response) => {
                if let Some(result) = response.data.result.first() {
                    if let Some(value_str) = result.value.get(1).and_then(|v| v.as_str()) {
                        if let Ok(value) = value_str.parse::<f64>() {
                            let status = if def.higher_is_better {
                                if value >= def.threshold {
                                    MetricStatus::Pass
                                } else {
                                    MetricStatus::Fail
                                }
                            } else if value <= def.threshold {
                                MetricStatus::Pass
                            } else {
                                MetricStatus::Fail
                            };

                            return SecurityMetric {
                                name: def.name.to_string(),
                                value,
                                threshold: def.threshold,
                                status,
                                description: def.description.clone().into_owned(),
                                timestamp: now,
                                tags: HashMap::new(),
                            };
                        }
                    }
                }
                Self::unknown_metric(now, def, "no data")
            }
            Err(e) => {
                error!("Failed to collect metric {}: {}", def.name, e);
                Self::unknown_metric(now, def, &format!("collection failed: {e}"))
            }
        }
    }

    fn unknown_metric(now: DateTime<Utc>, def: &MetricDef<'_>, reason: &str) -> SecurityMetric {
        SecurityMetric {
            name: def.name.to_string(),
            value: 0.0,
            threshold: def.threshold,
            status: MetricStatus::Unknown,
            description: format!("{} ({reason})", def.description),
            timestamp: now,
            tags: HashMap::new(),
        }
    }

    /// Get available metrics from Prometheus
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or the response indicates an error.
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
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails.
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

#[derive(Debug, Clone)]
struct MetricDef<'a> {
    name: &'a str,
    query: &'a str,
    threshold: f64,
    higher_is_better: bool,
    description: Cow<'a, str>,
}

impl<'a> MetricDef<'a> {
    const fn new(
        name: &'a str,
        query: &'a str,
        threshold: f64,
        higher_is_better: bool,
        description: &'a str,
    ) -> Self {
        Self {
            name,
            query,
            threshold,
            higher_is_better,
            description: Cow::Borrowed(description),
        }
    }
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

        let client = PrometheusClient::new(&mock_server.uri());
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

        let client = PrometheusClient::new(&mock_server.uri());
        let metrics = client.collect_security_metrics().await.unwrap();

        assert!(!metrics.is_empty());
    }
    */
}
