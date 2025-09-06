use crate::app::AppContainer;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct PolicyAuthorizeRequest {
    pub request_id: String,
    pub principal: serde_json::Value,
    pub action: String,
    pub resource: serde_json::Value,
    pub context: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct PolicyAuthorizeResponse {
    pub decision: String,
}

/// Minimal policy client helper that:
/// - propagates `x-request-id`
/// - times requests and increments counters in the app metrics collector
/// - returns the decision string (e.g., "Allow" or "Deny")
pub async fn authorize(
    container: &AppContainer,
    base_url: &str,
    req_id: &str,
    payload: &PolicyAuthorizeRequest,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;

    let url = format!("{}/v1/authorize", base_url.trim_end_matches('/'));
    let start = std::time::Instant::now();

    let resp = match client
        .post(url.clone())
        .header("content-type", "application/json")
        .header("x-request-id", req_id)
        .json(payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            #[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
            let elapsed = start.elapsed();
            #[cfg(feature = "metrics")]
            {
                let action = payload.action.as_str();
                let resource = payload
                    .resource
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");
                let endpoint_group = action
                    .split("::")
                    .next()
                    .unwrap_or("unknown")
                    .to_lowercase();
                crate::metrics::MetricsHelper::record_policy_evaluation(
                    "remote",
                    &endpoint_group,
                    resource,
                    action,
                    "error",
                    elapsed,
                );
            }
            container
                .metrics_collector
                .increment_counter("policy_authorization_http_errors_total", 1)
                .await;
            return Err(format!("policy-service send error: {}", e).into());
        }
    };

    #[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
    let elapsed = start.elapsed();

    // Record metrics in a minimal way via the infrastructure metrics collector
    container
        .metrics_collector
        .increment_counter("policy_authorization_requests_total", 1)
        .await;
    container
        .metrics_collector
        .set_gauge(
            "policy_authorization_last_latency_ms",
            elapsed.as_millis() as f64,
        )
        .await;

    let status = resp.status();
    if !status.is_success() {
        #[cfg(feature = "metrics")]
        {
            let action = payload.action.as_str();
            let resource = payload
                .resource
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let endpoint_group = action
                .split("::")
                .next()
                .unwrap_or("unknown")
                .to_lowercase();
            crate::metrics::MetricsHelper::record_policy_evaluation(
                "remote",
                &endpoint_group,
                resource,
                action,
                "error",
                elapsed,
            );
        }
        container
            .metrics_collector
            .increment_counter("policy_authorization_http_errors_total", 1)
            .await;
        return Err(format!("policy-service HTTP {}", status).into());
    }

    let body: PolicyAuthorizeResponse = resp.json().await?;
    let decision = body.decision.clone();

    #[cfg(feature = "metrics")]
    {
        // Best-effort labels for Prometheus metrics
        let result = if decision.eq_ignore_ascii_case("allow") {
            "allow"
        } else {
            "deny"
        };
        let action = payload.action.as_str();
        let resource = payload
            .resource
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");
        let endpoint_group = action
            .split("::")
            .next()
            .unwrap_or("unknown")
            .to_lowercase();
        crate::metrics::MetricsHelper::record_policy_evaluation(
            "remote",
            &endpoint_group,
            resource,
            action,
            result,
            elapsed,
        );
    }
    let counter_name = if decision.eq_ignore_ascii_case("allow") {
        "policy_authorization_allow_total"
    } else {
        "policy_authorization_deny_total"
    };
    container
        .metrics_collector
        .increment_counter(counter_name, 1)
        .await;

    // Emit a concise tracing event for debugging/correlation
    {
        let action = payload.action.as_str();
        let endpoint_group = action.split("::").next().unwrap_or("unknown");
        tracing::info!(
            target = "policy_client",
            req_id = %payload.request_id,
            endpoint_group = %endpoint_group,
            action = %payload.action,
            resource_type = %payload
                .resource
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown"),
            decision = %decision,
            latency_ms = %elapsed.as_millis(),
            "policy_authorize_completed"
        );
    }

    Ok(decision)
}

/// Simpler authorization client without metrics, suitable for direct handler use.
pub async fn authorize_basic(
    base_url: &str,
    req_id: &str,
    payload: &PolicyAuthorizeRequest,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;

    let url = format!("{}/v1/authorize", base_url.trim_end_matches('/'));
    let start = std::time::Instant::now();
    let resp = match client
        .post(url.clone())
        .header("content-type", "application/json")
        .header("x-request-id", req_id)
        .json(payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            #[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
            let elapsed = start.elapsed();
            #[cfg(feature = "metrics")]
            {
                let action = payload.action.as_str();
                let resource = payload
                    .resource
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");
                let endpoint_group = action
                    .split("::")
                    .next()
                    .unwrap_or("unknown")
                    .to_lowercase();
                crate::metrics::MetricsHelper::record_policy_evaluation(
                    "remote",
                    &endpoint_group,
                    resource,
                    action,
                    "error",
                    elapsed,
                );
            }
            return Err(format!("policy-service send error: {}", e).into());
        }
    };

    if !resp.status().is_success() {
        #[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
        let elapsed = start.elapsed();
        #[cfg(feature = "metrics")]
        {
            let action = payload.action.as_str();
            let resource = payload
                .resource
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let endpoint_group = action
                .split("::")
                .next()
                .unwrap_or("unknown")
                .to_lowercase();
            crate::metrics::MetricsHelper::record_policy_evaluation(
                "remote",
                &endpoint_group,
                resource,
                action,
                "error",
                elapsed,
            );
        }
        return Err(format!("policy-service HTTP {}", resp.status()).into());
    }

    let body: PolicyAuthorizeResponse = resp.json().await?;
    #[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
    let elapsed = start.elapsed();

    #[cfg(feature = "metrics")]
    {
        let result = if body.decision.eq_ignore_ascii_case("allow") {
            "allow"
        } else {
            "deny"
        };
        let action = payload.action.as_str();
        let resource = payload
            .resource
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");
        let endpoint_group = action
            .split("::")
            .next()
            .unwrap_or("unknown")
            .to_lowercase();
        crate::metrics::MetricsHelper::record_policy_evaluation(
            "remote",
            &endpoint_group,
            resource,
            action,
            result,
            elapsed,
        );
    }

    Ok(body.decision)
}
