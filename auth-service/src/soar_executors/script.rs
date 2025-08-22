//! Script and HTTP Executors
//!
//! This module provides executors for script execution and HTTP requests.

use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};
use crate::soar_core::{StepAction, StepError, StepExecutor, WorkflowStep};
use async_trait::async_trait;
use reqwest::{header::HeaderMap, Client};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{error, info, instrument, warn};

/// Script execution step executor
pub struct ScriptExecutor {
    // Configuration for script execution
}

impl ScriptExecutor {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl StepExecutor for ScriptExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::ExecuteScript {
            script_type,
            script_content,
            parameters,
        } = &step.action
        {
            info!("Executing {} script", script_type);

            // Security check: Only allow specific script types
            match script_type.as_str() {
                "bash" | "python" | "powershell" => {
                    // Allowed script types
                }
                _ => {
                    return Err(StepError {
                        code: "UNSUPPORTED_SCRIPT_TYPE".to_string(),
                        message: format!("Unsupported script type: {}", script_type),
                        details: None,
                        retryable: false,
                    });
                }
            }

            // Execute script with timeout
            match self
                .execute_script_with_timeout(script_type, script_content, parameters)
                .await
            {
                Ok((exit_code, stdout, stderr)) => {
                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::AdminAction,
                            SecuritySeverity::Medium,
                            "soar_executor".to_string(),
                            format!("Script executed: {} (exit code: {})", script_type, exit_code),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome(if exit_code == 0 { "success" } else { "failure" })
                        .with_reason("Script execution step completed".to_string())
                        .with_detail("script_type".to_string(), script_type.clone())
                        .with_detail("exit_code".to_string(), exit_code),
                    );

                    let mut outputs = HashMap::new();
                    outputs.insert("exit_code".to_string(), Value::Number(exit_code.into()));
                    outputs.insert("stdout".to_string(), Value::String(stdout));
                    outputs.insert("stderr".to_string(), Value::String(stderr));
                    outputs.insert("script_type".to_string(), Value::String(script_type.clone()));

                    if exit_code != 0 {
                        return Err(StepError {
                            code: "SCRIPT_EXECUTION_FAILED".to_string(),
                            message: format!("Script exited with code: {}", exit_code),
                            details: Some(serde_json::json!({
                                "exit_code": exit_code,
                                "stderr": stderr
                            })),
                            retryable: false,
                        });
                    }

                    Ok(outputs)
                }
                Err(e) => {
                    error!("Script execution failed: {}", e);

                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::SystemError,
                            SecuritySeverity::High,
                            "soar_executor".to_string(),
                            format!("Script execution failed: {}", script_type),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("failure".to_string())
                        .with_reason(format!("Script execution error: {}", e.to_string()))
                        .with_detail("script_type".to_string(), script_type.clone())
                        .with_detail("error".to_string(), e.to_string()),
                    );

                    Err(StepError {
                        code: "SCRIPT_EXECUTION_ERROR".to_string(),
                        message: format!("Script execution error: {}", e),
                        details: Some(serde_json::json!({
                            "script_type": script_type,
                            "error": e.to_string()
                        })),
                        retryable: true,
                    })
                }
            }
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not ExecuteScript".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "script".to_string()
    }
}

impl ScriptExecutor {
    async fn execute_script_with_timeout(
        &self,
        script_type: &str,
        script_content: &str,
        parameters: &HashMap<String, String>,
    ) -> Result<(i32, String, String), Box<dyn std::error::Error + Send + Sync>> {
        let timeout_duration = Duration::from_secs(300); // 5 minutes timeout

        // For security, we'll simulate script execution rather than actually executing
        // In a production environment, this would need proper sandboxing
        warn!("Script execution is simulated for security reasons");
        
        tokio::time::sleep(Duration::from_millis(100)).await; // Simulate execution time

        // Simulate successful execution
        let stdout = format!("Simulated {} script execution completed", script_type);
        let stderr = String::new();
        let exit_code = 0;

        Ok((exit_code, stdout, stderr))
    }
}

/// HTTP request step executor
pub struct HttpRequestExecutor {
    client: Client,
}

impl HttpRequestExecutor {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }
}

#[async_trait]
impl StepExecutor for HttpRequestExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::HttpRequest {
            method,
            url,
            headers,
            body,
        } = &step.action
        {
            info!("Making HTTP {} request to: {}", method, url);

            // Build headers
            let mut header_map = HeaderMap::new();
            for (key, value) in headers {
                if let (Ok(header_name), Ok(header_value)) = (
                    key.parse::<reqwest::header::HeaderName>(),
                    value.parse::<reqwest::header::HeaderValue>(),
                ) {
                    header_map.insert(header_name, header_value);
                }
            }

            // Build request
            let mut request_builder = match method.to_uppercase().as_str() {
                "GET" => self.client.get(url),
                "POST" => self.client.post(url),
                "PUT" => self.client.put(url),
                "DELETE" => self.client.delete(url),
                "PATCH" => self.client.patch(url),
                _ => {
                    return Err(StepError {
                        code: "UNSUPPORTED_HTTP_METHOD".to_string(),
                        message: format!("Unsupported HTTP method: {}", method),
                        details: None,
                        retryable: false,
                    });
                }
            };

            request_builder = request_builder.headers(header_map);

            if let Some(request_body) = body {
                request_builder = request_builder.body(request_body.clone());
            }

            // Execute request
            match request_builder.send().await {
                Ok(response) => {
                    let status_code = response.status().as_u16();
                    let response_headers: HashMap<String, String> = response
                        .headers()
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();

                    let response_body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unable to read response body".to_string());

                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::AdminAction,
                            SecuritySeverity::Low,
                            "soar_executor".to_string(),
                            format!("HTTP {} request to {} completed (status: {})", method, url, status_code),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome(if status_code < 400 { "success" } else { "failure" })
                        .with_reason("HTTP request step completed".to_string())
                        .with_detail("method".to_string(), method.clone())
                        .with_detail("url".to_string(), url.clone())
                        .with_detail("status_code".to_string(), status_code),
                    );

                    let mut outputs = HashMap::new();
                    outputs.insert("status_code".to_string(), Value::Number(status_code.into()));
                    outputs.insert("response_body".to_string(), Value::String(response_body));
                    outputs.insert(
                        "response_headers".to_string(),
                        serde_json::to_value(response_headers)?,
                    );
                    outputs.insert("method".to_string(), Value::String(method.clone()));
                    outputs.insert("url".to_string(), Value::String(url.clone()));

                    Ok(outputs)
                }
                Err(e) => {
                    error!("HTTP request failed: {}", e);

                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::SystemError,
                            SecuritySeverity::Medium,
                            "soar_executor".to_string(),
                            format!("HTTP {} request to {} failed", method, url),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("failure".to_string())
                        .with_reason(format!("HTTP request error: {}", e.to_string()))
                        .with_detail("method".to_string(), method.clone())
                        .with_detail("url".to_string(), url.clone())
                        .with_detail("error".to_string(), e.to_string()),
                    );

                    Err(StepError {
                        code: "HTTP_REQUEST_FAILED".to_string(),
                        message: format!("HTTP request failed: {}", e),
                        details: Some(serde_json::json!({
                            "method": method,
                            "url": url,
                            "error": e.to_string()
                        })),
                        retryable: true,
                    })
                }
            }
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not HttpRequest".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "http_request".to_string()
    }
}

impl Default for ScriptExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for HttpRequestExecutor {
    fn default() -> Self {
        Self::new()
    }
}
