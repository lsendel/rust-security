//! Query Executors
//!
//! This module provides executors for various query operations including
//! SIEM queries and database queries.

use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};
use crate::soar_core::{StepAction, StepError, StepExecutor, WorkflowStep};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, instrument};

use super::clients::SiemClient;

/// SIEM query step executor
pub struct SiemQueryExecutor {
    siem_client: Arc<SiemClient>,
}

impl SiemQueryExecutor {
    pub fn new() -> Self {
        Self {
            siem_client: Arc::new(SiemClient::new()),
        }
    }
}

#[async_trait]
impl StepExecutor for SiemQueryExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::QuerySiem {
            query,
            time_range,
            max_results,
        } = &step.action
        {
            info!("Executing SIEM query: {}", query);

            match self
                .siem_client
                .execute_query(query, time_range, *max_results)
                .await
            {
                Ok(results) => {
                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::AdminAction,
                            SecuritySeverity::Low,
                            "soar_executor".to_string(),
                            format!("SIEM query executed: {}", query),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("success".to_string())
                        .with_reason("SIEM query step executed successfully".to_string())
                        .with_detail("query".to_string(), query.clone())
                        .with_detail("time_range".to_string(), time_range.clone())
                        .with_detail("max_results".to_string(), *max_results),
                    );

                    let mut outputs = HashMap::new();
                    outputs.insert("query_results".to_string(), results);
                    outputs.insert("query".to_string(), Value::String(query.clone()));
                    outputs.insert("time_range".to_string(), Value::String(time_range.clone()));

                    Ok(outputs)
                }
                Err(e) => {
                    error!("SIEM query failed: {}", e);

                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::SystemError,
                            SecuritySeverity::Medium,
                            "soar_executor".to_string(),
                            format!("SIEM query failed: {}", query),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("failure".to_string())
                        .with_reason(format!("SIEM query failed: {}", e.to_string()))
                        .with_detail("query".to_string(), query.clone())
                        .with_detail("error".to_string(), e.to_string()),
                    );

                    Err(StepError {
                        code: "SIEM_QUERY_FAILED".to_string(),
                        message: format!("SIEM query failed: {}", e),
                        details: Some(serde_json::json!({
                            "query": query,
                            "error": e.to_string()
                        })),
                        retryable: true,
                    })
                }
            }
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not QuerySiem".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "siem_query".to_string()
    }
}

/// Database query step executor
pub struct DatabaseQueryExecutor {
    // Database connection would be initialized here
}

impl DatabaseQueryExecutor {
    pub fn new() -> Self {
        Self {
            // Initialize database connection
        }
    }
}

#[async_trait]
impl StepExecutor for DatabaseQueryExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::ExecuteQuery {
            query,
            parameters,
            timeout_seconds,
        } = &step.action
        {
            info!("Executing database query: {}", query);

            // Simulate database query execution
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // Mock results
            let mock_results = serde_json::json!([
                {"id": 1, "name": "result1", "value": "data1"},
                {"id": 2, "name": "result2", "value": "data2"}
            ]);

            SecurityLogger::log_event(
                &SecurityEvent::new(
                    SecurityEventType::AdminAction,
                    SecuritySeverity::Low,
                    "soar_executor".to_string(),
                    "Database query executed successfully".to_string(),
                )
                .with_actor("soar_system".to_string())
                .with_action("soar_execute".to_string())
                .with_target("soar_playbook".to_string())
                .with_outcome("success".to_string())
                .with_reason("Database query step executed successfully".to_string())
                .with_detail("query".to_string(), query.clone())
                .with_detail("timeout_seconds".to_string(), *timeout_seconds),
            );

            let mut outputs = HashMap::new();
            outputs.insert("query_results".to_string(), mock_results);
            outputs.insert("query".to_string(), Value::String(query.clone()));
            outputs.insert("rows_affected".to_string(), Value::Number(2.into()));

            Ok(outputs)
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not ExecuteQuery".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "database_query".to_string()
    }
}

impl Default for SiemQueryExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for DatabaseQueryExecutor {
    fn default() -> Self {
        Self::new()
    }
}
