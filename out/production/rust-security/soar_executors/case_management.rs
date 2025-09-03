//! Case Management Executors
//!
//! This module provides executors for case management operations including
//! ticket creation and case updates.

use crate::security_logging::{SecurityEvent, SecurityEventType, SecuritySeverity};
use crate::soar_core::{StepAction, StepError, StepExecutor, WorkflowStep};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, instrument};

use super::clients::{CaseManagerClient, TicketingClient};

/// Ticket creation step executor
pub struct TicketCreateExecutor {
    ticketing_client: Arc<TicketingClient>,
}

impl TicketCreateExecutor {
    pub fn new() -> Self {
        Self {
            ticketing_client: Arc::new(TicketingClient::new()),
        }
    }
}

#[async_trait]
impl StepExecutor for TicketCreateExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::CreateTicket {
            title,
            description,
            priority,
            assignee,
        } = &step.action
        {
            info!("Creating ticket: {}", title);

            match self
                .ticketing_client
                .create_ticket(title, description, priority, assignee.as_deref())
                .await
            {
                Ok(ticket_id) => {
                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::AdminAction,
                            SecuritySeverity::Low,
                            "soar_executor".to_string(),
                            format!("Ticket created: {}", ticket_id),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("success".to_string())
                        .with_reason("Ticket creation step executed successfully".to_string())
                        .with_detail("ticket_id".to_string(), ticket_id.clone())
                        .with_detail("title".to_string(), title.clone())
                        .with_detail("priority".to_string(), priority.clone()),
                    );

                    let mut outputs = HashMap::new();
                    outputs.insert("ticket_id".to_string(), Value::String(ticket_id));
                    outputs.insert("title".to_string(), Value::String(title.clone()));
                    outputs.insert("priority".to_string(), Value::String(priority.clone()));

                    Ok(outputs)
                }
                Err(e) => {
                    error!("Failed to create ticket: {}", e);

                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::SystemError,
                            SecuritySeverity::Medium,
                            "soar_executor".to_string(),
                            format!("Failed to create ticket: {}", title),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("failure".to_string())
                        .with_reason(format!("Ticket creation failed: {}", e.to_string()))
                        .with_detail("title".to_string(), title.clone())
                        .with_detail("error".to_string(), e.to_string()),
                    );

                    Err(StepError {
                        code: "TICKET_CREATION_FAILED".to_string(),
                        message: format!("Failed to create ticket: {}", e),
                        details: Some(serde_json::json!({
                            "title": title,
                            "error": e.to_string()
                        })),
                        retryable: true,
                    })
                }
            }
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not CreateTicket".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "ticket_create".to_string()
    }
}

/// Case update step executor
pub struct CaseUpdateExecutor {
    case_manager_client: Arc<CaseManagerClient>,
}

impl CaseUpdateExecutor {
    pub fn new() -> Self {
        Self {
            case_manager_client: Arc::new(CaseManagerClient::new()),
        }
    }
}

#[async_trait]
impl StepExecutor for CaseUpdateExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::UpdateCase {
            case_id,
            fields,
            add_note,
        } = &step.action
        {
            info!("Updating case: {}", case_id);

            // Update case fields
            match self.case_manager_client.update_case(case_id, fields).await {
                Ok(updated_case) => {
                    // Add note if specified
                    if let Some(note) = add_note {
                        if let Err(e) = self
                            .case_manager_client
                            .add_case_note(case_id, note, "soar_system")
                            .await
                        {
                            error!("Failed to add note to case {}: {}", case_id, e);
                        }
                    }

                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::AdminAction,
                            SecuritySeverity::Low,
                            "soar_executor".to_string(),
                            format!("Case updated: {}", case_id),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("success".to_string())
                        .with_reason("Case update step executed successfully".to_string())
                        .with_detail("case_id".to_string(), case_id.clone())
                        .with_detail("fields_updated".to_string(), fields.keys().len()),
                    );

                    let mut outputs = HashMap::new();
                    outputs.insert("case_id".to_string(), Value::String(case_id.clone()));
                    outputs.insert(
                        "updated_case".to_string(),
                        serde_json::to_value(updated_case)?,
                    );
                    outputs.insert("note_added".to_string(), Value::Bool(add_note.is_some()));

                    Ok(outputs)
                }
                Err(e) => {
                    error!("Failed to update case {}: {}", case_id, e);

                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::SystemError,
                            SecuritySeverity::Medium,
                            "soar_executor".to_string(),
                            format!("Failed to update case: {}", case_id),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("failure".to_string())
                        .with_reason(format!("Case update failed: {}", e.to_string()))
                        .with_detail("case_id".to_string(), case_id.clone())
                        .with_detail("error".to_string(), e.to_string()),
                    );

                    Err(StepError {
                        code: "CASE_UPDATE_FAILED".to_string(),
                        message: format!("Failed to update case: {}", e),
                        details: Some(serde_json::json!({
                            "case_id": case_id,
                            "error": e.to_string()
                        })),
                        retryable: true,
                    })
                }
            }
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not UpdateCase".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "case_update".to_string()
    }
}

impl Default for TicketCreateExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for CaseUpdateExecutor {
    fn default() -> Self {
        Self::new()
    }
}
