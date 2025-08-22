//! Step Executor Registry
//!
//! This module provides the registry for managing and accessing step executors.
//! It handles registration of all available executors and provides lookup functionality.

use super::*;
use crate::soar_core::StepExecutor;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// Registry for all step executors
pub struct StepExecutorRegistry {
    executors: HashMap<String, Arc<dyn StepExecutor + Send + Sync>>,
}

impl StepExecutorRegistry {
    /// Create a new registry with default executors
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut registry = Self {
            executors: HashMap::new(),
        };

        // Register default executors
        registry.register_default_executors().await?;

        Ok(registry)
    }

    /// Register all default step executors
    async fn register_default_executors(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Security action executors
        self.register_executor(Arc::new(IpBlockExecutor::new()))
            .await?;
        self.register_executor(Arc::new(AccountLockExecutor::new()))
            .await?;
        self.register_executor(Arc::new(TokenRevokeExecutor::new().await))
            .await?;

        // Notification executors
        self.register_executor(Arc::new(EmailNotificationExecutor::new().await?))
            .await?;
        self.register_executor(Arc::new(SlackNotificationExecutor::new()))
            .await?;
        self.register_executor(Arc::new(WebhookNotificationExecutor::new()))
            .await?;

        // SIEM and query executors
        self.register_executor(Arc::new(SiemQueryExecutor::new()))
            .await?;
        self.register_executor(Arc::new(DatabaseQueryExecutor::new()))
            .await?;

        // Ticketing and case management
        self.register_executor(Arc::new(TicketCreateExecutor::new()))
            .await?;
        self.register_executor(Arc::new(CaseUpdateExecutor::new()))
            .await?;

        // Script and custom executors
        self.register_executor(Arc::new(ScriptExecutor::new()))
            .await?;
        self.register_executor(Arc::new(HttpRequestExecutor::new()))
            .await?;

        // Control flow executors
        self.register_executor(Arc::new(DecisionExecutor::new()))
            .await?;
        self.register_executor(Arc::new(WaitExecutor::new()))
            .await?;

        info!("Registered {} step executors", self.executors.len());
        Ok(())
    }

    /// Register a step executor
    pub async fn register_executor(
        &mut self,
        executor: Arc<dyn StepExecutor + Send + Sync>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let step_type = executor.get_step_type();
        self.executors.insert(step_type.clone(), executor);
        debug!("Registered step executor: {}", step_type);
        Ok(())
    }

    /// Get executor by step type
    pub fn get_executor(&self, step_type: &str) -> Option<Arc<dyn StepExecutor + Send + Sync>> {
        self.executors.get(step_type).cloned()
    }

    /// Get all executor types
    pub fn get_executor_types(&self) -> Vec<String> {
        self.executors.keys().cloned().collect()
    }

    /// Check if executor exists
    pub fn has_executor(&self, step_type: &str) -> bool {
        self.executors.contains_key(step_type)
    }

    /// Get executor count
    pub fn executor_count(&self) -> usize {
        self.executors.len()
    }

    /// Remove executor
    pub fn remove_executor(&mut self, step_type: &str) -> Option<Arc<dyn StepExecutor + Send + Sync>> {
        self.executors.remove(step_type)
    }

    /// Clear all executors
    pub fn clear(&mut self) {
        self.executors.clear();
    }

    /// Get executor statistics
    pub fn get_statistics(&self) -> ExecutorStatistics {
        let mut stats = ExecutorStatistics {
            total_executors: self.executors.len(),
            security_executors: 0,
            notification_executors: 0,
            query_executors: 0,
            case_management_executors: 0,
            script_executors: 0,
            control_flow_executors: 0,
        };

        for executor_type in self.executors.keys() {
            match executor_type.as_str() {
                "ip_block" | "account_lock" | "token_revoke" => stats.security_executors += 1,
                "email_notification" | "slack_notification" | "webhook_notification" => {
                    stats.notification_executors += 1
                }
                "siem_query" | "database_query" => stats.query_executors += 1,
                "ticket_create" | "case_update" => stats.case_management_executors += 1,
                "script" | "http_request" => stats.script_executors += 1,
                "decision" | "wait" => stats.control_flow_executors += 1,
                _ => {} // Unknown executor type
            }
        }

        stats
    }
}

/// Statistics about registered executors
#[derive(Debug, Clone)]
pub struct ExecutorStatistics {
    pub total_executors: usize,
    pub security_executors: usize,
    pub notification_executors: usize,
    pub query_executors: usize,
    pub case_management_executors: usize,
    pub script_executors: usize,
    pub control_flow_executors: usize,
}

impl Default for StepExecutorRegistry {
    fn default() -> Self {
        Self {
            executors: HashMap::new(),
        }
    }
}
