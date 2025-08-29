//! Case Management Persistence Layer
//!
//! This module handles all database operations for case management.

use serde_json;
use sqlx::{Pool, Postgres, Row};
use std::fmt::Write;
use std::sync::Arc;
use tracing::{debug, info};

use super::errors::{SoarError, SoarResult};
use super::models::{CasePriority, CaseStatus, Evidence, SecurityCase};

/// Repository for case management data operations
#[derive(Clone)]
pub struct CaseRepository {
    /// Database connection pool
    pool: Arc<Pool<Postgres>>,
}

impl CaseRepository {
    /// Create a new case repository
    #[must_use]
    pub fn new(pool: Arc<Pool<Postgres>>) -> Self {
        Self { pool }
    }

    /// Save a case to the database
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub async fn save_case(&self, case: &SecurityCase) -> SoarResult<()> {
        let query = r"
            INSERT INTO security_cases (
                id, title, description, status, priority, assigned_to,
                created_at, updated_at, due_date, alerts, evidence, tags, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (id) DO UPDATE SET
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                status = EXCLUDED.status,
                priority = EXCLUDED.priority,
                assigned_to = EXCLUDED.assigned_to,
                updated_at = EXCLUDED.updated_at,
                due_date = EXCLUDED.due_date,
                alerts = EXCLUDED.alerts,
                evidence = EXCLUDED.evidence,
                tags = EXCLUDED.tags,
                metadata = EXCLUDED.metadata
        ";

        let alerts_json = serde_json::to_value(&case.alerts)
            .map_err(|e| SoarError::serialization_error("alerts", e))?;
        let evidence_json = serde_json::to_value(&case.evidence)
            .map_err(|e| SoarError::serialization_error("evidence", e))?;
        let tags_json = serde_json::to_value(&case.tags)
            .map_err(|e| SoarError::serialization_error("tags", e))?;
        let metadata_json = serde_json::to_value(&case.metadata)
            .map_err(|e| SoarError::serialization_error("metadata", e))?;

        sqlx::query(query)
            .bind(&case.id)
            .bind(&case.title)
            .bind(&case.description)
            .bind(&case.status)
            .bind(&case.priority)
            .bind(case.assigned_to.as_ref())
            .bind(&case.created_at)
            .bind(&case.updated_at)
            .bind(&case.due_date)
            .bind(&alerts_json)
            .bind(&evidence_json)
            .bind(&tags_json)
            .bind(&metadata_json)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| SoarError::database_error("save_case", e))?;

        debug!("Case {} saved to database", case.id);
        Ok(())
    }

    /// Get a case by ID
    ///
    /// # Errors
    /// Returns an error if the database query fails.
    pub async fn get_case(&self, case_id: &str) -> SoarResult<Option<SecurityCase>> {
        let query = r"
            SELECT id, title, description, status, priority, assigned_to,
                   created_at, updated_at, due_date, alerts, evidence, tags, metadata
            FROM security_cases WHERE id = $1
        ";

        let row = sqlx::query(query)
            .bind(case_id)
            .fetch_optional(self.pool.as_ref())
            .await
            .map_err(|e| format!("Failed to fetch case: {e}"))?;

        match row {
            Some(row) => {
                let alerts: Vec<String> = serde_json::from_value(row.get("alerts"))
                    .map_err(|e| format!("Failed to deserialize alerts: {e}"))?;
                let evidence: Vec<Evidence> = serde_json::from_value(row.get("evidence"))
                    .map_err(|e| format!("Failed to deserialize evidence: {e}"))?;
                let tags: Vec<String> = serde_json::from_value(row.get("tags"))
                    .map_err(|e| format!("Failed to deserialize tags: {e}"))?;
                let metadata: serde_json::Value = row.get("metadata");

                let case = SecurityCase {
                    id: row.get("id"),
                    title: row.get("title"),
                    description: row.get("description"),
                    status: row.get("status"),
                    priority: row.get("priority"),
                    assigned_to: row.get("assigned_to"),
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                    due_date: row.get("due_date"),
                    alerts,
                    evidence,
                    tags,
                    metadata: serde_json::from_value(metadata)
                        .map_err(|e| format!("Failed to deserialize metadata: {e}"))?,
                };

                Ok(Some(case))
            }
            None => Ok(None),
        }
    }

    /// Get all cases with optional filtering
    /// Retrieve security cases with optional filtering and pagination.
    ///
    /// # Errors
    /// Returns an error if the database query fails or results cannot be deserialized.
    pub async fn get_cases(
        &self,
        status: Option<CaseStatus>,
        priority: Option<CasePriority>,
        assigned_to: Option<&str>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> SoarResult<Vec<SecurityCase>> {
        let mut query = r"
            SELECT id, title, description, status, priority, assigned_to,
                   created_at, updated_at, due_date, alerts, evidence, tags, metadata
            FROM security_cases WHERE 1=1
            "
        .to_string();

        let mut bind_values = Vec::new();
        let mut param_count = 0;

        if let Some(status) = status {
            param_count += 1;
            write!(query, " AND status = ${param_count}").unwrap();
            bind_values.push(
                serde_json::to_value(status)
                    .map_err(|e| format!("Failed to serialize status: {e}"))?,
            );
        }

        if let Some(priority) = priority {
            param_count += 1;
            write!(query, " AND priority = ${param_count}").unwrap();
            bind_values.push(
                serde_json::to_value(priority)
                    .map_err(|e| format!("Failed to serialize priority: {e}"))?,
            );
        }

        if let Some(assigned_to) = assigned_to {
            param_count += 1;
            write!(query, " AND assigned_to = ${param_count}").unwrap();
            bind_values.push(
                serde_json::to_value(assigned_to)
                    .map_err(|e| format!("Failed to serialize assigned_to: {e}"))?,
            );
        }

        query.push_str(" ORDER BY created_at DESC");

        if let Some(limit) = limit {
            param_count += 1;
            write!(query, " LIMIT ${param_count}").unwrap();
            bind_values.push(
                serde_json::to_value(limit)
                    .map_err(|e| format!("Failed to serialize limit: {e}"))?,
            );
        }

        if let Some(offset) = offset {
            param_count += 1;
            write!(query, " OFFSET ${param_count}").unwrap();
            bind_values.push(
                serde_json::to_value(offset)
                    .map_err(|e| format!("Failed to serialize offset: {e}"))?,
            );
        }

        let mut sql_query = sqlx::query(&query);

        for value in bind_values {
            sql_query = sql_query.bind(value);
        }

        let rows = sql_query
            .fetch_all(self.pool.as_ref())
            .await
            .map_err(|e| format!("Failed to fetch cases: {e}"))?;

        let mut cases = Vec::new();

        for row in rows {
            let alerts: Vec<String> = serde_json::from_value(row.get("alerts"))
                .map_err(|e| format!("Failed to deserialize alerts: {}", e))?;
            let evidence: Vec<Evidence> = serde_json::from_value(row.get("evidence"))
                .map_err(|e| format!("Failed to deserialize evidence: {}", e))?;
            let tags: Vec<String> = serde_json::from_value(row.get("tags"))
                .map_err(|e| format!("Failed to deserialize tags: {}", e))?;
            let metadata: serde_json::Value = row.get("metadata");

            let case = SecurityCase {
                id: row.get("id"),
                title: row.get("title"),
                description: row.get("description"),
                status: row.get("status"),
                priority: row.get("priority"),
                assigned_to: row.get("assigned_to"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                due_date: row.get("due_date"),
                alerts,
                evidence,
                tags,
                metadata: serde_json::from_value(metadata)
                    .map_err(|e| format!("Failed to deserialize metadata: {e}"))?,
            };

            cases.push(case);
        }

        Ok(cases)
    }

    /// Delete a case
    /// Delete a security case by ID.
    ///
    /// # Errors
    /// Returns an error if the case does not exist or the deletion fails.
    pub async fn delete_case(&self, case_id: &str) -> SoarResult<()> {
        let query = "DELETE FROM security_cases WHERE id = $1";

        let result = sqlx::query(query)
            .bind(case_id)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| format!("Failed to delete case: {e}"))?;

        if result.rows_affected() == 0 {
            return Err(SoarError::case_not_found(case_id));
        }

        info!("Case {} deleted from database", case_id);
        Ok(())
    }

    /// Get case statistics
    /// Get comprehensive case statistics.
    ///
    /// # Errors
    /// Returns an error if the database query fails.
    pub async fn get_case_statistics(&self) -> SoarResult<CaseStatistics> {
        let query = r"
            SELECT
                COUNT(*) as total_cases,
                COUNT(CASE WHEN status = 'open' THEN 1 END) as open_cases,
                COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved_cases,
                COUNT(CASE WHEN priority = 'critical' THEN 1 END) as critical_cases,
                AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/3600) as avg_resolution_hours
            FROM security_cases
        ";

        let row = sqlx::query(query)
            .fetch_one(self.pool.as_ref())
            .await
            .map_err(|e| format!("Failed to fetch statistics: {e}"))?;

        let stats = CaseStatistics {
            total_cases: usize::try_from(row.get::<i64, _>("total_cases")).unwrap_or(0),
            open_cases: usize::try_from(row.get::<i64, _>("open_cases")).unwrap_or(0),
            resolved_cases: usize::try_from(row.get::<i64, _>("resolved_cases")).unwrap_or(0),
            critical_cases: usize::try_from(row.get::<i64, _>("critical_cases")).unwrap_or(0),
            avg_resolution_hours: row.get::<Option<f64>, _>("avg_resolution_hours"),
        };

        Ok(stats)
    }
}

/// Case statistics structure
#[derive(Debug, Clone)]
pub struct CaseStatistics {
    /// Total number of cases
    pub total_cases: usize,
    /// Number of open cases
    pub open_cases: usize,
    /// Number of resolved cases
    pub resolved_cases: usize,
    /// Number of critical priority cases
    pub critical_cases: usize,
    /// Average resolution time in hours
    pub avg_resolution_hours: Option<f64>,
}

impl CaseRepository {
    /// Create database tables if they don't exist
    /// Create the necessary database tables for SOAR case management.
    ///
    /// # Errors
    /// Returns an error if the database tables cannot be created.
    pub async fn create_tables(&self) -> SoarResult<()> {
        let create_table_query = r"
            CREATE TABLE IF NOT EXISTS security_cases (
                id VARCHAR PRIMARY KEY,
                title VARCHAR NOT NULL,
                description TEXT,
                status VARCHAR NOT NULL,
                priority VARCHAR NOT NULL,
                assigned_to VARCHAR,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                due_date TIMESTAMPTZ,
                alerts JSONB DEFAULT '[]'::jsonb,
                evidence JSONB DEFAULT '[]'::jsonb,
                tags JSONB DEFAULT '[]'::jsonb,
                metadata JSONB DEFAULT '{}'::jsonb
            );

            CREATE INDEX IF NOT EXISTS idx_security_cases_status ON security_cases(status);
            CREATE INDEX IF NOT EXISTS idx_security_cases_priority ON security_cases(priority);
            CREATE INDEX IF NOT EXISTS idx_security_cases_assigned_to ON security_cases(assigned_to);
            CREATE INDEX IF NOT EXISTS idx_security_cases_created_at ON security_cases(created_at);
        ";

        sqlx::query(create_table_query)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| format!("Failed to create tables: {e}"))?;

        info!("Database tables created/verified");
        Ok(())
    }
}
