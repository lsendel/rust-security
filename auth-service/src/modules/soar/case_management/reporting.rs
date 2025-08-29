//! Case Management Reporting
//!
//! This module provides reporting capabilities for case management analytics.

use chrono::{DateTime, Datelike, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

use super::errors::SoarResult;
use super::models::{CasePriority, CaseStatus, SecurityCase};
use super::persistence::CaseRepository;

/// Case reporting service
pub struct CaseReportingService {
    /// Case repository for data access
    repository: CaseRepository,
}

/// Case report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseReport {
    /// Report title
    pub title: String,
    /// Report description
    pub description: String,
    /// Generated timestamp
    pub generated_at: DateTime<Utc>,
    /// Report period
    pub period: ReportPeriod,
    /// Summary statistics
    pub summary: CaseSummary,
    /// Detailed metrics
    pub metrics: CaseMetrics,
    /// Priority distribution
    pub priority_distribution: HashMap<String, usize>,
    /// Status distribution
    pub status_distribution: HashMap<String, usize>,
    /// SLA compliance data
    pub sla_compliance: SlaCompliance,
}

/// Report period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportPeriod {
    /// Daily report
    Daily(DateTime<Utc>),
    /// Weekly report
    Weekly(DateTime<Utc>),
    /// Monthly report
    Monthly(DateTime<Utc>),
    /// Custom period
    Custom {
        /// Start date
        start: DateTime<Utc>,
        /// End date
        end: DateTime<Utc>,
    },
}

/// Case summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseSummary {
    /// Total cases
    pub total_cases: usize,
    /// Open cases
    pub open_cases: usize,
    /// Resolved cases
    pub resolved_cases: usize,
    /// Escalated cases
    pub escalated_cases: usize,
    /// Average resolution time in hours
    pub avg_resolution_hours: Option<f64>,
    /// Median resolution time in hours
    pub median_resolution_hours: Option<f64>,
}

/// Case metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseMetrics {
    /// Cases created per day (last 30 days)
    pub cases_created_per_day: Vec<(DateTime<Utc>, usize)>,
    /// Cases resolved per day (last 30 days)
    pub cases_resolved_per_day: Vec<(DateTime<Utc>, usize)>,
    /// Average response time by priority
    pub avg_response_time_by_priority: HashMap<String, f64>,
    /// Case volume by category
    pub cases_by_category: HashMap<String, usize>,
}

/// SLA compliance data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaCompliance {
    /// Overall SLA compliance percentage
    pub overall_compliance_percent: f64,
    /// Response time compliance
    pub response_time_compliance: f64,
    /// Resolution time compliance
    pub resolution_time_compliance: f64,
    /// SLA violations count
    pub violations_count: usize,
    /// SLA violations by priority
    pub violations_by_priority: HashMap<String, usize>,
}

impl CaseReportingService {
    /// Create a new reporting service
    #[must_use]
    pub fn new(repository: CaseRepository) -> Self {
        Self { repository }
    }

    /// Generate a comprehensive case report
    ///
    /// # Errors
    /// Returns an error if the case data cannot be retrieved or processed.
    pub async fn generate_report(
        &self,
        period: ReportPeriod,
        title: Option<String>,
        description: Option<String>,
    ) -> SoarResult<CaseReport> {
        let (start_date, end_date) = self.get_period_dates(&period);

        info!(
            "Generating case report for period: {:?} to {:?}",
            start_date, end_date
        );

        // Get all cases for the period
        let cases = self
            .repository
            .get_cases(None, None, None, None, None)
            .await?;

        // Filter cases by period
        let filtered_cases: Vec<_> = cases
            .into_iter()
            .filter(|case| case.created_at >= start_date && case.created_at <= end_date)
            .collect();

        // Generate summary
        let summary = self.generate_summary(&filtered_cases)?;

        // Generate metrics
        let metrics = self.generate_metrics(&filtered_cases).await?;

        // Generate SLA compliance
        let sla_compliance = self.generate_sla_compliance(&filtered_cases).await?;

        // Generate distributions
        let priority_distribution = self.generate_priority_distribution(&filtered_cases);
        let status_distribution = self.generate_status_distribution(&filtered_cases);

        let report = CaseReport {
            title: title.unwrap_or_else(|| format!("Case Report - {period:?}")),
            description: description.unwrap_or_else(|| {
                format!(
                    "Security case report for period from {start} to {end}",
                    start = start_date.format("%Y-%m-%d"),
                    end = end_date.format("%Y-%m-%d")
                )
            }),
            generated_at: Utc::now(),
            period,
            summary,
            metrics,
            priority_distribution,
            status_distribution,
            sla_compliance,
        };

        debug!("Generated case report with {} cases", filtered_cases.len());
        Ok(report)
    }

    /// Generate case summary
    fn generate_summary(&self, cases: &[SecurityCase]) -> SoarResult<CaseSummary> {
        let total_cases = cases.len();
        let open_cases = cases
            .iter()
            .filter(|c| c.status == CaseStatus::Open)
            .count();
        let resolved_cases = cases
            .iter()
            .filter(|c| c.status == CaseStatus::Resolved || c.status == CaseStatus::Closed)
            .count();
        let escalated_cases = cases
            .iter()
            .filter(|c| c.status == CaseStatus::Escalated)
            .count();

        // Calculate resolution times
        let resolution_times: Vec<f64> = cases
            .iter()
            .filter(|c| c.status == CaseStatus::Resolved || c.status == CaseStatus::Closed)
            .filter_map(|c| {
                let duration = c.updated_at.signed_duration_since(c.created_at);
                Some(duration.num_hours() as f64)
            })
            .collect();

        let avg_resolution_hours = if resolution_times.is_empty() {
            None
        } else {
            Some(resolution_times.iter().sum::<f64>() / resolution_times.len() as f64)
        };

        let median_resolution_hours = if resolution_times.is_empty() {
            None
        } else {
            let mut sorted = resolution_times;
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let mid = sorted.len() / 2;
            Some(sorted[mid])
        };

        Ok(CaseSummary {
            total_cases,
            open_cases,
            resolved_cases,
            escalated_cases,
            avg_resolution_hours,
            median_resolution_hours,
        })
    }

    /// Generate case metrics
    async fn generate_metrics(&self, cases: &[SecurityCase]) -> SoarResult<CaseMetrics> {
        let mut cases_created_per_day = Vec::new();
        let mut cases_resolved_per_day = Vec::new();

        // Group by day for the last 30 days
        let end_date = Utc::now();
        let start_date = end_date - Duration::days(30);

        let mut current_date = start_date;
        while current_date <= end_date {
            let next_date = current_date + Duration::days(1);

            let created_count = cases
                .iter()
                .filter(|c| c.created_at >= current_date && c.created_at < next_date)
                .count();

            let resolved_count = cases
                .iter()
                .filter(|c| {
                    (c.status == CaseStatus::Resolved || c.status == CaseStatus::Closed)
                        && c.updated_at >= current_date
                        && c.updated_at < next_date
                })
                .count();

            cases_created_per_day.push((current_date, created_count));
            cases_resolved_per_day.push((current_date, resolved_count));

            current_date = next_date;
        }

        // Calculate average response time by priority
        let mut avg_response_time_by_priority = HashMap::new();
        for priority in &[
            CasePriority::Low,
            CasePriority::Medium,
            CasePriority::High,
            CasePriority::Critical,
        ] {
            let priority_cases: Vec<_> = cases.iter().filter(|c| c.priority == *priority).collect();

            if !priority_cases.is_empty() {
                let total_response_time: f64 = priority_cases
                    .iter()
                    .filter_map(|c| {
                        // Assume first update represents response
                        let response_time = c.updated_at.signed_duration_since(c.created_at);
                        Some(response_time.num_hours() as f64)
                    })
                    .sum();

                let avg_response_time = total_response_time / priority_cases.len() as f64;
                avg_response_time_by_priority.insert(format!("{priority:?}"), avg_response_time);
            }
        }

        // Cases by category (using tags)
        let mut cases_by_category = HashMap::new();
        for case in cases {
            for tag in &case.tags {
                *cases_by_category.entry(tag.clone()).or_insert(0) += 1;
            }
        }

        Ok(CaseMetrics {
            cases_created_per_day,
            cases_resolved_per_day,
            avg_response_time_by_priority,
            cases_by_category,
        })
    }

    /// Generate SLA compliance data
    async fn generate_sla_compliance(&self, cases: &[SecurityCase]) -> SoarResult<SlaCompliance> {
        let total_cases = cases.len();
        if total_cases == 0 {
            return Ok(SlaCompliance {
                overall_compliance_percent: 100.0,
                response_time_compliance: 100.0,
                resolution_time_compliance: 100.0,
                violations_count: 0,
                violations_by_priority: HashMap::new(),
            });
        }

        // For now, use simple SLA calculations
        // In a real implementation, this would use the actual SLA configurations
        let response_sla_hours = 2.0; // 2 hours
        let resolution_sla_hours = 24.0; // 24 hours

        let mut response_compliant = 0;
        let mut resolution_compliant = 0;
        let mut violations = 0;
        let mut violations_by_priority = HashMap::new();

        for case in cases {
            // Simple SLA check based on case age
            let case_age_hours = Utc::now()
                .signed_duration_since(case.created_at)
                .num_hours() as f64;

            // Response time SLA (first update should be within SLA)
            if case_age_hours <= response_sla_hours {
                response_compliant += 1;
            }

            // Resolution time SLA
            if case.status == CaseStatus::Resolved || case.status == CaseStatus::Closed {
                let resolution_time_hours = case
                    .updated_at
                    .signed_duration_since(case.created_at)
                    .num_hours() as f64;
                if resolution_time_hours <= resolution_sla_hours {
                    resolution_compliant += 1;
                } else {
                    violations += 1;
                    *violations_by_priority
                        .entry(format!("{priority:?}", priority = case.priority))
                        .or_insert(0) += 1;
                }
            }
        }

        let response_time_compliance = (response_compliant as f64 / total_cases as f64) * 100.0;
        let resolution_time_compliance = if cases
            .iter()
            .any(|c| c.status == CaseStatus::Resolved || c.status == CaseStatus::Closed)
        {
            (resolution_compliant as f64
                / cases
                    .iter()
                    .filter(|c| c.status == CaseStatus::Resolved || c.status == CaseStatus::Closed)
                    .count() as f64)
                * 100.0
        } else {
            100.0
        };

        let overall_compliance = (response_time_compliance + resolution_time_compliance) / 2.0;

        Ok(SlaCompliance {
            overall_compliance_percent: overall_compliance,
            response_time_compliance,
            resolution_time_compliance,
            violations_count: violations,
            violations_by_priority,
        })
    }

    /// Generate priority distribution
    fn generate_priority_distribution(&self, cases: &[SecurityCase]) -> HashMap<String, usize> {
        let mut distribution = HashMap::new();
        for case in cases {
            *distribution
                .entry(format!("{priority:?}", priority = case.priority))
                .or_insert(0) += 1;
        }
        distribution
    }

    /// Generate status distribution
    fn generate_status_distribution(&self, cases: &[SecurityCase]) -> HashMap<String, usize> {
        let mut distribution = HashMap::new();
        for case in cases {
            *distribution
                .entry(format!("{status:?}", status = case.status))
                .or_insert(0) += 1;
        }
        distribution
    }

    /// Get period start and end dates
    fn get_period_dates(&self, period: &ReportPeriod) -> (DateTime<Utc>, DateTime<Utc>) {
        match period {
            ReportPeriod::Daily(date) => {
                let start = date
                    .date_naive()
                    .and_hms_opt(0, 0, 0)
                    .unwrap()
                    .and_local_timezone(Utc)
                    .unwrap();
                let end = date
                    .date_naive()
                    .and_hms_opt(23, 59, 59)
                    .unwrap()
                    .and_local_timezone(Utc)
                    .unwrap();
                (start, end)
            }
            ReportPeriod::Weekly(date) => {
                let start = date
                    .date_naive()
                    .and_hms_opt(0, 0, 0)
                    .unwrap()
                    .and_local_timezone(Utc)
                    .unwrap()
                    - Duration::days(i64::from(
                        date.date_naive().weekday().num_days_from_monday(),
                    ));
                let end = start + Duration::days(6) + Duration::seconds(86399);
                (start, end)
            }
            ReportPeriod::Monthly(date) => {
                let start = date
                    .date_naive()
                    .with_day(1)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap()
                    .and_local_timezone(Utc)
                    .unwrap();
                let end = if date.month() == 12 {
                    date.date_naive()
                        .with_year(date.year() + 1)
                        .unwrap()
                        .with_month(1)
                        .unwrap()
                        .with_day(1)
                        .unwrap()
                } else {
                    date.date_naive()
                        .with_month(date.month() + 1)
                        .unwrap()
                        .with_day(1)
                        .unwrap()
                }
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_local_timezone(Utc)
                .unwrap()
                    - Duration::seconds(1);
                (start, end)
            }
            ReportPeriod::Custom { start, end } => (*start, *end),
        }
    }
}
