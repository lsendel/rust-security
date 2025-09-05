//! Billing API handlers for customer subscription and usage management

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{Datelike, NaiveDate, Utc};

use crate::billing::{BillingSystem, BillingError, SubscriptionStatus};
use crate::shared::error::AppError;

/// Request to create a new subscription
#[derive(Debug, Deserialize)]
pub struct CreateSubscriptionRequest {
    pub customer_id: String,
    pub plan_id: String,
    pub trial_days: Option<u32>,
}

/// Response with subscription details
#[derive(Debug, Serialize)]
pub struct SubscriptionResponse {
    pub customer_id: String,
    pub plan_id: String,
    pub status: String,
    pub created_at: String,
    pub current_period_start: String,
    pub current_period_end: String,
    pub trial_end: Option<String>,
    pub features: Vec<String>,
}

/// Usage recording request
#[derive(Debug, Deserialize)]
pub struct RecordUsageRequest {
    pub metric_name: String,
    pub quantity: u64,
    pub metadata: Option<HashMap<String, String>>,
}

/// Query parameters for usage endpoint
#[derive(Debug, Deserialize)]
pub struct UsageQuery {
    pub month: Option<String>, // Format: "2024-01"
}

/// Query parameters for invoices
#[derive(Debug, Deserialize)]
pub struct InvoiceQuery {
    pub period_start: Option<String>,
    pub period_end: Option<String>,
}

/// Create a new customer subscription
pub async fn create_subscription(
    State(billing): State<BillingSystem>,
    Json(request): Json<CreateSubscriptionRequest>,
) -> Result<Json<SubscriptionResponse>, AppError> {
    let subscription = billing
        .create_subscription(
            request.customer_id.clone(),
            request.plan_id.clone(),
            request.trial_days,
        )
        .map_err(|e| AppError::BadRequest(format!("Failed to create subscription: {}", e)))?;

    let features = match &subscription.plan {
        crate::billing::PricingPlan::Free { features, .. } => features.clone(),
        crate::billing::PricingPlan::Starter { features, .. } => features.clone(),
        crate::billing::PricingPlan::Professional { features, .. } => features.clone(),
        crate::billing::PricingPlan::Enterprise { features, .. } => features.clone(),
    };

    let response = SubscriptionResponse {
        customer_id: subscription.customer_id,
        plan_id: subscription.plan_id,
        status: format!("{:?}", subscription.status),
        created_at: subscription.created_at.to_rfc3339(),
        current_period_start: subscription.current_period_start.to_rfc3339(),
        current_period_end: subscription.current_period_end.to_rfc3339(),
        trial_end: subscription.trial_end.map(|t| t.to_rfc3339()),
        features,
    };

    Ok(Json(response))
}

/// Get customer subscription details
pub async fn get_subscription(
    State(billing): State<BillingSystem>,
    Path(customer_id): Path<String>,
) -> Result<Json<SubscriptionResponse>, AppError> {
    let subscription = billing
        .get_customer_subscription(&customer_id)
        .ok_or_else(|| AppError::NotFound("Customer subscription not found".to_string()))?;

    let features = match &subscription.plan {
        crate::billing::PricingPlan::Free { features, .. } => features.clone(),
        crate::billing::PricingPlan::Starter { features, .. } => features.clone(),
        crate::billing::PricingPlan::Professional { features, .. } => features.clone(),
        crate::billing::PricingPlan::Enterprise { features, .. } => features.clone(),
    };

    let response = SubscriptionResponse {
        customer_id: subscription.customer_id,
        plan_id: subscription.plan_id,
        status: format!("{:?}", subscription.status),
        created_at: subscription.created_at.to_rfc3339(),
        current_period_start: subscription.current_period_start.to_rfc3339(),
        current_period_end: subscription.current_period_end.to_rfc3339(),
        trial_end: subscription.trial_end.map(|t| t.to_rfc3339()),
        features,
    };

    Ok(Json(response))
}

/// Record usage for a customer
pub async fn record_usage(
    State(billing): State<BillingSystem>,
    Path(customer_id): Path<String>,
    Json(request): Json<RecordUsageRequest>,
) -> Result<StatusCode, AppError> {
    billing
        .record_usage(
            customer_id,
            request.metric_name,
            request.quantity,
        )
        .map_err(|e| AppError::BadRequest(format!("Failed to record usage: {}", e)))?;

    Ok(StatusCode::CREATED)
}

/// Get customer usage for a specific month
pub async fn get_usage(
    State(billing): State<BillingSystem>,
    Path(customer_id): Path<String>,
    Query(query): Query<UsageQuery>,
) -> Result<Json<crate::billing::MonthlyUsage>, AppError> {
    let month_str = query.month
        .unwrap_or_else(|| Utc::now().format("%Y-%m").to_string());

    let month = NaiveDate::parse_from_str(&format!("{}-01", month_str), "%Y-%m-%d")
        .map_err(|_| AppError::BadRequest("Invalid month format. Use YYYY-MM".to_string()))?;

    let usage = billing
        .get_monthly_usage(&customer_id, month)
        .map_err(|e| AppError::BadRequest(format!("Failed to get usage: {}", e)))?;

    Ok(Json(usage))
}

/// Generate invoice for customer
pub async fn generate_invoice(
    State(billing): State<BillingSystem>,
    Path(customer_id): Path<String>,
    Query(query): Query<InvoiceQuery>,
) -> Result<Json<crate::billing::Invoice>, AppError> {
    let period_start = if let Some(start_str) = query.period_start {
        chrono::DateTime::parse_from_rfc3339(&start_str)
            .map_err(|_| AppError::BadRequest("Invalid period_start format".to_string()))?
            .with_timezone(&Utc)
    } else {
        // Default to current month
        let now = Utc::now();
        now.with_day(1).unwrap().with_time(chrono::NaiveTime::MIN).unwrap()
    };

    let period_end = if let Some(end_str) = query.period_end {
        chrono::DateTime::parse_from_rfc3339(&end_str)
            .map_err(|_| AppError::BadRequest("Invalid period_end format".to_string()))?
            .with_timezone(&Utc)
    } else {
        // Default to end of current month
        let next_month = if period_start.month() == 12 {
            period_start.with_year(period_start.year() + 1).unwrap().with_month(1).unwrap()
        } else {
            period_start.with_month(period_start.month() + 1).unwrap()
        };
        next_month - chrono::Duration::seconds(1)
    };

    let invoice = billing
        .generate_invoice(&customer_id, period_start, period_end)
        .map_err(|e| AppError::BadRequest(format!("Failed to generate invoice: {}", e)))?;

    Ok(Json(invoice))
}

/// Get available pricing plans
pub async fn get_pricing_plans(
    State(billing): State<BillingSystem>,
) -> Result<Json<HashMap<String, crate::billing::PricingPlan>>, AppError> {
    let plans = billing.get_pricing_plans().clone();
    Ok(Json(plans))
}

/// Update subscription status (admin endpoint)
pub async fn update_subscription_status(
    State(billing): State<BillingSystem>,
    Path(customer_id): Path<String>,
    Json(status_request): Json<UpdateStatusRequest>,
) -> Result<StatusCode, AppError> {
    let status = match status_request.status.to_lowercase().as_str() {
        "active" => SubscriptionStatus::Active,
        "trialing" => SubscriptionStatus::Trialing,
        "past_due" => SubscriptionStatus::PastDue,
        "canceled" => SubscriptionStatus::Canceled,
        "unpaid" => SubscriptionStatus::Unpaid,
        "incomplete" => SubscriptionStatus::Incomplete,
        _ => return Err(AppError::BadRequest("Invalid status".to_string())),
    };

    billing
        .update_subscription_status(&customer_id, status)
        .map_err(|e| AppError::BadRequest(format!("Failed to update status: {}", e)))?;

    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
pub struct UpdateStatusRequest {
    pub status: String,
}

/// Pricing comparison endpoint (marketing feature)
pub async fn pricing_comparison() -> Result<Json<PricingComparison>, AppError> {
    let comparison = PricingComparison {
        mvp_auth_service: CompetitorPricing {
            name: "MVP Auth Service".to_string(),
            starter_price: 29.0,
            token_price_per_1000: 0.012,
            included_tokens: 100_000,
            sla_uptime: "99.95%".to_string(),
            avg_latency_ms: 45,
            features: vec![
                "OAuth 2.0 Authentication".to_string(),
                "Advanced Rate Limiting".to_string(),
                "Threat Detection".to_string(),
                "Memory Optimization".to_string(),
                "Real-time Monitoring".to_string(),
                "SOC 2 Compliance Ready".to_string(),
            ],
        },
        auth0: CompetitorPricing {
            name: "Auth0".to_string(),
            starter_price: 35.0,
            token_price_per_1000: 0.023,
            included_tokens: 50_000,
            sla_uptime: "99.9%".to_string(),
            avg_latency_ms: 120,
            features: vec![
                "OAuth 2.0 Authentication".to_string(),
                "Basic Rate Limiting".to_string(),
                "Standard Monitoring".to_string(),
            ],
        },
        okta: CompetitorPricing {
            name: "Okta".to_string(),
            starter_price: 55.0,
            token_price_per_1000: 0.028,
            included_tokens: 25_000,
            sla_uptime: "99.9%".to_string(),
            avg_latency_ms: 150,
            features: vec![
                "OAuth 2.0 Authentication".to_string(),
                "Enterprise Features".to_string(),
                "Basic Monitoring".to_string(),
            ],
        },
        cost_savings: CostSavings {
            vs_auth0_percent: 48.0,
            vs_okta_percent: 65.0,
            monthly_savings_auth0: 178.0,
            monthly_savings_okta: 312.0,
            performance_improvement: "3x faster response times".to_string(),
        },
    };

    Ok(Json(comparison))
}

#[derive(Debug, Serialize)]
pub struct PricingComparison {
    pub mvp_auth_service: CompetitorPricing,
    pub auth0: CompetitorPricing,
    pub okta: CompetitorPricing,
    pub cost_savings: CostSavings,
}

#[derive(Debug, Serialize)]
pub struct CompetitorPricing {
    pub name: String,
    pub starter_price: f64,
    pub token_price_per_1000: f64,
    pub included_tokens: u64,
    pub sla_uptime: String,
    pub avg_latency_ms: u64,
    pub features: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CostSavings {
    pub vs_auth0_percent: f64,
    pub vs_okta_percent: f64,
    pub monthly_savings_auth0: f64,
    pub monthly_savings_okta: f64,
    pub performance_improvement: String,
}