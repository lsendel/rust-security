//! Billing and pricing system for MVP Auth Service
//!
//! Provides comprehensive billing management with:
//! - Usage-based pricing and metering
//! - Customer subscription management  
//! - Invoice generation and payment processing
//! - Integration with external billing services

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Pricing plans for the MVP Auth Service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PricingPlan {
    Free {
        monthly_token_limit: u64,
        features: Vec<String>,
    },
    Starter {
        monthly_base_fee: f64,
        token_price_per_1000: f64,
        included_tokens: u64,
        features: Vec<String>,
    },
    Professional {
        monthly_base_fee: f64,
        token_price_per_1000: f64,
        included_tokens: u64,
        features: Vec<String>,
    },
    Enterprise {
        monthly_base_fee: f64,
        token_price_per_1000: f64,
        included_tokens: u64,
        features: Vec<String>,
        custom_sla: bool,
    },
}

impl PricingPlan {
    // Pricing constants for the free tier overage
    const FREE_TIER_UPGRADE_BASE_FEE: f64 = 29.0;
    const FREE_TIER_UPGRADE_PRICE_PER_1000: f64 = 0.012;

    /// Get standard pricing plans
    pub fn get_standard_plans() -> HashMap<String, PricingPlan> {
        let mut plans = HashMap::new();

        plans.insert(
            "free".to_string(),
            PricingPlan::Free {
                monthly_token_limit: 10_000,
                features: vec![
                    "OAuth 2.0 Authentication".to_string(),
                    "JWT Token Management".to_string(),
                    "Basic Rate Limiting".to_string(),
                    "Community Support".to_string(),
                ],
            },
        );

        plans.insert(
            "starter".to_string(),
            PricingPlan::Starter {
                monthly_base_fee: 29.0,
                token_price_per_1000: 0.012, // $0.012 per 1000 tokens (vs Auth0's $0.023)
                included_tokens: 100_000,
                features: vec![
                    "OAuth 2.0 Authentication".to_string(),
                    "JWT Token Management".to_string(),
                    "Advanced Rate Limiting".to_string(),
                    "Threat Detection".to_string(),
                    "Email Support".to_string(),
                    "99.9% SLA".to_string(),
                ],
            },
        );

        plans.insert(
            "professional".to_string(),
            PricingPlan::Professional {
                monthly_base_fee: 99.0,
                token_price_per_1000: 0.010, // $0.010 per 1000 tokens
                included_tokens: 500_000,
                features: vec![
                    "All Starter Features".to_string(),
                    "Advanced Security Headers".to_string(),
                    "Memory Optimization".to_string(),
                    "Performance Monitoring".to_string(),
                    "Priority Support".to_string(),
                    "99.95% SLA".to_string(),
                    "Custom Rate Limits".to_string(),
                ],
            },
        );

        plans.insert(
            "enterprise".to_string(),
            PricingPlan::Enterprise {
                monthly_base_fee: 299.0,
                token_price_per_1000: 0.008, // $0.008 per 1000 tokens
                included_tokens: 2_000_000,
                custom_sla: true,
                features: vec![
                    "All Professional Features".to_string(),
                    "Custom SLA (99.99% available)".to_string(),
                    "Dedicated Support Engineer".to_string(),
                    "Custom Integration".to_string(),
                    "On-premise Deployment".to_string(),
                    "Advanced Analytics".to_string(),
                    "SOC 2 Compliance".to_string(),
                ],
            },
        );

        plans
    }

    /// Calculate monthly cost for given usage
    pub fn calculate_monthly_cost(&self, tokens_used: u64) -> f64 {
        const TOKENS_PER_THOUSAND: f64 = 1000.0;

        match self {
            PricingPlan::Free {
                monthly_token_limit,
                ..
            } => {
                if tokens_used <= *monthly_token_limit {
                    0.0
                } else {
                    // Automatically upgrade to starter pricing for overage
                    let overage = tokens_used - monthly_token_limit;
                    Self::FREE_TIER_UPGRADE_BASE_FEE
                        + ((overage as f64 / TOKENS_PER_THOUSAND)
                            * Self::FREE_TIER_UPGRADE_PRICE_PER_1000)
                }
            }
            PricingPlan::Starter {
                monthly_base_fee,
                token_price_per_1000,
                included_tokens,
                ..
            }
            | PricingPlan::Professional {
                monthly_base_fee,
                token_price_per_1000,
                included_tokens,
                ..
            }
            | PricingPlan::Enterprise {
                monthly_base_fee,
                token_price_per_1000,
                included_tokens,
                ..
            } => Self::calculate_tiered_cost(
                tokens_used,
                *included_tokens,
                *monthly_base_fee,
                *token_price_per_1000,
            ),
        }
    }

    fn calculate_tiered_cost(
        tokens_used: u64,
        included_tokens: u64,
        base_fee: f64,
        price_per_1000: f64,
    ) -> f64 {
        const TOKENS_PER_THOUSAND: f64 = 1000.0;

        if tokens_used <= included_tokens {
            base_fee
        } else {
            let overage = tokens_used - included_tokens;
            base_fee + ((overage as f64 / TOKENS_PER_THOUSAND) * price_per_1000)
        }
    }

    /// Get the number of tokens included in the plan
    pub fn get_included_tokens(&self) -> u64 {
        match self {
            PricingPlan::Free {
                monthly_token_limit,
                ..
            } => *monthly_token_limit,
            PricingPlan::Starter {
                included_tokens, ..
            }
            | PricingPlan::Professional {
                included_tokens, ..
            }
            | PricingPlan::Enterprise {
                included_tokens, ..
            } => *included_tokens,
        }
    }

    /// Get the token price per 1000 tokens for overage charges
    pub fn get_token_price_per_1000(&self) -> f64 {
        match self {
            PricingPlan::Free { .. } => Self::FREE_TIER_UPGRADE_PRICE_PER_1000,
            PricingPlan::Starter {
                token_price_per_1000,
                ..
            }
            | PricingPlan::Professional {
                token_price_per_1000,
                ..
            }
            | PricingPlan::Enterprise {
                token_price_per_1000,
                ..
            } => *token_price_per_1000,
        }
    }
}

/// Customer subscription information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerSubscription {
    pub customer_id: String,
    pub plan_id: String,
    pub plan: PricingPlan,
    pub status: SubscriptionStatus,
    pub created_at: DateTime<Utc>,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub trial_end: Option<DateTime<Utc>>,
    pub payment_method_id: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubscriptionStatus {
    Active,
    Trialing,
    PastDue,
    Canceled,
    Unpaid,
    Incomplete,
}

/// Usage tracking for billing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    pub customer_id: String,
    pub metric_name: String, // "tokens_issued", "tokens_introspected", etc.
    pub quantity: u64,
    pub timestamp: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Monthly usage summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonthlyUsage {
    pub customer_id: String,
    pub month: NaiveDate,
    pub tokens_issued: u64,
    pub tokens_introspected: u64,
    pub api_calls: u64,
    pub total_tokens: u64,
    pub estimated_cost: f64,
    pub plan_id: String,
}

/// Invoice for customer billing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: String,
    pub customer_id: String,
    pub subscription_id: String,
    pub amount_due: f64,
    pub currency: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub line_items: Vec<InvoiceLineItem>,
    pub status: InvoiceStatus,
    pub due_date: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub paid_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceLineItem {
    pub description: String,
    pub quantity: u64,
    pub unit_price: f64,
    pub amount: f64,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvoiceStatus {
    Draft,
    Open,
    Paid,
    Void,
    Uncollectible,
}

/// Main billing system
pub struct BillingSystem {
    subscriptions: Arc<Mutex<HashMap<String, CustomerSubscription>>>,
    usage_records: Arc<Mutex<Vec<UsageRecord>>>,
    invoices: Arc<Mutex<HashMap<String, Invoice>>>,
    pricing_plans: HashMap<String, PricingPlan>,
}

impl BillingSystem {
    pub fn new() -> Self {
        Self {
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            usage_records: Arc::new(Mutex::new(Vec::new())),
            invoices: Arc::new(Mutex::new(HashMap::new())),
            pricing_plans: PricingPlan::get_standard_plans(),
        }
    }

    /// Create a new customer subscription
    pub fn create_subscription(
        &self,
        customer_id: String,
        plan_id: String,
        trial_days: Option<u32>,
    ) -> Result<CustomerSubscription, BillingError> {
        let plan = self
            .pricing_plans
            .get(&plan_id)
            .ok_or_else(|| BillingError::InvalidPlan(plan_id.clone()))?
            .clone();

        let now = Utc::now();
        let trial_end = trial_days.map(|days| now + chrono::Duration::days(days as i64));

        let subscription = CustomerSubscription {
            customer_id: customer_id.clone(),
            plan_id: plan_id.clone(),
            plan,
            status: if trial_end.is_some() {
                SubscriptionStatus::Trialing
            } else {
                SubscriptionStatus::Active
            },
            created_at: now,
            current_period_start: now,
            current_period_end: now + chrono::Duration::days(30), // Monthly billing
            trial_end,
            payment_method_id: None,
            metadata: HashMap::new(),
        };

        self.subscriptions
            .lock()
            .unwrap()
            .insert(customer_id.clone(), subscription.clone());

        log::info!(
            "Created subscription for customer {}: {}",
            customer_id,
            plan_id
        );
        Ok(subscription)
    }

    /// Record usage for billing
    pub fn record_usage(
        &self,
        customer_id: String,
        metric_name: String,
        quantity: u64,
    ) -> Result<(), BillingError> {
        // Verify customer has active subscription
        let subscription = self
            .subscriptions
            .lock()
            .unwrap()
            .get(&customer_id)
            .ok_or_else(|| BillingError::CustomerNotFound(customer_id.clone()))?
            .clone();

        if !matches!(
            subscription.status,
            SubscriptionStatus::Active | SubscriptionStatus::Trialing
        ) {
            return Err(BillingError::InactiveSubscription(customer_id));
        }

        let usage_record = UsageRecord {
            customer_id,
            metric_name,
            quantity,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        };

        self.usage_records.lock().unwrap().push(usage_record);
        Ok(())
    }

    /// Get monthly usage for a customer
    pub fn get_monthly_usage(
        &self,
        customer_id: &str,
        month: NaiveDate,
    ) -> Result<MonthlyUsage, BillingError> {
        let subscription = self
            .subscriptions
            .lock()
            .unwrap()
            .get(customer_id)
            .ok_or_else(|| BillingError::CustomerNotFound(customer_id.to_string()))?
            .clone();

        let usage_records = self.usage_records.lock().unwrap();

        // Filter records for this customer and month
        let month_records: Vec<_> = usage_records
            .iter()
            .filter(|record| {
                record.customer_id == customer_id
                    && record.timestamp.date_naive().format("%Y-%m").to_string()
                        == month.format("%Y-%m").to_string()
            })
            .collect();

        let mut tokens_issued = 0;
        let mut tokens_introspected = 0;
        let mut api_calls = 0;

        for record in month_records {
            match record.metric_name.as_str() {
                "tokens_issued" => tokens_issued += record.quantity,
                "tokens_introspected" => tokens_introspected += record.quantity,
                "api_calls" => api_calls += record.quantity,
                _ => {}
            }
        }

        let total_tokens = tokens_issued + tokens_introspected;
        let estimated_cost = subscription.plan.calculate_monthly_cost(total_tokens);

        Ok(MonthlyUsage {
            customer_id: customer_id.to_string(),
            month,
            tokens_issued,
            tokens_introspected,
            api_calls,
            total_tokens,
            estimated_cost,
            plan_id: subscription.plan_id,
        })
    }

    /// Generate invoice for customer
    pub fn generate_invoice(
        &self,
        customer_id: &str,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Result<Invoice, BillingError> {
        let subscription = self
            .subscriptions
            .lock()
            .unwrap()
            .get(customer_id)
            .ok_or_else(|| BillingError::CustomerNotFound(customer_id.to_string()))?
            .clone();

        // Get usage for the period
        let month = period_start.date_naive().with_day(1).unwrap();
        let usage = self.get_monthly_usage(customer_id, month)?;

        let mut line_items = Vec::new();

        // Base subscription fee
        let base_fee = match &subscription.plan {
            PricingPlan::Free { .. } => 0.0,
            PricingPlan::Starter {
                monthly_base_fee, ..
            } => *monthly_base_fee,
            PricingPlan::Professional {
                monthly_base_fee, ..
            } => *monthly_base_fee,
            PricingPlan::Enterprise {
                monthly_base_fee, ..
            } => *monthly_base_fee,
        };

        if base_fee > 0.0 {
            line_items.push(InvoiceLineItem {
                description: format!("{} Plan - Monthly Subscription", subscription.plan_id),
                quantity: 1,
                unit_price: base_fee,
                amount: base_fee,
                period_start,
                period_end,
            });
        }

        // Usage-based charges
        let included_tokens = subscription.plan.get_included_tokens();

        if usage.total_tokens > included_tokens {
            let overage_tokens = usage.total_tokens - included_tokens;
            let token_price = subscription.plan.get_token_price_per_1000();

            const TOKENS_PER_THOUSAND: f64 = 1000.0;
            let overage_cost = (overage_tokens as f64 / TOKENS_PER_THOUSAND) * token_price;
            line_items.push(InvoiceLineItem {
                description: format!("Token Usage Overage ({} tokens)", overage_tokens),
                quantity: overage_tokens,
                unit_price: token_price / TOKENS_PER_THOUSAND, // Price per token
                amount: overage_cost,
                period_start,
                period_end,
            });
        }

        let total_amount = line_items.iter().map(|item| item.amount).sum();

        let invoice = Invoice {
            id: uuid::Uuid::new_v4().to_string(),
            customer_id: customer_id.to_string(),
            subscription_id: customer_id.to_string(), // Simplified for MVP
            amount_due: total_amount,
            currency: "USD".to_string(),
            period_start,
            period_end,
            line_items,
            status: InvoiceStatus::Open,
            due_date: period_end + chrono::Duration::days(30),
            created_at: Utc::now(),
            paid_at: None,
        };

        self.invoices
            .lock()
            .unwrap()
            .insert(invoice.id.clone(), invoice.clone());

        log::info!(
            "Generated invoice {} for customer {} - Amount: ${:.2}",
            invoice.id,
            customer_id,
            total_amount
        );

        Ok(invoice)
    }

    /// Get current pricing plans
    pub fn get_pricing_plans(&self) -> &HashMap<String, PricingPlan> {
        &self.pricing_plans
    }

    /// Check if customer has active subscription
    pub fn is_customer_active(&self, customer_id: &str) -> bool {
        self.subscriptions
            .lock()
            .unwrap()
            .get(customer_id)
            .map(|sub| {
                matches!(
                    sub.status,
                    SubscriptionStatus::Active | SubscriptionStatus::Trialing
                )
            })
            .unwrap_or(false)
    }

    /// Get customer subscription
    pub fn get_customer_subscription(&self, customer_id: &str) -> Option<CustomerSubscription> {
        self.subscriptions.lock().unwrap().get(customer_id).cloned()
    }

    /// Update subscription status
    pub fn update_subscription_status(
        &self,
        customer_id: &str,
        status: SubscriptionStatus,
    ) -> Result<(), BillingError> {
        let mut subscriptions = self.subscriptions.lock().unwrap();
        let subscription = subscriptions
            .get_mut(customer_id)
            .ok_or_else(|| BillingError::CustomerNotFound(customer_id.to_string()))?;

        subscription.status = status;
        log::info!("Updated subscription status for customer {}", customer_id);
        Ok(())
    }
}

impl Default for BillingSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Billing system errors
#[derive(Debug, thiserror::Error)]
pub enum BillingError {
    #[error("Customer not found: {0}")]
    CustomerNotFound(String),

    #[error("Invalid pricing plan: {0}")]
    InvalidPlan(String),

    #[error("Customer subscription is inactive: {0}")]
    InactiveSubscription(String),

    #[error("Usage recording failed: {0}")]
    UsageRecordingFailed(String),

    #[error("Invoice generation failed: {0}")]
    InvoiceGenerationFailed(String),
}
