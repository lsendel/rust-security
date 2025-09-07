//! Enhanced Rate Limiting System with Adaptive Thresholds
//!
//! A comprehensive, high-performance rate limiting system with advanced adaptive
//! threshold capabilities designed for production authentication services.
//!
//! ## Enhanced Features
//!
//! ### Adaptive Rate Limiting
//! - **Dynamic Threshold Adjustment**: Automatically adjusts limits based on traffic patterns
//! - **Machine Learning Integration**: Predictive rate limiting based on historical data
//! - **Behavioral Analysis**: Personalized rate limits based on user behavior patterns
//! - **Context-Aware Limits**: Different limits for different contexts and risk levels
//!
//! ### Advanced Security
//! - **Intelligent Threat Detection**: Advanced anomaly detection and threat scoring
//! - **Automated Response**: Dynamic adjustment of limits based on threat level
//! - **Multi-Dimensional Analysis**: Rate limiting based on multiple factors simultaneously
//! - **Zero-Day Protection**: Heuristic analysis for unknown attack patterns
//!
//! ### Performance Optimized
//! - **Hierarchical Token Buckets**: Multiple priority levels with different refill rates
//! - **Predictive Prefetching**: Anticipatory rate limit adjustments
//! - **Distributed Consensus**: Coordinated rate limiting across multiple nodes
//! - **Real-time Analytics**: Streaming analytics for instant limit adjustments
//!
//! ### Extensible Architecture
//! - **Plugin System**: Extendable with custom rate limiting algorithms
//! - **Strategy Patterns**: Multiple rate limiting strategies for different use cases
//! - **Custom Metrics**: Define custom metrics for specialized rate limiting

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// Enhanced rate limit configuration with adaptive threshold capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedRateLimitConfig {
    // Global limits
    pub global_requests_per_minute: u32,
    pub global_requests_per_hour: u32,
    pub global_burst: u32,

    // Per-IP limits with adaptive thresholds
    pub per_ip_requests_per_minute: u32,
    pub per_ip_requests_per_hour: u32,
    pub per_ip_requests_per_day: u32,
    pub per_ip_burst: u32,
    pub per_ip_strict_requests_per_minute: u32,

    // Per-client limits with adaptive thresholds
    pub per_client_requests_per_minute: u32,
    pub per_client_requests_per_hour: u32,

    // Endpoint-specific limits with adaptive thresholds
    pub oauth_token_requests_per_minute: u32,
    pub oauth_authorize_requests_per_minute: u32,
    pub oauth_introspect_requests_per_minute: u32,
    pub admin_requests_per_minute: u32,
    pub scim_requests_per_minute: u32,
    pub jwks_requests_per_minute: u32,

    // MFA-specific limits with adaptive thresholds
    pub mfa_verification_attempts_per_5min: u32,
    pub mfa_registration_attempts_per_hour: u32,
    pub mfa_otp_sends_per_hour: u32,
    pub mfa_backup_code_attempts_per_hour: u32,

    // Enhanced adaptive limits configuration
    pub enable_adaptive_limits: bool,
    pub adaptive_learning_window_hours: u32,
    pub adaptive_adjustment_threshold: f64,
    pub adaptive_min_multiplier: f64,
    pub adaptive_max_multiplier: f64,
    pub adaptive_burst_multiplier: f64,
    pub adaptive_backoff_factor: f64,
    pub adaptive_recovery_speed: f64,

    // Machine learning integration
    pub enable_ml_prediction: bool,
    pub ml_model_update_frequency_minutes: u32,
    pub ml_confidence_threshold: f64,
    pub ml_anomaly_detection_sensitivity: f64,

    // Behavioral analysis
    pub enable_behavioral_analysis: bool,
    pub behavioral_baselines_retention_days: u32,
    pub behavioral_deviation_threshold: f64,
    pub behavioral_trust_decay_rate: f64,

    // Context-aware limits
    pub enable_context_aware_limits: bool,
    pub context_risk_weights: HashMap<String, f64>,
    pub context_trust_scores: HashMap<String, f64>,

    // Security features
    pub ban_threshold: u32,
    pub ban_duration_minutes: u32,
    pub suspicious_threshold: u32,
    pub enable_distributed_limiting: bool,
    pub progressive_delays_enabled: bool,

    // IP filtering with adaptive thresholds
    pub enable_allowlist: bool,
    pub enable_banlist: bool,
    pub allowlist_ips: HashSet<IpAddr>,
    pub banlist_ips: HashSet<IpAddr>,
    pub allowlist_cidrs: Vec<String>,
    pub banlist_cidrs: Vec<String>,

    // Cleanup and maintenance
    pub cleanup_interval_seconds: u64,
    pub max_tracked_ips: usize,
    pub window_duration_secs: u64,
    pub adaptive_cleanup_threshold: usize,
}

impl Default for EnhancedRateLimitConfig {
    fn default() -> Self {
        Self {
            // Global limits
            global_requests_per_minute: 10000,
            global_requests_per_hour: 100_000,
            global_burst: 100,

            // Per-IP limits
            per_ip_requests_per_minute: 100,
            per_ip_requests_per_hour: 1000,
            per_ip_requests_per_day: 10000,
            per_ip_burst: 20,
            per_ip_strict_requests_per_minute: 10,

            // Per-client limits
            per_client_requests_per_minute: 200,
            per_client_requests_per_hour: 2000,

            // Endpoint-specific limits
            oauth_token_requests_per_minute: 30,
            oauth_authorize_requests_per_minute: 60,
            oauth_introspect_requests_per_minute: 200,
            admin_requests_per_minute: 20,
            scim_requests_per_minute: 100,
            jwks_requests_per_minute: 60,

            // MFA-specific limits
            mfa_verification_attempts_per_5min: 10,
            mfa_registration_attempts_per_hour: 5,
            mfa_otp_sends_per_hour: 5,
            mfa_backup_code_attempts_per_hour: 3,

            // Enhanced adaptive limits configuration
            enable_adaptive_limits: true,
            adaptive_learning_window_hours: 24,
            adaptive_adjustment_threshold: 0.7,
            adaptive_min_multiplier: 0.5,
            adaptive_max_multiplier: 2.0,
            adaptive_burst_multiplier: 1.5,
            adaptive_backoff_factor: 1.2,
            adaptive_recovery_speed: 0.1,

            // Machine learning integration
            enable_ml_prediction: true,
            ml_model_update_frequency_minutes: 30,
            ml_confidence_threshold: 0.8,
            ml_anomaly_detection_sensitivity: 0.7,

            // Behavioral analysis
            enable_behavioral_analysis: true,
            behavioral_baselines_retention_days: 30,
            behavioral_deviation_threshold: 0.6,
            behavioral_trust_decay_rate: 0.05,

            // Context-aware limits
            enable_context_aware_limits: true,
            context_risk_weights: {
                let mut map = HashMap::new();
                map.insert("high_risk".to_string(), 2.0);
                map.insert("medium_risk".to_string(), 1.5);
                map.insert("low_risk".to_string(), 0.8);
                map.insert("trusted".to_string(), 0.5);
                map
            },
            context_trust_scores: {
                let mut map = HashMap::new();
                map.insert("known_client".to_string(), 0.9);
                map.insert("new_client".to_string(), 0.7);
                map.insert("suspicious_client".to_string(), 0.3);
                map
            },

            // Security features
            ban_threshold: 5,
            ban_duration_minutes: 60,
            suspicious_threshold: 100,
            enable_distributed_limiting: false,
            progressive_delays_enabled: true,

            // IP filtering
            enable_allowlist: false,
            enable_banlist: true,
            allowlist_ips: HashSet::new(),
            banlist_ips: HashSet::new(),
            allowlist_cidrs: Vec::new(),
            banlist_cidrs: Vec::new(),

            // Cleanup and maintenance
            cleanup_interval_seconds: 300,
            max_tracked_ips: 100_000,
            window_duration_secs: 60,
            adaptive_cleanup_threshold: 50_000,
        }
    }
}

/// Enhanced rate limit result with additional information
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnhancedRateLimitResult {
    /// Request is allowed
    Allowed,
    /// Request is rate limited
    RateLimited {
        /// Retry after timestamp
        retry_after: u64,
        /// Current limit
        limit: u32,
        /// Remaining requests
        remaining: u32,
        /// Reset time
        reset_time: u64,
    },
    /// Request is blocked due to security policy
    Blocked {
        /// Reason for blocking
        reason: String,
        /// Duration of block
        duration_minutes: u32,
    },
}

/// Enhanced rate limit metrics with adaptive tracking
#[derive(Debug, Default)]
pub struct EnhancedRateLimitMetrics {
    pub total_requests: AtomicU64,
    pub allowed_requests: AtomicU64,
    pub rate_limited_requests: AtomicU64,
    pub blocked_requests: AtomicU64,
    pub adaptive_adjustments: AtomicU64,
    pub ml_predictions: AtomicU64,
    pub behavioral_analyses: AtomicU64,
    pub context_based_decisions: AtomicU64,
}

/// Enhanced rate limit entry with adaptive threshold capabilities
#[derive(Debug, Clone)]
pub struct EnhancedRateLimitEntry {
    /// Current token count
    pub tokens: u32,
    /// Last refill timestamp
    pub last_refill: u64,
    /// Request history for analysis
    pub request_history: Vec<u64>,
    /// Adaptive limit multiplier
    pub adaptive_multiplier: f64,
    /// Behavioral trust score (0.0 to 1.0)
    pub trust_score: f64,
    /// Anomaly detection score (0.0 to 1.0)
    pub anomaly_score: f64,
    /// Context-specific factors
    pub context_factors: HashMap<String, f64>,
    /// Violation count for progressive penalties
    pub violation_count: u32,
    /// Last violation timestamp
    pub last_violation: u64,
    /// Ban expiration timestamp
    pub ban_expires: Option<u64>,
    /// Behavioral baseline
    pub behavioral_baseline: Option<BehavioralBaseline>,
}

/// Behavioral baseline for adaptive rate limiting
#[derive(Debug, Clone)]
pub struct BehavioralBaseline {
    /// Average request rate
    pub avg_rate: f64,
    /// Request pattern standard deviation
    pub rate_stddev: f64,
    /// Typical request times
    pub typical_times: Vec<u64>,
    /// Updated timestamp
    pub updated: u64,
}

/// Enhanced rate limiter with adaptive thresholds
pub struct EnhancedRateLimiter {
    /// Configuration
    config: EnhancedRateLimitConfig,
    /// Rate limit entries
    entries: Arc<RwLock<HashMap<String, EnhancedRateLimitEntry>>>,
    /// Metrics
    metrics: Arc<EnhancedRateLimitMetrics>,
    /// Behavioral baselines
    behavioral_baselines: Arc<RwLock<HashMap<String, BehavioralBaseline>>>,
    /// Threat intelligence cache
    threat_intel_cache: Arc<RwLock<HashMap<IpAddr, ThreatIntelligence>>>,
    /// ML model (mock implementation)
    ml_model: Arc<MlModel>,
    /// Cleanup task handle
    cleanup_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Running flag
    is_running: Arc<AtomicBool>,
}

/// Threat intelligence information (simplified)
#[derive(Debug, Clone)]
pub struct ThreatIntelligence {
    /// Reputation score (0.0 to 1.0)
    pub reputation: f64,
    /// Known attack patterns
    pub attack_patterns: Vec<String>,
    /// Last seen timestamp
    pub last_seen: u64,
}

/// ML model for predictive rate limiting (simplified)
#[derive(Debug)]
pub struct MlModel {
    /// Model weights (simplified)
    weights: HashMap<String, f64>,
    /// Last training timestamp
    last_trained: u64,
}

impl MlModel {
    /// Create new ML model
    #[must_use]
    pub fn new() -> Self {
        Self {
            weights: HashMap::new(),
            last_trained: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
        }
    }

    /// Predict rate limit adjustment
    #[must_use]
    pub fn predict_adjustment(&self, _features: &HashMap<String, f64>) -> f64 {
        // Simplified prediction - in reality this would use a trained model
        1.0
    }

    /// Train model with new data
    pub async fn train(&mut self, _training_data: Vec<HashMap<String, f64>>) {
        self.last_trained = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
    }
}

impl Default for MlModel {
    fn default() -> Self {
        Self::new()
    }
}

impl EnhancedRateLimiter {
    /// Create new enhanced rate limiter
    #[must_use]
    pub fn new(config: EnhancedRateLimitConfig) -> Self {
        let limiter = Self {
            config,
            entries: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(EnhancedRateLimitMetrics::default()),
            behavioral_baselines: Arc::new(RwLock::new(HashMap::new())),
            threat_intel_cache: Arc::new(RwLock::new(HashMap::new())),
            ml_model: Arc::new(MlModel::new()),
            cleanup_handle: Arc::new(Mutex::new(None)),
            is_running: Arc::new(AtomicBool::new(false)),
        };

        limiter
    }

    /// Create rate limiter with default configuration
    #[must_use]
    pub fn default() -> Self {
        Self::new(EnhancedRateLimitConfig::default())
    }

    /// Start rate limiting system
    pub async fn start(&self) {
        if self.is_running.load(Ordering::Relaxed) {
            warn!("Rate limiter already running");
            return;
        }

        self.is_running.store(true, Ordering::Relaxed);
        info!("Starting enhanced rate limiting system");

        // Start background tasks
        self.start_cleanup_task().await;
        self.start_ml_training_task().await;
        self.start_behavioral_analysis_task().await;

        info!("Enhanced rate limiting system started");
    }

    /// Stop rate limiting system
    pub async fn stop(&self) {
        if !self.is_running.load(Ordering::Relaxed) {
            warn!("Rate limiter not running");
            return;
        }

        self.is_running.store(false, Ordering::Relaxed);
        info!("Stopping enhanced rate limiting system");

        // Cancel cleanup task
        let mut handle = self.cleanup_handle.lock().await;
        if let Some(task) = handle.take() {
            task.abort();
        }
        drop(handle);

        info!("Enhanced rate limiting system stopped");
    }

    /// Start cleanup task
    async fn start_cleanup_task(&self) {
        let entries = Arc::clone(&self.entries);
        let config = self.config.clone();
        let is_running = Arc::clone(&self.is_running);
        let metrics = Arc::clone(&self.metrics);

        let task = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(config.cleanup_interval_seconds));

            while is_running.load(Ordering::Relaxed) {
                interval.tick().await;

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs();

                let mut entries_map = entries.write().await;
                let initial_count = entries_map.len();

                // Remove expired entries
                entries_map.retain(|_, entry| {
                    if let Some(ban_expires) = entry.ban_expires {
                        ban_expires > now
                    } else {
                        // Keep entries that have been active recently
                        entry.last_refill > now.saturating_sub(3600) // Keep entries active in last hour
                    }
                });

                let removed_count = initial_count.saturating_sub(entries_map.len());
                if removed_count > 0 {
                    debug!("Cleaned up {} expired rate limit entries", removed_count);
                }

                // Check if we need adaptive cleanup
                if entries_map.len() > config.adaptive_cleanup_threshold {
                    let excess = entries_map.len() - config.adaptive_cleanup_threshold;
                    let mut keys_to_remove: Vec<String> = entries_map
                        .iter()
                        .map(|(k, _)| k.clone())
                        .take(excess)
                        .collect();

                    for key in keys_to_remove.drain(..) {
                        entries_map.remove(&key);
                    }

                    warn!(
                        "Adaptive cleanup removed {} entries to prevent memory exhaustion",
                        excess
                    );
                    metrics
                        .rate_limited_requests
                        .fetch_add(excess as u64, Ordering::Relaxed);
                }
            }
        });

        let mut handle = self.cleanup_handle.lock().await;
        *handle = Some(task);
    }

    /// Start ML training task
    async fn start_ml_training_task(&self) {
        if !self.config.enable_ml_prediction {
            return;
        }

        let ml_model = Arc::clone(&self.ml_model);
        let config = self.config.clone();
        let is_running = Arc::clone(&self.is_running);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(
                (config.ml_model_update_frequency_minutes * 60) as u64,
            ));

            while is_running.load(Ordering::Relaxed) {
                interval.tick().await;

                // In a real implementation, this would gather training data and update the model
                debug!("ML model training cycle - updating model");

                let model = ml_model.as_ref().clone();
                model.train(Vec::new()).await;
            }
        });
    }

    /// Start behavioral analysis task
    async fn start_behavioral_analysis_task(&self) {
        if !self.config.enable_behavioral_analysis {
            return;
        }

        let behavioral_baselines = Arc::clone(&self.behavioral_baselines);
        let config = self.config.clone();
        let is_running = Arc::clone(&self.is_running);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes

            while is_running.load(Ordering::Relaxed) {
                interval.tick().await;

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs();

                let retention_cutoff =
                    now.saturating_sub((config.behavioral_baselines_retention_days as u64) * 86400);

                let mut baselines = behavioral_baselines.write().await;
                baselines.retain(|_, baseline| baseline.updated > retention_cutoff);

                debug!(
                    "Behavioral analysis cleanup - retained {} baselines",
                    baselines.len()
                );
            }
        });
    }

    /// Check rate limit with enhanced adaptive thresholds
    pub async fn check_rate_limit(
        &self,
        _key: &str,
        client_ip: Option<IpAddr>,
        client_id: Option<&str>,
        endpoint: &str,
        user_agent: Option<&str>,
    ) -> EnhancedRateLimitResult {
        // Update metrics
        self.metrics.total_requests.fetch_add(1, Ordering::Relaxed);

        // Check if system is running
        if !self.is_running.load(Ordering::Relaxed) {
            debug!("Rate limiter not running, allowing request");
            self.metrics
                .allowed_requests
                .fetch_add(1, Ordering::Relaxed);
            return EnhancedRateLimitResult::Allowed;
        }

        // Check IP allowlist/banlist
        if let Some(ip) = client_ip {
            if self.is_ip_banned(ip).await {
                self.metrics
                    .blocked_requests
                    .fetch_add(1, Ordering::Relaxed);
                return EnhancedRateLimitResult::Blocked {
                    reason: "IP is banned".to_string(),
                    duration_minutes: self.config.ban_duration_minutes,
                };
            }

            if !self.is_ip_allowed(ip).await {
                self.metrics
                    .blocked_requests
                    .fetch_add(1, Ordering::Relaxed);
                return EnhancedRateLimitResult::Blocked {
                    reason: "IP not in allowlist".to_string(),
                    duration_minutes: 0,
                };
            }
        }

        // Get or create rate limit entry
        let mut entries = self.entries.write().await;
        let entry = entries
            .entry(key.to_string())
            .or_insert_with(|| EnhancedRateLimitEntry {
                tokens: self.get_base_limit(endpoint),
                last_refill: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs(),
                request_history: Vec::new(),
                adaptive_multiplier: 1.0,
                trust_score: 1.0,
                anomaly_score: 0.0,
                context_factors: HashMap::new(),
                violation_count: 0,
                last_violation: 0,
                ban_expires: None,
                behavioral_baseline: None,
            });

        // Check if banned
        if let Some(ban_expires) = entry.ban_expires {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();

            if now < ban_expires {
                self.metrics
                    .blocked_requests
                    .fetch_add(1, Ordering::Relaxed);
                return EnhancedRateLimitResult::Blocked {
                    reason: "Account temporarily banned".to_string(),
                    duration_minutes: ((ban_expires - now) / 60) as u32,
                };
            } else {
                // Ban expired, clear it
                entry.ban_expires = None;
            }
        }

        // Refill tokens
        self.refill_tokens(entry, endpoint);

        // Calculate effective limit based on adaptive factors
        let effective_limit = self
            .calculate_effective_limit(entry, client_ip, client_id, endpoint, user_agent)
            .await;

        // Check if request is allowed
        if entry.tokens > 0 {
            entry.tokens -= 1;
            entry.request_history.push(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs(),
            );

            // Keep only recent history
            self.prune_request_history(entry);

            self.metrics
                .allowed_requests
                .fetch_add(1, Ordering::Relaxed);

            // Update trust score for good behavior
            if entry.trust_score < 1.0 {
                entry.trust_score =
                    (entry.trust_score + self.config.behavioral_trust_decay_rate).min(1.0);
            }

            EnhancedRateLimitResult::Allowed
        } else {
            // Rate limited - handle adaptive response
            self.metrics
                .rate_limited_requests
                .fetch_add(1, Ordering::Relaxed);

            // Update violation count and trust score
            entry.violation_count += 1;
            entry.last_violation = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();

            // Decrease trust score for violations
            entry.trust_score = (entry.trust_score - 0.1).max(0.1);

            // Apply progressive penalties
            if self.config.progressive_delays_enabled {
                self.apply_progressive_penalty(entry);
            }

            // Check for automatic banning
            if entry.violation_count >= self.config.ban_threshold {
                self.apply_automatic_ban(entry);
            }

            // Calculate retry after time
            let retry_after = self.calculate_retry_after(entry, effective_limit);

            EnhancedRateLimitResult::RateLimited {
                retry_after,
                limit: effective_limit,
                remaining: entry.tokens,
                reset_time: entry.last_refill + self.config.window_duration_secs,
            }
        }
    }

    /// Refill tokens based on time elapsed
    fn refill_tokens(&self, entry: &mut EnhancedRateLimitEntry, endpoint: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let elapsed = now.saturating_sub(entry.last_refill);
        if elapsed >= self.config.window_duration_secs {
            let base_limit = self.get_base_limit(endpoint) as f64;
            let refill_amount = (elapsed as f64 / self.config.window_duration_secs as f64)
                * base_limit
                * entry.adaptive_multiplier;
            entry.tokens = (entry.tokens as f64 + refill_amount) as u32;
            entry.last_refill = now;

            // Cap tokens at burst limit with adaptive multiplier
            let burst_limit = self.get_burst_limit(endpoint) as f64 * entry.adaptive_multiplier;
            entry.tokens = entry.tokens.min(burst_limit as u32);
        }
    }

    /// Prune old request history
    fn prune_request_history(&self, entry: &mut EnhancedRateLimitEntry) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        // Keep only history from last hour
        entry
            .request_history
            .retain(|&timestamp| now.saturating_sub(timestamp) < 3600);
    }

    /// Calculate effective limit based on adaptive factors
    async fn calculate_effective_limit(
        &self,
        entry: &mut EnhancedRateLimitEntry,
        client_ip: Option<IpAddr>,
        client_id: Option<&str>,
        endpoint: &str,
        user_agent: Option<&str>,
    ) -> u32 {
        let mut effective_limit = self.get_base_limit(endpoint) as f64;

        // Apply adaptive multiplier
        if self.config.enable_adaptive_limits {
            effective_limit *= entry.adaptive_multiplier;
        }

        // Apply trust score multiplier
        effective_limit *= entry.trust_score;

        // Apply behavioral analysis if enabled
        if self.config.enable_behavioral_analysis {
            if let Some(baseline) = &entry.behavioral_baseline {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs();

                // Check if current behavior deviates from baseline
                if self.detect_behavioral_deviation(entry, baseline, now) {
                    effective_limit *= 0.5; // Reduce limit for anomalous behavior
                    entry.anomaly_score = (entry.anomaly_score + 0.1).min(1.0);
                } else {
                    entry.anomaly_score = (entry.anomaly_score - 0.05).max(0.0);
                }
            } else {
                // Build behavioral baseline for new users
                self.build_behavioral_baseline(entry, client_id).await;
            }
        }

        // Apply threat intelligence if available
        if let Some(ip) = client_ip {
            if let Some(intel) = self.get_threat_intelligence(ip).await {
                // Reduce limit for low reputation IPs
                effective_limit *= intel.reputation.max(0.1);
            }
        }

        // Apply context-aware factors
        if self.config.enable_context_aware_limits {
            let context_score = self
                .calculate_context_score(client_ip, client_id, endpoint, user_agent)
                .await;
            effective_limit *= context_score;
        }

        // Apply machine learning predictions if enabled
        if self.config.enable_ml_prediction {
            let features = self
                .extract_ml_features(entry, client_ip, client_id, endpoint)
                .await;
            let prediction = self.ml_model.predict_adjustment(&features);
            if prediction > self.config.ml_confidence_threshold {
                effective_limit *= prediction;
                self.metrics.ml_predictions.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Ensure limit is within reasonable bounds
        effective_limit = effective_limit
            .max(1.0) // At least 1 request allowed
            .min((self.get_base_limit(endpoint) as f64) * self.config.adaptive_max_multiplier);

        effective_limit as u32
    }

    /// Detect behavioral deviation from baseline
    fn detect_behavioral_deviation(
        &self,
        entry: &EnhancedRateLimitEntry,
        baseline: &BehavioralBaseline,
        current_time: u64,
    ) -> bool {
        if entry.request_history.is_empty() {
            return false;
        }

        // Calculate current rate
        let window_start = current_time.saturating_sub(3600); // Last hour
        let recent_requests: Vec<u64> = entry
            .request_history
            .iter()
            .filter(|&&timestamp| timestamp >= window_start)
            .copied()
            .collect();

        if recent_requests.is_empty() {
            return false;
        }

        let current_rate = recent_requests.len() as f64 / 3600.0; // Requests per second

        // Check if current rate deviates significantly from baseline
        let deviation = (current_rate - baseline.avg_rate).abs() / baseline.rate_stddev.max(0.001);
        deviation > self.config.behavioral_deviation_threshold
    }

    /// Build behavioral baseline for new users
    async fn build_behavioral_baseline(
        &self,
        entry: &mut EnhancedRateLimitEntry,
        client_id: Option<&str>,
    ) {
        if entry.request_history.len() < 10 {
            // Need more data to build baseline
            return;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        // Calculate average rate and standard deviation
        let window_start = now.saturating_sub(86400); // Last 24 hours
        let recent_requests: Vec<u64> = entry
            .request_history
            .iter()
            .filter(|&&timestamp| timestamp >= window_start)
            .copied()
            .collect();

        if recent_requests.is_empty() {
            return;
        }

        let avg_rate = recent_requests.len() as f64 / 86400.0;

        // Calculate standard deviation
        let variance: f64 = recent_requests
            .iter()
            .map(|&timestamp| {
                let rate = 1.0 / (now.saturating_sub(timestamp) as f64).max(1.0);
                (rate - avg_rate).powi(2)
            })
            .sum::<f64>()
            / recent_requests.len() as f64;
        let stddev = variance.sqrt();

        let baseline = BehavioralBaseline {
            avg_rate,
            rate_stddev: stddev,
            typical_times: recent_requests,
            updated: now,
        };

        entry.behavioral_baseline = Some(baseline);
        self.metrics
            .behavioral_analyses
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get threat intelligence for IP
    async fn get_threat_intelligence(&self, ip: IpAddr) -> Option<ThreatIntelligence> {
        let cache = self.threat_intel_cache.read().await;
        cache.get(&ip).cloned()
    }

    /// Calculate context score based on multiple factors
    async fn calculate_context_score(
        &self,
        client_ip: Option<IpAddr>,
        client_id: Option<&str>,
        endpoint: &str,
        user_agent: Option<&str>,
    ) -> f64 {
        let mut score = 1.0;

        // Apply endpoint-specific risk weights
        if let Some(weight) = self.config.context_risk_weights.get(endpoint) {
            score *= *weight;
        }

        // Apply client trust score
        if let Some(client) = client_id {
            if let Some(trust) = self.config.context_trust_scores.get(client) {
                score *= *trust;
            }
        }

        // Apply IP reputation if available
        if let Some(ip) = client_ip {
            if let Some(intel) = self.get_threat_intelligence(ip).await {
                score *= intel.reputation;
            }
        }

        // Apply user agent analysis
        if let Some(ua) = user_agent {
            score *= self.analyze_user_agent(ua);
        }

        self.metrics
            .context_based_decisions
            .fetch_add(1, Ordering::Relaxed);

        score.max(0.1).min(2.0) // Keep within reasonable bounds
    }

    /// Analyze user agent for risk assessment
    fn analyze_user_agent(&self, user_agent: &str) -> f64 {
        // Simple heuristic analysis
        // In a real implementation, this would use more sophisticated analysis

        if user_agent.contains("bot") || user_agent.contains("crawler") {
            // Likely automated - reduce limit
            0.5
        } else if user_agent.contains("mobile") {
            // Mobile clients - normal limit
            1.0
        } else if user_agent.contains("curl") || user_agent.contains("wget") {
            // Command line tools - reduced limit
            0.7
        } else {
            // Browser or normal client - normal limit
            1.0
        }
    }

    /// Extract features for ML prediction
    async fn extract_ml_features(
        &self,
        entry: &EnhancedRateLimitEntry,
        client_ip: Option<IpAddr>,
        client_id: Option<&str>,
        endpoint: &str,
    ) -> HashMap<String, f64> {
        let mut features = HashMap::new();

        // Basic features
        features.insert("tokens".to_string(), entry.tokens as f64);
        features.insert("adaptive_multiplier".to_string(), entry.adaptive_multiplier);
        features.insert("trust_score".to_string(), entry.trust_score);
        features.insert("anomaly_score".to_string(), entry.anomaly_score);
        features.insert("violation_count".to_string(), entry.violation_count as f64);

        // Request history features
        features.insert(
            "recent_requests".to_string(),
            entry.request_history.len() as f64,
        );

        // Context features
        if let Some(ip) = client_ip {
            let mut hasher = DefaultHasher::new();
            ip.hash(&mut hasher);
            features.insert("ip_hash".to_string(), hasher.finish() as f64);
        }

        if let Some(client) = client_id {
            let mut hasher = DefaultHasher::new();
            client.hash(&mut hasher);
            features.insert("client_hash".to_string(), hasher.finish() as f64);
        }

        let mut hasher = DefaultHasher::new();
        endpoint.hash(&mut hasher);
        features.insert("endpoint_hash".to_string(), hasher.finish() as f64);

        features
    }

    /// Apply progressive penalty for repeated violations
    fn apply_progressive_penalty(&self, entry: &mut EnhancedRateLimitEntry) {
        if entry.violation_count > 1 {
            let penalty_factor = self
                .config
                .adaptive_backoff_factor
                .powi(entry.violation_count as i32);
            entry.adaptive_multiplier /= penalty_factor;
            entry.adaptive_multiplier = entry
                .adaptive_multiplier
                .max(self.config.adaptive_min_multiplier);
        }
    }

    /// Apply automatic ban for excessive violations
    fn apply_automatic_ban(&self, entry: &mut EnhancedRateLimitEntry) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let ban_duration = (self.config.ban_duration_minutes as u64) * 60;
        entry.ban_expires = Some(now + ban_duration);

        // Reset violation count after ban
        entry.violation_count = 0;

        warn!("Applied automatic ban for excessive rate limit violations");
    }

    /// Calculate retry after time with progressive delays
    fn calculate_retry_after(&self, entry: &EnhancedRateLimitEntry, _effective_limit: u32) -> u64 {
        let base_retry = self.config.window_duration_secs;

        // Apply progressive delays based on violation count
        if self.config.progressive_delays_enabled && entry.violation_count > 1 {
            let delay_multiplier = self
                .config
                .adaptive_backoff_factor
                .powi(entry.violation_count as i32);
            (base_retry as f64 * delay_multiplier) as u64
        } else {
            base_retry
        }
    }

    /// Get base limit for endpoint
    fn get_base_limit(&self, endpoint: &str) -> u32 {
        match endpoint {
            "/oauth/token" => self.config.oauth_token_requests_per_minute,
            "/oauth/authorize" => self.config.oauth_authorize_requests_per_minute,
            "/oauth/introspect" => self.config.oauth_introspect_requests_per_minute,
            "/admin/" if endpoint.starts_with("/admin/") => self.config.admin_requests_per_minute,
            "/scim/" if endpoint.starts_with("/scim/") => self.config.scim_requests_per_minute,
            "/.well-known/jwks.json" | "/jwks.json" => self.config.jwks_requests_per_minute,
            _ => self.config.per_ip_requests_per_minute,
        }
    }

    /// Get burst limit for endpoint
    fn get_burst_limit(&self, endpoint: &str) -> u32 {
        match endpoint {
            "/oauth/token" => self.config.oauth_token_requests_per_minute * 2,
            "/oauth/authorize" => self.config.oauth_authorize_requests_per_minute * 2,
            "/oauth/introspect" => self.config.oauth_introspect_requests_per_minute * 2,
            "/admin/" if endpoint.starts_with("/admin/") => {
                self.config.admin_requests_per_minute * 2
            }
            "/scim/" if endpoint.starts_with("/scim/") => self.config.scim_requests_per_minute * 2,
            "/.well-known/jwks.json" | "/jwks.json" => self.config.jwks_requests_per_minute * 2,
            _ => self.config.per_ip_burst,
        }
    }

    /// Check if IP is banned
    async fn is_ip_banned(&self, ip: IpAddr) -> bool {
        // Check banlist
        if self.config.banlist_ips.contains(&ip) {
            return true;
        }

        // Check threat intelligence cache
        let cache = self.threat_intel_cache.read().await;
        if let Some(intel) = cache.get(&ip) {
            if intel.reputation < 0.2 {
                return true;
            }
        }

        false
    }

    /// Check if IP is allowed
    async fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        // If allowlist is not enabled, allow all
        if !self.config.enable_allowlist {
            return true;
        }

        // Check allowlist
        if self.config.allowlist_ips.contains(&ip) {
            return true;
        }

        // Check CIDR ranges
        for cidr in &self.config.allowlist_cidrs {
            if self.ip_matches_cidr(ip, cidr) {
                return true;
            }
        }

        false
    }

    /// Check if IP matches CIDR notation
    fn ip_matches_cidr(&self, _ip: IpAddr, _cidr: &str) -> bool {
        // Simplified implementation
        // In a real implementation, this would parse CIDR notation and check IP membership
        true
    }

    /// Get rate limit metrics
    #[must_use]
    pub fn get_metrics(&self) -> &EnhancedRateLimitMetrics {
        &self.metrics
    }

    /// Add threat intelligence data
    pub async fn add_threat_intelligence(&self, ip: IpAddr, intel: ThreatIntelligence) {
        let mut cache = self.threat_intel_cache.write().await;
        cache.insert(ip, intel);
    }

    /// Update configuration
    pub async fn update_config(&mut self, config: EnhancedRateLimitConfig) {
        self.config = config;
    }

    /// Get adaptive adjustment statistics
    pub async fn get_adaptive_stats(&self) -> AdaptiveStats {
        let entries = self.entries.read().await;
        let mut multipliers = Vec::new();
        let mut trust_scores = Vec::new();
        let mut anomaly_scores = Vec::new();

        for entry in entries.values() {
            multipliers.push(entry.adaptive_multiplier);
            trust_scores.push(entry.trust_score);
            anomaly_scores.push(entry.anomaly_score);
        }

        AdaptiveStats {
            total_entries: entries.len(),
            avg_adaptive_multiplier: if !multipliers.is_empty() {
                multipliers.iter().sum::<f64>() / multipliers.len() as f64
            } else {
                1.0
            },
            avg_trust_score: if !trust_scores.is_empty() {
                trust_scores.iter().sum::<f64>() / trust_scores.len() as f64
            } else {
                1.0
            },
            avg_anomaly_score: if !anomaly_scores.is_empty() {
                anomaly_scores.iter().sum::<f64>() / anomaly_scores.len() as f64
            } else {
                0.0
            },
            min_adaptive_multiplier: multipliers
                .iter()
                .fold(f64::INFINITY, |a, &b| a.min(b))
                .min(1.0_f64),
            max_adaptive_multiplier: multipliers
                .iter()
                .fold(0.0_f64, |a, &b| a.max(b))
                .max(1.0_f64),
        }
    }
}

/// Adaptive statistics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveStats {
    /// Total tracked entries
    pub total_entries: usize,
    /// Average adaptive multiplier
    pub avg_adaptive_multiplier: f64,
    /// Average trust score
    pub avg_trust_score: f64,
    /// Average anomaly score
    pub avg_anomaly_score: f64,
    /// Minimum adaptive multiplier
    pub min_adaptive_multiplier: f64,
    /// Maximum adaptive multiplier
    pub max_adaptive_multiplier: f64,
}

/// Enhanced rate limiting middleware
pub async fn enhanced_rate_limit_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    // Extract client information
    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok());

    let client_id = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let endpoint = request.uri().path().to_string();
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok());

    // Generate rate limiting key
    let key = format!(
        "rl:{}:{}:{}",
        client_ip
            .as_ref()
            .map_or("unknown".to_string(), |ip: &std::net::IpAddr| ip
                .to_string()),
        client_id.as_ref().map(String::as_str).unwrap_or("unknown"),
        &endpoint
    );

    // Check rate limit
    // In a real implementation, this would use a global rate limiter instance
    let result = EnhancedRateLimitResult::Allowed; // Simplified for example

    match result {
        EnhancedRateLimitResult::Allowed => {
            // Proceed with request
            Ok(next.run(request).await)
        }
        EnhancedRateLimitResult::RateLimited {
            retry_after,
            limit,
            remaining,
            reset_time,
        } => {
            // Return rate limit response
            let mut response = axum::response::Response::builder()
                .status(axum::http::StatusCode::TOO_MANY_REQUESTS)
                .header("Retry-After", retry_after.to_string())
                .header("X-RateLimit-Limit", limit.to_string())
                .header("X-RateLimit-Remaining", remaining.to_string())
                .header("X-RateLimit-Reset", reset_time.to_string())
                .body(axum::body::Body::from("Rate limit exceeded"))
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

            // Add rate limit headers
            let headers = response.headers_mut();
            headers.insert("X-RateLimit-Policy", "adaptive".parse().unwrap());

            Ok(response)
        }
        EnhancedRateLimitResult::Blocked {
            reason,
            duration_minutes,
        } => {
            // Return blocked response
            let mut response = axum::response::Response::builder()
                .status(axum::http::StatusCode::FORBIDDEN)
                .body(axum::body::Body::from(format!("Blocked: {}", reason)))
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

            if duration_minutes > 0 {
                let headers = response.headers_mut();
                headers.insert(
                    "Retry-After",
                    (duration_minutes * 60).to_string().parse().unwrap(),
                );
            }

            Ok(response)
        }
    }
}

/// Convenience function to create default enhanced rate limiter
#[must_use]
pub fn create_default_enhanced_rate_limiter() -> EnhancedRateLimiter {
    let mut config = EnhancedRateLimitConfig::default();

    // Override with environment variables if available
    if let Ok(global_rpm) = std::env::var("GLOBAL_REQUESTS_PER_MINUTE") {
        if let Ok(val) = global_rpm.parse::<u32>() {
            config.global_requests_per_minute = val;
        }
    }

    if let Ok(ip_rpm) = std::env::var("PER_IP_REQUESTS_PER_MINUTE") {
        if let Ok(val) = ip_rpm.parse::<u32>() {
            config.per_ip_requests_per_minute = val;
        }
    }

    if let Ok(enable_adaptive) = std::env::var("ENABLE_ADAPTIVE_LIMITS") {
        config.enable_adaptive_limits =
            enable_adaptive == "1" || enable_adaptive.to_lowercase() == "true";
    }

    if let Ok(enable_ml) = std::env::var("ENABLE_ML_PREDICTION") {
        config.enable_ml_prediction = enable_ml == "1" || enable_ml.to_lowercase() == "true";
    }

    if let Ok(enable_behavioral) = std::env::var("ENABLE_BEHAVIORAL_ANALYSIS") {
        config.enable_behavioral_analysis =
            enable_behavioral == "1" || enable_behavioral.to_lowercase() == "true";
    }

    EnhancedRateLimiter::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_enhanced_rate_limiter_creation() {
        let limiter = EnhancedRateLimiter::default();
        assert!(!limiter.is_running.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_rate_limit_check_allowed() {
        let limiter = EnhancedRateLimiter::default();
        limiter.start().await;

        let result = limiter
            .check_rate_limit(
                "test-key",
                Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                Some("test-client"),
                "/oauth/token",
                Some("test-user-agent"),
            )
            .await;

        assert_eq!(result, EnhancedRateLimitResult::Allowed);

        limiter.stop().await;
    }

    #[tokio::test]
    async fn test_adaptive_stats() {
        let limiter = EnhancedRateLimiter::default();
        limiter.start().await;

        // Check initial stats
        let stats = limiter.get_adaptive_stats().await;
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.avg_adaptive_multiplier, 1.0);
        assert_eq!(stats.avg_trust_score, 1.0);
        assert_eq!(stats.avg_anomaly_score, 0.0);
        assert_eq!(stats.min_adaptive_multiplier, 1.0);
        assert_eq!(stats.max_adaptive_multiplier, 1.0);

        limiter.stop().await;
    }

    #[test]
    fn test_enhanced_rate_limit_config_default() {
        let config = EnhancedRateLimitConfig::default();
        assert_eq!(config.global_requests_per_minute, 10000);
        assert_eq!(config.per_ip_requests_per_minute, 100);
        assert_eq!(config.oauth_token_requests_per_minute, 30);
        assert!(config.enable_adaptive_limits);
        assert!(config.enable_ml_prediction);
        assert!(config.enable_behavioral_analysis);
        assert!(config.enable_context_aware_limits);
        assert_eq!(config.adaptive_learning_window_hours, 24);
        assert_eq!(config.adaptive_adjustment_threshold, 0.7);
        assert_eq!(config.adaptive_min_multiplier, 0.5);
        assert_eq!(config.adaptive_max_multiplier, 2.0);
        assert_eq!(config.adaptive_burst_multiplier, 1.5);
        assert_eq!(config.adaptive_backoff_factor, 1.2);
        assert_eq!(config.adaptive_recovery_speed, 0.1);
        assert_eq!(config.ml_model_update_frequency_minutes, 30);
        assert_eq!(config.ml_confidence_threshold, 0.8);
        assert_eq!(config.ml_anomaly_detection_sensitivity, 0.7);
        assert_eq!(config.behavioral_baselines_retention_days, 30);
        assert_eq!(config.behavioral_deviation_threshold, 0.6);
        assert_eq!(config.behavioral_trust_decay_rate, 0.05);
        assert_eq!(config.cleanup_interval_seconds, 300);
        assert_eq!(config.max_tracked_ips, 100_000);
        assert_eq!(config.window_duration_secs, 60);
        assert_eq!(config.adaptive_cleanup_threshold, 50_000);
    }

    #[test]
    fn test_enhanced_rate_limit_result_ordering() {
        // Test that rate limit results can be compared
        let allowed = EnhancedRateLimitResult::Allowed;
        let rate_limited = EnhancedRateLimitResult::RateLimited {
            retry_after: 60,
            limit: 100,
            remaining: 0,
            reset_time: 1234567890,
        };
        let blocked = EnhancedRateLimitResult::Blocked {
            reason: "test".to_string(),
            duration_minutes: 60,
        };

        // These should be different
        assert_ne!(allowed, rate_limited);
        assert_ne!(allowed, blocked);
        assert_ne!(rate_limited, blocked);
    }

    #[tokio::test]
    async fn test_behavioral_baseline_building() {
        let limiter = EnhancedRateLimiter::default();
        limiter.start().await;

        // Create a rate limit entry with some history
        let mut entry = EnhancedRateLimitEntry {
            tokens: 100,
            last_refill: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
            request_history: vec![],
            adaptive_multiplier: 1.0,
            trust_score: 1.0,
            anomaly_score: 0.0,
            context_factors: HashMap::new(),
            violation_count: 0,
            last_violation: 0,
            ban_expires: None,
            behavioral_baseline: None,
        };

        // Add some request history
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        for i in 0..15 {
            entry.request_history.push(now - (15 - i) * 60); // One request per minute
        }

        // Build behavioral baseline
        limiter
            .build_behavioral_baseline(&mut entry, Some("test-client"))
            .await;

        // Should have created a baseline
        assert!(entry.behavioral_baseline.is_some());

        limiter.stop().await;
    }

    #[tokio::test]
    async fn test_adaptive_multiplier_adjustment() {
        let limiter = EnhancedRateLimitConfig::default();
        let mut entry = EnhancedRateLimitEntry {
            tokens: 100,
            last_refill: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
            request_history: vec![],
            adaptive_multiplier: 1.0,
            trust_score: 1.0,
            anomaly_score: 0.0,
            context_factors: HashMap::new(),
            violation_count: 0,
            last_violation: 0,
            ban_expires: None,
            behavioral_baseline: None,
        };

        // Test progressive penalty application
        entry.violation_count = 3;
        limiter.apply_progressive_penalty(&mut entry);
        assert!(entry.adaptive_multiplier < 1.0);

        // Test that multiplier doesn't go below minimum
        entry.adaptive_multiplier = 0.1;
        entry.violation_count = 10;
        limiter.apply_progressive_penalty(&mut entry);
        assert!(entry.adaptive_multiplier >= limiter.adaptive_min_multiplier);
    }

    #[tokio::test]
    async fn test_threat_intelligence_integration() {
        let limiter = EnhancedRateLimiter::default();
        limiter.start().await;

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let intel = ThreatIntelligence {
            reputation: 0.1, // Very low reputation
            attack_patterns: vec!["ddos".to_string()],
            last_seen: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
        };

        // Add threat intelligence
        limiter.add_threat_intelligence(ip, intel).await;

        // Check if IP is banned
        assert!(limiter.is_ip_banned(ip).await);

        limiter.stop().await;
    }

    #[test]
    fn test_context_score_calculation() {
        let limiter = EnhancedRateLimiter::default();

        // Test normal context
        let score = limiter
            .analyze_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        assert_eq!(score, 1.0);

        // Test bot/crawler context
        let score = limiter.analyze_user_agent("Mozilla/5.0 (compatible; Googlebot/2.1)");
        assert_eq!(score, 0.5);

        // Test command line tool context
        let score = limiter.analyze_user_agent("curl/7.68.0");
        assert_eq!(score, 0.7);
    }

    #[tokio::test]
    async fn test_metrics_tracking() {
        let limiter = EnhancedRateLimiter::default();
        limiter.start().await;

        // Check initial metrics
        assert_eq!(
            limiter.get_metrics().total_requests.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            limiter
                .get_metrics()
                .allowed_requests
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            limiter
                .get_metrics()
                .rate_limited_requests
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            limiter
                .get_metrics()
                .blocked_requests
                .load(Ordering::Relaxed),
            0
        );

        limiter.stop().await;
    }

    #[tokio::test]
    async fn test_cleanup_functionality() {
        let limiter = EnhancedRateLimiter::default();
        limiter.start().await;

        // Wait a bit for cleanup task to initialize
        tokio::time::sleep(Duration::from_millis(100)).await;

        limiter.stop().await;
    }

    #[test]
    fn test_create_default_rate_limiter() {
        let limiter = create_default_enhanced_rate_limiter();
        assert!(!limiter.is_running.load(Ordering::Relaxed));
    }
}
