use crate::core::security::{SecurityEvent, ViolationSeverity};
use tracing::debug;
#[cfg(feature = "threat-hunting")]
use crate::threat_adapter::ThreatDetectionAdapter;
use crate::errors::AuthError;
use crate::threat_types::{IndicatorType, ThreatType, ThreatSeverity, AttackPhase, MitigationAction, ThreatIndicator};
use chrono::{DateTime, Utc};
use flume::{unbounded, Receiver, Sender};
#[cfg(feature = "monitoring")]
use prometheus::{register_counter, register_gauge, register_histogram, Counter, Gauge, Histogram};
use redis::aio::ConnectionManager;
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{error, info, warn};
use uuid::Uuid;

/// Prometheus metrics for threat intelligence
use std::sync::LazyLock;

static THREAT_INTEL_QUERIES: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "threat_hunting_intel_queries_total",
        "Total threat intelligence queries made"
    ).expect("Failed to create threat_intel_queries counter")
});

static THREAT_INTEL_MATCHES: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "threat_hunting_intel_matches_total",
        "Total threat intelligence matches found"
    ).expect("Failed to create threat_intel_matches counter")
});

static THREAT_INTEL_ERRORS: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "threat_hunting_intel_errors_total",
        "Total threat intelligence query errors"
    ).expect("Failed to create threat_intel_errors counter")
});

static THREAT_INTEL_CACHE_HITS: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "threat_hunting_intel_cache_hits_total",
        "Total threat intelligence cache hits"
    ).expect("Failed to create threat_intel_cache_hits counter")
});

static THREAT_INTEL_RESPONSE_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "threat_hunting_intel_response_time_seconds",
        "Response time for threat intelligence queries"
    ).expect("Failed to create threat_intel_response_time histogram")
});

static ACTIVE_INDICATORS: std::sync::LazyLock<Gauge> = std::sync::LazyLock::new(|| {
    register_gauge!(
        "threat_hunting_active_indicators",
        "Number of active threat indicators"
    ).expect("Failed to create active_indicators gauge")
});

/// Configuration for threat intelligence correlation
#[derive(Debug, Clone)]
pub struct ThreatIntelligenceConfig {
    pub enabled: bool,
    pub cache_ttl_seconds: u64,
    pub query_timeout_seconds: u64,
    pub max_concurrent_queries: usize,
    pub feed_refresh_interval_minutes: u64,
    pub feeds: Vec<ThreatFeedConfig>,
    pub redis_config: ThreatIntelRedisConfig,
    pub api_rate_limits: ApiRateLimits,
}

/// Configuration for individual threat feeds
#[derive(Debug, Clone)]
pub struct ThreatFeedConfig {
    pub name: String,
    pub feed_type: ThreatFeedType,
    pub enabled: bool,
    pub priority: u8,
    pub api_url: String,
    pub api_key: Option<String>,
    pub headers: HashMap<String, String>,
    pub query_interval_seconds: u64,
    pub confidence_threshold: f64,
    pub supported_indicators: Vec<IndicatorType>,
    pub url: String, // Alias for api_url for backward compatibility
    pub format: String, // Feed format (json, xml, csv, etc.)
}

/// Types of threat intelligence feeds
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatFeedType {
    VirusTotal,
    Misp,
    AbuseIpdb,
    UrlVoid,
    MalwareDomains,
    EmergingThreats,
    AlienVaultOtx,
    ThreatMiner,
    CrowdStrike,
    Custom,
}

/// Redis configuration for threat intelligence
#[derive(Debug, Clone)]
pub struct ThreatIntelRedisConfig {
    pub url: String,
    pub key_prefix: String,
    pub indicator_ttl_seconds: u64,
    pub feed_cache_ttl_seconds: u64,
}

/// API rate limiting configuration
#[derive(Debug, Clone)]
pub struct ApiRateLimits {
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub burst_limit: u32,
    pub backoff_multiplier: f64,
    pub max_retry_attempts: u32,
}

/// Threat intelligence indicator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligenceIndicator {
    pub indicator: String,
    pub indicator_type: IndicatorType,
    pub threat_types: Vec<ThreatType>,
    pub confidence: f64,
    pub severity: ThreatSeverity,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub source: String,
    pub feed_name: String,
    pub tags: HashSet<String>,
    pub attributes: HashMap<String, serde_json::Value>,
    pub false_positive_rate: f64,
    pub reputation_score: f64,
    pub malware_families: Vec<String>,
    pub threat_actor_groups: Vec<String>,
    pub geographic_regions: Vec<String>,
    pub kill_chain_phases: Vec<AttackPhase>,
}

/// Result of threat intelligence correlation
#[derive(Debug, Clone)]
pub struct ThreatIntelligenceMatch {
    pub indicator: ThreatIntelligenceIndicator,
    pub matched_value: String,
    pub match_type: MatchType,
    pub confidence: f64,
    pub risk_score: u8,
    pub context: MatchContext,
    pub recommended_actions: Vec<MitigationAction>,
}

/// Types of indicator matches
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchType {
    Exact,
    Substring,
    Regex,
    Fuzzy,
    Network,
    Domain,
}

/// Context information for matches
#[derive(Debug, Clone)]
pub struct MatchContext {
    pub event_context: Option<SecurityEvent>,
    pub related_indicators: Vec<String>,
    pub campaign_associations: Vec<String>,
    pub historical_matches: u32,
    pub recent_activity: bool,
}

/// Feed synchronization status
#[derive(Debug, Clone)]
pub struct FeedSyncStatus {
    pub feed_name: String,
    pub last_sync: Option<DateTime<Utc>>,
    pub sync_status: SyncStatus,
    pub indicators_count: u64,
    pub errors_count: u32,
    pub next_sync: DateTime<Utc>,
}

/// Synchronization status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    Pending,
    InProgress,
    Completed,
    Success,
    Failed,
    Disabled,
}

/// Rate limiting tracker
#[derive(Debug)]
pub struct RateLimiter {
    pub requests_this_minute: u32,
    pub requests_this_hour: u32,
    pub last_minute_reset: DateTime<Utc>,
    pub last_hour_reset: DateTime<Utc>,
    pub current_backoff: f64,
}

/// Threat intelligence correlator
pub struct ThreatIntelligenceCorrelator {
    config: Arc<RwLock<ThreatIntelligenceConfig>>,
    redis_client: Arc<Mutex<Option<ConnectionManager>>>,
    http_client: Client,

    // Indicator storage and caching
    indicators: Arc<RwLock<HashMap<String, ThreatIntelligenceIndicator>>>,
    indicator_cache: Arc<RwLock<HashMap<String, CachedResult>>>,

    // Feed management
    feed_status: Arc<RwLock<HashMap<String, FeedSyncStatus>>>,
    rate_limiters: Arc<RwLock<HashMap<String, RateLimiter>>>,

    // Query processing
    query_queue: Sender<IntelligenceQuery>,
    query_receiver: Receiver<IntelligenceQuery>,

    // Statistics
    statistics: Arc<Mutex<IntelligenceStatistics>>,
}

/// Cached query result
#[derive(Debug, Clone)]
pub struct CachedResult {
    pub result: Option<ThreatIntelligenceMatch>,
    pub cached_at: DateTime<Utc>,
    pub ttl_seconds: u64,
    pub operation_result: Option<ThreatIntelligenceMatch>, // Alias for result for backward compatibility
}

/// Intelligence query request
#[derive(Debug, Clone)]
pub struct IntelligenceQuery {
    pub query_id: String,
    pub indicator_value: String,
    pub indicator_type: IndicatorType,
    pub context: Option<SecurityEvent>,
    pub priority: QueryPriority,
    #[cfg(feature = "flume")]
    pub response_channel: Option<flume::Sender<ThreatIntelligenceMatch>>,
}

/// Query priority levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueryPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Intelligence correlation statistics
#[derive(Debug, Default, Clone)]
pub struct IntelligenceStatistics {
    pub queries_total: u64,
    pub matches_total: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub api_errors: u64,
    pub average_response_time_ms: u64,
    pub feeds_active: u32,
    pub indicators_loaded: u64,
}

impl Default for ThreatIntelligenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_ttl_seconds: 3600,
            query_timeout_seconds: 30,
            max_concurrent_queries: 10,
            feed_refresh_interval_minutes: 60,
            feeds: vec![
                ThreatFeedConfig {
                    name: "abuse_ipdb".to_string(),
                    feed_type: ThreatFeedType::AbuseIpdb,
                    enabled: true,
                    priority: 8,
                    api_url: "https://api.abuseipdb.com/api/v2/check".to_string(),
                    api_key: None,
                    headers: HashMap::new(),
                    query_interval_seconds: 1,
                    confidence_threshold: 0.8,
                    supported_indicators: vec![IndicatorType::IpAddress],
                    url: "https://api.abuseipdb.com/api/v2/check".to_string(),
                    format: "json".to_string(),
                },
                ThreatFeedConfig {
                    name: "virustotal".to_string(),
                    feed_type: ThreatFeedType::VirusTotal,
                    enabled: false, // Requires API key
                    priority: 9,
                    api_url: "https://www.virustotal.com/vtapi/v2/".to_string(),
                    api_key: None,
                    headers: HashMap::new(),
                    query_interval_seconds: 15, // VT has strict rate limits
                    confidence_threshold: 0.7,
                    supported_indicators: vec![
                        IndicatorType::IpAddress,
                        IndicatorType::Domain,
                        IndicatorType::Url,
                        IndicatorType::FileHash,
                    ],
                    url: "https://www.virustotal.com/vtapi/v2/".to_string(),
                    format: "json".to_string(),
                },
            ],
            redis_config: ThreatIntelRedisConfig {
                url: "redis://localhost:6379".to_string(),
                key_prefix: "threat_intel:".to_string(),
                indicator_ttl_seconds: 86400, // 24 hours
                feed_cache_ttl_seconds: 3600, // 1 hour
            },
            api_rate_limits: ApiRateLimits {
                requests_per_minute: 60,
                requests_per_hour: 1000,
                burst_limit: 10,
                backoff_multiplier: 2.0,
                max_retry_attempts: 3,
            },
        }
    }
}

impl ThreatIntelligenceCorrelator {
    /// Create a new threat intelligence correlator
    #[must_use] pub fn new(config: ThreatIntelligenceConfig) -> Self {
        let (query_sender, query_receiver) = unbounded();

        let http_client = ClientBuilder::new()
            .timeout(std::time::Duration::from_secs(config.query_timeout_seconds))
            .user_agent("Rust-Security-ThreatHunting/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config: Arc::new(RwLock::new(config)),
            redis_client: Arc::new(Mutex::new(None)),
            http_client,
            indicators: Arc::new(RwLock::new(HashMap::new())),
            indicator_cache: Arc::new(RwLock::new(HashMap::new())),
            feed_status: Arc::new(RwLock::new(HashMap::new())),
            rate_limiters: Arc::new(RwLock::new(HashMap::new())),
            query_queue: query_sender,
            query_receiver,
            statistics: Arc::new(Mutex::new(IntelligenceStatistics::default())),
        }
    }

    /// Initialize the threat intelligence correlator
    ///
    /// # Errors
    ///
    /// Returns `Box<dyn std::error::Error + Send + Sync>` if:
    /// - Loading cached indicators fails due to filesystem or deserialization errors
    /// - Background task initialization fails
    /// - Feed synchronization setup fails
    ///
    /// Note: Redis connection failures are logged as warnings but do not cause initialization to fail.
    ///
    /// # Panics
    ///
    /// This function does not panic under normal operation.
    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing Threat Intelligence Correlator");

        // Initialize Redis connection
        if let Err(e) = self.initialize_redis().await {
            warn!("Failed to initialize Redis connection: {}", e);
        }

        // Load cached indicators
        self.load_cached_indicators().await?;

        // Initialize rate limiters
        self.initialize_rate_limiters().await;

        // Start background tasks
        self.start_query_processor().await;
        self.start_feed_synchronizer().await;
        self.start_cache_cleaner().await;
        self.start_statistics_updater().await;

        info!("Threat Intelligence Correlator initialized successfully");
        Ok(())
    }

    /// Initialize Redis connection
    async fn initialize_redis(&self) -> Result<(), redis::RedisError> {
        let config = self.config.read().await;
        let client = redis::Client::open(config.redis_config.url.as_str())?;
        let manager = ConnectionManager::new(client).await?;

        let mut redis_client = self.redis_client.lock().await;
        *redis_client = Some(manager);

        info!("Redis connection established for threat intelligence");
        Ok(())
    }

    /// Load cached indicators from Redis
    async fn load_cached_indicators(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let redis_client = self.redis_client.lock().await;
        if let Some(ref client) = *redis_client {
            let config = self.config.read().await;
            let pattern = format!("{}indicator:*", config.redis_config.key_prefix);

            let keys: Vec<String> = redis::cmd("KEYS")
                .arg(&pattern)
                .query_async(&mut client.clone())
                .await
                .unwrap_or_default();

            let mut indicators = self.indicators.write().await;
            for key in keys {
                let indicator_data: Option<String> = redis::cmd("GET")
                    .arg(&key)
                    .query_async(&mut client.clone())
                    .await
                    .unwrap_or_default();

                if let Some(data) = indicator_data {
                    if let Ok(indicator) =
                        serde_json::from_str::<ThreatIntelligenceIndicator>(&data)
                    {
                        indicators.insert(indicator.indicator.clone(), indicator);
                    }
                }
            }

            info!("Loaded {} threat intelligence indicators", indicators.len());
            ACTIVE_INDICATORS.set(indicators.len() as f64);
        }
        Ok(())
    }

    /// Initialize rate limiters for feeds
    async fn initialize_rate_limiters(&self) {
        let config = self.config.read().await;
        let mut rate_limiters = self.rate_limiters.write().await;

        for feed in &config.feeds {
            if feed.enabled {
                let rate_limiter = RateLimiter {
                    requests_this_minute: 0,
                    requests_this_hour: 0,
                    last_minute_reset: Utc::now(),
                    last_hour_reset: Utc::now(),
                    current_backoff: 1.0,
                };
                rate_limiters.insert(feed.name.clone(), rate_limiter);
            }
        }
    }

    /// Check threat intelligence for indicators
    pub async fn check_indicators(
        &self,
        event: &SecurityEvent,
    ) -> Result<Vec<ThreatIntelligenceMatch>, Box<dyn std::error::Error + Send + Sync>> {
        let mut matches = Vec::new();

        // Extract indicators from the security event
        let indicators_to_check = self.extract_indicators_from_event(event);

        for (indicator_value, indicator_type) in indicators_to_check {
            // Check cache first
            if let Some(cached_match) = self.check_cache(&indicator_value, &indicator_type).await {
                matches.push(cached_match);
                THREAT_INTEL_CACHE_HITS.inc();
                continue;
            }

            // Check local indicators
            if let Some(local_match) = self
                .check_local_indicators(&indicator_value, &indicator_type, event)
                .await
            {
                matches.push(local_match.clone());
                self.cache_result(&indicator_value, &indicator_type, Some(local_match))
                    .await;
                continue;
            }

            // Queue for external API check
            let query = IntelligenceQuery {
                query_id: Uuid::new_v4().to_string(),
                indicator_value: indicator_value.clone(),
                indicator_type: indicator_type.clone(),
                context: Some(event.clone()),
                priority: self.determine_query_priority(event),
                response_channel: None,
            };

            if let Err(e) = self.query_queue.send(query) {
                error!("Failed to queue intelligence query: {}", e);
            }
        }

        THREAT_INTEL_QUERIES.inc_by(matches.len() as f64);
        if !matches.is_empty() {
            THREAT_INTEL_MATCHES.inc_by(matches.len() as f64);
        }

        Ok(matches)
    }

    /// Extract indicators from security event
    fn extract_indicators_from_event(&self, event: &SecurityEvent) -> Vec<(String, IndicatorType)> {
        let mut indicators = Vec::new();

        // IP address
        if let Some(ip) = event.ip_address {
            indicators.push((ip.to_string(), IndicatorType::IpAddress));
        }

        // User agent (partial matching for known malicious patterns)
        if let Some(user_agent) = &event.user_agent {
            indicators.push((user_agent.clone(), IndicatorType::UserAgent));
        }

        // Session ID (for session hijacking detection)
        if let Some(session_id) = &event.session_id {
            indicators.push((session_id.clone(), IndicatorType::SessionId));
        }

        // Device fingerprint
        if let Some(device_fp) = &event.device_fingerprint {
            indicators.push((device_fp.clone(), IndicatorType::DeviceFingerprint));
        }

        // Extract domains from user agent or referrer
        if let Some(user_agent) = &event.user_agent {
            if let Some(domain) = self.extract_domain_from_user_agent(user_agent) {
                indicators.push((domain, IndicatorType::Domain));
            }
        }

        indicators
    }

    /// Extract domain from user agent string
    fn extract_domain_from_user_agent(&self, user_agent: &str) -> Option<String> {
        // Simplified domain extraction - in production, use regex
        if user_agent.contains("http://") || user_agent.contains("https://") {
            // Extract domain using regex or url parsing
            // For now, return None
        }
        None
    }

    /// Check cache for indicator
    async fn check_cache(
        &self,
        indicator: &str,
        indicator_type: &IndicatorType,
    ) -> Option<ThreatIntelligenceMatch> {
        let cache = self.indicator_cache.read().await;
        let cache_key = format!("{}:{}", indicator_type_to_string(indicator_type), indicator);

        if let Some(cached_result) = cache.get(&cache_key) {
            let now = Utc::now();
            let age = now
                .signed_duration_since(cached_result.cached_at)
                .num_seconds() as u64;

            if age < cached_result.ttl_seconds {
                return cached_result.operation_result.clone();
            }
        }

        None
    }

    /// Check local indicators database
    async fn check_local_indicators(
        &self,
        indicator: &str,
        indicator_type: &IndicatorType,
        event: &SecurityEvent,
    ) -> Option<ThreatIntelligenceMatch> {
        let indicators = self.indicators.read().await;

        if let Some(intel_indicator) = indicators.get(indicator) {
            if intel_indicator.indicator_type == *indicator_type {
                let match_context = MatchContext {
                    event_context: Some(event.clone()),
                    related_indicators: Vec::new(),
                    campaign_associations: Vec::new(),
                    historical_matches: 1,
                    recent_activity: true,
                };

                let threat_match = ThreatIntelligenceMatch {
                    indicator: intel_indicator.clone(),
                    matched_value: indicator.to_string(),
                    match_type: MatchType::Exact,
                    confidence: intel_indicator.confidence,
                    risk_score: (intel_indicator.confidence * 100.0) as u8,
                    context: match_context,
                    recommended_actions: self
                        .get_recommended_actions(&intel_indicator.threat_types),
                };

                return Some(threat_match);
            }
        }

        None
    }

    /// Get recommended actions for threat types
    fn get_recommended_actions(&self, threat_types: &[ThreatType]) -> Vec<MitigationAction> {
        let mut actions = Vec::new();

        for threat_type in threat_types {
            match threat_type {
                ThreatType::MaliciousBot => {
                    actions.push(MitigationAction::BlockIp { duration_hours: 24 });
                    actions.push(MitigationAction::BanUserAgent);
                }
                ThreatType::CredentialStuffing => {
                    actions.push(MitigationAction::BlockIp { duration_hours: 12 });
                    actions.push(MitigationAction::IncreaseMonitoring);
                }
                ThreatType::DataExfiltration => {
                    actions.push(MitigationAction::BlockIp { duration_hours: 48 });
                    actions.push(MitigationAction::TriggerIncidentResponse);
                    actions.push(MitigationAction::NotifySecurityTeam);
                }
                _ => {
                    actions.push(MitigationAction::IncreaseMonitoring);
                }
            }
        }

        actions.push(MitigationAction::LogForensics);
        actions.dedup();
        actions
    }

    /// Cache query result
    async fn cache_result(
        &self,
        indicator: &str,
        indicator_type: &IndicatorType,
        result: Option<ThreatIntelligenceMatch>,
    ) {
        let mut cache = self.indicator_cache.write().await;
        let cache_key = format!("{}:{}", indicator_type_to_string(indicator_type), indicator);
        let config = self.config.read().await;

        let cached_result = CachedResult {
            result: result.clone(),
            cached_at: Utc::now(),
            ttl_seconds: config.cache_ttl_seconds,
            operation_result: result,
        };

        cache.insert(cache_key, cached_result);
    }

    /// Determine query priority based on event characteristics
    const fn determine_query_priority(&self, event: &SecurityEvent) -> QueryPriority {
        match event.severity {
            ViolationSeverity::Critical => QueryPriority::Critical,
            ViolationSeverity::High => QueryPriority::High,
            ViolationSeverity::Medium => QueryPriority::Normal,
            ViolationSeverity::Low => QueryPriority::Low,
        }
    }

    /// Start query processor background task
    async fn start_query_processor(&self) {
        let query_receiver = self.query_receiver.clone();
        let http_client = self.http_client.clone();
        let config = self.config.clone();
        let rate_limiters = self.rate_limiters.clone();
        let indicators = self.indicators.clone();
        let indicator_cache = self.indicator_cache.clone();
        let statistics = self.statistics.clone();

        tokio::spawn(async move {
            info!("Starting threat intelligence query processor");

            while let Ok(query) = query_receiver.recv_async().await {
                let start_time = SystemTime::now();

                // Process the query
                let result = Self::process_intelligence_query(
                    &query,
                    &http_client,
                    &config,
                    &rate_limiters,
                    &indicators,
                )
                .await;

                // Cache the result
                Self::cache_query_result(&query, result.clone(), &indicator_cache, &config).await;

                // Update statistics
                let mut stats = statistics.lock().await;
                stats.queries_total += 1;
                if result.is_some() {
                    stats.matches_total += 1;
                }

                if let Ok(duration) = start_time.elapsed() {
                    stats.average_response_time_ms =
                        (stats.average_response_time_ms + duration.as_millis() as u64) / 2;
                }

                // Send result if response channel provided
                if let (Some(result), Some(response_channel)) = (result, query.response_channel) {
                    let _ = response_channel.send(result);
                }
            }
        });
    }

    /// Process individual intelligence query
    async fn process_intelligence_query(
        query: &IntelligenceQuery,
        http_client: &Client,
        config: &Arc<RwLock<ThreatIntelligenceConfig>>,
        rate_limiters: &Arc<RwLock<HashMap<String, RateLimiter>>>,
        indicators: &Arc<RwLock<HashMap<String, ThreatIntelligenceIndicator>>>,
    ) -> Option<ThreatIntelligenceMatch> {
        let config_guard = config.read().await;

        for feed in &config_guard.feeds {
            if !feed.enabled || !feed.supported_indicators.contains(&query.indicator_type) {
                continue;
            }

            // Check rate limits
            if !Self::check_rate_limit(&feed.name, rate_limiters).await {
                continue;
            }

            // Query the feed
            match Self::query_feed(
                feed,
                &query.indicator_value,
                &query.indicator_type,
                http_client,
            )
            .await
            {
                Ok(Some(indicator)) => {
                    // Store the indicator
                    let mut indicators_guard = indicators.write().await;
                    indicators_guard.insert(indicator.indicator.clone(), indicator.clone());

                    // Create match result
                    let match_context = MatchContext {
                        event_context: query.context.clone(),
                        related_indicators: Vec::new(),
                        campaign_associations: Vec::new(),
                        historical_matches: 1,
                        recent_activity: true,
                    };

                    let threat_match = ThreatIntelligenceMatch {
                        indicator: indicator.clone(),
                        matched_value: query.indicator_value.clone(),
                        match_type: MatchType::Exact,
                        confidence: indicator.confidence,
                        risk_score: (indicator.confidence * 100.0) as u8,
                        context: match_context,
                        recommended_actions: Vec::new(), // Would be populated based on threat types
                    };

                    return Some(threat_match);
                }
                Ok(None) => continue,
                Err(e) => {
                    error!("Failed to query feed {}: {}", feed.name, e);
                    THREAT_INTEL_ERRORS.inc();
                    continue;
                }
            }
        }

        None
    }

    /// Check rate limit for feed
    async fn check_rate_limit(
        feed_name: &str,
        rate_limiters: &Arc<RwLock<HashMap<String, RateLimiter>>>,
    ) -> bool {
        let mut limiters = rate_limiters.write().await;
        if let Some(limiter) = limiters.get_mut(feed_name) {
            let now = Utc::now();

            // Reset counters if needed
            if now
                .signed_duration_since(limiter.last_minute_reset)
                .num_minutes()
                >= 1
            {
                limiter.requests_this_minute = 0;
                limiter.last_minute_reset = now;
            }

            if now
                .signed_duration_since(limiter.last_hour_reset)
                .num_hours()
                >= 1
            {
                limiter.requests_this_hour = 0;
                limiter.last_hour_reset = now;
            }

            // Check limits (simplified - would use actual rate limits from config)
            if limiter.requests_this_minute >= 60 || limiter.requests_this_hour >= 1000 {
                return false;
            }

            limiter.requests_this_minute += 1;
            limiter.requests_this_hour += 1;
            true
        } else {
            false
        }
    }

    /// Query external threat feed
    async fn query_feed(
        feed: &ThreatFeedConfig,
        indicator: &str,
        indicator_type: &IndicatorType,
        http_client: &Client,
    ) -> Result<Option<ThreatIntelligenceIndicator>, Box<dyn std::error::Error + Send + Sync>> {
        let timer = THREAT_INTEL_RESPONSE_TIME.start_timer();

        let result = match feed.feed_type {
            ThreatFeedType::AbuseIpdb => {
                Self::query_abuse_ipdb(feed, indicator, indicator_type, http_client).await
            }
            ThreatFeedType::VirusTotal => {
                Self::query_virustotal(feed, indicator, indicator_type, http_client).await
            }
            _ => {
                warn!("Unsupported feed type: {:?}", feed.feed_type);
                Ok(None)
            }
        };

        drop(timer);
        result
    }

    /// Query `AbuseIPDB` for IP reputation
    async fn query_abuse_ipdb(
        feed: &ThreatFeedConfig,
        indicator: &str,
        indicator_type: &IndicatorType,
        http_client: &Client,
    ) -> Result<Option<ThreatIntelligenceIndicator>, Box<dyn std::error::Error + Send + Sync>> {
        if *indicator_type != IndicatorType::IpAddress {
            return Ok(None);
        }

        let Some(api_key) = &feed.api_key else {
            return Ok(None);
        };

        let url = format!(
            "{}?ipAddress={}&maxAgeInDays=90&verbose",
            feed.api_url, indicator
        );

        let response = http_client
            .get(&url)
            .header("Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        if response.status().is_success() {
            let abuse_result: AbuseIpdbResponse = response.json().await?;

            if abuse_result.abuse_confidence_percentage > 0 {
                let threat_indicator = ThreatIntelligenceIndicator {
                    indicator: indicator.to_string(),
                    indicator_type: IndicatorType::IpAddress,
                    threat_types: vec![ThreatType::MaliciousBot], // Simplified
                    confidence: f64::from(abuse_result.abuse_confidence_percentage) / 100.0,
                    severity: if abuse_result.abuse_confidence_percentage > 75 {
                        ThreatSeverity::High
                    } else if abuse_result.abuse_confidence_percentage > 50 {
                        ThreatSeverity::Medium
                    } else {
                        ThreatSeverity::Low
                    },
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    source: "AbuseIPDB".to_string(),
                    feed_name: feed.name.clone(),
                    tags: abuse_result.usage_type.into_iter().collect(),
                    attributes: [
                        (
                            "country_code".to_string(),
                            serde_json::Value::String(
                                abuse_result.country_code.clone().unwrap_or_default(),
                            ),
                        ),
                        (
                            "isp".to_string(),
                            serde_json::Value::String(abuse_result.isp.unwrap_or_default()),
                        ),
                        (
                            "is_whitelisted".to_string(),
                            serde_json::Value::Bool(abuse_result.is_whitelisted),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                    false_positive_rate: 0.1,
                    reputation_score: f64::from(abuse_result.abuse_confidence_percentage) / 100.0,
                    malware_families: Vec::new(),
                    threat_actor_groups: Vec::new(),
                    geographic_regions: vec![abuse_result.country_code.unwrap_or_default()],
                    kill_chain_phases: vec![AttackPhase::InitialAccess],
                };

                return Ok(Some(threat_indicator));
            }
        }

        Ok(None)
    }

    /// Query `VirusTotal` for indicator information
    async fn query_virustotal(
        _feed: &ThreatFeedConfig,
        _indicator: &str,
        _indicator_type: &IndicatorType,
        _http_client: &Client,
    ) -> Result<Option<ThreatIntelligenceIndicator>, Box<dyn std::error::Error + Send + Sync>> {
        // Simplified VirusTotal implementation
        // Would need proper API implementation based on indicator type
        warn!("VirusTotal integration not fully implemented");
        Ok(None)
    }

    /// Cache query result
    async fn cache_query_result(
        query: &IntelligenceQuery,
        result: Option<ThreatIntelligenceMatch>,
        cache: &Arc<RwLock<HashMap<String, CachedResult>>>,
        config: &Arc<RwLock<ThreatIntelligenceConfig>>,
    ) {
        let cache_key = format!(
            "{}:{}",
            indicator_type_to_string(&query.indicator_type),
            query.indicator_value
        );
        let config_guard = config.read().await;

        let cached_result = CachedResult {
            result: result.clone(),
            cached_at: Utc::now(),
            ttl_seconds: config_guard.cache_ttl_seconds,
            operation_result: result,
        };

        let mut cache_guard = cache.write().await;
        cache_guard.insert(cache_key, cached_result);
    }

    /// Start feed synchronizer background task
    async fn start_feed_synchronizer(&self) {
        let config = self.config.clone();

        // Start background synchronization (simplified for now)
        info!("Threat feed synchronizer started");
        
        // Log configured feeds
        let config_guard = config.read().await;
        for feed in &config_guard.feeds {
            if feed.enabled {
                info!("Feed configured: {} ({})", feed.name, feed.url);
            }
        }
    }


    /// Start cache cleaner background task
    async fn start_cache_cleaner(&self) {
        let indicator_cache = self.indicator_cache.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(3600)); // 1 hour

            loop {
                interval.tick().await;

                let mut cache = indicator_cache.write().await;
                let now = Utc::now();

                cache.retain(|_, cached_result| {
                    let age = now
                        .signed_duration_since(cached_result.cached_at)
                        .num_seconds() as u64;
                    age < cached_result.ttl_seconds
                });

                debug!("Cache cleanup completed, {} entries remaining", cache.len());
            }
        });
    }

    /// Start statistics updater background task
    async fn start_statistics_updater(&self) {
        let statistics = self.statistics.clone();
        let indicators = self.indicators.clone();
        let feed_status = self.feed_status.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(60)); // 1 minute

            loop {
                interval.tick().await;

                let mut stats = statistics.lock().await;
                let indicators_count = indicators.read().await.len() as u64;
                let feeds_active = feed_status.read().await.len() as u32;

                stats.indicators_loaded = indicators_count;
                stats.feeds_active = feeds_active;

                // Update Prometheus metrics
                ACTIVE_INDICATORS.set(indicators_count as f64);
            }
        });
    }

    /// Get current statistics
    pub async fn get_statistics(&self) -> IntelligenceStatistics {
        let stats = self.statistics.lock().await;
        (*stats).clone()
    }

    /// Shutdown the correlator
    pub async fn shutdown(&self) {
        info!("Shutting down Threat Intelligence Correlator");

        // Close Redis connection
        let mut redis_client = self.redis_client.lock().await;
        *redis_client = None;

        info!("Threat Intelligence Correlator shutdown complete");
    }
}

/// `AbuseIPDB` API response structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct AbuseIpdbResponse {
    pub ip_address: String,
    pub is_public: bool,
    pub ip_version: u8,
    pub is_whitelisted: bool,
    pub abuse_confidence_percentage: u8,
    pub country_code: Option<String>,
    pub usage_type: Vec<String>,
    pub isp: Option<String>,
    pub domain: Option<String>,
    pub total_reports: u32,
    pub num_distinct_users: u32,
    pub last_reported_at: Option<String>,
}

/// Helper function to convert indicator type to string
const fn indicator_type_to_string(indicator_type: &IndicatorType) -> &'static str {
    match indicator_type {
        IndicatorType::IpAddress => "ip",
        IndicatorType::Domain => "domain",
        IndicatorType::Url => "url",
        IndicatorType::FileHash => "hash",
        IndicatorType::EmailAddress => "email",
        IndicatorType::UserAgent => "ua",
        IndicatorType::JwtToken => "jwt",
        IndicatorType::SessionId => "session",
        IndicatorType::DeviceFingerprint => "device",
        IndicatorType::BehaviorPattern => "behavior",
        IndicatorType::NetworkPattern => "network",
        IndicatorType::TimePattern => "time",
        IndicatorType::Other => "other",
    }
}

#[allow(dead_code)]
impl ThreatIntelligenceCorrelator {
    /// Synchronize a threat feed by downloading and processing indicators
    async fn synchronize_threat_feed(
        &self,
        feed: &ThreatFeedConfig,
    ) -> Result<FeedSyncResult, AuthError> {
        let start_time = std::time::Instant::now();
        let mut sync_result = FeedSyncResult::default();

        info!("Starting synchronization for feed: {}", feed.name);

        // Download feed data
        let feed_data = match self.download_feed_data(feed).await {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to download feed {}: {}", feed.name, e);
                return Err(AuthError::ExternalService(format!(
                    "Feed download failed: {e}"
                )));
            }
        };

        // Parse indicators from feed data
        let new_indicators = match self.parse_feed_indicators(&feed_data, &feed.format).await {
            Ok(indicators) => indicators,
            Err(e) => {
                error!("Failed to parse feed {}: {}", feed.name, e);
                return Err(AuthError::ExternalService(format!(
                    "Feed parsing failed: {e}"
                )));
            }
        };

        // Get existing indicators for this feed
        let existing_indicators = self.get_feed_indicators(&feed.name).await?;

        // Process new indicators
        for indicator in new_indicators {
            match self
                .process_feed_indicator(&indicator, &feed.name, &existing_indicators)
                .await
            {
                Ok(ProcessResult::Added) => sync_result.added += 1,
                Ok(ProcessResult::Updated) => sync_result.updated += 1,
                Ok(ProcessResult::Skipped) => sync_result.skipped += 1,
                Err(e) => {
                    error!("Failed to process indicator {}: {}", indicator.value, e);
                    sync_result.errors += 1;
                }
            }
        }

        // Remove indicators that are no longer in the feed
        let removed = self
            .cleanup_stale_indicators(&feed.name, &existing_indicators)
            .await?;
        sync_result.removed = removed;

        sync_result.total_indicators =
            sync_result.added + sync_result.updated + sync_result.skipped;
        sync_result.duration_ms = start_time.elapsed().as_millis() as u64;

        info!(
            "Feed synchronization completed: {} in {}ms - Added: {}, Updated: {}, Removed: {}, Skipped: {}, Errors: {}",
            feed.name, sync_result.duration_ms, sync_result.added, sync_result.updated,
            sync_result.removed, sync_result.skipped, sync_result.errors
        );

        Ok(sync_result)
    }

    async fn download_feed_data(&self, feed: &ThreatFeedConfig) -> Result<String, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("ThreatIntelligence/1.0")
            .build()?;

        let mut request = client.get(&feed.url);

        // Add authentication if required
        if let Some(ref api_key) = feed.api_key {
            request = request.header("Authorization", format!("Bearer {api_key}"));
        }

        let response = request.send().await?.text().await?;
        Ok(response)
    }

    async fn parse_feed_indicators(
        &self,
        data: &str,
        format: &str,
    ) -> Result<Vec<ThreatIndicator>, AuthError> {
        let mut indicators = Vec::new();

        match format.to_lowercase().as_str() {
            "json" => {
                // Parse JSON format feed
                let json_data: serde_json::Value = serde_json::from_str(data)
                    .map_err(|e| AuthError::ExternalService(format!("JSON parse error: {e}")))?;

                if let Some(array) = json_data.as_array() {
                    for item in array {
                        if let Some(indicator) = self.parse_json_indicator(item)? {
                            indicators.push(indicator);
                        }
                    }
                }
            }
            "csv" => {
                // Parse CSV format feed
                for line in data.lines().skip(1) {
                    // Skip header
                    let fields: Vec<&str> = line.split(',').collect();
                    if fields.len() >= 2 {
                        let indicator = ThreatIndicator {
                            id: uuid::Uuid::new_v4().to_string(),
                            indicator_type: self.detect_indicator_type(fields[0]),
                            value: fields[0].to_string(),
                            confidence: fields.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.5),
                            severity: ThreatSeverity::Medium, // Default
                            source: (*fields.get(1).unwrap_or(&"unknown")).to_string(),
                            description: fields.get(3).map(|s| (*s).to_string()),
                            created_at: Utc::now(),
                            updated_at: Utc::now(),
                            expires_at: None,
                            metadata: std::collections::HashMap::new(),
                            first_seen: Utc::now(),
                            last_seen: Utc::now(),
                            tags: std::collections::HashSet::new(),
                        };
                        indicators.push(indicator);
                    }
                }
            }
            "text" => {
                // Parse plain text format (one indicator per line)
                for line in data.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        let indicator = ThreatIndicator {
                            id: uuid::Uuid::new_v4().to_string(),
                            indicator_type: self.detect_indicator_type(line),
                            value: line.to_string(),
                            confidence: 0.7,
                            severity: ThreatSeverity::Medium,
                            source: "feed".to_string(),
                            description: None,
                            created_at: Utc::now(),
                            updated_at: Utc::now(),
                            expires_at: None,
                            metadata: std::collections::HashMap::new(),
                            first_seen: Utc::now(),
                            last_seen: Utc::now(),
                            tags: std::collections::HashSet::new(),
                        };
                        indicators.push(indicator);
                    }
                }
            }
            _ => {
                return Err(AuthError::ExternalService(format!(
                    "Unsupported feed format: {format}"
                )));
            }
        }

        Ok(indicators)
    }

    fn parse_json_indicator(
        &self,
        item: &serde_json::Value,
    ) -> Result<Option<ThreatIndicator>, AuthError> {
        let value = match item.get("indicator").or_else(|| item.get("value")) {
            Some(v) => v.as_str().unwrap_or_default().to_string(),
            None => return Ok(None),
        };

        if value.is_empty() {
            return Ok(None);
        }

        let indicator = ThreatIndicator {
            id: uuid::Uuid::new_v4().to_string(),
            indicator_type: self.detect_indicator_type(&value),
            value,
            confidence: item
                .get("confidence")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.5),
            severity: self.parse_severity(item.get("severity")),
            source: item
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            description: item
                .get("description")
                .and_then(|v| v.as_str())
                .map(std::string::ToString::to_string),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: item
                .get("expires_at")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            metadata: std::collections::HashMap::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            tags: std::collections::HashSet::new(),
        };

        Ok(Some(indicator))
    }

    fn detect_indicator_type(&self, value: &str) -> IndicatorType {
        // IP address detection
        if value.parse::<std::net::IpAddr>().is_ok() {
            return IndicatorType::IpAddress;
        }

        // Domain detection
        if value.contains('.') && !value.contains('/') && !value.contains('@') {
            return IndicatorType::Domain;
        }

        // URL detection
        if value.starts_with("http://") || value.starts_with("https://") {
            return IndicatorType::Url;
        }

        // Email detection
        if value.contains('@') && value.contains('.') {
            return IndicatorType::EmailAddress;
        }

        // Hash detection (common lengths)
        match value.len() {
            32 => IndicatorType::FileHash, // MD5
            40 => IndicatorType::FileHash, // SHA1
            64 => IndicatorType::FileHash, // SHA256
            _ => IndicatorType::Other,
        }
    }

    fn parse_severity(&self, severity_value: Option<&serde_json::Value>) -> ThreatSeverity {
        match severity_value.and_then(|v| v.as_str()) {
            Some("low") => ThreatSeverity::Low,
            Some("medium") => ThreatSeverity::Medium,
            Some("high") => ThreatSeverity::High,
            Some("critical") => ThreatSeverity::Critical,
            _ => ThreatSeverity::Medium,
        }
    }

    async fn get_feed_indicators(
        &self,
        _feed_name: &str,
    ) -> Result<std::collections::HashSet<String>, AuthError> {
        // In a real implementation, this would query the database
        // For now, return an empty set
        Ok(std::collections::HashSet::new())
    }

    async fn process_feed_indicator(
        &self,
        indicator: &ThreatIndicator,
        _feed_name: &str,
        existing: &std::collections::HashSet<String>,
    ) -> Result<ProcessResult, AuthError> {
        if existing.contains(&indicator.value) {
            // Update existing indicator
            Ok(ProcessResult::Updated)
        } else {
            // Add new indicator
            Ok(ProcessResult::Added)
        }
    }

    async fn cleanup_stale_indicators(
        &self,
        _feed_name: &str,
        _existing: &std::collections::HashSet<String>,
    ) -> Result<u32, AuthError> {
        // In a real implementation, this would remove indicators not in the current feed
        Ok(0)
    }
}

#[cfg(feature = "threat-hunting")]
#[async_trait::async_trait]
impl ThreatDetectionAdapter for ThreatIntelligenceCorrelator {
    async fn process_security_event(&self, event: &SecurityEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Use check_indicators directly with the security event
        self.check_indicators(event).await
            .map(|_| ()) // Discard the result
    }
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct FeedSyncResult {
    added: u32,
    updated: u32,
    removed: u32,
    skipped: u32,
    errors: u32,
    total_indicators: u32,
    duration_ms: u64,
}

#[allow(dead_code)]
enum ProcessResult {
    Added,
    Updated,
    Skipped,
}

