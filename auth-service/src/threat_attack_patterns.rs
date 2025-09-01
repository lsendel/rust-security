use crate::core::security::{SecurityEvent, SecurityEventType, ViolationSeverity};
use crate::threat_types::{
    AttackPattern, AttackPatternType, AttackPhase, BusinessImpact, EventOutcome, MitigationAction,
    ThreatSeverity, TimingConstraint, TimingConstraintType,
};
use chrono::{DateTime, Duration, Utc};
use petgraph::{graph::NodeIndex, Directed, Graph};
#[cfg(feature = "monitoring")]
use prometheus::{register_counter, register_gauge, register_histogram, Counter, Gauge, Histogram};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{debug, info};
use uuid::Uuid;

#[cfg(feature = "monitoring")]
lazy_static::lazy_static! {
    static ref ATTACK_PATTERNS_DETECTED: Counter = register_counter!(
        "threat_hunting_attack_patterns_detected_total",
        "Total attack patterns detected"
    ).unwrap();

    static ref GRAPH_ANALYSIS_DURATION: Histogram = register_histogram!(
        "threat_hunting_graph_analysis_duration_seconds",
        "Duration of graph analysis operations"
    ).unwrap();

    static ref ACTIVE_ATTACK_SEQUENCES: Gauge = register_gauge!(
        "threat_hunting_active_attack_sequences",
        "Number of active attack sequences being tracked"
    ).unwrap();

    static ref PATTERN_CORRELATION_MATCHES: Counter = register_counter!(
        "threat_hunting_pattern_correlations_total",
        "Total pattern correlations found"
    ).unwrap();
}

/// Configuration for attack pattern detection
#[derive(Debug, Clone)]
pub struct AttackPatternConfig {
    pub enabled: bool,
    pub max_graph_nodes: usize,
    pub max_sequence_length: usize,
    pub pattern_timeout_hours: u64,
    pub correlation_window_minutes: u64,
    pub min_confidence_threshold: f64,
    pub graph_analysis_interval_seconds: u64,
    pub sequence_detection_rules: Vec<SequenceDetectionRule>,
    pub behavioral_clustering_config: BehavioralClusteringConfig,
    pub temporal_analysis_config: TemporalAnalysisConfig,
}

/// Rules for detecting attack sequences
#[derive(Debug, Clone)]
pub struct SequenceDetectionRule {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub pattern_type: AttackPatternType,
    pub event_sequence: Vec<SequenceEventMatcher>,
    pub timing_constraints: Vec<TimingConstraint>,
    pub confidence_weight: f64,
    pub severity_modifier: f64,
    pub required_entities: EntityRequirements,
}

/// Matcher for events in a sequence
#[derive(Debug, Clone)]
pub struct SequenceEventMatcher {
    pub event_types: Vec<SecurityEventType>,
    pub outcome_filter: Option<EventOutcome>,
    pub severity_filter: Option<ThreatSeverity>,
    pub custom_filters: HashMap<String, serde_json::Value>,
    pub optional: bool,
    pub max_occurrences: Option<u32>,
}

/// Requirements for entities in patterns
#[derive(Debug, Clone)]
pub struct EntityRequirements {
    pub same_user: bool,
    pub same_ip: bool,
    pub same_session: bool,
    pub same_device: bool,
    pub ip_proximity: Option<f64>, // CIDR proximity
    pub geo_proximity_km: Option<f64>,
}

/// Configuration for behavioral clustering
#[derive(Debug, Clone)]
pub struct BehavioralClusteringConfig {
    pub enabled: bool,
    pub cluster_radius: f64,
    pub min_cluster_size: usize,
    pub max_clusters: usize,
    pub feature_weights: HashMap<String, f64>,
    pub outlier_threshold: f64,
}

/// Configuration for temporal analysis
#[derive(Debug, Clone)]
pub struct TemporalAnalysisConfig {
    pub enabled: bool,
    pub window_size_minutes: u64,
    pub overlap_percentage: f64,
    pub trend_analysis_enabled: bool,
    pub periodicity_detection_enabled: bool,
    pub burst_detection_threshold: f64,
}

/// Node in the attack graph representing an entity or event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraphNode {
    pub node_id: String,
    pub node_type: AttackNodeType,
    pub entity_id: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub event_count: u32,
    pub risk_score: f64,
    pub attributes: HashMap<String, serde_json::Value>,
    pub metadata: AttackNodeMetadata,
}

/// Types of nodes in attack graph
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AttackNodeType {
    User,
    IpAddress,
    Device,
    Session,
    Resource,
    Event,
    ThreatActor,
    Campaign,
}

/// Metadata for attack graph nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackNodeMetadata {
    pub labels: HashSet<String>,
    pub confidence: f64,
    pub threat_indicators: Vec<String>,
    pub related_campaigns: Vec<String>,
    pub kill_chain_phases: Vec<AttackPhase>,
}

/// Edge in the attack graph representing relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraphEdge {
    pub edge_id: String,
    pub edge_type: AttackEdgeType,
    pub weight: f64,
    pub confidence: f64,
    pub first_observed: DateTime<Utc>,
    pub last_observed: DateTime<Utc>,
    pub observation_count: u32,
    pub temporal_pattern: TemporalPattern,
    pub attributes: HashMap<String, serde_json::Value>,
}

/// Types of edges in attack graph
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttackEdgeType {
    SameEntity,
    TemporalSequence,
    GeographicProximity,
    BehavioralSimilarity,
    NetworkConnection,
    ThreatIntelligence,
    CampaignAssociation,
    KillChainProgression,
}

/// Temporal patterns for edges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalPattern {
    pub pattern_type: TemporalPatternType,
    pub interval_seconds: Option<u64>,
    pub periodicity: Option<f64>,
    pub trend_direction: TrendDirection,
    pub volatility: f64,
}

/// Types of temporal patterns
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TemporalPatternType {
    Sequential,
    Periodic,
    Burst,
    Gradual,
    Random,
    Seasonal,
}

/// Trend directions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrendDirection {
    Increasing,
    Decreasing,
    Stable,
    Oscillating,
    Unknown,
}

/// Detected attack sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedAttackSequence {
    pub sequence_id: String,
    pub pattern_id: String,
    pub attack_pattern: AttackPattern,
    pub matched_events: Vec<SecurityEvent>,
    pub confidence: f64,
    pub completeness: f64, // How complete the pattern is (0.0 to 1.0)
    pub risk_score: u8,
    pub first_event: DateTime<Utc>,
    pub last_event: DateTime<Utc>,
    pub duration_minutes: i64,
    pub affected_entities: HashMap<AttackNodeType, HashSet<String>>,
    pub kill_chain_coverage: Vec<AttackPhase>,
    pub prediction: AttackPrediction,
}

/// Prediction for attack sequence evolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPrediction {
    pub next_likely_phases: Vec<AttackPhase>,
    pub probability_scores: HashMap<AttackPhase, f64>,
    pub estimated_completion_time: Option<DateTime<Utc>>,
    pub recommended_monitoring: Vec<String>,
    pub risk_escalation_factors: Vec<String>,
}

/// Cluster of related attack behaviors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackCluster {
    pub cluster_id: String,
    pub cluster_type: ClusterType,
    pub events: Vec<SecurityEvent>,
    pub centroid: Vec<f64>,
    pub radius: f64,
    pub density: f64,
    pub outlier_score: f64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub characteristics: ClusterCharacteristics,
}

/// Types of attack clusters
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClusterType {
    BehavioralAnomaly,
    CoordinatedAttack,
    CampaignActivity,
    BotnetActivity,
    InsiderThreat,
    Unknown,
}

/// Characteristics of attack clusters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterCharacteristics {
    pub dominant_event_types: Vec<SecurityEventType>,
    pub geographic_distribution: Vec<String>,
    pub temporal_distribution: TemporalDistribution,
    pub entity_overlap: EntityOverlapMetrics,
    pub threat_indicators: Vec<String>,
}

/// Temporal distribution of cluster events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalDistribution {
    pub peak_hours: Vec<u8>,
    pub peak_days: Vec<u8>,
    pub burst_patterns: Vec<BurstPattern>,
    pub periodicity_score: f64,
}

/// Burst pattern in temporal analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstPattern {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub intensity: f64,
    pub event_count: u32,
    pub trigger_indicators: Vec<String>,
}

/// Entity overlap metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityOverlapMetrics {
    pub user_overlap_ratio: f64,
    pub ip_overlap_ratio: f64,
    pub device_overlap_ratio: f64,
    pub session_overlap_ratio: f64,
    pub unique_entities_count: HashMap<AttackNodeType, usize>,
}

/// Attack pattern detector with graph analysis
pub struct AttackPatternDetector {
    config: Arc<RwLock<AttackPatternConfig>>,

    // Attack graph
    attack_graph: Arc<Mutex<Graph<AttackGraphNode, AttackGraphEdge, Directed>>>,
    node_indices: Arc<RwLock<HashMap<String, NodeIndex>>>,

    // Pattern detection
    active_sequences: Arc<RwLock<HashMap<String, DetectedAttackSequence>>>,
    detection_rules: Arc<RwLock<HashMap<String, SequenceDetectionRule>>>,

    // Clustering and analysis
    behavioral_clusters: Arc<RwLock<HashMap<String, AttackCluster>>>,
    temporal_windows: Arc<RwLock<VecDeque<TemporalWindow>>>,

    // Event processing
    event_buffer: Arc<Mutex<VecDeque<SecurityEvent>>>,
    #[allow(dead_code)]
    correlation_cache: Arc<RwLock<HashMap<String, CorrelationResult>>>,

    // Statistics
    detection_statistics: Arc<Mutex<DetectionStatistics>>,
}

/// Temporal window for analysis
#[derive(Debug, Clone)]
pub struct TemporalWindow {
    pub window_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub events: Vec<SecurityEvent>,
    pub analysis_complete: bool,
    pub detected_patterns: Vec<String>,
}

/// Correlation result cache entry
#[derive(Debug, Clone)]
pub struct CorrelationResult {
    pub correlation_id: String,
    pub entities: Vec<String>,
    pub correlation_strength: f64,
    pub correlation_type: CorrelationType,
    pub cached_at: DateTime<Utc>,
    pub ttl_seconds: u64,
}

/// Types of correlations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelationType {
    Temporal,
    Spatial,
    Behavioral,
    Network,
    ThreatIntelligence,
}

/// Detection statistics
#[derive(Debug, Default, Clone)]
pub struct DetectionStatistics {
    pub patterns_detected: u64,
    pub sequences_analyzed: u64,
    pub graph_nodes: usize,
    pub graph_edges: usize,
    pub clusters_identified: u64,
    pub correlations_found: u64,
    pub processing_time_ms: u64,
}

impl Default for AttackPatternConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_graph_nodes: 10000,
            max_sequence_length: 20,
            pattern_timeout_hours: 24,
            correlation_window_minutes: 60,
            min_confidence_threshold: 0.6,
            graph_analysis_interval_seconds: 300,
            sequence_detection_rules: Self::default_rules(),
            behavioral_clustering_config: BehavioralClusteringConfig::default(),
            temporal_analysis_config: TemporalAnalysisConfig::default(),
        }
    }
}

impl AttackPatternConfig {
    fn default_rules() -> Vec<SequenceDetectionRule> {
        vec![
            SequenceDetectionRule {
                rule_id: "credential_stuffing_sequence".to_string(),
                name: "Credential Stuffing Attack Sequence".to_string(),
                description: "Detects patterns consistent with credential stuffing attacks"
                    .to_string(),
                enabled: true,
                pattern_type: AttackPatternType::Sequential,
                event_sequence: vec![
                    SequenceEventMatcher {
                        event_types: vec![SecurityEventType::AuthenticationFailure],
                        outcome_filter: Some(EventOutcome::Failure),
                        severity_filter: None,
                        custom_filters: HashMap::new(),
                        optional: false,
                        max_occurrences: None,
                    },
                    SequenceEventMatcher {
                        event_types: vec![SecurityEventType::AuthenticationSuccess],
                        outcome_filter: Some(EventOutcome::Success),
                        severity_filter: None,
                        custom_filters: HashMap::new(),
                        optional: true,
                        max_occurrences: Some(1),
                    },
                ],
                timing_constraints: vec![TimingConstraint {
                    constraint_type: TimingConstraintType::MaxInterval,
                    min_duration_seconds: None,
                    max_duration_seconds: Some(300), // 5 minutes
                    frequency_threshold: Some(0.5),
                }],
                confidence_weight: 0.8,
                severity_modifier: 1.2,
                required_entities: EntityRequirements {
                    same_user: false,
                    same_ip: true,
                    same_session: false,
                    same_device: false,
                    ip_proximity: None,
                    geo_proximity_km: None,
                },
            },
            SequenceDetectionRule {
                rule_id: "account_takeover_sequence".to_string(),
                name: "Account Takeover Sequence".to_string(),
                description: "Detects multi-stage account takeover attempts".to_string(),
                enabled: true,
                pattern_type: AttackPatternType::MultiStage,
                event_sequence: vec![
                    SequenceEventMatcher {
                        event_types: vec![SecurityEventType::AuthenticationFailure],
                        outcome_filter: Some(EventOutcome::Failure),
                        severity_filter: None,
                        custom_filters: HashMap::new(),
                        optional: false,
                        max_occurrences: Some(5),
                    },
                    SequenceEventMatcher {
                        event_types: vec![SecurityEventType::AuthenticationSuccess],
                        outcome_filter: Some(EventOutcome::Success),
                        severity_filter: None,
                        custom_filters: HashMap::new(),
                        optional: false,
                        max_occurrences: Some(1),
                    },
                    SequenceEventMatcher {
                        event_types: vec![
                            SecurityEventType::PasswordChange,
                            SecurityEventType::MfaChallenge,
                        ],
                        outcome_filter: None,
                        severity_filter: None,
                        custom_filters: HashMap::new(),
                        optional: true,
                        max_occurrences: Some(3),
                    },
                ],
                timing_constraints: vec![TimingConstraint {
                    constraint_type: TimingConstraintType::MaxInterval,
                    min_duration_seconds: None,
                    max_duration_seconds: Some(3600), // 1 hour
                    frequency_threshold: None,
                }],
                confidence_weight: 0.9,
                severity_modifier: 1.5,
                required_entities: EntityRequirements {
                    same_user: true,
                    same_ip: false,
                    same_session: false,
                    same_device: false,
                    ip_proximity: None,
                    geo_proximity_km: Some(1000.0),
                },
            },
        ]
    }
}

impl Default for BehavioralClusteringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cluster_radius: 2.0,
            min_cluster_size: 3,
            max_clusters: 50,
            feature_weights: [
                ("temporal".to_string(), 0.3),
                ("spatial".to_string(), 0.2),
                ("behavioral".to_string(), 0.5),
            ]
            .into_iter()
            .collect(),
            outlier_threshold: 2.5,
        }
    }
}

impl Default for TemporalAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_size_minutes: 15,
            overlap_percentage: 0.5,
            trend_analysis_enabled: true,
            periodicity_detection_enabled: true,
            burst_detection_threshold: 3.0,
        }
    }
}

impl AttackPatternDetector {
    /// Create a new attack pattern detector
    #[must_use]
    pub fn new(config: AttackPatternConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            attack_graph: Arc::new(Mutex::new(Graph::new())),
            node_indices: Arc::new(RwLock::new(HashMap::new())),
            active_sequences: Arc::new(RwLock::new(HashMap::new())),
            detection_rules: Arc::new(RwLock::new(HashMap::new())),
            behavioral_clusters: Arc::new(RwLock::new(HashMap::new())),
            temporal_windows: Arc::new(RwLock::new(VecDeque::new())),
            event_buffer: Arc::new(Mutex::new(VecDeque::new())),
            correlation_cache: Arc::new(RwLock::new(HashMap::new())),
            detection_statistics: Arc::new(Mutex::new(DetectionStatistics::default())),
        }
    }

    /// Initialize the attack pattern detector
    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing Attack Pattern Detector");

        // Load detection rules
        self.load_detection_rules().await?;

        // Start background analysis tasks
        self.start_graph_analyzer().await;
        self.start_sequence_detector().await;
        self.start_behavioral_clustering().await;
        self.start_temporal_analyzer().await;

        info!("Attack Pattern Detector initialized successfully");
        Ok(())
    }

    /// Load detection rules into the system
    async fn load_detection_rules(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = self.config.read().await;
        let mut rules = self.detection_rules.write().await;

        for rule in &config.sequence_detection_rules {
            rules.insert(rule.rule_id.clone(), rule.clone());
        }

        info!("Loaded {} attack detection rules", rules.len());
        Ok(())
    }

    /// Process a security event for attack pattern detection
    pub async fn process_event(
        &self,
        event: SecurityEvent,
    ) -> Result<Vec<DetectedAttackSequence>, Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(feature = "monitoring")]
        let timer = GRAPH_ANALYSIS_DURATION.start_timer();
        #[cfg(not(feature = "monitoring"))]
        let timer = || {}; // No-op timer when monitoring is disabled
        let mut detected_sequences = Vec::new();

        // Add event to buffer
        {
            let mut buffer = self.event_buffer.lock().await;
            let config = self.config.read().await;

            buffer.push_back(event.clone());
            if buffer.len() > config.max_graph_nodes {
                buffer.pop_front();
            }
        }

        // Update attack graph
        self.update_attack_graph(&event).await?;

        // Check for immediate pattern matches
        detected_sequences.extend(self.detect_immediate_patterns(&event).await?);

        // Update temporal windows
        self.update_temporal_windows(&event).await;

        // Update statistics
        let mut stats = self.detection_statistics.lock().await;
        stats.sequences_analyzed += 1;
        stats.patterns_detected += detected_sequences.len() as u64;

        #[cfg(feature = "monitoring")]
        drop(timer);
        Ok(detected_sequences)
    }

    /// Update the attack graph with a new event
    async fn update_attack_graph(
        &self,
        event: &SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut graph = self.attack_graph.lock().await;
        let mut node_indices = self.node_indices.write().await;

        // Create or update nodes for entities in the event
        let mut event_nodes = Vec::new();

        // User node
        if let Some(user_id) = &event.user_id {
            let node_id = format!("user:{user_id}");
            let node_index = self.get_or_create_node(
                &mut graph,
                &mut node_indices,
                &node_id,
                AttackNodeType::User,
                user_id,
                event.timestamp,
            );
            event_nodes.push((node_index, AttackNodeType::User));
        }

        // IP address node
        if let Some(ip) = event.ip_address {
            let node_id = format!("ip:{ip}");
            let node_index = self.get_or_create_node(
                &mut graph,
                &mut node_indices,
                &node_id,
                AttackNodeType::IpAddress,
                &ip.to_string(),
                event.timestamp,
            );
            event_nodes.push((node_index, AttackNodeType::IpAddress));
        }

        // Device node
        if let Some(device) = &event.device_fingerprint {
            let node_id = format!("device:{device}");
            let node_index = self.get_or_create_node(
                &mut graph,
                &mut node_indices,
                &node_id,
                AttackNodeType::Device,
                device,
                event.timestamp,
            );
            event_nodes.push((node_index, AttackNodeType::Device));
        }

        // Session node
        if let Some(session) = &event.session_id {
            let node_id = format!("session:{session}");
            let node_index = self.get_or_create_node(
                &mut graph,
                &mut node_indices,
                &node_id,
                AttackNodeType::Session,
                session,
                event.timestamp,
            );
            event_nodes.push((node_index, AttackNodeType::Session));
        }

        // Create edges between related nodes
        for i in 0..event_nodes.len() {
            for j in (i + 1)..event_nodes.len() {
                let (node1, type1) = &event_nodes[i];
                let (node2, type2) = &event_nodes[j];

                let edge_type = self.determine_edge_type(type1, type2);
                let edge = AttackGraphEdge {
                    edge_id: Uuid::new_v4().to_string(),
                    edge_type,
                    weight: 1.0,
                    confidence: 0.8,
                    first_observed: event.timestamp,
                    last_observed: event.timestamp,
                    observation_count: 1,
                    temporal_pattern: TemporalPattern {
                        pattern_type: TemporalPatternType::Sequential,
                        interval_seconds: None,
                        periodicity: None,
                        trend_direction: TrendDirection::Unknown,
                        volatility: 0.0,
                    },
                    attributes: HashMap::new(),
                };

                graph.add_edge(*node1, *node2, edge);
            }
        }

        // Update statistics
        let mut stats = self.detection_statistics.lock().await;
        stats.graph_nodes = graph.node_count();
        stats.graph_edges = graph.edge_count();

        Ok(())
    }

    /// Get or create a node in the attack graph
    fn get_or_create_node(
        &self,
        graph: &mut Graph<AttackGraphNode, AttackGraphEdge, Directed>,
        node_indices: &mut HashMap<String, NodeIndex>,
        node_id: &str,
        node_type: AttackNodeType,
        entity_id: &str,
        timestamp: DateTime<Utc>,
    ) -> NodeIndex {
        if let Some(&existing_index) = node_indices.get(node_id) {
            // Update existing node
            if let Some(node) = graph.node_weight_mut(existing_index) {
                node.last_seen = timestamp;
                node.event_count += 1;
            }
            existing_index
        } else {
            // Create new node
            let node = AttackGraphNode {
                node_id: node_id.to_string(),
                node_type,
                entity_id: entity_id.to_string(),
                first_seen: timestamp,
                last_seen: timestamp,
                event_count: 1,
                risk_score: 0.0,
                attributes: HashMap::new(),
                metadata: AttackNodeMetadata {
                    labels: HashSet::new(),
                    confidence: 1.0,
                    threat_indicators: Vec::new(),
                    related_campaigns: Vec::new(),
                    kill_chain_phases: Vec::new(),
                },
            };

            let index = graph.add_node(node);
            node_indices.insert(node_id.to_string(), index);
            index
        }
    }

    /// Determine edge type between two node types
    const fn determine_edge_type(
        &self,
        type1: &AttackNodeType,
        type2: &AttackNodeType,
    ) -> AttackEdgeType {
        match (type1, type2) {
            (AttackNodeType::User, AttackNodeType::IpAddress) => AttackEdgeType::NetworkConnection,
            (AttackNodeType::User, AttackNodeType::Device) => AttackEdgeType::SameEntity,
            (AttackNodeType::User, AttackNodeType::Session) => AttackEdgeType::SameEntity,
            (AttackNodeType::IpAddress, AttackNodeType::Device) => {
                AttackEdgeType::NetworkConnection
            }
            (AttackNodeType::Device, AttackNodeType::Session) => AttackEdgeType::SameEntity,
            _ => AttackEdgeType::TemporalSequence,
        }
    }

    /// Detect immediate patterns in the current event
    async fn detect_immediate_patterns(
        &self,
        event: &SecurityEvent,
    ) -> Result<Vec<DetectedAttackSequence>, Box<dyn std::error::Error + Send + Sync>> {
        let mut detected_sequences = Vec::new();
        let rules = self.detection_rules.read().await;
        let buffer = self.event_buffer.lock().await;

        for rule in rules.values() {
            if !rule.enabled {
                continue;
            }

            if let Some(sequence) = self.check_rule_match(rule, event, &buffer).await {
                detected_sequences.push(sequence);
                #[cfg(feature = "monitoring")]
                ATTACK_PATTERNS_DETECTED.inc();
            }
        }

        Ok(detected_sequences)
    }

    /// Check if a rule matches the current event sequence
    async fn check_rule_match(
        &self,
        rule: &SequenceDetectionRule,
        current_event: &SecurityEvent,
        event_buffer: &VecDeque<SecurityEvent>,
    ) -> Option<DetectedAttackSequence> {
        let config = self.config.read().await;
        let time_window = Duration::minutes(config.correlation_window_minutes as i64);
        let cutoff_time = current_event.timestamp - time_window;

        // Get relevant events within time window
        let relevant_events: Vec<_> = event_buffer
            .iter()
            .filter(|e| e.timestamp > cutoff_time)
            .cloned()
            .collect();

        // Check if the event sequence matches the rule
        let matched_events = self.match_event_sequence(rule, &relevant_events, current_event)?;

        // Verify entity requirements
        if !self.check_entity_requirements(&rule.required_entities, &matched_events) {
            return None;
        }

        // Verify timing constraints
        if !self.check_timing_constraints(&rule.timing_constraints, &matched_events) {
            return None;
        }

        // Calculate confidence and completeness
        let confidence =
            rule.confidence_weight * self.calculate_sequence_confidence(&matched_events);
        if confidence < config.min_confidence_threshold {
            return None;
        }

        let completeness = matched_events.len() as f64 / rule.event_sequence.len() as f64;

        // Create attack pattern
        let attack_pattern = AttackPattern {
            pattern_id: rule.rule_id.clone(),
            pattern_name: rule.name.clone(),
            description: rule.description.clone(),
            pattern_type: rule.pattern_type.clone(),
            complexity_score: (matched_events.len() * 10) as u8,
            detection_confidence: confidence,
            first_observed: matched_events.first()?.timestamp,
            last_observed: matched_events.last()?.timestamp,
            event_sequence: matched_events
                .iter()
                .map(|e| e.event_type.clone().into())
                .collect(),
            timing_constraints: rule.timing_constraints.clone(),
            entity_relationships: Vec::new(), // Would be populated with actual relationships
            statistical_signatures: Vec::new(), // Would be populated with statistical analysis
            potential_impact: BusinessImpact::Medium,
            recommended_responses: vec![
                MitigationAction::IncreaseMonitoring,
                MitigationAction::NotifySecurityTeam,
            ],
            false_positive_rate: 0.1,
            related_patterns: Vec::new(),
        };

        // Create detected sequence
        let sequence = DetectedAttackSequence {
            sequence_id: Uuid::new_v4().to_string(),
            pattern_id: rule.rule_id.clone(),
            attack_pattern,
            matched_events: matched_events.clone(),
            confidence,
            completeness,
            risk_score: (confidence * 100.0 * rule.severity_modifier) as u8,
            first_event: matched_events.first()?.timestamp,
            last_event: matched_events.last()?.timestamp,
            duration_minutes: matched_events
                .last()?
                .timestamp
                .signed_duration_since(matched_events.first()?.timestamp)
                .num_minutes(),
            affected_entities: self.extract_affected_entities(&matched_events),
            kill_chain_coverage: self.analyze_kill_chain_coverage(&matched_events),
            prediction: self.generate_attack_prediction(&matched_events, rule),
        };

        Some(sequence)
    }

    /// Match event sequence against rule pattern
    fn match_event_sequence(
        &self,
        rule: &SequenceDetectionRule,
        events: &[SecurityEvent],
        current_event: &SecurityEvent,
    ) -> Option<Vec<SecurityEvent>> {
        let mut matched_events = Vec::new();
        let mut event_iter = events.iter().chain(std::iter::once(current_event));

        for matcher in &rule.event_sequence {
            let mut found = false;
            let mut match_count = 0;

            for event in event_iter.by_ref() {
                if self.event_matches_criteria(event, matcher) {
                    matched_events.push(event.clone());
                    found = true;
                    match_count += 1;

                    if let Some(max_occ) = matcher.max_occurrences {
                        if match_count >= max_occ {
                            break;
                        }
                    } else {
                        break; // Single match by default
                    }
                }
            }

            if !found && !matcher.optional {
                return None; // Required event not found
            }
        }

        if matched_events.is_empty() {
            None
        } else {
            Some(matched_events)
        }
    }

    /// Check if event matches criteria
    fn event_matches_criteria(
        &self,
        event: &SecurityEvent,
        matcher: &SequenceEventMatcher,
    ) -> bool {
        // Check event type
        if !matcher.event_types.contains(&event.event_type) {
            return false;
        }

        // Check outcome filter
        if let Some(required_outcome) = &matcher.outcome_filter {
            let outcome_str = match required_outcome {
                EventOutcome::Success => "success",
                EventOutcome::Failure => "failure",
                EventOutcome::Blocked => "blocked",
                EventOutcome::Suspicious => "suspicious",
                EventOutcome::Timeout => "timeout",
                EventOutcome::Error => "error",
            };
            if event.outcome.as_deref() != Some(outcome_str) {
                return false;
            }
        }

        // Check severity filter
        if let Some(required_severity) = &matcher.severity_filter {
            let event_threat_severity = match event.severity {
                ViolationSeverity::Low => ThreatSeverity::Low,
                ViolationSeverity::Medium => ThreatSeverity::Medium,
                ViolationSeverity::High => ThreatSeverity::High,
                ViolationSeverity::Critical => ThreatSeverity::Critical,
            };
            if &event_threat_severity != required_severity {
                return false;
            }
        }

        // Check custom filters
        for (key, expected_value) in &matcher.custom_filters {
            if let Some(actual_value) = event.details.get(key) {
                if actual_value != expected_value {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }

    /// Check entity requirements for matched events
    fn check_entity_requirements(
        &self,
        requirements: &EntityRequirements,
        events: &[SecurityEvent],
    ) -> bool {
        if events.len() < 2 {
            return true; // No requirements to check for single event
        }

        for i in 1..events.len() {
            let prev_event = &events[i - 1];
            let curr_event = &events[i];

            if requirements.same_user
                && (prev_event.user_id != curr_event.user_id || prev_event.user_id.is_none())
            {
                return false;
            }

            if requirements.same_ip
                && (prev_event.ip_address != curr_event.ip_address
                    || prev_event.ip_address.is_none())
            {
                return false;
            }

            if requirements.same_session
                && (prev_event.session_id != curr_event.session_id
                    || prev_event.session_id.is_none())
            {
                return false;
            }

            if requirements.same_device
                && (prev_event.device_fingerprint != curr_event.device_fingerprint
                    || prev_event.device_fingerprint.is_none())
            {
                return false;
            }

            // TODO: Implement IP proximity and geo proximity checks
        }

        true
    }

    /// Check timing constraints for matched events
    fn check_timing_constraints(
        &self,
        constraints: &[TimingConstraint],
        events: &[SecurityEvent],
    ) -> bool {
        if events.len() < 2 {
            return true;
        }

        for constraint in constraints {
            match constraint.constraint_type {
                TimingConstraintType::MaxInterval => {
                    if let Some(max_duration) = constraint.max_duration_seconds {
                        let total_duration = events
                            .last()
                            .unwrap()
                            .timestamp
                            .signed_duration_since(events.first().unwrap().timestamp)
                            .num_seconds() as u64;

                        if total_duration > max_duration {
                            return false;
                        }
                    }
                }
                TimingConstraintType::MinInterval => {
                    if let Some(min_duration) = constraint.min_duration_seconds {
                        let total_duration = events
                            .last()
                            .unwrap()
                            .timestamp
                            .signed_duration_since(events.first().unwrap().timestamp)
                            .num_seconds() as u64;

                        if total_duration < min_duration {
                            return false;
                        }
                    }
                }
                TimingConstraintType::Frequency => {
                    if let Some(threshold) = constraint.frequency_threshold {
                        let duration = events
                            .last()
                            .unwrap()
                            .timestamp
                            .signed_duration_since(events.first().unwrap().timestamp)
                            .num_seconds() as f64;

                        let frequency = events.len() as f64 / (duration / 60.0); // events per minute

                        if frequency < threshold {
                            return false;
                        }
                    }
                }
                _ => {} // Other constraint types not implemented yet
            }
        }

        true
    }

    /// Calculate confidence score for event sequence
    fn calculate_sequence_confidence(&self, events: &[SecurityEvent]) -> f64 {
        if events.is_empty() {
            return 0.0;
        }

        // Simplified confidence calculation
        let mut confidence = 0.8; // Base confidence

        // Increase confidence for suspicious events
        let suspicious_count = events.iter().filter(|e| e.is_security_failure()).count();
        confidence += (suspicious_count as f64 / events.len() as f64) * 0.2;

        // Decrease confidence for very short sequences
        if events.len() < 3 {
            confidence *= 0.8;
        }

        confidence.min(1.0)
    }

    /// Extract affected entities from events
    fn extract_affected_entities(
        &self,
        events: &[SecurityEvent],
    ) -> HashMap<AttackNodeType, HashSet<String>> {
        let mut entities = HashMap::new();

        for event in events {
            if let Some(user_id) = &event.user_id {
                entities
                    .entry(AttackNodeType::User)
                    .or_insert_with(HashSet::new)
                    .insert(user_id.clone());
            }

            if let Some(ip) = event.ip_address {
                entities
                    .entry(AttackNodeType::IpAddress)
                    .or_insert_with(HashSet::new)
                    .insert(ip.to_string());
            }

            if let Some(device) = &event.device_fingerprint {
                entities
                    .entry(AttackNodeType::Device)
                    .or_insert_with(HashSet::new)
                    .insert(device.clone());
            }

            if let Some(session) = &event.session_id {
                entities
                    .entry(AttackNodeType::Session)
                    .or_insert_with(HashSet::new)
                    .insert(session.clone());
            }
        }

        entities
    }

    /// Analyze kill chain coverage
    fn analyze_kill_chain_coverage(&self, events: &[SecurityEvent]) -> Vec<AttackPhase> {
        let mut phases = Vec::new();

        // Map event types to kill chain phases
        for event in events {
            let phase = match event.event_type {
                SecurityEventType::AuthenticationFailure => AttackPhase::CredentialAccess,
                SecurityEventType::AuthenticationSuccess => AttackPhase::InitialAccess,
                SecurityEventType::MfaFailure => AttackPhase::DefenseEvasion,
                SecurityEventType::DataAccess => AttackPhase::Collection,
                SecurityEventType::PasswordChange => AttackPhase::Persistence,
                _ => AttackPhase::Discovery,
            };

            if !phases.contains(&phase) {
                phases.push(phase);
            }
        }

        phases
    }

    /// Generate attack prediction
    fn generate_attack_prediction(
        &self,
        events: &[SecurityEvent],
        _rule: &SequenceDetectionRule,
    ) -> AttackPrediction {
        // Simplified prediction logic
        let mut next_phases = Vec::new();
        let mut probability_scores = HashMap::new();

        // Predict next likely phases based on current coverage
        let current_phases = self.analyze_kill_chain_coverage(events);

        if !current_phases.contains(&AttackPhase::Persistence) {
            next_phases.push(AttackPhase::Persistence);
            probability_scores.insert(AttackPhase::Persistence, 0.7);
        }

        if !current_phases.contains(&AttackPhase::Collection) {
            next_phases.push(AttackPhase::Collection);
            probability_scores.insert(AttackPhase::Collection, 0.6);
        }

        AttackPrediction {
            next_likely_phases: next_phases,
            probability_scores,
            estimated_completion_time: Some(Utc::now() + Duration::hours(2)),
            recommended_monitoring: vec![
                "Monitor for data access patterns".to_string(),
                "Watch for privilege escalation attempts".to_string(),
            ],
            risk_escalation_factors: vec![
                "Multiple authentication failures".to_string(),
                "Geographic anomalies detected".to_string(),
            ],
        }
    }

    /// Update temporal windows with new event
    async fn update_temporal_windows(&self, event: &SecurityEvent) {
        let config = self.config.read().await;
        let window_size =
            Duration::minutes(config.temporal_analysis_config.window_size_minutes as i64);

        let mut windows = self.temporal_windows.write().await;

        // Create new window if needed
        if windows.is_empty()
            || event
                .timestamp
                .signed_duration_since(windows.back().unwrap().end_time)
                > window_size
        {
            let new_window = TemporalWindow {
                window_id: Uuid::new_v4().to_string(),
                start_time: event.timestamp,
                end_time: event.timestamp + window_size,
                events: vec![event.clone()],
                analysis_complete: false,
                detected_patterns: Vec::new(),
            };

            windows.push_back(new_window);
        } else {
            // Add to existing window
            if let Some(current_window) = windows.back_mut() {
                if event.timestamp <= current_window.end_time {
                    current_window.events.push(event.clone());
                }
            }
        }

        // Keep only recent windows
        let cutoff_time = event.timestamp - Duration::hours(24);
        windows.retain(|w| w.end_time > cutoff_time);
    }

    /// Start graph analyzer background task
    async fn start_graph_analyzer(&self) {
        let attack_graph = self.attack_graph.clone();
        let config = self.config.clone();
        let _active_sequences = self.active_sequences.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(300)); // 5 minutes

            loop {
                interval.tick().await;

                let graph = attack_graph.lock().await;
                let _config_guard = config.read().await;

                if graph.node_count() > 0 {
                    // Perform graph analysis
                    // TODO: Implement sophisticated graph algorithms
                    // - Community detection
                    // - Centrality analysis
                    // - Path analysis
                    // - Anomaly detection in graph structure

                    debug!(
                        "Graph analysis completed: {} nodes, {} edges",
                        graph.node_count(),
                        graph.edge_count()
                    );
                }
            }
        });
    }

    /// Start sequence detector background task
    async fn start_sequence_detector(&self) {
        let active_sequences = self.active_sequences.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(60)); // 1 minute

            loop {
                interval.tick().await;

                let mut sequences = active_sequences.write().await;
                let config_guard = config.read().await;
                let cutoff_time =
                    Utc::now() - Duration::hours(config_guard.pattern_timeout_hours as i64);

                // Remove expired sequences
                sequences.retain(|_, sequence| sequence.last_event > cutoff_time);

                #[cfg(feature = "monitoring")]
                ACTIVE_ATTACK_SEQUENCES.set(sequences.len() as f64);
            }
        });
    }

    /// Start behavioral clustering background task
    async fn start_behavioral_clustering(&self) {
        let _behavioral_clusters = self.behavioral_clusters.clone();
        let event_buffer = self.event_buffer.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(900)); // 15 minutes

            loop {
                interval.tick().await;

                let buffer = event_buffer.lock().await;
                let config_guard = config.read().await;

                if buffer.len() > config_guard.behavioral_clustering_config.min_cluster_size {
                    // TODO: Implement clustering algorithm
                    // - Feature extraction from events
                    // - DBSCAN or similar clustering
                    // - Cluster analysis and characterization

                    debug!("Behavioral clustering analysis completed");
                }
            }
        });
    }

    /// Start temporal analyzer background task
    async fn start_temporal_analyzer(&self) {
        let temporal_windows = self.temporal_windows.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(60)); // 1 minute

            loop {
                interval.tick().await;

                let mut windows = temporal_windows.write().await;
                let _config_guard = config.read().await;

                // Analyze completed windows
                for window in windows.iter_mut() {
                    if !window.analysis_complete && Utc::now() > window.end_time {
                        // TODO: Implement temporal analysis
                        // - Burst detection
                        // - Periodicity analysis
                        // - Trend analysis

                        window.analysis_complete = true;
                        debug!(
                            "Temporal analysis completed for window {}",
                            window.window_id
                        );
                    }
                }
            }
        });
    }

    /// Get currently active attack sequences
    pub async fn get_active_sequences(&self) -> Vec<DetectedAttackSequence> {
        let sequences = self.active_sequences.read().await;
        sequences.values().cloned().collect()
    }

    /// Get detection statistics
    pub async fn get_statistics(&self) -> DetectionStatistics {
        let stats = self.detection_statistics.lock().await;
        (*stats).clone()
    }

    /// Shutdown the detector
    pub fn shutdown(&self) {
        info!("Shutting down Attack Pattern Detector");

        // Save important state
        // Clean up resources

        info!("Attack Pattern Detector shutdown complete");
    }
}
