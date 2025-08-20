//! Advanced Persistent Threat (APT) Detection Engine
//! Sophisticated detection system for identifying complex, multi-stage attacks

use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;
use prometheus::{register_counter_vec, register_gauge_vec, register_histogram_vec, CounterVec, GaugeVec, HistogramVec};

// Metrics
static APT_DETECTIONS: once_cell::sync::Lazy<CounterVec> = once_cell::sync::Lazy::new(|| {
    register_counter_vec!(
        "apt_detections_total",
        "Total APT detections",
        &["apt_group", "confidence_level", "stage"]
    ).unwrap()
});

static ACTIVE_CAMPAIGNS: once_cell::sync::Lazy<GaugeVec> = once_cell::sync::Lazy::new(|| {
    register_gauge_vec!(
        "apt_active_campaigns",
        "Number of active APT campaigns",
        &["severity"]
    ).unwrap()
});

static BEHAVIOR_ANALYSIS_TIME: once_cell::sync::Lazy<HistogramVec> = once_cell::sync::Lazy::new(|| {
    register_histogram_vec!(
        "apt_behavior_analysis_seconds",
        "Time taken for APT behavior analysis",
        &["analysis_type"]
    ).unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum APTStage {
    Reconnaissance,
    InitialAccess,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APTSignature {
    pub id: Uuid,
    pub name: String,
    pub apt_group: String,
    pub description: String,
    pub stage: APTStage,
    pub ttps: Vec<String>, // MITRE ATT&CK TTPs
    pub indicators: Vec<IOC>,
    pub behavior_patterns: Vec<BehaviorPattern>,
    pub confidence_threshold: f64,
    pub created_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IOC {
    pub ioc_type: IOCType,
    pub value: String,
    pub description: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IOCType {
    FileHash,
    IPAddress,
    Domain,
    URL,
    Registry,
    Mutex,
    Certificate,
    UserAgent,
    ProcessName,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorPattern {
    pub pattern_type: BehaviorType,
    pub description: String,
    pub indicators: Vec<String>,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BehaviorType {
    NetworkTraffic,
    ProcessExecution,
    FileSystemActivity,
    RegistryActivity,
    MemoryPatterns,
    TimeBasedPatterns,
    CommunicationPatterns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APTCampaign {
    pub id: Uuid,
    pub campaign_name: String,
    pub apt_group: String,
    pub description: String,
    pub severity: ConfidenceLevel,
    pub first_detected: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub affected_assets: HashSet<String>,
    pub detected_stages: HashSet<APTStage>,
    pub indicators_matched: Vec<IOC>,
    pub behavior_score: f64,
    pub timeline: Vec<APTEvent>,
    pub attribution_confidence: f64,
    pub impact_assessment: ImpactAssessment,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APTEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub description: String,
    pub source: String,
    pub stage: APTStage,
    pub confidence: f64,
    pub artifacts: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAssessment {
    pub data_at_risk: DataRiskLevel,
    pub systems_compromised: u32,
    pub business_impact: BusinessImpact,
    pub estimated_dwell_time_days: u32,
    pub potential_data_loss_gb: f64,
    pub compliance_implications: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BusinessImpact {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    pub apt_group: String,
    pub aliases: Vec<String>,
    pub origin_country: Option<String>,
    pub targets: Vec<String>,
    pub motivations: Vec<String>,
    pub capabilities: Vec<String>,
    pub infrastructure: ThreatInfrastructure,
    pub tools_used: Vec<String>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfrastructure {
    pub c2_domains: Vec<String>,
    pub c2_ips: Vec<String>,
    pub email_domains: Vec<String>,
    pub hosting_providers: Vec<String>,
    pub ssl_certificates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorAnalysis {
    pub entity: String, // Host, user, or IP
    pub time_window: TimeWindow,
    pub baseline: BehaviorBaseline,
    pub current_behavior: BehaviorMetrics,
    pub anomaly_score: f64,
    pub behavioral_indicators: Vec<BehaviorIndicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub duration_hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorBaseline {
    pub network_connections_per_hour: f64,
    pub processes_spawned_per_hour: f64,
    pub files_accessed_per_hour: f64,
    pub registry_modifications_per_hour: f64,
    pub typical_connection_destinations: HashSet<String>,
    pub typical_processes: HashSet<String>,
    pub activity_time_patterns: Vec<u8>, // 24-hour pattern
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorMetrics {
    pub network_connections_per_hour: f64,
    pub processes_spawned_per_hour: f64,
    pub files_accessed_per_hour: f64,
    pub registry_modifications_per_hour: f64,
    pub new_connection_destinations: HashSet<String>,
    pub new_processes: HashSet<String>,
    pub off_hours_activity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorIndicator {
    pub indicator_type: String,
    pub description: String,
    pub severity: f64,
    pub evidence: Vec<String>,
}

pub struct APTDetectionEngine {
    signatures: Arc<DashMap<Uuid, APTSignature>>,
    campaigns: Arc<DashMap<Uuid, APTCampaign>>,
    threat_intel: Arc<DashMap<String, ThreatIntelligence>>,
    behavior_baselines: Arc<DashMap<String, BehaviorBaseline>>,
    correlation_engine: Arc<CorrelationEngine>,
    ml_engine: Arc<MLEngine>,
}

pub struct CorrelationEngine {
    correlation_window_hours: u32,
    minimum_events_for_campaign: u32,
    stage_progression_weights: HashMap<APTStage, f64>,
}

pub struct MLEngine {
    models: HashMap<String, MLModel>,
    feature_extractors: Vec<FeatureExtractor>,
}

#[derive(Debug, Clone)]
pub struct MLModel {
    pub model_type: String,
    pub accuracy: f64,
    pub last_trained: DateTime<Utc>,
    pub feature_count: u32,
}

#[derive(Debug, Clone)]
pub struct FeatureExtractor {
    pub name: String,
    pub feature_type: String,
    pub weight: f64,
}

impl APTDetectionEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            signatures: Arc::new(DashMap::new()),
            campaigns: Arc::new(DashMap::new()),
            threat_intel: Arc::new(DashMap::new()),
            behavior_baselines: Arc::new(DashMap::new()),
            correlation_engine: Arc::new(CorrelationEngine::new()),
            ml_engine: Arc::new(MLEngine::new()),
        };

        // Load default APT signatures
        engine.load_default_signatures();
        engine
    }

    fn load_default_signatures(&self) {
        // APT1 (Comment Crew) signature
        let apt1_signature = APTSignature {
            id: Uuid::new_v4(),
            name: "APT1 Comment Crew Detection".to_string(),
            apt_group: "APT1".to_string(),
            description: "Detection patterns for APT1 (Comment Crew) activities".to_string(),
            stage: APTStage::LateralMovement,
            ttps: vec![
                "T1021.001".to_string(), // Remote Desktop Protocol
                "T1059.003".to_string(), // Windows Command Shell
                "T1083".to_string(),     // File and Directory Discovery
            ],
            indicators: vec![
                IOC {
                    ioc_type: IOCType::Domain,
                    value: "*.aptsimulator.com".to_string(),
                    description: "Known APT1 C2 domain pattern".to_string(),
                    confidence: 0.9,
                },
                IOC {
                    ioc_type: IOCType::ProcessName,
                    value: "rundll32.exe".to_string(),
                    description: "Suspicious rundll32 usage".to_string(),
                    confidence: 0.7,
                },
            ],
            behavior_patterns: vec![
                BehaviorPattern {
                    pattern_type: BehaviorType::NetworkTraffic,
                    description: "Regular beaconing to external domains".to_string(),
                    indicators: vec!["periodic_connections".to_string(), "small_payload_sizes".to_string()],
                    weight: 0.8,
                },
            ],
            confidence_threshold: 0.75,
            created_at: Utc::now(),
            last_updated: Utc::now(),
        };

        self.signatures.insert(apt1_signature.id, apt1_signature);

        // Lazarus Group signature
        let lazarus_signature = APTSignature {
            id: Uuid::new_v4(),
            name: "Lazarus Group Detection".to_string(),
            apt_group: "Lazarus".to_string(),
            description: "Detection patterns for Lazarus Group activities".to_string(),
            stage: APTStage::InitialAccess,
            ttps: vec![
                "T1566.001".to_string(), // Spearphishing Attachment
                "T1055".to_string(),     // Process Injection
                "T1027".to_string(),     // Obfuscated Files or Information
            ],
            indicators: vec![
                IOC {
                    ioc_type: IOCType::FileHash,
                    value: "a1b2c3d4e5f6".to_string(),
                    description: "Known Lazarus malware hash".to_string(),
                    confidence: 0.95,
                },
                IOC {
                    ioc_type: IOCType::Registry,
                    value: "HKLM\\Software\\Classes\\CLSID\\{*}\\InProcServer32".to_string(),
                    description: "Registry persistence mechanism".to_string(),
                    confidence: 0.8,
                },
            ],
            behavior_patterns: vec![
                BehaviorPattern {
                    pattern_type: BehaviorType::ProcessExecution,
                    description: "Process injection techniques".to_string(),
                    indicators: vec!["dll_injection".to_string(), "process_hollowing".to_string()],
                    weight: 0.9,
                },
            ],
            confidence_threshold: 0.8,
            created_at: Utc::now(),
            last_updated: Utc::now(),
        };

        self.signatures.insert(lazarus_signature.id, lazarus_signature);

        info!("Loaded {} default APT signatures", self.signatures.len());
    }

    pub async fn analyze_event(&self, event_data: HashMap<String, String>) -> Result<Option<APTCampaign>> {
        let _timer = BEHAVIOR_ANALYSIS_TIME
            .with_label_values(&["event_analysis"])
            .start_timer();

        info!("Analyzing event for APT indicators");

        // Extract key fields from event
        let source_ip = event_data.get("source_ip").cloned();
        let destination_ip = event_data.get("destination_ip").cloned();
        let process_name = event_data.get("process_name").cloned();
        let file_hash = event_data.get("file_hash").cloned();

        // Check against IOC signatures
        for signature_entry in self.signatures.iter() {
            let signature = signature_entry.value();
            let mut matched_indicators = Vec::new();
            let mut confidence_score = 0.0;

            // Check IOCs
            for ioc in &signature.indicators {
                if self.matches_ioc(&ioc, &event_data) {
                    matched_indicators.push(ioc.clone());
                    confidence_score += ioc.confidence;
                }
            }

            // Check behavior patterns
            let behavior_score = self.evaluate_behavior_patterns(&signature.behavior_patterns, &event_data).await;
            confidence_score += behavior_score;

            // Normalize confidence score
            confidence_score = confidence_score.min(1.0);

            if confidence_score >= signature.confidence_threshold {
                // High confidence match - create or update campaign
                let campaign = self.create_or_update_campaign(
                    signature,
                    matched_indicators,
                    confidence_score,
                    event_data.clone(),
                ).await?;

                // Update metrics
                APT_DETECTIONS
                    .with_label_values(&[
                        &signature.apt_group,
                        &self.confidence_to_string(confidence_score),
                        &format!("{:?}", signature.stage),
                    ])
                    .inc();

                return Ok(Some(campaign));
            }
        }

        // Perform behavioral analysis for unknown patterns
        self.perform_behavioral_analysis(&event_data).await?;

        Ok(None)
    }

    fn matches_ioc(&self, ioc: &IOC, event_data: &HashMap<String, String>) -> bool {
        match ioc.ioc_type {
            IOCType::FileHash => {
                if let Some(hash) = event_data.get("file_hash") {
                    hash == &ioc.value
                } else {
                    false
                }
            }
            IOCType::IPAddress => {
                event_data.get("source_ip") == Some(&ioc.value) ||
                event_data.get("destination_ip") == Some(&ioc.value)
            }
            IOCType::Domain => {
                if let Some(domain) = event_data.get("domain") {
                    if ioc.value.starts_with('*') {
                        domain.ends_with(&ioc.value[1..])
                    } else {
                        domain == &ioc.value
                    }
                } else {
                    false
                }
            }
            IOCType::ProcessName => {
                if let Some(process) = event_data.get("process_name") {
                    process == &ioc.value
                } else {
                    false
                }
            }
            IOCType::Registry => {
                if let Some(registry) = event_data.get("registry_key") {
                    registry.contains(&ioc.value) || ioc.value.contains('*')
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    async fn evaluate_behavior_patterns(&self, patterns: &[BehaviorPattern], event_data: &HashMap<String, String>) -> f64 {
        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        for pattern in patterns {
            let mut pattern_matches = 0;
            let total_indicators = pattern.indicators.len();

            for indicator in &pattern.indicators {
                if self.event_matches_behavior_indicator(indicator, event_data) {
                    pattern_matches += 1;
                }
            }

            if pattern_matches > 0 {
                let pattern_score = (pattern_matches as f64 / total_indicators as f64) * pattern.weight;
                total_score += pattern_score;
                total_weight += pattern.weight;
            }
        }

        if total_weight > 0.0 {
            total_score / total_weight
        } else {
            0.0
        }
    }

    fn event_matches_behavior_indicator(&self, indicator: &str, event_data: &HashMap<String, String>) -> bool {
        match indicator {
            "periodic_connections" => {
                // Check if this looks like periodic beaconing
                event_data.get("connection_pattern").map_or(false, |p| p == "periodic")
            }
            "small_payload_sizes" => {
                event_data.get("payload_size").and_then(|s| s.parse::<u32>().ok()).map_or(false, |size| size < 1024)
            }
            "dll_injection" => {
                event_data.get("technique").map_or(false, |t| t.contains("injection"))
            }
            "process_hollowing" => {
                event_data.get("technique").map_or(false, |t| t.contains("hollowing"))
            }
            _ => false,
        }
    }

    async fn create_or_update_campaign(
        &self,
        signature: &APTSignature,
        matched_indicators: Vec<IOC>,
        confidence_score: f64,
        event_data: HashMap<String, String>,
    ) -> Result<APTCampaign> {
        // Check if campaign already exists for this APT group
        let existing_campaign = self.campaigns.iter()
            .find(|entry| entry.value().apt_group == signature.apt_group)
            .map(|entry| (entry.key().clone(), entry.value().clone()));

        let campaign_id = if let Some((id, mut campaign)) = existing_campaign {
            // Update existing campaign
            campaign.last_activity = Utc::now();
            campaign.detected_stages.insert(signature.stage.clone());
            campaign.indicators_matched.extend(matched_indicators);
            campaign.behavior_score = (campaign.behavior_score + confidence_score) / 2.0;

            // Add affected asset
            if let Some(asset) = event_data.get("hostname") {
                campaign.affected_assets.insert(asset.clone());
            }

            // Add timeline event
            campaign.timeline.push(APTEvent {
                timestamp: Utc::now(),
                event_type: "Signature Match".to_string(),
                description: format!("Matched signature: {}", signature.name),
                source: event_data.get("source").unwrap_or(&"Unknown".to_string()).clone(),
                stage: signature.stage.clone(),
                confidence: confidence_score,
                artifacts: event_data.clone(),
            });

            self.campaigns.insert(id, campaign.clone());
            id
        } else {
            // Create new campaign
            let campaign_id = Uuid::new_v4();
            let mut affected_assets = HashSet::new();
            if let Some(asset) = event_data.get("hostname") {
                affected_assets.insert(asset.clone());
            }

            let mut detected_stages = HashSet::new();
            detected_stages.insert(signature.stage.clone());

            let campaign = APTCampaign {
                id: campaign_id,
                campaign_name: format!("{} Campaign {}", signature.apt_group, Utc::now().format("%Y%m%d")),
                apt_group: signature.apt_group.clone(),
                description: format!("Detected {} activity", signature.apt_group),
                severity: self.score_to_confidence_level(confidence_score),
                first_detected: Utc::now(),
                last_activity: Utc::now(),
                affected_assets,
                detected_stages,
                indicators_matched: matched_indicators,
                behavior_score: confidence_score,
                timeline: vec![APTEvent {
                    timestamp: Utc::now(),
                    event_type: "Campaign Created".to_string(),
                    description: format!("Campaign created from signature: {}", signature.name),
                    source: event_data.get("source").unwrap_or(&"Unknown".to_string()).clone(),
                    stage: signature.stage.clone(),
                    confidence: confidence_score,
                    artifacts: event_data,
                }],
                attribution_confidence: confidence_score,
                impact_assessment: self.assess_impact(&signature.apt_group, 1).await,
                recommendations: self.generate_recommendations(&signature.apt_group, &signature.stage).await,
            };

            self.campaigns.insert(campaign_id, campaign.clone());

            // Update metrics
            ACTIVE_CAMPAIGNS
                .with_label_values(&[&format!("{:?}", campaign.severity)])
                .inc();

            campaign_id
        };

        let campaign = self.campaigns.get(&campaign_id).unwrap().clone();
        
        warn!(
            campaign_id = %campaign_id,
            apt_group = %signature.apt_group,
            confidence = %confidence_score,
            "APT campaign detected or updated"
        );

        Ok(campaign)
    }

    async fn perform_behavioral_analysis(&self, event_data: &HashMap<String, String>) -> Result<()> {
        // Extract entity (host/user/IP) for behavioral analysis
        let entity = event_data.get("hostname")
            .or_else(|| event_data.get("username"))
            .or_else(|| event_data.get("source_ip"))
            .cloned();

        if let Some(entity) = entity {
            // Get or create baseline
            let baseline = self.get_or_create_baseline(&entity).await;
            
            // Analyze current behavior against baseline
            let analysis = self.analyze_behavior_deviation(&entity, &baseline, event_data).await?;
            
            if analysis.anomaly_score > 0.7 {
                info!(
                    entity = %entity,
                    anomaly_score = %analysis.anomaly_score,
                    "High behavioral anomaly detected"
                );
                
                // Could trigger further investigation or create a low-confidence campaign
            }
        }

        Ok(())
    }

    async fn get_or_create_baseline(&self, entity: &str) -> BehaviorBaseline {
        if let Some(baseline) = self.behavior_baselines.get(entity) {
            baseline.clone()
        } else {
            // Create default baseline
            let baseline = BehaviorBaseline {
                network_connections_per_hour: 10.0,
                processes_spawned_per_hour: 5.0,
                files_accessed_per_hour: 50.0,
                registry_modifications_per_hour: 2.0,
                typical_connection_destinations: HashSet::new(),
                typical_processes: HashSet::new(),
                activity_time_patterns: vec![0; 24],
            };
            
            self.behavior_baselines.insert(entity.to_string(), baseline.clone());
            baseline
        }
    }

    async fn analyze_behavior_deviation(
        &self,
        entity: &str,
        baseline: &BehaviorBaseline,
        event_data: &HashMap<String, String>
    ) -> Result<BehaviorAnalysis> {
        // Simplified behavioral analysis
        let current_metrics = BehaviorMetrics {
            network_connections_per_hour: 15.0, // Would be calculated from actual data
            processes_spawned_per_hour: 8.0,
            files_accessed_per_hour: 75.0,
            registry_modifications_per_hour: 5.0,
            new_connection_destinations: HashSet::new(),
            new_processes: HashSet::new(),
            off_hours_activity: Utc::now().hour() < 6 || Utc::now().hour() > 22,
        };

        // Calculate anomaly score
        let mut anomaly_score = 0.0;
        
        // Network connections deviation
        let net_deviation = (current_metrics.network_connections_per_hour - baseline.network_connections_per_hour).abs() 
            / baseline.network_connections_per_hour.max(1.0);
        anomaly_score += net_deviation * 0.3;

        // Process spawning deviation
        let proc_deviation = (current_metrics.processes_spawned_per_hour - baseline.processes_spawned_per_hour).abs()
            / baseline.processes_spawned_per_hour.max(1.0);
        anomaly_score += proc_deviation * 0.3;

        // Off-hours activity
        if current_metrics.off_hours_activity {
            anomaly_score += 0.4;
        }

        anomaly_score = anomaly_score.min(1.0);

        Ok(BehaviorAnalysis {
            entity: entity.to_string(),
            time_window: TimeWindow {
                start: Utc::now() - chrono::Duration::hours(1),
                end: Utc::now(),
                duration_hours: 1,
            },
            baseline: baseline.clone(),
            current_behavior: current_metrics,
            anomaly_score,
            behavioral_indicators: vec![],
        })
    }

    async fn assess_impact(&self, apt_group: &str, systems_compromised: u32) -> ImpactAssessment {
        // Assess impact based on APT group capabilities and systems compromised
        let (data_risk, business_impact) = match apt_group {
            "APT1" | "Lazarus" => (DataRiskLevel::High, BusinessImpact::High),
            "APT28" | "APT29" => (DataRiskLevel::Critical, BusinessImpact::Critical),
            _ => (DataRiskLevel::Medium, BusinessImpact::Medium),
        };

        ImpactAssessment {
            data_at_risk: data_risk,
            systems_compromised,
            business_impact,
            estimated_dwell_time_days: 30, // Default estimate
            potential_data_loss_gb: systems_compromised as f64 * 100.0, // Rough estimate
            compliance_implications: vec![
                "GDPR notification required".to_string(),
                "SOX controls review needed".to_string(),
            ],
        }
    }

    async fn generate_recommendations(&self, apt_group: &str, stage: &APTStage) -> Vec<String> {
        let mut recommendations = Vec::new();

        recommendations.push("Immediately isolate affected systems".to_string());
        recommendations.push("Reset all potentially compromised credentials".to_string());
        recommendations.push("Deploy additional monitoring on network perimeter".to_string());

        match stage {
            APTStage::InitialAccess => {
                recommendations.push("Review email security controls".to_string());
                recommendations.push("Update endpoint protection signatures".to_string());
            }
            APTStage::Persistence => {
                recommendations.push("Audit startup programs and scheduled tasks".to_string());
                recommendations.push("Review service configurations".to_string());
            }
            APTStage::LateralMovement => {
                recommendations.push("Implement network segmentation".to_string());
                recommendations.push("Review privileged account usage".to_string());
            }
            APTStage::Exfiltration => {
                recommendations.push("Monitor outbound data transfers".to_string());
                recommendations.push("Implement data loss prevention controls".to_string());
            }
            _ => {}
        }

        match apt_group {
            "Lazarus" => {
                recommendations.push("Review cryptocurrency wallet security".to_string());
                recommendations.push("Monitor for destructive payloads".to_string());
            }
            "APT1" => {
                recommendations.push("Focus on intellectual property protection".to_string());
                recommendations.push("Review RDP access controls".to_string());
            }
            _ => {}
        }

        recommendations
    }

    fn confidence_to_string(&self, confidence: f64) -> String {
        if confidence >= 0.9 {
            "Critical".to_string()
        } else if confidence >= 0.75 {
            "High".to_string()
        } else if confidence >= 0.5 {
            "Medium".to_string()
        } else {
            "Low".to_string()
        }
    }

    fn score_to_confidence_level(&self, score: f64) -> ConfidenceLevel {
        if score >= 0.9 {
            ConfidenceLevel::Critical
        } else if score >= 0.75 {
            ConfidenceLevel::High
        } else if score >= 0.5 {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        }
    }

    pub async fn get_active_campaigns(&self) -> Vec<APTCampaign> {
        self.campaigns.iter().map(|entry| entry.value().clone()).collect()
    }

    pub async fn get_campaign_details(&self, campaign_id: Uuid) -> Option<APTCampaign> {
        self.campaigns.get(&campaign_id).map(|entry| entry.value().clone())
    }
}

impl CorrelationEngine {
    fn new() -> Self {
        let mut stage_weights = HashMap::new();
        stage_weights.insert(APTStage::Reconnaissance, 0.1);
        stage_weights.insert(APTStage::InitialAccess, 0.2);
        stage_weights.insert(APTStage::Persistence, 0.3);
        stage_weights.insert(APTStage::PrivilegeEscalation, 0.4);
        stage_weights.insert(APTStage::DefenseEvasion, 0.3);
        stage_weights.insert(APTStage::CredentialAccess, 0.5);
        stage_weights.insert(APTStage::Discovery, 0.2);
        stage_weights.insert(APTStage::LateralMovement, 0.6);
        stage_weights.insert(APTStage::Collection, 0.7);
        stage_weights.insert(APTStage::CommandAndControl, 0.8);
        stage_weights.insert(APTStage::Exfiltration, 0.9);
        stage_weights.insert(APTStage::Impact, 1.0);

        Self {
            correlation_window_hours: 72,
            minimum_events_for_campaign: 3,
            stage_progression_weights: stage_weights,
        }
    }
}

impl MLEngine {
    fn new() -> Self {
        let mut models = HashMap::new();
        
        models.insert("behavioral_anomaly".to_string(), MLModel {
            model_type: "Isolation Forest".to_string(),
            accuracy: 0.87,
            last_trained: Utc::now() - chrono::Duration::days(1),
            feature_count: 25,
        });

        models.insert("apt_classification".to_string(), MLModel {
            model_type: "Random Forest".to_string(),
            accuracy: 0.91,
            last_trained: Utc::now() - chrono::Duration::days(2),
            feature_count: 50,
        });

        let feature_extractors = vec![
            FeatureExtractor {
                name: "network_features".to_string(),
                feature_type: "numerical".to_string(),
                weight: 0.3,
            },
            FeatureExtractor {
                name: "process_features".to_string(),
                feature_type: "categorical".to_string(),
                weight: 0.25,
            },
            FeatureExtractor {
                name: "file_features".to_string(),
                feature_type: "numerical".to_string(),
                weight: 0.2,
            },
            FeatureExtractor {
                name: "temporal_features".to_string(),
                feature_type: "numerical".to_string(),
                weight: 0.25,
            },
        ];

        Self {
            models,
            feature_extractors,
        }
    }
}

// REST API Handlers
async fn analyze_event(
    State(engine): State<APTDetectionEngine>,
    Json(event_data): Json<HashMap<String, String>>,
) -> Result<Json<Option<APTCampaign>>, StatusCode> {
    match engine.analyze_event(event_data).await {
        Ok(campaign) => Ok(Json(campaign)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_campaigns(
    State(engine): State<APTDetectionEngine>,
) -> Json<Vec<APTCampaign>> {
    let campaigns = engine.get_active_campaigns().await;
    Json(campaigns)
}

async fn get_campaign(
    State(engine): State<APTDetectionEngine>,
    Path(campaign_id): Path<Uuid>,
) -> Result<Json<APTCampaign>, StatusCode> {
    match engine.get_campaign_details(campaign_id).await {
        Some(campaign) => Ok(Json(campaign)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn health_check() -> Json<HashMap<String, String>> {
    Json(HashMap::from([
        ("status".to_string(), "healthy".to_string()),
        ("service".to_string(), "apt-detection-engine".to_string()),
        ("timestamp".to_string(), Utc::now().to_rfc3339()),
    ]))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .init();

    info!("Starting APT Detection Engine");

    let engine = APTDetectionEngine::new();

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/analyze", post(analyze_event))
        .route("/api/v1/campaigns", get(get_campaigns))
        .route("/api/v1/campaigns/:id", get(get_campaign))
        .with_state(engine);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8083").await?;
    
    info!("APT Detection Engine listening on http://0.0.0.0:8083");
    
    axum::serve(listener, app).await?;

    Ok(())
}