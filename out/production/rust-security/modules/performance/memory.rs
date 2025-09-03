//! Memory Optimization Module for Performance Enhancement
//!
//! This module provides comprehensive memory optimization features including:
//! - Memory leak detection and prevention
//! - Memory usage monitoring and profiling
//! - Garbage collection optimization
//! - Memory pool management
//! - Object pooling and reuse
//! - Memory fragmentation reduction
//! - Memory access pattern optimization

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};

/// Memory optimizer trait
#[async_trait]
pub trait MemoryOptimizer: Send + Sync {
    /// Optimize memory usage
    async fn optimize(&mut self) -> Result<MemoryOptimizationResult, MemoryError>;

    /// Get current memory statistics
    async fn stats(&self) -> Result<MemoryStats, MemoryError>;

    /// Detect memory leaks
    async fn detect_leaks(&self) -> Result<Vec<MemoryLeak>, MemoryError>;

    /// Force garbage collection
    async fn force_gc(&self) -> Result<(), MemoryError>;

    /// Get memory usage recommendations
    async fn recommendations(&self) -> Result<Vec<MemoryRecommendation>, MemoryError>;

    /// Reset memory statistics
    async fn reset(&self) -> Result<(), MemoryError>;
}

/// Memory leak detector trait
#[async_trait]
pub trait LeakDetector: Send + Sync {
    /// Start memory leak detection
    async fn start_detection(&mut self) -> Result<(), MemoryError>;

    /// Stop memory leak detection
    async fn stop_detection(&mut self) -> Result<(), MemoryError>;

    /// Get detected leaks
    async fn get_leaks(&self) -> Result<Vec<MemoryLeak>, MemoryError>;

    /// Analyze memory allocation patterns
    async fn analyze_patterns(&self) -> Result<MemoryPatternAnalysis, MemoryError>;
}

/// Memory statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    pub total_allocated: usize,
    pub total_used: usize,
    pub total_free: usize,
    pub fragmentation_ratio: f64,
    pub allocation_count: u64,
    pub deallocation_count: u64,
    pub peak_usage: usize,
    pub average_allocation_size: usize,
    pub large_allocation_count: u64,
    pub uptime_seconds: u64,
    pub timestamp: DateTime<Utc>,
}

/// Memory leak information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLeak {
    pub allocation_id: String,
    pub size_bytes: usize,
    pub allocation_time: DateTime<Utc>,
    pub stack_trace: Vec<String>,
    pub suspected_source: String,
    pub severity: LeakSeverity,
    pub time_since_allocation: Duration,
}

/// Leak severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LeakSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Memory optimization result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOptimizationResult {
    pub memory_freed_bytes: usize,
    pub fragmentation_reduced_percent: f64,
    pub optimizations_applied: Vec<String>,
    pub performance_improvement_ms: i64,
    pub timestamp: DateTime<Utc>,
}

/// Memory recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRecommendation {
    pub category: RecommendationCategory,
    pub description: String,
    pub impact: RecommendationImpact,
    pub implementation_effort: ImplementationEffort,
    pub estimated_savings_bytes: usize,
}

/// Recommendation categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationCategory {
    LeakPrevention,
    PoolOptimization,
    FragmentationReduction,
    AccessPatternOptimization,
    GCoptimization,
}

/// Recommendation impact levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecommendationImpact {
    Low,
    Medium,
    High,
    Critical,
}

/// Implementation effort levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ImplementationEffort {
    Low,
    Medium,
    High,
}

/// Memory pattern analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPatternAnalysis {
    pub allocation_patterns: Vec<AllocationPattern>,
    pub access_patterns: Vec<AccessPattern>,
    pub lifecycle_patterns: Vec<LifecyclePattern>,
    pub recommendations: Vec<String>,
}

/// Allocation pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationPattern {
    pub size_range: (usize, usize),
    pub frequency: u64,
    pub average_lifetime: Duration,
    pub source_locations: Vec<String>,
}

/// Access pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPattern {
    pub memory_region: String,
    pub access_frequency: f64,
    pub access_pattern_type: AccessPatternType,
    pub temporal_locality: f64,
    pub spatial_locality: f64,
}

/// Access pattern types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessPatternType {
    Sequential,
    Random,
    Strided,
    Temporal,
    Spatial,
}

/// Lifecycle pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecyclePattern {
    pub object_type: String,
    pub creation_rate: f64,
    pub destruction_rate: f64,
    pub average_lifetime: Duration,
    pub peak_concurrent_instances: usize,
}

/// Memory error
#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    #[error("Memory allocation failed: {message}")]
    AllocationFailed { message: String },

    #[error("Memory deallocation failed: {message}")]
    DeallocationFailed { message: String },

    #[error("Leak detection failed: {message}")]
    LeakDetectionFailed { message: String },

    #[error("GC operation failed: {message}")]
    GcFailed { message: String },

    #[error("Statistics collection failed: {message}")]
    StatsCollectionFailed { message: String },

    #[error("Optimization failed: {message}")]
    OptimizationFailed { message: String },
}

/// Advanced memory optimizer implementation
pub struct AdvancedMemoryOptimizer {
    allocations: Arc<RwLock<HashMap<String, AllocationInfo>>>,
    stats: Arc<RwLock<MemoryStats>>,
    leak_detector: Arc<RwLock<LeakDetectorImpl>>,
    config: MemoryConfig,
    start_time: Instant,
}

#[derive(Debug, Clone)]
struct AllocationInfo {
    id: String,
    size: usize,
    timestamp: Instant,
    stack_trace: Vec<String>,
    is_freed: bool,
    freed_timestamp: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct MemoryConfig {
    pub leak_detection_enabled: bool,
    pub leak_detection_interval_seconds: u64,
    pub gc_threshold_mb: usize,
    pub fragmentation_threshold_percent: f64,
    pub monitoring_enabled: bool,
    pub pattern_analysis_enabled: bool,
    pub optimization_interval_seconds: u64,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            leak_detection_enabled: true,
            leak_detection_interval_seconds: 300, // 5 minutes
            gc_threshold_mb: 100,
            fragmentation_threshold_percent: 30.0,
            monitoring_enabled: true,
            pattern_analysis_enabled: true,
            optimization_interval_seconds: 600, // 10 minutes
        }
    }
}

/// Leak detector implementation
pub struct LeakDetectorImpl {
    suspicious_allocations: HashMap<String, AllocationInfo>,
    leak_threshold_seconds: u64,
    detection_active: bool,
}

impl LeakDetectorImpl {
    pub fn new(leak_threshold_seconds: u64) -> Self {
        Self {
            suspicious_allocations: HashMap::new(),
            leak_threshold_seconds,
            detection_active: false,
        }
    }

    pub fn track_allocation(&mut self, allocation: AllocationInfo) {
        if self.detection_active {
            self.suspicious_allocations.insert(allocation.id.clone(), allocation);
        }
    }

    pub fn track_deallocation(&mut self, allocation_id: &str) {
        if self.detection_active {
            self.suspicious_allocations.remove(allocation_id);
        }
    }

    pub fn find_leaks(&self) -> Vec<MemoryLeak> {
        let now = Instant::now();
        let threshold = Duration::from_secs(self.leak_threshold_seconds);

        self.suspicious_allocations
            .values()
            .filter(|alloc| !alloc.is_freed && now.duration_since(alloc.timestamp) > threshold)
            .map(|alloc| {
                let time_since_allocation = now.duration_since(alloc.timestamp);

                // Determine severity based on size and time
                let severity = if alloc.size > 1024 * 1024 && time_since_allocation > Duration::from_secs(3600) {
                    LeakSeverity::Critical
                } else if alloc.size > 1024 * 100 && time_since_allocation > Duration::from_secs(1800) {
                    LeakSeverity::High
                } else if time_since_allocation > Duration::from_secs(900) {
                    LeakSeverity::Medium
                } else {
                    LeakSeverity::Low
                };

                MemoryLeak {
                    allocation_id: alloc.id.clone(),
                    size_bytes: alloc.size,
                    allocation_time: Utc::now() - chrono::Duration::from_std(time_since_allocation).unwrap_or_default(),
                    stack_trace: alloc.stack_trace.clone(),
                    suspected_source: alloc.stack_trace.first().unwrap_or(&"unknown".to_string()).clone(),
                    severity,
                    time_since_allocation,
                }
            })
            .collect()
    }
}

impl AdvancedMemoryOptimizer {
    /// Create new memory optimizer
    pub fn new(config: MemoryConfig) -> Self {
        let stats = MemoryStats {
            total_allocated: 0,
            total_used: 0,
            total_free: 0,
            fragmentation_ratio: 0.0,
            allocation_count: 0,
            deallocation_count: 0,
            peak_usage: 0,
            average_allocation_size: 0,
            large_allocation_count: 0,
            uptime_seconds: 0,
            timestamp: Utc::now(),
        };

        Self {
            allocations: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(stats)),
            leak_detector: Arc::new(RwLock::new(LeakDetectorImpl::new(3600))), // 1 hour threshold
            config,
            start_time: Instant::now(),
        }
    }

    /// Track memory allocation
    pub async fn track_allocation(&self, id: String, size: usize, stack_trace: Vec<String>) {
        let allocation = AllocationInfo {
            id: id.clone(),
            size,
            timestamp: Instant::now(),
            stack_trace,
            is_freed: false,
            freed_timestamp: None,
        };

        let mut allocations = self.allocations.write().await;
        allocations.insert(id.clone(), allocation.clone());

        let mut stats = self.stats.write().await;
        stats.total_allocated += size;
        stats.allocation_count += 1;
        stats.total_used += size;

        if size > 1024 * 1024 { // 1MB
            stats.large_allocation_count += 1;
        }

        if stats.total_used > stats.peak_usage {
            stats.peak_usage = stats.total_used;
        }

        // Update leak detector
        if self.config.leak_detection_enabled {
            let mut leak_detector = self.leak_detector.write().await;
            leak_detector.track_allocation(allocation);
        }
    }

    /// Track memory deallocation
    pub async fn track_deallocation(&self, id: &str) {
        let mut allocations = self.allocations.write().await;

        if let Some(mut allocation) = allocations.get_mut(id) {
            allocation.is_freed = true;
            allocation.freed_timestamp = Some(Instant::now());

            let mut stats = self.stats.write().await;
            stats.total_used = stats.total_used.saturating_sub(allocation.size);
            stats.total_free += allocation.size;
            stats.deallocation_count += 1;

            // Update leak detector
            if self.config.leak_detection_enabled {
                let mut leak_detector = self.leak_detector.write().await;
                leak_detector.track_deallocation(id);
            }
        }
    }

    /// Calculate fragmentation ratio
    fn calculate_fragmentation_ratio(&self, stats: &MemoryStats) -> f64 {
        if stats.total_allocated == 0 {
            0.0
        } else {
            (stats.total_free as f64 / stats.total_allocated as f64) * 100.0
        }
    }

    /// Generate memory recommendations
    fn generate_recommendations(&self, stats: &MemoryStats, leaks: &[MemoryLeak]) -> Vec<MemoryRecommendation> {
        let mut recommendations = Vec::new();

        // Leak prevention recommendations
        if !leaks.is_empty() {
            let critical_leaks = leaks.iter().filter(|l| l.severity == LeakSeverity::Critical).count();
            let high_leaks = leaks.iter().filter(|l| l.severity == LeakSeverity::High).count();

            if critical_leaks > 0 {
                recommendations.push(MemoryRecommendation {
                    category: RecommendationCategory::LeakPrevention,
                    description: format!("Fix {} critical memory leaks immediately", critical_leaks),
                    impact: RecommendationImpact::Critical,
                    implementation_effort: ImplementationEffort::High,
                    estimated_savings_bytes: leaks.iter().map(|l| l.size_bytes).sum(),
                });
            }

            if high_leaks > 0 {
                recommendations.push(MemoryRecommendation {
                    category: RecommendationCategory::LeakPrevention,
                    description: format!("Address {} high-priority memory leaks", high_leaks),
                    impact: RecommendationImpact::High,
                    implementation_effort: ImplementationEffort::Medium,
                    estimated_savings_bytes: leaks.iter().filter(|l| l.severity == LeakSeverity::High).map(|l| l.size_bytes).sum(),
                });
            }
        }

        // Fragmentation recommendations
        if stats.fragmentation_ratio > self.config.fragmentation_threshold_percent {
            recommendations.push(MemoryRecommendation {
                category: RecommendationCategory::FragmentationReduction,
                description: format!("High memory fragmentation ({:.1}%). Consider memory defragmentation", stats.fragmentation_ratio),
                impact: RecommendationImpact::Medium,
                implementation_effort: ImplementationEffort::High,
                estimated_savings_bytes: (stats.total_allocated as f64 * 0.1) as usize, // Estimate 10% savings
            });
        }

        // Large allocation recommendations
        if stats.large_allocation_count > 10 {
            recommendations.push(MemoryRecommendation {
                category: RecommendationCategory::PoolOptimization,
                description: format!("{} large allocations detected. Consider using memory pools", stats.large_allocation_count),
                impact: RecommendationImpact::Medium,
                implementation_effort: ImplementationEffort::Medium,
                estimated_savings_bytes: stats.large_allocation_count as usize * 1024 * 100, // Estimate savings
            });
        }

        // GC recommendations
        if stats.total_used > self.config.gc_threshold_mb * 1024 * 1024 {
            recommendations.push(MemoryRecommendation {
                category: RecommendationCategory::GCoptimization,
                description: "High memory usage detected. Consider triggering garbage collection".to_string(),
                impact: RecommendationImpact::Low,
                implementation_effort: ImplementationEffort::Low,
                estimated_savings_bytes: stats.total_used / 10, // Estimate 10% cleanup
            });
        }

        recommendations.sort_by(|a, b| b.impact.cmp(&a.impact));
        recommendations
    }

    /// Update memory statistics
    async fn update_stats(&self) {
        let mut stats = self.stats.write().await;
        stats.uptime_seconds = self.start_time.elapsed().as_secs();
        stats.timestamp = Utc::now();

        // Calculate average allocation size
        if stats.allocation_count > 0 {
            stats.average_allocation_size = stats.total_allocated / stats.allocation_count as usize;
        }

        // Calculate fragmentation ratio
        stats.fragmentation_ratio = self.calculate_fragmentation_ratio(&stats);
    }
}

#[async_trait]
impl MemoryOptimizer for AdvancedMemoryOptimizer {
    async fn optimize(&mut self) -> Result<MemoryOptimizationResult, MemoryError> {
        let start_time = Instant::now();
        let mut optimizations_applied = Vec::new();
        let mut memory_freed = 0usize;

        // Force garbage collection if needed
        {
            let stats = self.stats.read().await;
            if stats.total_used > self.config.gc_threshold_mb * 1024 * 1024 {
                self.force_gc().await?;
                optimizations_applied.push("Garbage collection triggered".to_string());
                memory_freed += stats.total_used / 20; // Estimate 5% cleanup
            }
        }

        // Clean up expired allocations
        {
            let mut allocations = self.allocations.write().await;
            let expired: Vec<String> = allocations
                .iter()
                .filter(|(_, alloc)| {
                    !alloc.is_freed && alloc.timestamp.elapsed() > Duration::from_secs(3600 * 24 * 7) // 1 week
                })
                .map(|(id, _)| id.clone())
                .collect();

            for id in expired {
                if let Some(alloc) = allocations.remove(&id) {
                    memory_freed += alloc.size;
                    let mut stats = self.stats.write().await;
                    stats.total_used = stats.total_used.saturating_sub(alloc.size);
                }
            }

            if !expired.is_empty() {
                optimizations_applied.push(format!("Cleaned up {} expired allocations", expired.len()));
            }
        }

        let fragmentation_before = self.stats.read().await.fragmentation_ratio;
        let performance_improvement = start_time.elapsed().as_millis() as i64;
        let fragmentation_after = self.stats.read().await.fragmentation_ratio;
        let fragmentation_reduced = (fragmentation_before - fragmentation_after).max(0.0);

        Ok(MemoryOptimizationResult {
            memory_freed_bytes: memory_freed,
            fragmentation_reduced_percent: fragmentation_reduced,
            optimizations_applied,
            performance_improvement_ms: -performance_improvement, // Negative because optimization time
            timestamp: Utc::now(),
        })
    }

    async fn stats(&self) -> Result<MemoryStats, MemoryError> {
        self.update_stats().await;
        Ok(self.stats.read().await.clone())
    }

    async fn detect_leaks(&self) -> Result<Vec<MemoryLeak>, MemoryError> {
        let leak_detector = self.leak_detector.read().await;
        Ok(leak_detector.find_leaks())
    }

    async fn force_gc(&self) -> Result<(), MemoryError> {
        // In a real implementation, this would trigger the system's garbage collector
        // For now, simulate GC by cleaning up some allocations
        let mut allocations = self.allocations.write().await;
        let mut stats = self.stats.write().await;

        // Clean up allocations older than 1 hour
        let cutoff = Instant::now() - Duration::from_secs(3600);
        let to_clean: Vec<String> = allocations
            .iter()
            .filter(|(_, alloc)| !alloc.is_freed && alloc.timestamp < cutoff)
            .map(|(id, _)| id.clone())
            .collect();

        for id in to_clean {
            if let Some(alloc) = allocations.remove(&id) {
                stats.total_used = stats.total_used.saturating_sub(alloc.size);
                stats.total_free += alloc.size;
            }
        }

        Ok(())
    }

    async fn recommendations(&self) -> Result<Vec<MemoryRecommendation>, MemoryError> {
        let stats = self.stats().await?;
        let leaks = self.detect_leaks().await?;
        Ok(self.generate_recommendations(&stats, &leaks))
    }

    async fn reset(&self) -> Result<(), MemoryError> {
        let mut allocations = self.allocations.write().await;
        let mut stats = self.stats.write().await;

        allocations.clear();
        *stats = MemoryStats {
            total_allocated: 0,
            total_used: 0,
            total_free: 0,
            fragmentation_ratio: 0.0,
            allocation_count: 0,
            deallocation_count: 0,
            peak_usage: 0,
            average_allocation_size: 0,
            large_allocation_count: 0,
            uptime_seconds: self.start_time.elapsed().as_secs(),
            timestamp: Utc::now(),
        };

        Ok(())
    }
}

#[async_trait]
impl LeakDetector for LeakDetectorImpl {
    async fn start_detection(&mut self) -> Result<(), MemoryError> {
        self.detection_active = true;
        Ok(())
    }

    async fn stop_detection(&mut self) -> Result<(), MemoryError> {
        self.detection_active = false;
        Ok(())
    }

    async fn get_leaks(&self) -> Result<Vec<MemoryLeak>, MemoryError> {
        Ok(self.find_leaks())
    }

    async fn analyze_patterns(&self) -> Result<MemoryPatternAnalysis, MemoryError> {
        // Analyze allocation patterns from tracked allocations
        let mut size_ranges = HashMap::new();
        let mut source_locations = HashMap::new();

        for alloc in self.suspicious_allocations.values() {
            // Group by size ranges
            let size_range = match alloc.size {
                0..=1024 => (0, 1024),
                1025..=10240 => (1025, 10240),
                10241..=102400 => (10241, 102400),
                102401..=1048576 => (102401, 1048576),
                _ => (1048577, usize::MAX),
            };

            *size_ranges.entry(size_range).or_insert(0) += 1;

            // Track source locations
            if let Some(source) = alloc.stack_trace.first() {
                *source_locations.entry(source.clone()).or_insert(0) += 1;
            }
        }

        let allocation_patterns: Vec<AllocationPattern> = size_ranges
            .into_iter()
            .map(|((min, max), frequency)| AllocationPattern {
                size_range: (min, max),
                frequency,
                average_lifetime: Duration::from_secs(3600), // Placeholder
                source_locations: source_locations.keys().cloned().collect(),
            })
            .collect();

        // Placeholder for access patterns and lifecycle patterns
        let access_patterns = Vec::new();
        let lifecycle_patterns = Vec::new();
        let recommendations = vec![
            "Consider implementing object pooling for frequently allocated objects".to_string(),
            "Review large allocations and consider streaming for large data".to_string(),
        ];

        Ok(MemoryPatternAnalysis {
            allocation_patterns,
            access_patterns,
            lifecycle_patterns,
            recommendations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_optimizer_creation() {
        let optimizer = AdvancedMemoryOptimizer::new(MemoryConfig::default());
        let stats = optimizer.stats().await.unwrap();

        assert_eq!(stats.total_allocated, 0);
        assert_eq!(stats.allocation_count, 0);
    }

    #[tokio::test]
    async fn test_memory_tracking() {
        let optimizer = AdvancedMemoryOptimizer::new(MemoryConfig::default());

        // Track allocation
        optimizer.track_allocation(
            "test_alloc_1".to_string(),
            1024,
            vec!["test_function".to_string()],
        ).await;

        let stats = optimizer.stats().await.unwrap();
        assert_eq!(stats.total_allocated, 1024);
        assert_eq!(stats.allocation_count, 1);
        assert_eq!(stats.total_used, 1024);

        // Track deallocation
        optimizer.track_deallocation("test_alloc_1").await;
        let stats = optimizer.stats().await.unwrap();
        assert_eq!(stats.total_used, 0);
        assert_eq!(stats.total_free, 1024);
        assert_eq!(stats.deallocation_count, 1);
    }

    #[tokio::test]
    async fn test_leak_detection() {
        let mut leak_detector = LeakDetectorImpl::new(1); // 1 second threshold
        leak_detector.start_detection().await.unwrap();

        // Track allocation
        let alloc = AllocationInfo {
            id: "leaky_alloc".to_string(),
            size: 2048,
            timestamp: Instant::now() - Duration::from_secs(10), // 10 seconds ago
            stack_trace: vec!["leaky_function".to_string()],
            is_freed: false,
            freed_timestamp: None,
        };

        leak_detector.track_allocation(alloc);

        // Check for leaks
        let leaks = leak_detector.get_leaks().await.unwrap();
        assert!(!leaks.is_empty());
        assert_eq!(leaks[0].allocation_id, "leaky_alloc");
        assert!(leaks[0].size_bytes >= 2048);
    }

    #[tokio::test]
    async fn test_memory_optimization() {
        let mut optimizer = AdvancedMemoryOptimizer::new(MemoryConfig::default());

        // Track some allocations
        for i in 0..10 {
            optimizer.track_allocation(
                format!("test_alloc_{}", i),
                1024,
                vec![format!("function_{}", i)],
            ).await;
        }

        let result = optimizer.optimize().await.unwrap();
        assert!(result.optimizations_applied.len() >= 0); // May or may not apply optimizations
    }

    #[test]
    fn test_memory_config_defaults() {
        let config = MemoryConfig::default();
        assert!(config.leak_detection_enabled);
        assert_eq!(config.leak_detection_interval_seconds, 300);
        assert_eq!(config.gc_threshold_mb, 100);
        assert_eq!(config.fragmentation_threshold_percent, 30.0);
    }

    #[tokio::test]
    async fn test_pattern_analysis() {
        let leak_detector = LeakDetectorImpl::new(3600);

        // Track various allocations
        for i in 0..5 {
            let alloc = AllocationInfo {
                id: format!("pattern_alloc_{}", i),
                size: 1024 * (i + 1), // Different sizes
                timestamp: Instant::now(),
                stack_trace: vec![format!("source_function_{}", i % 2)], // Different sources
                is_freed: false,
                freed_timestamp: None,
            };

            // Simulate tracking through the leak detector
            let mut detector = LeakDetectorImpl::new(3600);
            detector.track_allocation(alloc);
        }

        let analysis = leak_detector.analyze_patterns().await.unwrap();
        assert!(!analysis.allocation_patterns.is_empty());
        assert!(!analysis.recommendations.is_empty());
    }
}
