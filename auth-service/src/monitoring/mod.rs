//! Performance and memory monitoring for MVP Auth Service

pub mod heap_profiler;
pub mod memory_optimizer;
pub mod production_alerts;

pub use heap_profiler::{
    HeapProfiler, 
    MemoryMonitorConfig, 
    MemoryStats, 
    MemoryReport, 
    MemoryLeakIndicator,
    LeakSeverity,
};

pub use memory_optimizer::{
    MemoryOptimizer,
    MemoryOptimizerConfig,
    OptimizationStats,
    SmartCache,
    ObjectPool,
    CleanupResult,
    MemoryOptimizerStats,
};

pub use production_alerts::{
    ProductionMonitor,
    SlaConfig,
    ProductionAlert,
    AlertSeverity,
    AlertType,
    CustomerImpact,
    ImpactSeverity,
    SlaMetrics,
    ProductionStatus,
    SystemHealth,
};