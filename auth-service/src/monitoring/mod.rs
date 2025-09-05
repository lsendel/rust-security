//! Performance and memory monitoring for MVP Auth Service

pub mod heap_profiler;
pub mod memory_optimizer;
pub mod production_alerts;

pub use heap_profiler::{
    HeapProfiler, LeakSeverity, MemoryLeakIndicator, MemoryMonitorConfig, MemoryReport, MemoryStats,
};

pub use memory_optimizer::{
    CleanupResult, MemoryOptimizer, MemoryOptimizerConfig, MemoryOptimizerStats, ObjectPool,
    OptimizationStats, SmartCache,
};

pub use production_alerts::{
    AlertSeverity, AlertType, CustomerImpact, ImpactSeverity, ProductionAlert, ProductionMonitor,
    ProductionStatus, SlaConfig, SlaMetrics, SystemHealth,
};
