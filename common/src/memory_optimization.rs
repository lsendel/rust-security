// Phase 3: Memory Optimization with Custom Allocators and Profiling
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, instrument};
use prometheus::{Counter, Histogram, Gauge};

/// High-performance memory allocator with profiling and optimization
pub struct OptimizedAllocator {
    inner: System,
    stats: Arc<AllocationStats>,
    pools: Arc<RwLock<HashMap<usize, MemoryPool>>>,
}

#[derive(Debug)]
pub struct AllocationStats {
    pub total_allocated: AtomicUsize,
    pub total_deallocated: AtomicUsize,
    pub current_allocated: AtomicUsize,
    pub allocation_count: AtomicUsize,
    pub deallocation_count: AtomicUsize,
    pub peak_memory: AtomicUsize,
}

/// Memory pool for frequent allocations of same size
pub struct MemoryPool {
    size: usize,
    capacity: usize,
    available: Vec<*mut u8>,
    allocated: usize,
    hits: u64,
    misses: u64,
    created_at: Instant,
}

/// Memory profiler for tracking allocation patterns
#[derive(Clone)]
pub struct MemoryProfiler {
    stats: Arc<AllocationStats>,
    metrics: MemoryMetrics,
    pools: Arc<RwLock<HashMap<usize, MemoryPool>>>,
    profiling_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct MemoryMetrics {
    pub allocations_total: Counter,
    pub deallocations_total: Counter,
    pub memory_usage_bytes: Gauge,
    pub allocation_size_histogram: Histogram,
    pub pool_hit_rate: Histogram,
    pub memory_fragmentation: Gauge,
}

/// Zero-copy buffer for high-performance data operations
pub struct ZeroCopyBuffer {
    data: *mut u8,
    len: usize,
    capacity: usize,
    pool_size: usize,
}

/// Memory-mapped region for large data structures
pub struct MemoryMappedRegion {
    ptr: *mut u8,
    size: usize,
    file_backed: bool,
}

unsafe impl GlobalAlloc for OptimizedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _size = layout.size();
        
        // Try to get from memory pool first for common sizes
        if let Some(ptr) = self.try_pool_alloc(size).await {
            self.stats.allocation_count.fetch_add(1, Ordering::Relaxed);
            self.stats.current_allocated.fetch_add(size, Ordering::Relaxed);
            self.stats.total_allocated.fetch_add(size, Ordering::Relaxed);
            
            // Update peak memory
            let current = self.stats.current_allocated.load(Ordering::Relaxed);
            let mut peak = self.stats.peak_memory.load(Ordering::Relaxed);
            while current > peak {
                match self.stats.peak_memory.compare_exchange_weak(
                    peak, current, Ordering::Relaxed, Ordering::Relaxed
                ) {
                    Ok(_) => break,
                    Err(x) => peak = x,
                }
            }
            
            return ptr;
        }
        
        // Fall back to system allocator
        let ptr = self.inner.alloc(layout);
        if !ptr.is_null() {
            self.stats.allocation_count.fetch_add(1, Ordering::Relaxed);
            self.stats.current_allocated.fetch_add(size, Ordering::Relaxed);
            self.stats.total_allocated.fetch_add(size, Ordering::Relaxed);
        }
        
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _size = layout.size();
        
        // Try to return to memory pool
        if self.try_pool_dealloc(ptr, size).await {
            self.stats.deallocation_count.fetch_add(1, Ordering::Relaxed);
            self.stats.current_allocated.fetch_sub(size, Ordering::Relaxed);
            self.stats.total_deallocated.fetch_add(size, Ordering::Relaxed);
            return;
        }
        
        // Fall back to system deallocator
        self.inner.dealloc(ptr, layout);
        self.stats.deallocation_count.fetch_add(1, Ordering::Relaxed);
        self.stats.current_allocated.fetch_sub(size, Ordering::Relaxed);
        self.stats.total_deallocated.fetch_add(size, Ordering::Relaxed);
    }
}

impl OptimizedAllocator {
    pub fn new() -> Self {
        Self {
            inner: System,
            stats: Arc::new(AllocationStats {
                total_allocated: AtomicUsize::new(0),
                total_deallocated: AtomicUsize::new(0),
                current_allocated: AtomicUsize::new(0),
                allocation_count: AtomicUsize::new(0),
                deallocation_count: AtomicUsize::new(0),
                peak_memory: AtomicUsize::new(0),
            }),
            pools: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn try_pool_alloc(&self, size: usize) -> Option<*mut u8> {
        // Only use pools for common sizes (powers of 2, up to 4KB)
        if !self.is_poolable_size(size) {
            return None;
        }

        let mut pools = self.pools.write().await;
        let pool = pools.entry(size).or_insert_with(|| MemoryPool::new(size, 1000));
        
        if let Some(ptr) = pool.allocate() {
            pool.hits += 1;
            Some(ptr)
        } else {
            pool.misses += 1;
            None
        }
    }

    async fn try_pool_dealloc(&self, ptr: *mut u8, size: usize) -> bool {
        if !self.is_poolable_size(size) {
            return false;
        }

        let mut pools = self.pools.write().await;
        if let Some(pool) = pools.get_mut(&size) {
            pool.deallocate(ptr)
        } else {
            false
        }
    }

    fn is_poolable_size(&self, size: usize) -> bool {
        // Pool common sizes: 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096 bytes
        size <= 4096 && size.is_power_of_two() && size >= 8
    }

    pub fn get_stats(&self) -> AllocationStats {
        AllocationStats {
            total_allocated: AtomicUsize::new(self.stats.total_allocated.load(Ordering::Relaxed)),
            total_deallocated: AtomicUsize::new(self.stats.total_deallocated.load(Ordering::Relaxed)),
            current_allocated: AtomicUsize::new(self.stats.current_allocated.load(Ordering::Relaxed)),
            allocation_count: AtomicUsize::new(self.stats.allocation_count.load(Ordering::Relaxed)),
            deallocation_count: AtomicUsize::new(self.stats.deallocation_count.load(Ordering::Relaxed)),
            peak_memory: AtomicUsize::new(self.stats.peak_memory.load(Ordering::Relaxed)),
        }
    }
}

impl MemoryPool {
    fn new(size: usize, capacity: usize) -> Self {
        Self {
            size,
            capacity,
            available: Vec::with_capacity(capacity),
            allocated: 0,
            hits: 0,
            misses: 0,
            created_at: Instant::now(),
        }
    }

    fn allocate(&mut self) -> Option<*mut u8> {
        if let Some(ptr) = self.available.pop() {
            self.allocated += 1;
            Some(ptr)
        } else if self.allocated < self.capacity {
            // Allocate new block
            let layout = Layout::from_size_align(self.size, 8).ok()?;
            let ptr = unsafe { System.alloc(layout) };
            if !ptr.is_null() {
                self.allocated += 1;
                Some(ptr)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn deallocate(&mut self, ptr: *mut u8) -> bool {
        if self.available.len() < self.capacity / 2 {
            // Return to pool if we have space
            self.available.push(ptr);
            self.allocated -= 1;
            true
        } else {
            // Pool is full, actually deallocate
            let layout = Layout::from_size_align(self.size, 8).unwrap();
            unsafe { System.dealloc(ptr, layout) };
            self.allocated -= 1;
            false
        }
    }

    fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total > 0 {
            self.hits as f64 / total as f64
        } else {
            0.0
        }
    }
}

impl MemoryProfiler {
    pub fn new(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        let metrics = MemoryMetrics::new(registry)?;
        
        Ok(Self {
            stats: Arc::new(AllocationStats {
                total_allocated: AtomicUsize::new(0),
                total_deallocated: AtomicUsize::new(0),
                current_allocated: AtomicUsize::new(0),
                allocation_count: AtomicUsize::new(0),
                deallocation_count: AtomicUsize::new(0),
                peak_memory: AtomicUsize::new(0),
            }),
            metrics,
            pools: Arc::new(RwLock::new(HashMap::new())),
            profiling_enabled: true,
        })
    }

    /// Profile memory allocation patterns
    #[instrument(skip(self))]
    pub async fn profile_allocation(&self, size: usize, duration: Duration) {
        if !self.profiling_enabled {
            return;
        }

        self.metrics.allocations_total.inc();
        self.metrics.allocation_size_histogram.observe(size as f64);
        
        // Update current memory usage
        let current = self.stats.current_allocated.load(Ordering::Relaxed);
        self.metrics.memory_usage_bytes.set(current as f64);
        
        // Calculate fragmentation
        let fragmentation = self.calculate_fragmentation().await;
        self.metrics.memory_fragmentation.set(fragmentation);
        
        debug!("Memory allocation profiled: size={}, duration={:?}", size, duration);
    }

    /// Analyze memory usage patterns and suggest optimizations
    pub async fn analyze_patterns(&self) -> MemoryAnalysis {
        let stats = self.get_current_stats();
        let pools = self.pools.read().await;
        
        let mut pool_stats = Vec::new();
        for (size, pool) in pools.iter() {
            pool_stats.push(PoolAnalysis {
                size: *size,
                hit_rate: pool.hit_rate(),
                allocated: pool.allocated,
                capacity: pool.capacity,
                age: pool.created_at.elapsed(),
            });
        }
        
        // Calculate efficiency metrics
        let allocation_efficiency = if stats.allocation_count > 0 {
            stats.total_allocated as f64 / stats.allocation_count as f64
        } else {
            0.0
        };
        
        let memory_utilization = if stats.peak_memory > 0 {
            stats.current_allocated as f64 / stats.peak_memory as f64
        } else {
            0.0
        };
        
        MemoryAnalysis {
            current_usage: stats.current_allocated,
            peak_usage: stats.peak_memory,
            total_allocations: stats.allocation_count,
            allocation_efficiency,
            memory_utilization,
            fragmentation: self.calculate_fragmentation().await,
            pool_stats,
            recommendations: self.generate_recommendations(&stats, &pool_stats).await,
        }
    }

    async fn calculate_fragmentation(&self) -> f64 {
        // Simplified fragmentation calculation
        // In a real implementation, this would analyze memory layout
        let stats = self.get_current_stats();
        if stats.peak_memory > 0 {
            1.0 - (stats.current_allocated as f64 / stats.peak_memory as f64)
        } else {
            0.0
        }
    }

    async fn generate_recommendations(&self, stats: &AllocationStats, pools: &[PoolAnalysis]) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        // Check memory utilization
        let utilization = if stats.peak_memory > 0 {
            stats.current_allocated as f64 / stats.peak_memory as f64
        } else {
            0.0
        };
        
        if utilization < 0.7 {
            recommendations.push("Consider reducing memory allocation to improve efficiency".to_string());
        }
        
        // Check pool efficiency
        for pool in pools {
            if pool.hit_rate < 0.8 {
                recommendations.push(format!("Pool for size {} has low hit rate ({:.2}%), consider adjusting capacity", pool.size, pool.hit_rate * 100.0));
            }
        }
        
        // Check fragmentation
        let fragmentation = self.calculate_fragmentation().await;
        if fragmentation > 0.3 {
            recommendations.push("High memory fragmentation detected, consider memory compaction".to_string());
        }
        
        recommendations
    }

    fn get_current_stats(&self) -> AllocationStats {
        AllocationStats {
            total_allocated: AtomicUsize::new(self.stats.total_allocated.load(Ordering::Relaxed)),
            total_deallocated: AtomicUsize::new(self.stats.total_deallocated.load(Ordering::Relaxed)),
            current_allocated: AtomicUsize::new(self.stats.current_allocated.load(Ordering::Relaxed)),
            allocation_count: AtomicUsize::new(self.stats.allocation_count.load(Ordering::Relaxed)),
            deallocation_count: AtomicUsize::new(self.stats.deallocation_count.load(Ordering::Relaxed)),
            peak_memory: AtomicUsize::new(self.stats.peak_memory.load(Ordering::Relaxed)),
        }
    }

    /// Start background memory optimization task
    pub async fn start_optimization_task(&self) {
        let stats = Arc::clone(&self.stats);
        let pools = Arc::clone(&self.pools);
        let metrics = self.metrics.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                
                // Update metrics
                let current = stats.current_allocated.load(Ordering::Relaxed);
                metrics.memory_usage_bytes.set(current as f64);
                
                // Optimize pools
                let mut pools_guard = pools.write().await;
                pools_guard.retain(|_, pool| {
                    // Remove pools with very low hit rates and old age
                    !(pool.hit_rate() < 0.1 && pool.created_at.elapsed() > Duration::from_secs(300))
                });
                
                // Update pool metrics
                for pool in pools_guard.values() {
                    metrics.pool_hit_rate.observe(pool.hit_rate());
                }
            }
        });
    }
}

impl ZeroCopyBuffer {
    pub fn new(capacity: usize) -> Result<Self, std::io::Error> {
        let layout = Layout::from_size_align(capacity, 8)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid layout"))?;
        
        let data = unsafe { System.alloc(layout) };
        if data.is_null() {
            return Err(std::io::Error::new(std::io::ErrorKind::OutOfMemory, "Allocation failed"));
        }
        
        Ok(Self {
            data,
            len: 0,
            capacity,
            pool_size: capacity,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.data, self.capacity) }
    }

    pub fn set_len(&mut self, len: usize) {
        assert!(len <= self.capacity);
        self.len = len;
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Zero-copy append from another buffer
    pub unsafe fn append_unchecked(&mut self, src: &[u8]) {
        if self.len + src.len() <= self.capacity {
            std::ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.data.add(self.len),
                src.len()
            );
            self.len += src.len();
        }
    }
}

impl Drop for ZeroCopyBuffer {
    fn drop(&mut self) {
        if !self.data.is_null() {
            let layout = Layout::from_size_align(self.capacity, 8).unwrap();
            unsafe { System.dealloc(self.data, layout) };
        }
    }
}

impl MemoryMetrics {
    fn new(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        use prometheus::{Counter, Histogram, Gauge, Opts, HistogramOpts};

        let allocations_total = Counter::with_opts(
            Opts::new("memory_allocations_total", "Total memory allocations")
        )?;

        let deallocations_total = Counter::with_opts(
            Opts::new("memory_deallocations_total", "Total memory deallocations")
        )?;

        let memory_usage_bytes = Gauge::with_opts(
            Opts::new("memory_usage_bytes", "Current memory usage in bytes")
        )?;

        let allocation_size_histogram = Histogram::with_opts(
            HistogramOpts::new("memory_allocation_size_bytes", "Memory allocation size distribution")
                .buckets(vec![8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0, 8192.0])
        )?;

        let pool_hit_rate = Histogram::with_opts(
            HistogramOpts::new("memory_pool_hit_rate", "Memory pool hit rate")
                .buckets(vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
        )?;

        let memory_fragmentation = Gauge::with_opts(
            Opts::new("memory_fragmentation_ratio", "Memory fragmentation ratio (0-1)")
        )?;

        registry.register(Box::new(allocations_total.clone()))?;
        registry.register(Box::new(deallocations_total.clone()))?;
        registry.register(Box::new(memory_usage_bytes.clone()))?;
        registry.register(Box::new(allocation_size_histogram.clone()))?;
        registry.register(Box::new(pool_hit_rate.clone()))?;
        registry.register(Box::new(memory_fragmentation.clone()))?;

        Ok(Self {
            allocations_total,
            deallocations_total,
            memory_usage_bytes,
            allocation_size_histogram,
            pool_hit_rate,
            memory_fragmentation,
        })
    }
}

// Analysis types
#[derive(Debug)]
pub struct MemoryAnalysis {
    pub current_usage: usize,
    pub peak_usage: usize,
    pub total_allocations: usize,
    pub allocation_efficiency: f64,
    pub memory_utilization: f64,
    pub fragmentation: f64,
    pub pool_stats: Vec<PoolAnalysis>,
    pub recommendations: Vec<String>,
}

#[derive(Debug)]
pub struct PoolAnalysis {
    pub size: usize,
    pub hit_rate: f64,
    pub allocated: usize,
    pub capacity: usize,
    pub age: Duration,
}

// Global allocator setup
#[global_allocator]
static GLOBAL_ALLOCATOR: OptimizedAllocator = OptimizedAllocator {
    inner: System,
    stats: Arc::new(AllocationStats {
        total_allocated: AtomicUsize::new(0),
        total_deallocated: AtomicUsize::new(0),
        current_allocated: AtomicUsize::new(0),
        allocation_count: AtomicUsize::new(0),
        deallocation_count: AtomicUsize::new(0),
        peak_memory: AtomicUsize::new(0),
    }),
    pools: Arc::new(RwLock::const_new(HashMap::new())),
};

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_memory_pool() {
        let mut pool = MemoryPool::new(64, 10);
        
        // Test allocation
        let ptr1 = pool.allocate().unwrap();
        let ptr2 = pool.allocate().unwrap();
        
        assert_ne!(ptr1, ptr2);
        assert_eq!(pool.allocated, 2);
        
        // Test deallocation
        assert!(pool.deallocate(ptr1));
        assert_eq!(pool.allocated, 1);
        assert_eq!(pool.available.len(), 1);
        
        // Test reuse
        let ptr3 = pool.allocate().unwrap();
        assert_eq!(ptr3, ptr1); // Should reuse the returned pointer
    }

    #[test]
    async fn test_zero_copy_buffer() {
        let mut buffer = ZeroCopyBuffer::new(1024).unwrap();
        
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.capacity(), 1024);
        
        let data = b"Hello, World!";
        unsafe {
            buffer.append_unchecked(data);
        }
        
        assert_eq!(buffer.len(), data.len());
        assert_eq!(buffer.as_slice(), data);
    }

    #[test]
    async fn test_memory_profiler() {
        let registry = prometheus::Registry::new();
        let profiler = MemoryProfiler::new(&registry).unwrap();
        
        profiler.profile_allocation(1024, Duration::from_millis(1)).await;
        
        let analysis = profiler.analyze_patterns().await;
        assert_eq!(analysis.total_allocations, 1);
    }
}
