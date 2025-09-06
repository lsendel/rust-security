#!/bin/bash
# Clean Code: Performance Optimization
# Implements targeted performance improvements

set -euo pipefail

echo "⚡ Performance Optimization"
echo "========================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Create performance utilities
create_performance_utils() {
    echo -e "${YELLOW}📦 Creating performance utilities...${NC}"
    
    # String optimization utilities
    cat > common/src/performance_utils.rs << 'EOF'
//! Performance optimization utilities
//! 
//! This module provides zero-cost abstractions and performance-optimized
//! implementations for common operations in the security platform.

use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Efficient string concatenation that avoids unnecessary allocations
/// 
/// # Examples
/// 
/// ```rust
/// use common::performance_utils::efficient_concat;
/// 
/// let result = efficient_concat("prefix_", "suffix");
/// // Only allocates if both parts are non-empty
/// ```
pub fn efficient_concat<'a>(prefix: &'a str, suffix: &'a str) -> Cow<'a, str> {
    match (prefix.is_empty(), suffix.is_empty()) {
        (true, false) => suffix.into(),
        (false, true) => prefix.into(),
        (true, true) => "".into(),
        (false, false) => format!("{}{}", prefix, suffix).into(),
    }
}

/// Smart string builder that reuses capacity
pub struct SmartStringBuilder {
    buffer: String,
    reuse_threshold: usize,
}

impl SmartStringBuilder {
    pub fn new() -> Self {
        Self {
            buffer: String::with_capacity(256),
            reuse_threshold: 1024,
        }
    }
    
    pub fn build<F>(&mut self, builder: F) -> String 
    where 
        F: FnOnce(&mut String),
    {
        self.buffer.clear();
        builder(&mut self.buffer);
        
        let result = self.buffer.clone();
        
        // Reset if buffer grew too large
        if self.buffer.capacity() > self.reuse_threshold {
            self.buffer = String::with_capacity(256);
        }
        
        result
    }
}

/// High-performance cache with metrics
pub struct PerformanceCache<K, V> {
    cache: HashMap<K, CacheEntry<V>>,
    hits: AtomicU64,
    misses: AtomicU64,
    max_size: usize,
}

struct CacheEntry<V> {
    value: V,
    created_at: Instant,
    ttl: Duration,
    access_count: AtomicU64,
}

impl<K, V> PerformanceCache<K, V> 
where 
    K: Eq + Hash + Clone,
    V: Clone,
{
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: HashMap::with_capacity(max_size),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            max_size,
        }
    }
    
    pub fn get(&self, key: &K) -> Option<V> {
        if let Some(entry) = self.cache.get(key) {
            if entry.created_at.elapsed() < entry.ttl {
                entry.access_count.fetch_add(1, Ordering::Relaxed);
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(entry.value.clone());
            }
        }
        
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }
    
    pub fn insert(&mut self, key: K, value: V, ttl: Duration) {
        if self.cache.len() >= self.max_size {
            self.evict_oldest();
        }
        
        let entry = CacheEntry {
            value,
            created_at: Instant::now(),
            ttl,
            access_count: AtomicU64::new(0),
        };
        
        self.cache.insert(key, entry);
    }
    
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
    
    fn evict_oldest(&mut self) {
        if let Some((key, _)) = self.cache
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(k, v)| (k.clone(), v.created_at))
        {
            self.cache.remove(&key);
        }
    }
}

/// Batch processor for async operations with bounded concurrency
pub struct BatchProcessor;

impl BatchProcessor {
    /// Process items in batches with controlled concurrency
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// use common::performance_utils::BatchProcessor;
    /// 
    /// let results = BatchProcessor::process_concurrent(
    ///     vec![1, 2, 3, 4, 5],
    ///     3, // batch size
    ///     |item| async move { item * 2 }
    /// ).await;
    /// ```
    pub async fn process_concurrent<T, R, F, Fut>(
        items: Vec<T>,
        batch_size: usize,
        processor: F,
    ) -> Vec<Result<R, Box<dyn std::error::Error + Send + Sync>>>
    where
        T: Send + 'static,
        R: Send + 'static,
        F: Fn(T) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<R, Box<dyn std::error::Error + Send + Sync>>> + Send,
    {
        use futures::stream::{self, StreamExt};
        
        stream::iter(items)
            .map(processor)
            .buffer_unordered(batch_size)
            .collect()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_efficient_concat() {
        assert_eq!(efficient_concat("", "test"), "test");
        assert_eq!(efficient_concat("test", ""), "test");
        assert_eq!(efficient_concat("hello", "world"), "helloworld");
    }
    
    #[test]
    fn test_performance_cache() {
        let mut cache = PerformanceCache::new(2);
        
        cache.insert("key1", "value1", Duration::from_secs(60));
        assert_eq!(cache.get(&"key1"), Some("value1"));
        assert!(cache.hit_rate() > 0.0);
    }
}
EOF

    echo -e "${GREEN}✅ Performance utilities created${NC}"
}

# Optimize async operations
optimize_async_operations() {
    echo -e "${YELLOW}🔄 Optimizing async operations...${NC}"
    
    # Create async optimization utilities
    cat > auth-service/src/async_optimized.rs << 'EOF'
//! Optimized async operations for the auth service
//! 
//! This module provides performance-optimized async utilities specifically
//! designed for authentication and authorization workflows.

use futures::future::{BoxFuture, FutureExt};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use std::time::{Duration, Instant};

/// Async operation pool with intelligent batching
pub struct AsyncOperationPool<T, R> {
    semaphore: Arc<Semaphore>,
    pending_operations: Arc<Mutex<VecDeque<PendingOperation<T, R>>>>,
    batch_size: usize,
    batch_timeout: Duration,
}

struct PendingOperation<T, R> {
    input: T,
    sender: tokio::sync::oneshot::Sender<R>,
    created_at: Instant,
}

impl<T, R> AsyncOperationPool<T, R> 
where 
    T: Send + 'static,
    R: Send + 'static,
{
    pub fn new(max_concurrent: usize, batch_size: usize, batch_timeout: Duration) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            pending_operations: Arc::new(Mutex::new(VecDeque::new())),
            batch_size,
            batch_timeout,
        }
    }
    
    /// Execute operation with intelligent batching
    pub async fn execute<F, Fut>(&self, input: T, operation: F) -> Result<R, Box<dyn std::error::Error + Send + Sync>>
    where
        F: FnOnce(Vec<T>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Vec<R>> + Send,
    {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        
        // Add to pending operations
        {
            let mut pending = self.pending_operations.lock().await;
            pending.push_back(PendingOperation {
                input,
                sender,
                created_at: Instant::now(),
            });
            
            // Trigger batch processing if conditions are met
            if pending.len() >= self.batch_size {
                self.process_batch(operation).await;
            }
        }
        
        // Wait for result
        receiver.await.map_err(|e| e.into())
    }
    
    async fn process_batch<F, Fut>(&self, operation: F)
    where
        F: FnOnce(Vec<T>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Vec<R>> + Send,
    {
        let _permit = self.semaphore.acquire().await.unwrap();
        
        let batch = {
            let mut pending = self.pending_operations.lock().await;
            let batch_size = std::cmp::min(self.batch_size, pending.len());
            (0..batch_size).map(|_| pending.pop_front().unwrap()).collect::<Vec<_>>()
        };
        
        if batch.is_empty() {
            return;
        }
        
        let inputs: Vec<T> = batch.iter().map(|op| op.input).collect();
        let senders: Vec<_> = batch.into_iter().map(|op| op.sender).collect();
        
        // Execute batch operation
        let results = operation(inputs).await;
        
        // Send results back
        for (sender, result) in senders.into_iter().zip(results.into_iter()) {
            let _ = sender.send(result);
        }
    }
}

/// Smart retry mechanism with exponential backoff
pub struct SmartRetry {
    max_attempts: usize,
    base_delay: Duration,
    max_delay: Duration,
    backoff_multiplier: f64,
}

impl SmartRetry {
    pub fn new() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }
    
    pub async fn execute<F, Fut, T, E>(&self, operation: F) -> Result<T, E>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        let mut attempt = 0;
        let mut delay = self.base_delay;
        
        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    attempt += 1;
                    
                    if attempt >= self.max_attempts {
                        return Err(error);
                    }
                    
                    tokio::time::sleep(delay).await;
                    
                    delay = std::cmp::min(
                        Duration::from_millis((delay.as_millis() as f64 * self.backoff_multiplier) as u64),
                        self.max_delay,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_smart_retry() {
        let retry = SmartRetry::new();
        let mut attempts = 0;
        
        let result = retry.execute(|| async {
            attempts += 1;
            if attempts < 3 {
                Err("temporary error")
            } else {
                Ok("success")
            }
        }).await;
        
        assert_eq!(result, Ok("success"));
        assert_eq!(attempts, 3);
    }
}
EOF

    echo -e "${GREEN}✅ Async optimizations implemented${NC}"
}

# Create memory optimization utilities
create_memory_optimizations() {
    echo -e "${YELLOW}🧠 Creating memory optimizations...${NC}"
    
    cat > common/src/memory_optimization.rs << 'EOF'
//! Memory optimization utilities
//! 
//! Provides tools for efficient memory usage in high-performance scenarios.

use std::sync::Arc;
use std::collections::HashMap;
use std::hash::Hash;

/// Interned string pool for reducing memory usage with repeated strings
pub struct StringPool {
    pool: HashMap<String, Arc<str>>,
}

impl StringPool {
    pub fn new() -> Self {
        Self {
            pool: HashMap::new(),
        }
    }
    
    /// Get or create an interned string
    pub fn intern(&mut self, s: &str) -> Arc<str> {
        if let Some(interned) = self.pool.get(s) {
            interned.clone()
        } else {
            let interned: Arc<str> = s.into();
            self.pool.insert(s.to_string(), interned.clone());
            interned
        }
    }
    
    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            entries: self.pool.len(),
            estimated_memory: self.pool.iter()
                .map(|(k, v)| k.len() + v.len())
                .sum(),
        }
    }
}

pub struct PoolStats {
    pub entries: usize,
    pub estimated_memory: usize,
}

/// Object pool for expensive-to-create objects
pub struct ObjectPool<T> {
    objects: Vec<T>,
    factory: Box<dyn Fn() -> T + Send + Sync>,
}

impl<T> ObjectPool<T> 
where 
    T: Send + 'static,
{
    pub fn new<F>(factory: F) -> Self 
    where 
        F: Fn() -> T + Send + Sync + 'static,
    {
        Self {
            objects: Vec::new(),
            factory: Box::new(factory),
        }
    }
    
    pub fn get(&mut self) -> T {
        self.objects.pop().unwrap_or_else(|| (self.factory)())
    }
    
    pub fn return_object(&mut self, obj: T) {
        if self.objects.len() < 100 { // Prevent unbounded growth
            self.objects.push(obj);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_string_pool() {
        let mut pool = StringPool::new();
        
        let s1 = pool.intern("test");
        let s2 = pool.intern("test");
        
        assert!(Arc::ptr_eq(&s1, &s2));
        assert_eq!(pool.stats().entries, 1);
    }
}
EOF

    echo -e "${GREEN}✅ Memory optimizations created${NC}"
}

# Update module exports
update_module_exports() {
    echo -e "${YELLOW}📝 Updating module exports...${NC}"
    
    # Update common/src/lib.rs
    if ! grep -q "pub mod performance_utils" common/src/lib.rs; then
        echo "pub mod performance_utils;" >> common/src/lib.rs
    fi
    
    if ! grep -q "pub mod memory_optimization" common/src/lib.rs; then
        echo "pub mod memory_optimization;" >> common/src/lib.rs
    fi
    
    # Update auth-service/src/lib.rs  
    if ! grep -q "pub mod async_optimized" auth-service/src/lib.rs; then
        echo "pub mod async_optimized;" >> auth-service/src/lib.rs
    fi
    
    echo -e "${GREEN}✅ Module exports updated${NC}"
}

# Run performance benchmarks
run_benchmarks() {
    echo -e "${YELLOW}📊 Running performance benchmarks...${NC}"
    
    if [[ -f "Cargo.toml" ]] && grep -q "\[\[bench\]\]" Cargo.toml; then
        echo "Running existing benchmarks..."
        cargo bench --bench performance_suite 2>/dev/null || echo "No performance_suite benchmark found"
    fi
    
    # Create a simple benchmark if none exists
    if [[ ! -d "benches" ]]; then
        mkdir -p benches
        cat > benches/clean_code_performance.rs << 'EOF'
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use common::performance_utils::{efficient_concat, PerformanceCache};
use std::time::Duration;

fn benchmark_string_concat(c: &mut Criterion) {
    c.bench_function("efficient_concat", |b| {
        b.iter(|| {
            efficient_concat(black_box("prefix_"), black_box("suffix"))
        })
    });
}

fn benchmark_cache_operations(c: &mut Criterion) {
    let mut cache = PerformanceCache::new(1000);
    cache.insert("test_key", "test_value", Duration::from_secs(60));
    
    c.bench_function("cache_get", |b| {
        b.iter(|| {
            cache.get(black_box(&"test_key"))
        })
    });
}

criterion_group!(benches, benchmark_string_concat, benchmark_cache_operations);
criterion_main!(benches);
EOF
    fi
    
    echo -e "${GREEN}✅ Benchmarks ready${NC}"
}

# Main execution
main() {
    echo "Starting performance optimization..."
    echo ""
    
    create_performance_utils
    echo ""
    
    optimize_async_operations  
    echo ""
    
    create_memory_optimizations
    echo ""
    
    update_module_exports
    echo ""
    
    run_benchmarks
    echo ""
    
    echo -e "${GREEN}🎉 Performance optimization complete!${NC}"
    echo ""
    echo "Improvements implemented:"
    echo "• String allocation optimization with Cow<str>"
    echo "• Smart caching with hit rate metrics"
    echo "• Async batch processing with bounded concurrency"
    echo "• Memory optimization with object pooling"
    echo "• Intelligent retry mechanisms"
    echo ""
    echo "Next steps:"
    echo "1. Run 'cargo test' to verify all tests pass"
    echo "2. Run 'cargo bench' to measure performance improvements"
    echo "3. Update code to use new performance utilities"
    echo "4. Monitor performance metrics in production"
}

main "$@"
