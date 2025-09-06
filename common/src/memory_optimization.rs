//! Memory optimization utilities
//!
//! Provides tools for efficient memory usage in high-performance scenarios.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

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
            estimated_memory: self.pool.iter().map(|(k, v)| k.len() + v.len()).sum(),
        }
    }
}

impl Default for StringPool {
    fn default() -> Self {
        Self::new()
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
        if self.objects.len() < 100 {
            // Prevent unbounded growth
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
