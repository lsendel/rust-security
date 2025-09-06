//! Optimized async operations for the auth service
//!
//! This module provides performance-optimized async utilities specifically
//! designed for authentication and authorization workflows.

use futures::future::{BoxFuture, FutureExt};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};

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
    T: Clone + Send + 'static,
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
    pub async fn execute<F, Fut>(
        &self,
        input: T,
        operation: F,
    ) -> Result<R, Box<dyn std::error::Error + Send + Sync>>
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
            (0..batch_size)
                .map(|_| pending.pop_front().unwrap())
                .collect::<Vec<_>>()
        };

        if batch.is_empty() {
            return;
        }

        let inputs: Vec<T> = batch.iter().map(|op| op.input.clone()).collect();
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

impl Default for SmartRetry {
    fn default() -> Self {
        Self::new()
    }
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
                        Duration::from_millis(
                            (delay.as_millis() as f64 * self.backoff_multiplier) as u64,
                        ),
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
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let result = retry
            .execute(|| {
                let attempts = std::sync::Arc::clone(&attempts);
                async move {
                    let current = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    if current < 3 {
                        Err("temporary error")
                    } else {
                        Ok("success")
                    }
                }
            })
            .await;

        assert_eq!(result, Ok("success"));
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
    }
}
