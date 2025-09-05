use futures::stream::{self, StreamExt};
use std::future::Future;
use tokio::time::{timeout, Duration};

/// Process items concurrently with bounded parallelism
pub async fn process_batch<T, F, Fut, R, E>(
    items: Vec<T>,
    processor: F,
    concurrency: usize,
) -> Result<Vec<R>, E>
where
    F: Fn(T) -> Fut + Clone,
    Fut: Future<Output = Result<R, E>>,
{
    stream::iter(items)
        .map(processor)
        .buffer_unordered(concurrency)
        .try_collect()
        .await
}

/// Execute with timeout and proper error handling
pub async fn execute_with_timeout<F, T, E>(
    future: F,
    timeout_duration: Duration,
) -> Result<T, TimeoutError<E>>
where
    F: Future<Output = Result<T, E>>,
{
    match timeout(timeout_duration, future).await {
        Ok(result) => result.map_err(TimeoutError::Inner),
        Err(_) => Err(TimeoutError::Timeout),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TimeoutError<E> {
    #[error("Operation timed out")]
    Timeout,
    #[error("Inner error: {0}")]
    Inner(E),
}
