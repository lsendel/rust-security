use crate::session_manager::{SessionManager, SessionError};
use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};
use crate::security_metrics::SECURITY_METRICS;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{broadcast, RwLock};
use tokio::time::{interval, sleep, MissedTickBehavior};
use tracing::{debug, error, info, span, warn, Instrument, Level};
use uuid::Uuid;

/// Configuration for session cleanup scheduling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCleanupConfig {
    /// Base cleanup interval in seconds
    pub base_interval_secs: u64,
    /// Maximum jitter percentage (0.0 to 1.0)
    pub jitter_percent: f64,
    /// Minimum interval between cleanups in seconds
    pub min_interval_secs: u64,
    /// Maximum interval between cleanups in seconds
    pub max_interval_secs: u64,
    /// Batch size for processing sessions
    pub batch_size: u32,
    /// Maximum time budget for cleanup operation in seconds
    pub max_cleanup_time_secs: u64,
    /// Retry attempts for failed cleanup operations
    pub retry_attempts: u8,
    /// Retry delay in seconds
    pub retry_delay_secs: u64,
    /// Enable observability metrics
    pub enable_metrics: bool,
    /// Enable distributed cleanup coordination
    pub enable_coordination: bool,
    /// Cleanup priority levels
    pub priority_levels: CleanupPriorityConfig,
}

impl Default for SessionCleanupConfig {
    fn default() -> Self {
        Self {
            base_interval_secs: 300, // 5 minutes
            jitter_percent: 0.1,     // 10% jitter
            min_interval_secs: 60,   // 1 minute minimum
            max_interval_secs: 900,  // 15 minutes maximum
            batch_size: 100,
            max_cleanup_time_secs: 30, // 30 seconds budget
            retry_attempts: 3,
            retry_delay_secs: 5,
            enable_metrics: true,
            enable_coordination: true,
            priority_levels: CleanupPriorityConfig::default(),
        }
    }
}

/// Priority levels for different types of cleanup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupPriorityConfig {
    /// Priority for expired sessions (1-5, 5 is highest)
    pub expired_sessions: u8,
    /// Priority for inactive sessions
    pub inactive_sessions: u8,
    /// Priority for revoked sessions  
    pub revoked_sessions: u8,
    /// Priority for orphaned sessions
    pub orphaned_sessions: u8,
}

impl Default for CleanupPriorityConfig {
    fn default() -> Self {
        Self {
            expired_sessions: 5,    // Highest priority
            inactive_sessions: 4,
            revoked_sessions: 3,
            orphaned_sessions: 2,   // Lowest priority
        }
    }
}

/// Cleanup operation statistics
#[derive(Debug, Clone, Default)]
pub struct CleanupStats {
    pub total_runs: u64,
    pub successful_runs: u64,
    pub failed_runs: u64,
    pub total_sessions_cleaned: u64,
    pub expired_sessions_cleaned: u64,
    pub inactive_sessions_cleaned: u64,
    pub revoked_sessions_cleaned: u64,
    pub orphaned_sessions_cleaned: u64,
    pub avg_cleanup_time_ms: f64,
    pub last_cleanup_time: Option<u64>,
    pub next_scheduled_time: Option<u64>,
}

/// Shutdown signals for graceful cleanup termination
#[derive(Debug, Clone)]
pub enum ShutdownSignal {
    Graceful,
    Immediate,
    DrainAndStop,
}

/// Session cleanup scheduler with jitter and observability
pub struct SessionCleanupScheduler {
    config: SessionCleanupConfig,
    session_manager: Arc<SessionManager>,
    stats: Arc<RwLock<CleanupStats>>,
    is_running: AtomicBool,
    shutdown_sender: Arc<RwLock<Option<broadcast::Sender<ShutdownSignal>>>>,
    current_operation_id: AtomicU64,
    cleanup_start_time: AtomicU64,
}

impl SessionCleanupScheduler {
    pub fn new(config: SessionCleanupConfig, session_manager: Arc<SessionManager>) -> Self {
        Self {
            config,
            session_manager,
            stats: Arc::new(RwLock::new(CleanupStats::default())),
            is_running: AtomicBool::new(false),
            shutdown_sender: Arc::new(RwLock::new(None)),
            current_operation_id: AtomicU64::new(0),
            cleanup_start_time: AtomicU64::new(0),
        }
    }

    /// Start the cleanup scheduler with graceful shutdown support
    pub async fn start(&self) -> Result<(), CleanupError> {
        if self.is_running.swap(true, Ordering::SeqCst) {
            return Err(CleanupError::AlreadyRunning);
        }

        let (shutdown_sender, mut shutdown_receiver) = broadcast::channel(16);
        {
            let mut sender_guard = self.shutdown_sender.write().await;
            *sender_guard = Some(shutdown_sender);
        }

        info!("Starting session cleanup scheduler");
        
        // Log scheduler startup
        SecurityLogger::log_event(&SecurityEvent::new(
            SecurityEventType::SystemEvent,
            SecuritySeverity::Low,
            "auth-service".to_string(),
            "Session cleanup scheduler started".to_string(),
        )
        .with_detail("base_interval_secs".to_string(), self.config.base_interval_secs)
        .with_detail("jitter_percent".to_string(), self.config.jitter_percent)
        .with_detail("batch_size".to_string(), self.config.batch_size));

        let mut cleanup_interval = self.create_jittered_interval();
        cleanup_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = cleanup_interval.tick() => {
                    if let Err(e) = self.run_cleanup_cycle().await {
                        error!(error = %e, "Cleanup cycle failed");
                        self.increment_failed_runs().await;
                    }
                }
                
                signal = shutdown_receiver.recv() => {
                    match signal {
                        Ok(ShutdownSignal::Graceful) => {
                            info!("Received graceful shutdown signal, finishing current cleanup");
                            self.graceful_shutdown().await;
                            break;
                        }
                        Ok(ShutdownSignal::DrainAndStop) => {
                            info!("Received drain signal, completing all pending operations");
                            self.drain_and_stop().await;
                            break;
                        }
                        Ok(ShutdownSignal::Immediate) => {
                            warn!("Received immediate shutdown signal, stopping cleanup");
                            break;
                        }
                        Err(_) => {
                            // Shutdown sender dropped, normal shutdown
                            break;
                        }
                    }
                }
            }
        }

        self.is_running.store(false, Ordering::SeqCst);
        info!("Session cleanup scheduler stopped");
        
        // Log scheduler shutdown
        let stats = self.stats.read().await;
        SecurityLogger::log_event(&SecurityEvent::new(
            SecurityEventType::SystemEvent,
            SecuritySeverity::Low,
            "auth-service".to_string(),
            "Session cleanup scheduler stopped".to_string(),
        )
        .with_detail("total_runs".to_string(), stats.total_runs)
        .with_detail("successful_runs".to_string(), stats.successful_runs)
        .with_detail("failed_runs".to_string(), stats.failed_runs)
        .with_detail("total_sessions_cleaned".to_string(), stats.total_sessions_cleaned));

        Ok(())
    }

    /// Send shutdown signal to the scheduler
    pub async fn shutdown(&self, signal: ShutdownSignal) -> Result<(), CleanupError> {
        let sender_guard = self.shutdown_sender.read().await;
        if let Some(sender) = sender_guard.as_ref() {
            sender.send(signal).map_err(|_| CleanupError::ShutdownFailed)?;
            Ok(())
        } else {
            Err(CleanupError::NotRunning)
        }
    }

    /// Get current cleanup statistics
    pub async fn get_stats(&self) -> CleanupStats {
        self.stats.read().await.clone()
    }

    /// Check if scheduler is running
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /// Force an immediate cleanup cycle (for testing/admin)
    pub async fn force_cleanup(&self) -> Result<CleanupStats, CleanupError> {
        if !self.is_running() {
            return Err(CleanupError::NotRunning);
        }

        self.run_cleanup_cycle().await?;
        Ok(self.get_stats().await)
    }

    /// Create an interval with jitter
    fn create_jittered_interval(&self) -> tokio::time::Interval {
        let jittered_duration = self.calculate_jittered_interval();
        interval(jittered_duration)
    }

    /// Calculate the next cleanup interval with jitter
    fn calculate_jittered_interval(&self) -> Duration {
        let base_duration = Duration::from_secs(self.config.base_interval_secs);
        let jitter_amount = base_duration.as_secs_f64() * self.config.jitter_percent;
        
        let mut rng = rand::thread_rng();
        let jitter = rng.gen_range(-jitter_amount..=jitter_amount);
        
        let jittered_secs = (base_duration.as_secs() as f64 + jitter).max(0.0) as u64;
        let clamped_secs = jittered_secs
            .max(self.config.min_interval_secs)
            .min(self.config.max_interval_secs);
        
        Duration::from_secs(clamped_secs)
    }

    /// Run a complete cleanup cycle with observability
    async fn run_cleanup_cycle(&self) -> Result<(), CleanupError> {
        let operation_id = self.current_operation_id.fetch_add(1, Ordering::SeqCst);
        let start_time = Instant::now();
        let timestamp = current_timestamp();
        
        self.cleanup_start_time.store(timestamp, Ordering::SeqCst);
        
        let span = span!(Level::INFO, "cleanup_cycle", operation_id = operation_id);
        
        async move {
            debug!(operation_id = operation_id, "Starting cleanup cycle");
            
            // Update next scheduled time
            {
                let mut stats = self.stats.write().await;
                stats.next_scheduled_time = Some(timestamp + self.config.base_interval_secs);
            }

            let mut cleanup_result = CleanupCycleResult::new(operation_id);
            
            // Run cleanup with timeout
            let cleanup_future = self.execute_cleanup_with_retries(&mut cleanup_result);
            let timeout_duration = Duration::from_secs(self.config.max_cleanup_time_secs);
            
            match tokio::time::timeout(timeout_duration, cleanup_future).await {
                Ok(result) => {
                    match result {
                        Ok(_) => {
                            self.update_successful_cleanup_stats(cleanup_result, start_time.elapsed()).await;
                            debug!(operation_id = operation_id, "Cleanup cycle completed successfully");
                        }
                        Err(e) => {
                            error!(operation_id = operation_id, error = %e, "Cleanup cycle failed");
                            self.increment_failed_runs().await;
                            return Err(e);
                        }
                    }
                }
                Err(_) => {
                    let timeout_error = CleanupError::TimeoutExceeded(self.config.max_cleanup_time_secs);
                    error!(operation_id = operation_id, error = %timeout_error, "Cleanup cycle timed out");
                    self.increment_failed_runs().await;
                    return Err(timeout_error);
                }
            }
            
            // Update metrics if enabled
            if self.config.enable_metrics {
                SECURITY_METRICS.session_cleanups_total.inc();
                SECURITY_METRICS.session_cleanup_duration
                    .observe(start_time.elapsed().as_secs_f64());
            }
            
            Ok(())
        }.instrument(span).await
    }

    /// Execute cleanup with retry logic
    async fn execute_cleanup_with_retries(&self, result: &mut CleanupCycleResult) -> Result<(), CleanupError> {
        let mut last_error = None;
        
        for attempt in 1..=self.config.retry_attempts {
            match self.execute_single_cleanup(result).await {
                Ok(_) => {
                    if attempt > 1 {
                        info!(
                            operation_id = result.operation_id,
                            attempt = attempt,
                            "Cleanup succeeded after retry"
                        );
                    }
                    return Ok(());
                }
                Err(e) => {
                    last_error = Some(e.clone());
                    warn!(
                        operation_id = result.operation_id,
                        attempt = attempt,
                        max_attempts = self.config.retry_attempts,
                        error = %e,
                        "Cleanup attempt failed"
                    );
                    
                    if attempt < self.config.retry_attempts {
                        sleep(Duration::from_secs(self.config.retry_delay_secs)).await;
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or(CleanupError::UnknownError))
    }

    /// Execute a single cleanup operation
    async fn execute_single_cleanup(&self, result: &mut CleanupCycleResult) -> Result<(), CleanupError> {
        // Prioritized cleanup operations
        let operations = [
            ("expired", self.config.priority_levels.expired_sessions),
            ("inactive", self.config.priority_levels.inactive_sessions),
            ("revoked", self.config.priority_levels.revoked_sessions),
            ("orphaned", self.config.priority_levels.orphaned_sessions),
        ];
        
        // Sort by priority (highest first)
        let mut sorted_ops = operations.to_vec();
        sorted_ops.sort_by(|a, b| b.1.cmp(&a.1));
        
        for (cleanup_type, _priority) in sorted_ops {
            match cleanup_type {
                "expired" => {
                    let count = self.session_manager.cleanup_sessions().await
                        .map_err(|e| CleanupError::SessionManager(e))?;
                    result.expired_sessions_cleaned += count;
                    
                    debug!(
                        operation_id = result.operation_id,
                        count = count,
                        "Cleaned expired sessions"
                    );
                }
                "inactive" => {
                    // Additional inactive session cleanup could be added here
                    // For now, included in the main cleanup_sessions() call
                }
                "revoked" => {
                    // Additional revoked session cleanup could be added here
                    // This would require extending the session manager
                }
                "orphaned" => {
                    // Additional orphaned session cleanup could be added here
                    // This would require extending the session manager
                }
                _ => {} // Should not happen with current implementation
            }
        }
        
        // Log cleanup results
        if result.total_cleaned() > 0 {
            SecurityLogger::log_event(&SecurityEvent::new(
                SecurityEventType::DataAccess,
                SecuritySeverity::Low,
                "auth-service".to_string(),
                "Session cleanup completed".to_string(),
            )
            .with_detail("operation_id".to_string(), result.operation_id)
            .with_detail("expired_cleaned".to_string(), result.expired_sessions_cleaned)
            .with_detail("total_cleaned".to_string(), result.total_cleaned()));
        }
        
        Ok(())
    }

    /// Update statistics after successful cleanup
    async fn update_successful_cleanup_stats(&self, result: CleanupCycleResult, elapsed: Duration) {
        let mut stats = self.stats.write().await;
        
        stats.total_runs += 1;
        stats.successful_runs += 1;
        stats.total_sessions_cleaned += result.total_cleaned() as u64;
        stats.expired_sessions_cleaned += result.expired_sessions_cleaned as u64;
        stats.inactive_sessions_cleaned += result.inactive_sessions_cleaned as u64;
        stats.revoked_sessions_cleaned += result.revoked_sessions_cleaned as u64;
        stats.orphaned_sessions_cleaned += result.orphaned_sessions_cleaned as u64;
        stats.last_cleanup_time = Some(current_timestamp());
        
        // Update average cleanup time using exponential moving average
        let elapsed_ms = elapsed.as_millis() as f64;
        if stats.avg_cleanup_time_ms == 0.0 {
            stats.avg_cleanup_time_ms = elapsed_ms;
        } else {
            stats.avg_cleanup_time_ms = 0.9 * stats.avg_cleanup_time_ms + 0.1 * elapsed_ms;
        }
    }

    /// Increment failed runs counter
    async fn increment_failed_runs(&self) {
        let mut stats = self.stats.write().await;
        stats.total_runs += 1;
        stats.failed_runs += 1;
    }

    /// Gracefully shutdown, finishing current operation
    async fn graceful_shutdown(&self) {
        info!("Performing graceful cleanup scheduler shutdown");
        
        // Wait for current cleanup to complete if running
        let max_wait = Duration::from_secs(self.config.max_cleanup_time_secs + 10);
        let start_wait = Instant::now();
        
        while start_wait.elapsed() < max_wait {
            let current_start = self.cleanup_start_time.load(Ordering::SeqCst);
            if current_start == 0 || 
               current_timestamp().saturating_sub(current_start) > self.config.max_cleanup_time_secs {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// Drain all operations and stop
    async fn drain_and_stop(&self) {
        info!("Draining cleanup operations before shutdown");
        
        // Force one final cleanup
        if let Err(e) = self.run_cleanup_cycle().await {
            warn!(error = %e, "Final cleanup cycle failed during drain");
        }
        
        self.graceful_shutdown().await;
    }
}

/// Result of a cleanup cycle
#[derive(Debug)]
struct CleanupCycleResult {
    operation_id: u64,
    expired_sessions_cleaned: u32,
    inactive_sessions_cleaned: u32,
    revoked_sessions_cleaned: u32,
    orphaned_sessions_cleaned: u32,
}

impl CleanupCycleResult {
    fn new(operation_id: u64) -> Self {
        Self {
            operation_id,
            expired_sessions_cleaned: 0,
            inactive_sessions_cleaned: 0,
            revoked_sessions_cleaned: 0,
            orphaned_sessions_cleaned: 0,
        }
    }
    
    fn total_cleaned(&self) -> u32 {
        self.expired_sessions_cleaned + 
        self.inactive_sessions_cleaned + 
        self.revoked_sessions_cleaned + 
        self.orphaned_sessions_cleaned
    }
}

/// Cleanup scheduler errors
#[derive(Debug, Error)]
pub enum CleanupError {
    #[error("Scheduler is already running")]
    AlreadyRunning,
    #[error("Scheduler is not running")]
    NotRunning,
    #[error("Shutdown failed")]
    ShutdownFailed,
    #[error("Session manager error: {0}")]
    SessionManager(#[from] SessionError),
    #[error("Cleanup operation timed out after {0} seconds")]
    TimeoutExceeded(u64),
    #[error("Unknown error occurred")]
    UnknownError,
}

/// Helper function to get current timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Factory function to create and start session cleanup scheduler
pub async fn create_and_start_session_cleanup(
    config: SessionCleanupConfig,
    session_manager: Arc<SessionManager>,
) -> Result<Arc<SessionCleanupScheduler>, CleanupError> {
    let scheduler = Arc::new(SessionCleanupScheduler::new(config, session_manager));
    let scheduler_clone = Arc::clone(&scheduler);
    
    // Start the scheduler in a background task
    tokio::spawn(async move {
        if let Err(e) = scheduler_clone.start().await {
            error!(error = %e, "Session cleanup scheduler failed to start");
        }
    });
    
    // Wait a moment to ensure scheduler is initialized
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    Ok(scheduler)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_manager::SessionConfig;
    
    #[tokio::test]
    async fn test_jittered_interval_calculation() {
        let config = SessionCleanupConfig {
            base_interval_secs: 300,
            jitter_percent: 0.1,
            min_interval_secs: 60,
            max_interval_secs: 900,
            ..Default::default()
        };
        
        let session_manager = Arc::new(SessionManager::new(SessionConfig::default()));
        let scheduler = SessionCleanupScheduler::new(config.clone(), session_manager);
        
        // Test multiple intervals to ensure they're within bounds
        for _ in 0..10 {
            let interval = scheduler.calculate_jittered_interval();
            let secs = interval.as_secs();
            
            assert!(secs >= config.min_interval_secs);
            assert!(secs <= config.max_interval_secs);
            
            // Should be within jitter range of base interval
            let base = config.base_interval_secs as f64;
            let max_jitter = base * config.jitter_percent;
            assert!(secs as f64 >= base - max_jitter);
            assert!(secs as f64 <= base + max_jitter);
        }
    }
    
    #[tokio::test]
    async fn test_scheduler_lifecycle() {
        let config = SessionCleanupConfig {
            base_interval_secs: 1, // Fast for testing
            max_cleanup_time_secs: 5,
            ..Default::default()
        };
        
        let session_manager = Arc::new(SessionManager::new(SessionConfig::default()));
        let scheduler = Arc::new(SessionCleanupScheduler::new(config, session_manager));
        
        assert!(!scheduler.is_running());
        
        // Start scheduler in background
        let scheduler_clone = Arc::clone(&scheduler);
        let handle = tokio::spawn(async move {
            scheduler_clone.start().await
        });
        
        // Wait for startup
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(scheduler.is_running());
        
        // Test graceful shutdown
        scheduler.shutdown(ShutdownSignal::Graceful).await.unwrap();
        
        // Wait for shutdown
        tokio::time::timeout(Duration::from_secs(2), handle).await.unwrap().unwrap();
        assert!(!scheduler.is_running());
    }
    
    #[tokio::test]
    async fn test_cleanup_stats() {
        let config = SessionCleanupConfig::default();
        let session_manager = Arc::new(SessionManager::new(SessionConfig::default()));
        let scheduler = SessionCleanupScheduler::new(config, session_manager);
        
        let stats = scheduler.get_stats().await;
        assert_eq!(stats.total_runs, 0);
        assert_eq!(stats.successful_runs, 0);
        assert_eq!(stats.failed_runs, 0);
        assert_eq!(stats.total_sessions_cleaned, 0);
    }
    
    #[test]
    fn test_cleanup_cycle_result() {
        let mut result = CleanupCycleResult::new(123);
        assert_eq!(result.operation_id, 123);
        assert_eq!(result.total_cleaned(), 0);
        
        result.expired_sessions_cleaned = 5;
        result.inactive_sessions_cleaned = 3;
        assert_eq!(result.total_cleaned(), 8);
    }
}