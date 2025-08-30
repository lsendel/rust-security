//! Graceful shutdown handling for production deployments
//!
//! This module provides graceful shutdown capabilities for the authentication service,
//! ensuring that ongoing requests are completed and resources are properly cleaned up.

use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::{broadcast, Notify};
use tracing::{error, info, warn};

/// Graceful shutdown coordinator
#[derive(Clone)]
pub struct ShutdownCoordinator {
    /// Shutdown signal broadcaster
    shutdown_tx: broadcast::Sender<()>,
    /// Notification for shutdown completion
    completed: Arc<Notify>,
    /// Maximum time to wait for graceful shutdown
    graceful_timeout: Duration,
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator
    #[must_use]
    pub fn new(graceful_timeout: Duration) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            shutdown_tx,
            completed: Arc::new(Notify::new()),
            graceful_timeout,
        }
    }

    /// Get a shutdown signal receiver
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Start listening for shutdown signals
    pub async fn listen_for_shutdown(&self) {
        info!("Setting up graceful shutdown handlers");

        let signal_type = self.wait_for_any_shutdown_signal().await;
        info!("Received {}, initiating graceful shutdown", signal_type);
        self.initiate_shutdown().await;
    }

    /// Wait for any shutdown signal and return the signal type
    async fn wait_for_any_shutdown_signal(&self) -> &'static str {
        tokio::select! {
            () = self.wait_for_sigint() => "SIGINT",
            () = self.wait_for_sigterm() => "SIGTERM",
        }
    }

    async fn initiate_shutdown(&self) {
        self.broadcast_shutdown_signal();
        self.wait_for_shutdown_completion().await;
    }

    /// Broadcast shutdown signal to all components
    fn broadcast_shutdown_signal(&self) {
        if let Err(e) = self.shutdown_tx.send(()) {
            warn!("Failed to send shutdown signal: {}", e);
        }
    }

    /// Wait for graceful shutdown completion or timeout
    async fn wait_for_shutdown_completion(&self) {
        tokio::select! {
            () = self.completed.notified() => {
                info!("Graceful shutdown completed successfully");
            }
            () = tokio::time::sleep(self.graceful_timeout) => {
                warn!(
                    timeout_seconds = self.graceful_timeout.as_secs(),
                    "Graceful shutdown timeout reached, forcing exit"
                );
            }
        }
    }

    /// Wait for SIGINT signal
    async fn wait_for_sigint(&self) {
        #[cfg(unix)]
        {
            if let Err(e) = signal::ctrl_c().await {
                error!("Failed to listen for SIGINT: {}", e);
            }
        }

        #[cfg(not(unix))]
        {
            if let Err(e) = signal::ctrl_c().await {
                error!("Failed to listen for Ctrl+C: {}", e);
            }
        }
    }

    /// Wait for SIGTERM signal (Unix only)
    async fn wait_for_sigterm(&self) {
        #[cfg(unix)]
        {
            use signal::unix::{signal, SignalKind};

            match signal(SignalKind::terminate()) {
                Ok(mut stream) => {
                    stream.recv().await;
                }
                Err(e) => {
                    error!("Failed to register SIGTERM handler: {}", e);
                    // Fallback to infinite sleep on non-Unix or error
                    std::future::pending::<()>().await;
                }
            }
        }

        #[cfg(not(unix))]
        {
            // On non-Unix systems, just wait indefinitely
            std::future::pending::<()>().await;
        }
    }

    /// Notify that shutdown has completed
    pub fn notify_completed(&self) {
        self.completed.notify_waiters();
    }
}

/// Graceful shutdown service for managing active connections and resources
#[derive(Clone)]
pub struct GracefulShutdownService {
    coordinator: ShutdownCoordinator,
    active_connections: Arc<tokio::sync::RwLock<u32>>,
    is_shutting_down: Arc<tokio::sync::RwLock<bool>>,
}

impl GracefulShutdownService {
    /// Create a new graceful shutdown service
    #[must_use]
    pub fn new(graceful_timeout: Duration) -> Self {
        Self {
            coordinator: ShutdownCoordinator::new(graceful_timeout),
            active_connections: Arc::new(tokio::sync::RwLock::new(0)),
            is_shutting_down: Arc::new(tokio::sync::RwLock::new(false)),
        }
    }

    /// Get the shutdown coordinator
    #[must_use]
    pub const fn coordinator(&self) -> &ShutdownCoordinator {
        &self.coordinator
    }

    /// Start the graceful shutdown listener
    pub fn start_shutdown_listener(&self) {
        let coordinator = self.coordinator.clone();
        let service = self.clone();

        tokio::spawn(async move {
            coordinator.listen_for_shutdown().await;
            service.begin_shutdown().await;
        });
    }

    /// Check if the service is shutting down
    pub async fn is_shutting_down(&self) -> bool {
        *self.is_shutting_down.read().await
    }

    /// Increment active connections count
    pub async fn connection_started(&self) {
        let mut count = self.active_connections.write().await;
        *count += 1;
    }

    /// Decrement active connections count
    pub async fn connection_ended(&self) {
        let mut count = self.active_connections.write().await;
        if *count > 0 {
            *count -= 1;
        }
    }

    /// Get current active connections count
    pub async fn active_connections(&self) -> u32 {
        *self.active_connections.read().await
    }

    /// Begin the shutdown process
    async fn begin_shutdown(&self) {
        info!("Beginning graceful shutdown process");

        // Mark as shutting down
        {
            let mut shutting_down = self.is_shutting_down.write().await;
            *shutting_down = true;
        }

        // Wait for active connections to finish
        self.wait_for_connections_to_finish().await;

        // Perform cleanup tasks
        self.cleanup_resources().await;

        // Notify completion
        self.coordinator.notify_completed();
    }

    async fn wait_for_connections_to_finish(&self) {
        const MAX_WAIT_TIME: Duration = Duration::from_secs(30);
        const CHECK_INTERVAL: Duration = Duration::from_secs(1);

        let start_time = std::time::Instant::now();

        while !self.should_stop_waiting(start_time, MAX_WAIT_TIME).await {
            let active = self.active_connections().await;

            if active == 0 {
                info!("All connections completed, shutdown ready");
                return;
            }

            self.log_waiting_status(active);
            tokio::time::sleep(CHECK_INTERVAL).await;
        }

        self.handle_shutdown_timeout().await;
    }

    /// Check if we should stop waiting for connections
    async fn should_stop_waiting(
        &self,
        start_time: std::time::Instant,
        max_wait: Duration,
    ) -> bool {
        start_time.elapsed() > max_wait
    }

    /// Log current waiting status
    fn log_waiting_status(active_connections: u32) {
        info!(
            active_connections = active_connections,
            "Waiting for connections to complete"
        );
    }

    /// Handle shutdown timeout scenario
    async fn handle_shutdown_timeout(&self) {
        let active = self.active_connections().await;
        warn!(
            active_connections = active,
            "Shutdown timeout reached with active connections"
        );
    }

    /// Perform resource cleanup
    async fn cleanup_resources(&self) {
        info!("Performing resource cleanup");

        // In a real implementation, you would:
        // - Close database connections
        // - Flush logs
        // - Save any pending data
        // - Close file handles
        // - Cleanup temporary files

        // Simulate cleanup work
        tokio::time::sleep(Duration::from_millis(100)).await;

        info!("Resource cleanup completed");
    }
}

/// Middleware for tracking active connections
pub struct ConnectionTracker {
    #[allow(dead_code)]
    service: GracefulShutdownService,
}

impl ConnectionTracker {
    #[must_use]
    pub const fn new(service: GracefulShutdownService) -> Self {
        Self { service }
    }
}

/// RAII guard for connection tracking
pub struct ConnectionGuard {
    service: GracefulShutdownService,
    _dropped: bool,
}

impl ConnectionGuard {
    pub async fn new(service: GracefulShutdownService) -> Option<Self> {
        // Don't accept new connections during shutdown
        if service.is_shutting_down().await {
            return None;
        }

        service.connection_started().await;

        Some(Self {
            service,
            _dropped: false,
        })
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let service = self.service.clone();
        tokio::spawn(async move {
            service.connection_ended().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_shutdown_coordinator_creation() {
        let coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        let _receiver = coordinator.subscribe();

        // Should be able to create multiple receivers
        let _receiver2 = coordinator.subscribe();
    }

    #[tokio::test]
    async fn test_graceful_shutdown_service() {
        let service = GracefulShutdownService::new(Duration::from_secs(1));

        // Initially no connections
        assert_eq!(service.active_connections().await, 0);
        assert!(!service.is_shutting_down().await);

        // Add connection
        service.connection_started().await;
        assert_eq!(service.active_connections().await, 1);

        // Remove connection
        service.connection_ended().await;
        assert_eq!(service.active_connections().await, 0);
    }

    #[tokio::test]
    async fn test_connection_guard() {
        let service = GracefulShutdownService::new(Duration::from_secs(1));

        {
            let _guard = ConnectionGuard::new(service.clone()).await.unwrap();
            assert_eq!(service.active_connections().await, 1);
        } // Guard drops here

        // Give some time for the Drop to execute
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(service.active_connections().await, 0);
    }

    #[tokio::test]
    async fn test_shutdown_blocks_new_connections() {
        let service = GracefulShutdownService::new(Duration::from_secs(1));

        // Mark as shutting down
        {
            let mut shutting_down = service.is_shutting_down.write().await;
            *shutting_down = true;
        }

        // Should reject new connections
        let guard = ConnectionGuard::new(service.clone()).await;
        assert!(guard.is_none());
    }
}
