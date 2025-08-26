// Phase 2: Redis Streams Message Bus for Async Communication
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use redis::streams::{StreamReadOptions, StreamReadReply};
use redis::{AsyncCommands, RedisResult};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn, instrument};
use uuid::Uuid;

/// High-performance message bus using Redis Streams
#[derive(Clone)]
pub struct MessageBus {
    redis: redis::aio::ConnectionManager,
    consumer_group: String,
    consumer_name: String,
    metrics: MessageBusMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMessage {
    pub id: Uuid,
    pub service: String,
    pub operation: String,
    pub payload: serde_json::Value,
    pub timestamp: u64,
    pub priority: MessagePriority,
    pub retry_count: u32,
    pub correlation_id: Option<Uuid>,
    pub trace_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessagePriority {
    Critical = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    Background = 4,
}

#[derive(Debug, Clone)]
pub struct MessageBusMetrics {
    pub messages_sent: prometheus::Counter,
    pub messages_received: prometheus::Counter,
    pub messages_processed: prometheus::Counter,
    pub messages_failed: prometheus::Counter,
    pub processing_duration: prometheus::Histogram,
    pub queue_depth: prometheus::Gauge,
}

impl MessageBus {
    pub async fn new(
        redis_url: &str,
        consumer_group: String,
        consumer_name: String,
        registry: &prometheus::Registry,
    ) -> Result<Self, MessageBusError> {
        let client = redis::Client::open(redis_url)?;
        let redis = client.get_connection_manager().await?;
        
        let metrics = MessageBusMetrics::new(registry)?;
        
        let bus = Self {
            redis,
            consumer_group,
            consumer_name,
            metrics,
        };
        
        // Initialize consumer groups for different message types
        bus.initialize_streams().await?;
        
        Ok(bus)
    }

    async fn initialize_streams(&self) -> Result<(), MessageBusError> {
        let streams = vec![
            "auth:events",
            "policy:events", 
            "audit:events",
            "metrics:events",
            "notifications:events",
        ];

        for stream in streams {
            // Create consumer group (ignore error if already exists)
            let _: RedisResult<()> = redis::cmd("XGROUP")
                .arg("CREATE")
                .arg(stream)
                .arg(&self.consumer_group)
                .arg("0")
                .arg("MKSTREAM")
                .query_async(&mut self.redis.clone())
                .await;
        }

        info!("Initialized message bus streams for consumer group: {}", self.consumer_group);
        Ok(())
    }

    /// Publish a message to a stream with automatic partitioning
    #[instrument(skip(self, message))]
    pub async fn publish(&self, stream: &str, message: ServiceMessage) -> Result<String, MessageBusError> {
        let mut redis = self.redis.clone();
        
        // Serialize message
        let serialized = serde_json::to_string(&message)?;
        
        // Add message to stream with automatic ID generation
        let message_id: String = redis.xadd(
            stream,
            "*",  // Auto-generate ID
            &[
                ("data", serialized.as_str()),
                ("service", message.service.as_str()),
                ("operation", message.operation.as_str()),
                ("priority", &(message.priority as u8).to_string()),
                ("timestamp", &message.timestamp.to_string()),
            ]
        ).await?;

        self.metrics.messages_sent.inc();
        debug!("Published message {} to stream {}", message_id, stream);
        
        Ok(message_id)
    }

    /// Publish high-priority message with immediate processing
    pub async fn publish_priority(&self, stream: &str, mut message: ServiceMessage) -> Result<String, MessageBusError> {
        message.priority = MessagePriority::High;
        let priority_stream = format!("{}:priority", stream);
        self.publish(&priority_stream, message).await
    }

    /// Publish fire-and-forget message for background processing
    pub async fn publish_background(&self, stream: &str, mut message: ServiceMessage) -> Result<String, MessageBusError> {
        message.priority = MessagePriority::Background;
        let background_stream = format!("{}:background", stream);
        self.publish(&background_stream, message).await
    }

    /// Subscribe to messages from multiple streams with priority handling
    #[instrument(skip(self))]
    pub async fn subscribe_multi(&self, streams: Vec<&str>, batch_size: usize) -> Result<mpsc::Receiver<ServiceMessage>, MessageBusError> {
        let (tx, rx) = mpsc::channel(1000);  // Buffer for high throughput
        let mut redis = self.redis.clone();
        let consumer_group = self.consumer_group.clone();
        let consumer_name = self.consumer_name.clone();
        let metrics = self.metrics.clone();

        tokio::spawn(async move {
            loop {
                // Read from priority streams first
                let mut priority_streams = Vec::new();
                let mut normal_streams = Vec::new();
                
                for stream in &streams {
                    priority_streams.push(format!("{}:priority", stream));
                    normal_streams.push(stream.to_string());
                }

                // Process priority messages first
                if let Ok(messages) = Self::read_stream_batch(
                    &mut redis,
                    &priority_streams,
                    &consumer_group,
                    &consumer_name,
                    batch_size / 2,  // Half batch size for priority
                ).await {
                    for message in messages {
                        if tx.send(message).await.is_err() {
                            warn!("Message channel closed, stopping subscriber");
                            return;
                        }
                        metrics.messages_received.inc();
                    }
                }

                // Then process normal messages
                if let Ok(messages) = Self::read_stream_batch(
                    &mut redis,
                    &normal_streams,
                    &consumer_group,
                    &consumer_name,
                    batch_size,
                ).await {
                    for message in messages {
                        if tx.send(message).await.is_err() {
                            warn!("Message channel closed, stopping subscriber");
                            return;
                        }
                        metrics.messages_received.inc();
                    }
                }

                // Small delay to prevent busy waiting
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        Ok(rx)
    }

    async fn read_stream_batch(
        redis: &mut redis::aio::ConnectionManager,
        streams: &[String],
        consumer_group: &str,
        consumer_name: &str,
        count: usize,
    ) -> Result<Vec<ServiceMessage>, MessageBusError> {
        if streams.is_empty() {
            return Ok(Vec::new());
        }

        // Build XREADGROUP command
        let mut cmd = redis::cmd("XREADGROUP");
        cmd.arg("GROUP")
           .arg(consumer_group)
           .arg(consumer_name)
           .arg("COUNT")
           .arg(count)
           .arg("BLOCK")
           .arg(50)  // 50ms block timeout
           .arg("STREAMS");

        // Add stream names
        for stream in streams {
            cmd.arg(stream);
        }

        // Add ">" for each stream to read new messages
        for _ in streams {
            cmd.arg(">");
        }

        let reply: StreamReadReply = cmd.query_async(redis).await?;
        let mut messages = Vec::new();

        for stream_key in reply.keys {
            for stream_id in stream_key.ids {
                if let Some(data) = stream_id.map.get("data") {
                    if let redis::Value::Data(bytes) = data {
                        match serde_json::from_slice::<ServiceMessage>(bytes) {
                            Ok(message) => messages.push(message),
                            Err(e) => {
                                error!("Failed to deserialize message: {}", e);
                            }
                        }
                    }
                }
            }
        }

        Ok(messages)
    }

    /// Acknowledge message processing completion
    pub async fn ack_message(&self, stream: &str, message_id: &str) -> Result<(), MessageBusError> {
        let mut redis = self.redis.clone();
        
        let _: i32 = redis::cmd("XACK")
            .arg(stream)
            .arg(&self.consumer_group)
            .arg(message_id)
            .query_async(&mut redis)
            .await?;

        self.metrics.messages_processed.inc();
        debug!("Acknowledged message {} in stream {}", message_id, stream);
        
        Ok(())
    }

    /// Get pending messages for this consumer
    pub async fn get_pending_messages(&self, stream: &str) -> Result<Vec<PendingMessage>, MessageBusError> {
        let mut redis = self.redis.clone();
        
        let reply: redis::Value = redis::cmd("XPENDING")
            .arg(stream)
            .arg(&self.consumer_group)
            .arg("-")
            .arg("+")
            .arg(100)  // Max 100 pending messages
            .query_async(&mut redis)
            .await?;

        let mut pending = Vec::new();
        
        if let redis::Value::Bulk(items) = reply {
            for item in items {
                if let redis::Value::Bulk(details) = item {
                    if details.len() >= 4 {
                        if let (
                            redis::Value::Data(id),
                            redis::Value::Data(consumer),
                            redis::Value::Int(idle_time),
                            redis::Value::Int(delivery_count),
                        ) = (&details[0], &details[1], &details[2], &details[3]) {
                            pending.push(PendingMessage {
                                id: String::from_utf8_lossy(id).to_string(),
                                consumer: String::from_utf8_lossy(consumer).to_string(),
                                idle_time_ms: *idle_time as u64,
                                delivery_count: *delivery_count as u32,
                            });
                        }
                    }
                }
            }
        }

        Ok(pending)
    }

    /// Claim and retry pending messages
    pub async fn claim_pending_messages(&self, stream: &str, min_idle_time_ms: u64) -> Result<Vec<ServiceMessage>, MessageBusError> {
        let pending = self.get_pending_messages(stream).await?;
        let mut claimed_messages = Vec::new();

        for pending_msg in pending {
            if pending_msg.idle_time_ms >= min_idle_time_ms {
                // Claim the message
                let mut redis = self.redis.clone();
                let reply: StreamReadReply = redis::cmd("XCLAIM")
                    .arg(stream)
                    .arg(&self.consumer_group)
                    .arg(&self.consumer_name)
                    .arg(min_idle_time_ms)
                    .arg(&pending_msg.id)
                    .query_async(&mut redis)
                    .await?;

                // Parse claimed messages
                for stream_key in reply.keys {
                    for stream_id in stream_key.ids {
                        if let Some(data) = stream_id.map.get("data") {
                            if let redis::Value::Data(bytes) = data {
                                if let Ok(mut message) = serde_json::from_slice::<ServiceMessage>(bytes) {
                                    message.retry_count += 1;
                                    claimed_messages.push(message);
                                }
                            }
                        }
                    }
                }
            }
        }

        info!("Claimed {} pending messages from stream {}", claimed_messages.len(), stream);
        Ok(claimed_messages)
    }

    /// Get stream information and metrics
    pub async fn get_stream_info(&self, stream: &str) -> Result<StreamInfo, MessageBusError> {
        let mut redis = self.redis.clone();
        
        let reply: redis::Value = redis::cmd("XINFO")
            .arg("STREAM")
            .arg(stream)
            .query_async(&mut redis)
            .await?;

        let mut info = StreamInfo {
            length: 0,
            radix_tree_keys: 0,
            radix_tree_nodes: 0,
            groups: 0,
            last_generated_id: String::new(),
            first_entry: None,
            last_entry: None,
        };

        if let redis::Value::Bulk(items) = reply {
            for chunk in items.chunks(2) {
                if chunk.len() == 2 {
                    if let (redis::Value::Data(key), value) = (&chunk[0], &chunk[1]) {
                        let key_str = String::from_utf8_lossy(key);
                        match key_str.as_ref() {
                            "length" => {
                                if let redis::Value::Int(len) = value {
                                    info.length = *len as u64;
                                }
                            }
                            "radix-tree-keys" => {
                                if let redis::Value::Int(keys) = value {
                                    info.radix_tree_keys = *keys as u64;
                                }
                            }
                            "radix-tree-nodes" => {
                                if let redis::Value::Int(nodes) = value {
                                    info.radix_tree_nodes = *nodes as u64;
                                }
                            }
                            "groups" => {
                                if let redis::Value::Int(groups) = value {
                                    info.groups = *groups as u64;
                                }
                            }
                            "last-generated-id" => {
                                if let redis::Value::Data(id) = value {
                                    info.last_generated_id = String::from_utf8_lossy(id).to_string();
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(info)
    }

    /// Update queue depth metric
    pub async fn update_queue_metrics(&self, streams: &[&str]) -> Result<(), MessageBusError> {
        let mut total_depth = 0;
        
        for stream in streams {
            if let Ok(info) = self.get_stream_info(stream).await {
                total_depth += info.length;
            }
        }
        
        self.metrics.queue_depth.set(total_depth as f64);
        Ok(())
    }
}

impl MessageBusMetrics {
    fn new(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        use prometheus::{Counter, Histogram, Gauge, Opts, HistogramOpts};

        let messages_sent = Counter::with_opts(
            Opts::new("message_bus_messages_sent_total", "Total messages sent")
        )?;

        let messages_received = Counter::with_opts(
            Opts::new("message_bus_messages_received_total", "Total messages received")
        )?;

        let messages_processed = Counter::with_opts(
            Opts::new("message_bus_messages_processed_total", "Total messages processed")
        )?;

        let messages_failed = Counter::with_opts(
            Opts::new("message_bus_messages_failed_total", "Total messages failed")
        )?;

        let processing_duration = Histogram::with_opts(
            HistogramOpts::new("message_bus_processing_duration_seconds", "Message processing duration")
                .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
        )?;

        let queue_depth = Gauge::with_opts(
            Opts::new("message_bus_queue_depth", "Current queue depth across all streams")
        )?;

        registry.register(Box::new(messages_sent.clone()))?;
        registry.register(Box::new(messages_received.clone()))?;
        registry.register(Box::new(messages_processed.clone()))?;
        registry.register(Box::new(messages_failed.clone()))?;
        registry.register(Box::new(processing_duration.clone()))?;
        registry.register(Box::new(queue_depth.clone()))?;

        Ok(Self {
            messages_sent,
            messages_received,
            messages_processed,
            messages_failed,
            processing_duration,
            queue_depth,
        })
    }
}

// Helper types
#[derive(Debug)]
pub struct PendingMessage {
    pub id: String,
    pub consumer: String,
    pub idle_time_ms: u64,
    pub delivery_count: u32,
}

#[derive(Debug)]
pub struct StreamInfo {
    pub length: u64,
    pub radix_tree_keys: u64,
    pub radix_tree_nodes: u64,
    pub groups: u64,
    pub last_generated_id: String,
    pub first_entry: Option<String>,
    pub last_entry: Option<String>,
}

// Utility functions for creating messages
impl ServiceMessage {
    pub fn new(service: String, operation: String, payload: serde_json::Value) -> Self {
        Self {
            id: Uuid::new_v4(),
            service,
            operation,
            payload,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            priority: MessagePriority::Normal,
            retry_count: 0,
            correlation_id: None,
            trace_id: None,
        }
    }

    pub fn with_priority(mut self, priority: MessagePriority) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: Uuid) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    pub fn with_trace_id(mut self, trace_id: String) -> Self {
        self.trace_id = Some(trace_id);
        self
    }
}

// Error types
#[derive(Debug, thiserror::Error)]
pub enum MessageBusError {
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Prometheus error: {0}")]
    PrometheusError(#[from] prometheus::Error),
    #[error("Channel error: {0}")]
    ChannelError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_message_creation() {
        let message = ServiceMessage::new(
            "auth-service".to_string(),
            "user_login".to_string(),
            serde_json::json!({"user_id": "123", "timestamp": 1234567890}),
        ).with_priority(MessagePriority::High);

        assert_eq!(message.service, "auth-service");
        assert_eq!(message.operation, "user_login");
        assert_eq!(message.priority, MessagePriority::High);
        assert!(message.id != Uuid::nil());
    }

    #[test]
    async fn test_message_serialization() {
        let message = ServiceMessage::new(
            "test-service".to_string(),
            "test_operation".to_string(),
            serde_json::json!({"test": "data"}),
        );

        let serialized = serde_json::to_string(&message).unwrap();
        let deserialized: ServiceMessage = serde_json::from_str(&serialized).unwrap();

        assert_eq!(message.id, deserialized.id);
        assert_eq!(message.service, deserialized.service);
        assert_eq!(message.operation, deserialized.operation);
    }
}
