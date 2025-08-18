"""
Configuration management for the ML Attack Detection System.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml
import os
from .types import ThreatLevel, AttackCategory


@dataclass
class ModelConfig:
    """Configuration for individual ML models."""
    name: str = "default_model"
    model_type: str = "isolation_forest"
    enabled: bool = True
    
    # Model parameters
    hyperparameters: Dict[str, Any] = field(default_factory=dict)
    feature_columns: List[str] = field(default_factory=list)
    
    # Training configuration
    train_test_split: float = 0.8
    validation_split: float = 0.2
    cross_validation_folds: int = 5
    
    # Detection thresholds
    threshold: float = 0.8
    min_confidence: float = 0.6
    
    # Performance settings
    batch_size: int = 1000
    max_memory_usage: str = "1GB"
    enable_gpu: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "model_type": self.model_type,
            "enabled": self.enabled,
            "hyperparameters": self.hyperparameters,
            "feature_columns": self.feature_columns,
            "train_test_split": self.train_test_split,
            "validation_split": self.validation_split,
            "cross_validation_folds": self.cross_validation_folds,
            "threshold": self.threshold,
            "min_confidence": self.min_confidence,
            "batch_size": self.batch_size,
            "max_memory_usage": self.max_memory_usage,
            "enable_gpu": self.enable_gpu
        }


@dataclass
class FeatureConfig:
    """Configuration for feature engineering."""
    # Behavioral features
    enable_behavioral_features: bool = True
    login_frequency_window: int = 3600  # seconds
    session_timeout: int = 1800  # seconds
    
    # Network features
    enable_network_features: bool = True
    ip_geolocation: bool = True
    dns_resolution: bool = True
    
    # Temporal features
    enable_temporal_features: bool = True
    time_window_sizes: List[int] = field(default_factory=lambda: [60, 300, 3600])
    
    # Text features (for log analysis)
    enable_text_features: bool = True
    max_text_length: int = 1000
    text_vectorizer: str = "tfidf"  # tfidf, word2vec, bert
    
    # Feature scaling and normalization
    scaling_method: str = "standard"  # standard, minmax, robust
    handle_missing_values: str = "median"  # median, mean, drop, forward_fill
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "enable_behavioral_features": self.enable_behavioral_features,
            "login_frequency_window": self.login_frequency_window,
            "session_timeout": self.session_timeout,
            "enable_network_features": self.enable_network_features,
            "ip_geolocation": self.ip_geolocation,
            "dns_resolution": self.dns_resolution,
            "enable_temporal_features": self.enable_temporal_features,
            "time_window_sizes": self.time_window_sizes,
            "enable_text_features": self.enable_text_features,
            "max_text_length": self.max_text_length,
            "text_vectorizer": self.text_vectorizer,
            "scaling_method": self.scaling_method,
            "handle_missing_values": self.handle_missing_values
        }


@dataclass
class AlertConfig:
    """Configuration for alerting and notifications."""
    # Threshold settings
    critical_threshold: float = 0.95
    high_threshold: float = 0.85
    medium_threshold: float = 0.7
    low_threshold: float = 0.5
    
    # Rate limiting
    max_alerts_per_minute: int = 10
    max_alerts_per_hour: int = 100
    alert_cooldown: int = 300  # seconds
    
    # Notification channels
    enable_email: bool = False
    enable_slack: bool = False
    enable_webhook: bool = True
    webhook_url: Optional[str] = None
    
    # Alert correlation
    enable_correlation: bool = True
    correlation_window: int = 900  # seconds
    min_correlation_events: int = 3
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "critical_threshold": self.critical_threshold,
            "high_threshold": self.high_threshold,
            "medium_threshold": self.medium_threshold,
            "low_threshold": self.low_threshold,
            "max_alerts_per_minute": self.max_alerts_per_minute,
            "max_alerts_per_hour": self.max_alerts_per_hour,
            "alert_cooldown": self.alert_cooldown,
            "enable_email": self.enable_email,
            "enable_slack": self.enable_slack,
            "enable_webhook": self.enable_webhook,
            "webhook_url": self.webhook_url,
            "enable_correlation": self.enable_correlation,
            "correlation_window": self.correlation_window,
            "min_correlation_events": self.min_correlation_events
        }


@dataclass
class DataConfig:
    """Configuration for data sources and storage."""
    # Input sources
    input_sources: List[str] = field(default_factory=lambda: ["redis", "kafka", "file"])
    redis_url: str = "redis://localhost:6379"
    kafka_brokers: List[str] = field(default_factory=lambda: ["localhost:9092"])
    kafka_topics: List[str] = field(default_factory=lambda: ["security-events"])
    
    # Data storage
    database_url: str = "sqlite:///attack_detection.db"
    enable_data_retention: bool = True
    data_retention_days: int = 90
    
    # Data preprocessing
    max_event_size: int = 1048576  # 1MB
    enable_data_validation: bool = True
    drop_invalid_events: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "input_sources": self.input_sources,
            "redis_url": self.redis_url,
            "kafka_brokers": self.kafka_brokers,
            "kafka_topics": self.kafka_topics,
            "database_url": self.database_url,
            "enable_data_retention": self.enable_data_retention,
            "data_retention_days": self.data_retention_days,
            "max_event_size": self.max_event_size,
            "enable_data_validation": self.enable_data_validation,
            "drop_invalid_events": self.drop_invalid_events
        }


@dataclass
class DetectionConfig:
    """Main configuration class for the detection system."""
    # Model configurations
    models: List[ModelConfig] = field(default_factory=list)
    
    # Feature engineering
    features: FeatureConfig = field(default_factory=FeatureConfig)
    
    # Alerting
    alerts: AlertConfig = field(default_factory=AlertConfig)
    
    # Data management
    data: DataConfig = field(default_factory=DataConfig)
    
    # System settings
    enable_online_learning: bool = True
    model_update_interval: int = 3600  # seconds
    enable_model_drift_detection: bool = True
    
    # Performance settings
    max_concurrent_requests: int = 1000
    request_timeout: int = 30  # seconds
    enable_caching: bool = True
    cache_ttl: int = 300  # seconds
    
    # Logging and monitoring
    log_level: str = "INFO"
    enable_metrics: bool = True
    metrics_port: int = 9090
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "models": [model.to_dict() for model in self.models],
            "features": self.features.to_dict(),
            "alerts": self.alerts.to_dict(),
            "data": self.data.to_dict(),
            "enable_online_learning": self.enable_online_learning,
            "model_update_interval": self.model_update_interval,
            "enable_model_drift_detection": self.enable_model_drift_detection,
            "max_concurrent_requests": self.max_concurrent_requests,
            "request_timeout": self.request_timeout,
            "enable_caching": self.enable_caching,
            "cache_ttl": self.cache_ttl,
            "log_level": self.log_level,
            "enable_metrics": self.enable_metrics,
            "metrics_port": self.metrics_port
        }
    
    @classmethod
    def from_file(cls, config_path: Union[str, Path]) -> 'DetectionConfig':
        """Load configuration from YAML file."""
        config_path = Path(config_path)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_path, 'r') as f:
            data = yaml.safe_load(f)
        
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DetectionConfig':
        """Create configuration from dictionary."""
        # Parse models
        models = []
        for model_data in data.get('models', []):
            models.append(ModelConfig(**model_data))
        
        # Parse other components
        features = FeatureConfig(**data.get('features', {}))
        alerts = AlertConfig(**data.get('alerts', {}))
        data_config = DataConfig(**data.get('data', {}))
        
        return cls(
            models=models,
            features=features,
            alerts=alerts,
            data=data_config,
            enable_online_learning=data.get('enable_online_learning', True),
            model_update_interval=data.get('model_update_interval', 3600),
            enable_model_drift_detection=data.get('enable_model_drift_detection', True),
            max_concurrent_requests=data.get('max_concurrent_requests', 1000),
            request_timeout=data.get('request_timeout', 30),
            enable_caching=data.get('enable_caching', True),
            cache_ttl=data.get('cache_ttl', 300),
            log_level=data.get('log_level', 'INFO'),
            enable_metrics=data.get('enable_metrics', True),
            metrics_port=data.get('metrics_port', 9090)
        )
    
    def save_to_file(self, config_path: Union[str, Path]) -> None:
        """Save configuration to YAML file."""
        config_path = Path(config_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, indent=2)
    
    def add_model(self, model_config: ModelConfig) -> None:
        """Add a model configuration."""
        self.models.append(model_config)
    
    def get_model_config(self, name: str) -> Optional[ModelConfig]:
        """Get model configuration by name."""
        for model in self.models:
            if model.name == name:
                return model
        return None
    
    def remove_model(self, name: str) -> bool:
        """Remove model configuration by name."""
        for i, model in enumerate(self.models):
            if model.name == name:
                del self.models[i]
                return True
        return False


def load_default_config() -> DetectionConfig:
    """Load the default configuration."""
    # Default model configurations
    isolation_forest = ModelConfig(
        name="isolation_forest",
        model_type="isolation_forest",
        hyperparameters={
            "n_estimators": 100,
            "contamination": 0.1,
            "random_state": 42
        },
        threshold=0.8
    )
    
    autoencoder = ModelConfig(
        name="autoencoder",
        model_type="autoencoder",
        hyperparameters={
            "hidden_layers": [128, 64, 32, 64, 128],
            "activation": "relu",
            "optimizer": "adam",
            "learning_rate": 0.001,
            "epochs": 100,
            "batch_size": 32
        },
        threshold=0.75
    )
    
    random_forest = ModelConfig(
        name="random_forest",
        model_type="random_forest",
        hyperparameters={
            "n_estimators": 100,
            "max_depth": 10,
            "min_samples_split": 2,
            "min_samples_leaf": 1,
            "random_state": 42
        },
        threshold=0.85
    )
    
    return DetectionConfig(
        models=[isolation_forest, autoencoder, random_forest]
    )


def get_config_from_env() -> DetectionConfig:
    """Get configuration from environment variables."""
    config = load_default_config()
    
    # Override with environment variables if present
    if redis_url := os.getenv("REDIS_URL"):
        config.data.redis_url = redis_url
    
    if kafka_brokers := os.getenv("KAFKA_BROKERS"):
        config.data.kafka_brokers = kafka_brokers.split(",")
    
    if database_url := os.getenv("DATABASE_URL"):
        config.data.database_url = database_url
    
    if log_level := os.getenv("LOG_LEVEL"):
        config.log_level = log_level
    
    if webhook_url := os.getenv("WEBHOOK_URL"):
        config.alerts.webhook_url = webhook_url
        config.alerts.enable_webhook = True
    
    return config