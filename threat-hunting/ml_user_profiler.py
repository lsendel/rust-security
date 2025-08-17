#!/usr/bin/env python3
"""
Advanced Machine Learning User Behavior Profiling System
for Threat Hunting in Rust Authentication Service

This module implements sophisticated ML models for user behavior profiling,
anomaly detection, and risk scoring to identify potential account compromises
and insider threats.
"""

import asyncio
import json
import logging
import numpy as np
import pandas as pd
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, time
from typing import Dict, List, Optional, Tuple, Any, Set
import joblib
import pickle

# Machine Learning imports
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.decomposition import PCA
from scipy import stats
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import LSTM, Dense, Dropout, Input, Embedding
from tensorflow.keras.optimizers import Adam

# Database and caching
import asyncpg
import redis.asyncio as redis

# Monitoring
from prometheus_client import Counter, Histogram, Gauge

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Prometheus metrics
ML_PREDICTIONS = Counter(
    'ml_predictions_total',
    'Total ML predictions made',
    ['model_type', 'prediction_type']
)

MODEL_ACCURACY = Gauge(
    'model_accuracy_score',
    'Current model accuracy scores',
    ['model_name']
)

PROFILING_DURATION = Histogram(
    'user_profiling_duration_seconds',
    'Duration of user profiling operations',
    ['operation_type']
)

ANOMALY_SCORES = Histogram(
    'user_anomaly_scores',
    'Distribution of user anomaly scores',
    buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
)


@dataclass
class UserFeatures:
    """Comprehensive user feature set for ML models"""
    user_id: str
    
    # Temporal features
    avg_login_hour: float
    login_hour_variance: float
    avg_session_duration: float
    login_frequency_weekly: float
    weekend_login_ratio: float
    
    # Geographic features
    unique_locations_count: int
    location_entropy: float
    avg_distance_from_home: float
    
    # Device and technical features
    unique_devices_count: int
    unique_user_agents_count: int
    device_switching_frequency: float
    
    # Behavioral features
    failed_login_rate: float
    mfa_usage_rate: float
    privilege_escalation_attempts: int
    
    # Risk indicators
    security_events_count: int
    suspicious_activity_score: float
    compliance_violations: int
    
    # Network features
    unique_ip_count: int
    vpn_usage_rate: float
    proxy_usage_rate: float
    
    # Advanced features
    typing_pattern_consistency: float
    mouse_movement_consistency: float
    screen_resolution_changes: int


@dataclass
class RiskAssessment:
    """Risk assessment result for a user"""
    user_id: str
    risk_score: float
    risk_level: str  # low, medium, high, critical
    confidence: float
    contributing_factors: List[str]
    anomaly_indicators: List[str]
    recommended_actions: List[str]
    model_predictions: Dict[str, float]
    assessment_timestamp: datetime


class AdvancedUserProfiler:
    """Advanced ML-based user behavior profiling and risk assessment"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379", 
                 postgres_url: str = "postgresql://localhost/security_db"):
        self.redis_url = redis_url
        self.postgres_url = postgres_url
        self.redis_client = None
        self.db_pool = None
        
        # ML Models
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        
        # Feature cache
        self.feature_cache = {}
        self.user_baselines = {}
        
        # Model configurations
        self.model_config = {
            'isolation_forest': {
                'contamination': 0.1,
                'n_estimators': 100,
                'random_state': 42
            },
            'lstm_behavioral': {
                'sequence_length': 30,
                'features': 20,
                'epochs': 50,
                'batch_size': 32
            },
            'risk_classifier': {
                'n_estimators': 200,
                'max_depth': 10,
                'random_state': 42
            }
        }

    async def initialize(self):
        """Initialize the profiler with database connections and ML models"""
        try:
            # Initialize connections
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logger.info("Redis connection established for ML profiler")
            
            self.db_pool = await asyncpg.create_pool(self.postgres_url)
            logger.info("PostgreSQL connection pool established for ML profiler")
            
            # Initialize ML models
            await self._initialize_models()
            
            # Load existing user baselines
            await self._load_user_baselines()
            
        except Exception as e:
            logger.error(f"Failed to initialize ML profiler: {e}")
            raise

    async def _initialize_models(self):
        """Initialize and train ML models"""
        try:
            # Load or train models
            await self._load_or_train_isolation_forest()
            await self._load_or_train_lstm_model()
            await self._load_or_train_risk_classifier()
            
            logger.info("All ML models initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")
            raise

    async def _load_or_train_isolation_forest(self):
        """Load or train the isolation forest for anomaly detection"""
        try:
            # Try to load existing model
            try:
                self.models['isolation_forest'] = joblib.load('models/isolation_forest.pkl')
                self.scalers['isolation_forest'] = joblib.load('models/isolation_forest_scaler.pkl')
                logger.info("Loaded existing isolation forest model")
                return
            except FileNotFoundError:
                logger.info("Training new isolation forest model")
            
            # Train new model
            training_data = await self._get_training_data_for_anomaly_detection()
            
            if len(training_data) > 100:  # Minimum data requirement
                X = np.array([list(features.values()) for features in training_data])
                
                # Scale features
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)
                
                # Train isolation forest
                model = IsolationForest(**self.model_config['isolation_forest'])
                model.fit(X_scaled)
                
                # Save models
                joblib.dump(model, 'models/isolation_forest.pkl')
                joblib.dump(scaler, 'models/isolation_forest_scaler.pkl')
                
                self.models['isolation_forest'] = model
                self.scalers['isolation_forest'] = scaler
                
                logger.info(f"Trained isolation forest on {len(training_data)} samples")
            else:
                logger.warning("Insufficient training data for isolation forest")
                
        except Exception as e:
            logger.error(f"Error with isolation forest model: {e}")

    async def _load_or_train_lstm_model(self):
        """Load or train LSTM model for behavioral sequence analysis"""
        try:
            # Try to load existing model
            try:
                self.models['lstm_behavioral'] = tf.keras.models.load_model('models/lstm_behavioral.h5')
                self.scalers['lstm_behavioral'] = joblib.load('models/lstm_behavioral_scaler.pkl')
                logger.info("Loaded existing LSTM behavioral model")
                return
            except:
                logger.info("Training new LSTM behavioral model")
            
            # Get sequential training data
            sequences, labels = await self._get_sequential_training_data()
            
            if len(sequences) > 200:  # Minimum sequences requirement
                X = np.array(sequences)
                y = np.array(labels)
                
                # Scale features
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X.reshape(-1, X.shape[-1])).reshape(X.shape)
                
                # Build LSTM model
                model = Sequential([
                    Input(shape=(self.model_config['lstm_behavioral']['sequence_length'], 
                               self.model_config['lstm_behavioral']['features'])),
                    LSTM(128, return_sequences=True),
                    Dropout(0.2),
                    LSTM(64),
                    Dropout(0.2),
                    Dense(32, activation='relu'),
                    Dense(1, activation='sigmoid')
                ])
                
                model.compile(optimizer=Adam(learning_rate=0.001),
                            loss='binary_crossentropy',
                            metrics=['accuracy'])
                
                # Train model
                history = model.fit(X_scaled, y, 
                                  epochs=self.model_config['lstm_behavioral']['epochs'],
                                  batch_size=self.model_config['lstm_behavioral']['batch_size'],
                                  validation_split=0.2,
                                  verbose=0)
                
                # Save models
                model.save('models/lstm_behavioral.h5')
                joblib.dump(scaler, 'models/lstm_behavioral_scaler.pkl')
                
                self.models['lstm_behavioral'] = model
                self.scalers['lstm_behavioral'] = scaler
                
                final_accuracy = history.history['val_accuracy'][-1]
                MODEL_ACCURACY.labels(model_name='lstm_behavioral').set(final_accuracy)
                
                logger.info(f"Trained LSTM model on {len(sequences)} sequences, accuracy: {final_accuracy:.3f}")
            else:
                logger.warning("Insufficient sequential data for LSTM training")
                
        except Exception as e:
            logger.error(f"Error with LSTM model: {e}")

    async def _load_or_train_risk_classifier(self):
        """Load or train random forest classifier for risk assessment"""
        try:
            # Try to load existing model
            try:
                self.models['risk_classifier'] = joblib.load('models/risk_classifier.pkl')
                self.scalers['risk_classifier'] = joblib.load('models/risk_classifier_scaler.pkl')
                self.encoders['risk_classifier'] = joblib.load('models/risk_classifier_encoder.pkl')
                logger.info("Loaded existing risk classifier model")
                return
            except FileNotFoundError:
                logger.info("Training new risk classifier model")
            
            # Get labeled training data
            features, labels = await self._get_labeled_training_data()
            
            if len(features) > 500:  # Minimum data requirement
                X = np.array(features)
                y = np.array(labels)
                
                # Scale features
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)
                
                # Encode labels
                encoder = LabelEncoder()
                y_encoded = encoder.fit_transform(y)
                
                # Train Random Forest
                model = RandomForestClassifier(**self.model_config['risk_classifier'])
                X_train, X_test, y_train, y_test = train_test_split(
                    X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
                )
                
                model.fit(X_train, y_train)
                
                # Evaluate model
                test_accuracy = model.score(X_test, y_test)
                MODEL_ACCURACY.labels(model_name='risk_classifier').set(test_accuracy)
                
                # Save models
                joblib.dump(model, 'models/risk_classifier.pkl')
                joblib.dump(scaler, 'models/risk_classifier_scaler.pkl')
                joblib.dump(encoder, 'models/risk_classifier_encoder.pkl')
                
                self.models['risk_classifier'] = model
                self.scalers['risk_classifier'] = scaler
                self.encoders['risk_classifier'] = encoder
                
                logger.info(f"Trained risk classifier on {len(features)} samples, accuracy: {test_accuracy:.3f}")
            else:
                logger.warning("Insufficient labeled data for risk classifier training")
                
        except Exception as e:
            logger.error(f"Error with risk classifier model: {e}")

    async def _get_training_data_for_anomaly_detection(self) -> List[Dict]:
        """Get training data for anomaly detection models"""
        training_data = []
        
        try:
            async with self.db_pool.acquire() as conn:
                # Get user activity data from last 30 days
                query = """
                SELECT user_id, 
                       EXTRACT(HOUR FROM timestamp) as login_hour,
                       location, device_fingerprint, user_agent, ip_address,
                       event_type, outcome, risk_score
                FROM security_events 
                WHERE timestamp > NOW() - INTERVAL '30 days'
                AND user_id IS NOT NULL
                ORDER BY user_id, timestamp
                """
                rows = await conn.fetch(query)
                
                # Group by user and extract features
                user_data = defaultdict(list)
                for row in rows:
                    user_data[row['user_id']].append(dict(row))
                
                for user_id, events in user_data.items():
                    if len(events) >= 10:  # Minimum events per user
                        features = self._extract_features_from_events(user_id, events)
                        if features:
                            training_data.append(features)
                            
        except Exception as e:
            logger.error(f"Error getting training data: {e}")
        
        return training_data

    async def _get_sequential_training_data(self) -> Tuple[List, List]:
        """Get sequential training data for LSTM model"""
        sequences = []
        labels = []
        
        try:
            async with self.db_pool.acquire() as conn:
                # Get sequential user behavior data
                query = """
                SELECT user_id, timestamp, event_type, outcome, risk_score, ip_address,
                       EXTRACT(HOUR FROM timestamp) as hour,
                       EXTRACT(DOW FROM timestamp) as day_of_week,
                       location, device_fingerprint
                FROM security_events 
                WHERE timestamp > NOW() - INTERVAL '60 days'
                AND user_id IS NOT NULL
                ORDER BY user_id, timestamp
                """
                rows = await conn.fetch(query)
                
                # Group by user and create sequences
                user_events = defaultdict(list)
                for row in rows:
                    user_events[row['user_id']].append(dict(row))
                
                seq_length = self.model_config['lstm_behavioral']['sequence_length']
                
                for user_id, events in user_events.items():
                    if len(events) >= seq_length + 10:  # Minimum for meaningful sequences
                        # Create sequences from user events
                        for i in range(len(events) - seq_length):
                            sequence_events = events[i:i+seq_length]
                            next_event = events[i+seq_length]
                            
                            # Extract features for sequence
                            sequence_features = []
                            for event in sequence_events:
                                features = self._extract_sequence_features(event)
                                sequence_features.append(features)
                            
                            # Label: 1 if next event is suspicious (high risk), 0 otherwise
                            label = 1 if (next_event.get('risk_score', 0) or 0) > 70 else 0
                            
                            sequences.append(sequence_features)
                            labels.append(label)
                            
        except Exception as e:
            logger.error(f"Error getting sequential training data: {e}")
        
        return sequences, labels

    async def _get_labeled_training_data(self) -> Tuple[List, List]:
        """Get labeled training data for risk classification"""
        features = []
        labels = []
        
        try:
            async with self.db_pool.acquire() as conn:
                # Get users with known risk levels (from manual assessments or confirmed incidents)
                query = """
                SELECT u.user_id, u.risk_level,
                       COUNT(CASE WHEN se.event_type = 'authentication_failure' THEN 1 END) as failed_logins,
                       COUNT(CASE WHEN se.event_type = 'authentication_success' THEN 1 END) as successful_logins,
                       COUNT(DISTINCT se.ip_address) as unique_ips,
                       COUNT(DISTINCT se.location) as unique_locations,
                       AVG(se.risk_score) as avg_risk_score,
                       COUNT(CASE WHEN se.severity IN ('high', 'critical') THEN 1 END) as high_risk_events
                FROM user_risk_assessments u
                LEFT JOIN security_events se ON u.user_id = se.user_id
                WHERE se.timestamp > NOW() - INTERVAL '30 days'
                GROUP BY u.user_id, u.risk_level
                HAVING COUNT(se.event_id) >= 20
                """
                rows = await conn.fetch(query)
                
                for row in rows:
                    # Extract comprehensive features
                    user_features = [
                        row['failed_logins'] / max(row['successful_logins'], 1),  # Failure rate
                        row['unique_ips'],
                        row['unique_locations'],
                        row['avg_risk_score'] or 0,
                        row['high_risk_events']
                    ]
                    
                    features.append(user_features)
                    labels.append(row['risk_level'])
                    
        except Exception as e:
            logger.error(f"Error getting labeled training data: {e}")
        
        return features, labels

    def _extract_features_from_events(self, user_id: str, events: List[Dict]) -> Dict:
        """Extract comprehensive features from user events"""
        try:
            # Temporal features
            login_hours = [e['login_hour'] for e in events if e.get('login_hour') is not None]
            avg_login_hour = np.mean(login_hours) if login_hours else 12
            login_hour_variance = np.var(login_hours) if len(login_hours) > 1 else 0
            
            # Location features
            locations = [e['location'] for e in events if e.get('location')]
            unique_locations = len(set(locations))
            location_entropy = self._calculate_entropy(locations) if locations else 0
            
            # Device features
            devices = [e['device_fingerprint'] for e in events if e.get('device_fingerprint')]
            unique_devices = len(set(devices))
            
            # User agent features
            user_agents = [e['user_agent'] for e in events if e.get('user_agent')]
            unique_user_agents = len(set(user_agents))
            
            # Behavioral features
            total_events = len(events)
            failed_events = len([e for e in events if e.get('outcome') == 'failure'])
            failed_login_rate = failed_events / total_events if total_events > 0 else 0
            
            # Risk features
            risk_scores = [e['risk_score'] for e in events if e.get('risk_score') is not None]
            avg_risk_score = np.mean(risk_scores) if risk_scores else 0
            
            # IP features
            ips = [e['ip_address'] for e in events if e.get('ip_address')]
            unique_ips = len(set(ips))
            
            return {
                'avg_login_hour': avg_login_hour,
                'login_hour_variance': login_hour_variance,
                'unique_locations': unique_locations,
                'location_entropy': location_entropy,
                'unique_devices': unique_devices,
                'unique_user_agents': unique_user_agents,
                'failed_login_rate': failed_login_rate,
                'avg_risk_score': avg_risk_score,
                'unique_ips': unique_ips,
                'total_events': total_events
            }
            
        except Exception as e:
            logger.error(f"Error extracting features for user {user_id}: {e}")
            return {}

    def _extract_sequence_features(self, event: Dict) -> List[float]:
        """Extract features for sequence analysis"""
        features = [
            event.get('hour', 0),
            event.get('day_of_week', 0),
            event.get('risk_score', 0) or 0,
            1 if event.get('outcome') == 'success' else 0,
            1 if event.get('event_type') == 'authentication_failure' else 0,
            # Add more features as needed
        ]
        
        # Pad or truncate to desired feature count
        target_features = self.model_config['lstm_behavioral']['features']
        while len(features) < target_features:
            features.append(0.0)
        
        return features[:target_features]

    def _calculate_entropy(self, values: List) -> float:
        """Calculate entropy of a list of values"""
        try:
            value_counts = defaultdict(int)
            for value in values:
                value_counts[value] += 1
            
            total = len(values)
            entropy = 0
            for count in value_counts.values():
                probability = count / total
                if probability > 0:
                    entropy -= probability * np.log2(probability)
            
            return entropy
        except:
            return 0.0

    async def analyze_user_behavior(self, user_id: str, 
                                  time_window_days: int = 30) -> RiskAssessment:
        """Comprehensive user behavior analysis and risk assessment"""
        try:
            with PROFILING_DURATION.labels(operation_type='full_analysis').time():
                # Get user events
                events = await self._get_user_events(user_id, time_window_days)
                
                if not events:
                    return RiskAssessment(
                        user_id=user_id,
                        risk_score=0.0,
                        risk_level="unknown",
                        confidence=0.0,
                        contributing_factors=["Insufficient data"],
                        anomaly_indicators=[],
                        recommended_actions=["Gather more behavioral data"],
                        model_predictions={},
                        assessment_timestamp=datetime.now()
                    )
                
                # Extract features
                features = self._extract_features_from_events(user_id, events)
                
                # Get predictions from all models
                predictions = {}
                contributing_factors = []
                anomaly_indicators = []
                
                # Isolation Forest prediction
                if 'isolation_forest' in self.models and features:
                    anomaly_score = await self._predict_anomaly(features)
                    predictions['anomaly_score'] = anomaly_score
                    
                    if anomaly_score > 0.6:
                        anomaly_indicators.append(f"Behavioral anomaly detected (score: {anomaly_score:.2f})")
                        contributing_factors.append("Unusual behavior patterns")
                
                # LSTM behavioral prediction
                if 'lstm_behavioral' in self.models:
                    behavioral_risk = await self._predict_behavioral_risk(user_id, events)
                    predictions['behavioral_risk'] = behavioral_risk
                    
                    if behavioral_risk > 0.7:
                        anomaly_indicators.append(f"High behavioral risk (score: {behavioral_risk:.2f})")
                        contributing_factors.append("Suspicious activity sequence")
                
                # Risk classification
                if 'risk_classifier' in self.models and features:
                    risk_class, risk_prob = await self._classify_risk(features)
                    predictions['risk_classification'] = risk_prob
                    
                    if risk_class in ['high', 'critical']:
                        contributing_factors.append(f"Classified as {risk_class} risk")
                
                # Statistical analysis
                statistical_anomalies = await self._detect_statistical_anomalies(user_id, events)
                if statistical_anomalies:
                    anomaly_indicators.extend(statistical_anomalies)
                    contributing_factors.append("Statistical deviations from baseline")
                
                # Calculate overall risk score
                risk_score = self._calculate_overall_risk_score(predictions, features)
                
                # Determine risk level
                risk_level = self._determine_risk_level(risk_score)
                
                # Calculate confidence
                confidence = self._calculate_confidence(predictions, len(events))
                
                # Generate recommendations
                recommendations = self._generate_recommendations(risk_score, anomaly_indicators)
                
                # Record metrics
                ANOMALY_SCORES.observe(risk_score)
                ML_PREDICTIONS.labels(
                    model_type='comprehensive',
                    prediction_type=risk_level
                ).inc()
                
                return RiskAssessment(
                    user_id=user_id,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    confidence=confidence,
                    contributing_factors=contributing_factors,
                    anomaly_indicators=anomaly_indicators,
                    recommended_actions=recommendations,
                    model_predictions=predictions,
                    assessment_timestamp=datetime.now()
                )
                
        except Exception as e:
            logger.error(f"Error analyzing user behavior for {user_id}: {e}")
            raise

    async def _get_user_events(self, user_id: str, days: int) -> List[Dict]:
        """Get user events from database"""
        try:
            async with self.db_pool.acquire() as conn:
                query = """
                SELECT * FROM security_events 
                WHERE user_id = $1 
                AND timestamp > NOW() - INTERVAL '%s days'
                ORDER BY timestamp DESC
                """ % days
                
                rows = await conn.fetch(query, user_id)
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Error getting user events: {e}")
            return []

    async def _predict_anomaly(self, features: Dict) -> float:
        """Predict anomaly score using isolation forest"""
        try:
            if 'isolation_forest' not in self.models:
                return 0.0
            
            # Convert features to array
            feature_array = np.array([list(features.values())]).reshape(1, -1)
            
            # Scale features
            if 'isolation_forest' in self.scalers:
                feature_array = self.scalers['isolation_forest'].transform(feature_array)
            
            # Get anomaly score
            anomaly_score = self.models['isolation_forest'].decision_function(feature_array)[0]
            
            # Convert to 0-1 scale (higher = more anomalous)
            normalized_score = max(0, min(1, (0.5 - anomaly_score) / 0.5))
            
            return normalized_score
            
        except Exception as e:
            logger.error(f"Error in anomaly prediction: {e}")
            return 0.0

    async def _predict_behavioral_risk(self, user_id: str, events: List[Dict]) -> float:
        """Predict behavioral risk using LSTM model"""
        try:
            if 'lstm_behavioral' not in self.models:
                return 0.0
            
            seq_length = self.model_config['lstm_behavioral']['sequence_length']
            
            if len(events) < seq_length:
                return 0.0
            
            # Create sequence from recent events
            recent_events = events[:seq_length]
            sequence = []
            
            for event in recent_events:
                features = self._extract_sequence_features(event)
                sequence.append(features)
            
            # Convert to numpy array and reshape
            X = np.array(sequence).reshape(1, seq_length, -1)
            
            # Scale if scaler available
            if 'lstm_behavioral' in self.scalers:
                X = self.scalers['lstm_behavioral'].transform(X.reshape(-1, X.shape[-1])).reshape(X.shape)
            
            # Predict
            prediction = self.models['lstm_behavioral'].predict(X, verbose=0)[0][0]
            
            return float(prediction)
            
        except Exception as e:
            logger.error(f"Error in behavioral risk prediction: {e}")
            return 0.0

    async def _classify_risk(self, features: Dict) -> Tuple[str, float]:
        """Classify risk level using random forest"""
        try:
            if 'risk_classifier' not in self.models:
                return "unknown", 0.0
            
            # Convert features to array
            feature_array = np.array([list(features.values())]).reshape(1, -1)
            
            # Scale features
            if 'risk_classifier' in self.scalers:
                feature_array = self.scalers['risk_classifier'].transform(feature_array)
            
            # Predict
            prediction = self.models['risk_classifier'].predict(feature_array)[0]
            probabilities = self.models['risk_classifier'].predict_proba(feature_array)[0]
            
            # Decode prediction
            if 'risk_classifier' in self.encoders:
                risk_class = self.encoders['risk_classifier'].inverse_transform([prediction])[0]
            else:
                risk_class = str(prediction)
            
            max_probability = max(probabilities)
            
            return risk_class, max_probability
            
        except Exception as e:
            logger.error(f"Error in risk classification: {e}")
            return "unknown", 0.0

    async def _detect_statistical_anomalies(self, user_id: str, events: List[Dict]) -> List[str]:
        """Detect statistical anomalies in user behavior"""
        anomalies = []
        
        try:
            # Get user baseline if available
            baseline = self.user_baselines.get(user_id)
            if not baseline:
                return anomalies
            
            # Check login timing anomalies
            login_hours = [e.get('login_hour') for e in events if e.get('login_hour') is not None]
            if login_hours:
                current_hour_variance = np.var(login_hours)
                baseline_hour_variance = baseline.get('hour_variance', current_hour_variance)
                
                if current_hour_variance > baseline_hour_variance * 2:
                    anomalies.append("Unusual login timing patterns")
            
            # Check location anomalies
            locations = [e.get('location') for e in events if e.get('location')]
            unique_current_locations = len(set(locations))
            baseline_locations = baseline.get('typical_location_count', unique_current_locations)
            
            if unique_current_locations > baseline_locations * 1.5:
                anomalies.append("Unusual number of login locations")
            
            # Check failure rate anomalies
            total_events = len(events)
            failed_events = len([e for e in events if e.get('outcome') == 'failure'])
            current_failure_rate = failed_events / total_events if total_events > 0 else 0
            baseline_failure_rate = baseline.get('failure_rate', current_failure_rate)
            
            if current_failure_rate > baseline_failure_rate * 3:
                anomalies.append("Elevated authentication failure rate")
                
        except Exception as e:
            logger.error(f"Error in statistical anomaly detection: {e}")
        
        return anomalies

    def _calculate_overall_risk_score(self, predictions: Dict, features: Dict) -> float:
        """Calculate overall risk score from all predictions"""
        try:
            weights = {
                'anomaly_score': 0.3,
                'behavioral_risk': 0.4,
                'risk_classification': 0.3
            }
            
            weighted_score = 0.0
            total_weight = 0.0
            
            for pred_type, score in predictions.items():
                if pred_type in weights:
                    weighted_score += score * weights[pred_type]
                    total_weight += weights[pred_type]
            
            if total_weight > 0:
                base_score = weighted_score / total_weight
            else:
                base_score = 0.0
            
            # Adjust based on raw features
            if features:
                # Higher failure rate increases risk
                failure_rate = features.get('failed_login_rate', 0)
                if failure_rate > 0.2:
                    base_score += 0.1
                
                # Many unique IPs increases risk
                unique_ips = features.get('unique_ips', 0)
                if unique_ips > 10:
                    base_score += 0.1
                
                # High average risk score increases risk
                avg_risk = features.get('avg_risk_score', 0)
                if avg_risk > 60:
                    base_score += 0.1
            
            return min(1.0, base_score)
            
        except Exception as e:
            logger.error(f"Error calculating overall risk score: {e}")
            return 0.0

    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level from risk score"""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        elif risk_score >= 0.2:
            return "low"
        else:
            return "minimal"

    def _calculate_confidence(self, predictions: Dict, event_count: int) -> float:
        """Calculate confidence in the assessment"""
        base_confidence = min(1.0, event_count / 100)  # More events = higher confidence
        
        # Higher confidence if multiple models agree
        if len(predictions) > 1:
            prediction_values = list(predictions.values())
            std_dev = np.std(prediction_values)
            agreement_factor = max(0, 1 - std_dev)  # Lower std = higher agreement
            base_confidence *= agreement_factor
        
        return base_confidence

    def _generate_recommendations(self, risk_score: float, anomalies: List[str]) -> List[str]:
        """Generate recommendations based on risk assessment"""
        recommendations = []
        
        if risk_score >= 0.8:
            recommendations.extend([
                "Immediately review account activity",
                "Consider temporarily suspending account",
                "Require additional authentication factors",
                "Investigate recent access patterns"
            ])
        elif risk_score >= 0.6:
            recommendations.extend([
                "Enhance monitoring for this user",
                "Require MFA for sensitive operations",
                "Review and validate recent activities",
                "Consider notification to user"
            ])
        elif risk_score >= 0.4:
            recommendations.extend([
                "Increase authentication monitoring",
                "Review access patterns periodically",
                "Consider additional security awareness training"
            ])
        else:
            recommendations.append("Continue normal monitoring")
        
        # Add specific recommendations based on anomalies
        if any("location" in anomaly.lower() for anomaly in anomalies):
            recommendations.append("Verify new login locations with user")
        
        if any("timing" in anomaly.lower() for anomaly in anomalies):
            recommendations.append("Investigate unusual access timing")
        
        if any("failure" in anomaly.lower() for anomaly in anomalies):
            recommendations.append("Check for potential brute force attacks")
        
        return recommendations

    async def _load_user_baselines(self):
        """Load user baselines from Redis"""
        try:
            keys = await self.redis_client.keys("user_baseline:*")
            for key in keys:
                baseline_data = await self.redis_client.get(key)
                if baseline_data:
                    user_id = key.decode().split(":")[-1]
                    self.user_baselines[user_id] = json.loads(baseline_data)
            
            logger.info(f"Loaded {len(self.user_baselines)} user baselines")
        except Exception as e:
            logger.error(f"Failed to load user baselines: {e}")

    async def update_user_baseline(self, user_id: str, events: List[Dict]):
        """Update baseline behavior for a user"""
        try:
            # Calculate baseline metrics
            login_hours = [e.get('login_hour') for e in events if e.get('login_hour') is not None]
            locations = [e.get('location') for e in events if e.get('location')]
            failures = [e for e in events if e.get('outcome') == 'failure']
            
            baseline = {
                'hour_variance': np.var(login_hours) if len(login_hours) > 1 else 0,
                'typical_location_count': len(set(locations)),
                'failure_rate': len(failures) / len(events) if events else 0,
                'last_updated': datetime.now().isoformat(),
                'sample_size': len(events)
            }
            
            self.user_baselines[user_id] = baseline
            
            # Save to Redis
            await self.redis_client.set(
                f"user_baseline:{user_id}",
                json.dumps(baseline),
                ex=86400 * 60  # 60 days expiry
            )
            
        except Exception as e:
            logger.error(f"Error updating baseline for user {user_id}: {e}")

    async def batch_assess_users(self, user_ids: List[str]) -> Dict[str, RiskAssessment]:
        """Perform batch risk assessment for multiple users"""
        assessments = {}
        
        # Process users in batches to avoid overwhelming the system
        batch_size = 10
        for i in range(0, len(user_ids), batch_size):
            batch = user_ids[i:i + batch_size]
            
            tasks = []
            for user_id in batch:
                task = self.analyze_user_behavior(user_id)
                tasks.append(task)
            
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for j, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.error(f"Error assessing user {batch[j]}: {result}")
                    else:
                        assessments[batch[j]] = result
                        
                # Small delay between batches
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in batch processing: {e}")
        
        return assessments

    async def retrain_models(self):
        """Retrain ML models with latest data"""
        try:
            logger.info("Starting model retraining...")
            
            # Backup existing models
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if 'isolation_forest' in self.models:
                joblib.dump(self.models['isolation_forest'], f'models/backup/isolation_forest_{timestamp}.pkl')
            
            # Retrain all models
            await self._load_or_train_isolation_forest()
            await self._load_or_train_lstm_model()
            await self._load_or_train_risk_classifier()
            
            logger.info("Model retraining completed successfully")
            
        except Exception as e:
            logger.error(f"Error during model retraining: {e}")
            raise

    async def close(self):
        """Close connections and cleanup"""
        try:
            if self.redis_client:
                await self.redis_client.close()
            
            if self.db_pool:
                await self.db_pool.close()
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


async def main():
    """Example usage of the ML user profiler"""
    profiler = AdvancedUserProfiler()
    await profiler.initialize()
    
    # Example: Analyze a specific user
    assessment = await profiler.analyze_user_behavior("user_123")
    
    print(f"Risk Assessment for {assessment.user_id}:")
    print(f"Risk Score: {assessment.risk_score:.2f}")
    print(f"Risk Level: {assessment.risk_level}")
    print(f"Confidence: {assessment.confidence:.2f}")
    print(f"Contributing Factors: {assessment.contributing_factors}")
    print(f"Recommendations: {assessment.recommended_actions}")
    
    await profiler.close()


if __name__ == "__main__":
    asyncio.run(main())