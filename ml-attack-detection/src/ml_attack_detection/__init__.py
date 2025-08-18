"""
ML Attack Detection System

A comprehensive machine learning framework for detecting and analyzing
attack patterns in red team exercises.
"""

from .core.detector import AttackDetector
from .core.config import ModelConfig, DetectionConfig
from .core.types import DetectionResult, ThreatLevel, AttackPattern
from .models.anomaly import AnomalyDetector
from .models.classification import ThreatClassifier
from .models.ensemble import EnsembleDetector
from .api.server import create_app
from .integration.rust_ffi import RustFFIBridge

__version__ = "0.1.0"
__author__ = "Security Research Team"
__email__ = "security@example.com"

# Core exports
__all__ = [
    # Core components
    "AttackDetector",
    "ModelConfig", 
    "DetectionConfig",
    "DetectionResult",
    "ThreatLevel",
    "AttackPattern",
    
    # Models
    "AnomalyDetector",
    "ThreatClassifier", 
    "EnsembleDetector",
    
    # API and Integration
    "create_app",
    "RustFFIBridge",
    
    # Package metadata
    "__version__",
    "__author__",
    "__email__",
]

# Package-level configuration
import logging
import sys
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Package logger
logger = logging.getLogger(__name__)

# Ensure models directory exists
MODELS_DIR = Path(__file__).parent / "models" / "saved"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# Configuration directory
CONFIG_DIR = Path(__file__).parent / "config"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

logger.info(f"ML Attack Detection System v{__version__} initialized")
logger.info(f"Models directory: {MODELS_DIR}")
logger.info(f"Config directory: {CONFIG_DIR}")