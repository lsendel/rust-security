"""
Configuration settings for the Security Dashboard
"""
import os
from pathlib import Path

# Application settings
APP_TITLE = "Red Team Security Dashboard"
APP_VERSION = "1.0.0"
DEBUG = os.getenv("DEBUG", "False").lower() == "true"

# Dashboard settings
DEFAULT_REFRESH_INTERVAL = 30  # seconds
MAX_REPORTS_TO_LOAD = 100
DEFAULT_DATE_RANGE_DAYS = 30

# File paths
BASE_DIR = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"
EXPORTS_DIR = BASE_DIR / "exports"
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

# Ensure directories exist
REPORTS_DIR.mkdir(exist_ok=True)
EXPORTS_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)

# Dashboard themes
DASHBOARD_THEME = {
    "primary": "#2E86AB",
    "secondary": "#A23B72",
    "success": "#F18F01",
    "warning": "#C73E1D",
    "danger": "#FF6B6B",
    "info": "#4ECDC4",
    "light": "#F8F9FA",
    "dark": "#343A40"
}

# Security posture colors
POSTURE_COLORS = {
    "Excellent": "#28a745",
    "Good": "#6cb400", 
    "Fair": "#ffc107",
    "Poor": "#fd7e14",
    "Critical": "#dc3545"
}

# Risk level colors
RISK_COLORS = {
    "Critical": "#dc3545",
    "High": "#fd7e14", 
    "Medium": "#ffc107",
    "Low": "#6cb400",
    "Info": "#17a2b8"
}

# Chart settings
CHART_CONFIG = {
    "displayModeBar": True,
    "displaylogo": False,
    "modeBarButtonsToRemove": ["pan2d", "lasso2d"],
    "toImageButtonOptions": {
        "format": "png",
        "filename": "security_chart",
        "height": 600,
        "width": 1000,
        "scale": 2
    }
}

# Export settings
PDF_CONFIG = {
    "pagesize": "A4",
    "orientation": "portrait",
    "margins": {
        "top": 72,
        "bottom": 72,
        "left": 72,
        "right": 72
    }
}

# Dashboard layout
SIDEBAR_WIDTH = 300
MAIN_CONTENT_PADDING = 20