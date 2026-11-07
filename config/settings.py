"""
RecallOps - Configuration Settings
Centralized management of paths, environment variables, categories, and memory bank identifiers.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base paths
CONFIG_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CONFIG_DIR.parent
DATA_DIR = PROJECT_ROOT / "data"
PROCESSED_DATA_DIR = PROJECT_ROOT / "processed_data"
REPORTS_DIR = PROJECT_ROOT / "reports"
DEMO_SAMPLES_DIR = PROJECT_ROOT / "demo_samples"
SRC_DIR = PROJECT_ROOT / "src"

# Load environment variables
load_dotenv(PROJECT_ROOT / ".env")

# API Keys & Endpoints
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
HINDSIGHT_API_URL = os.getenv("HINDSIGHT_API_URL", "https://api.hindsight.ai/v1")
HINDSIGHT_API_KEY = os.getenv("HINDSIGHT_API_KEY", "")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'recallops.db'}")

# Datasets
HDFS_RAW_PATH = DATA_DIR / "HDFS_2k.log_structured.csv"
SWEBENCH_RAW_PATH = DATA_DIR / "swebench_lite.csv"
HDFS_CLEAN_PATH = PROCESSED_DATA_DIR / "hdfs_clean.csv"
SWEBENCH_CLEAN_PATH = PROCESSED_DATA_DIR / "swebench_clean.csv"

# Hindsight Memory Banks
BANKS = {
    "hdfs": "hdfs-intelligence",
    "swe": "swebench-intelligence",
    "incidents": "incident-intelligence"
}

# 10 Standard Error Categories
CATEGORIES = [
    "Database connection errors",
    "Authentication errors",
    "Memory errors",
    "Network errors",
    "API failures",
    "Application exceptions",
    "Configuration errors",
    "Dependency errors",
    "Resource exhaustion",
    "Unknown or unclassified errors"
]

# Severity Levels
SEVERITY_LEVELS = [
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational"
]

