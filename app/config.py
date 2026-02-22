import os
import logging
from pathlib import Path

DATA_ROOT = Path(os.getenv("SIEM_DATA_DIR", "data"))

RAW_DIR = DATA_ROOT / "raw"
NORMALIZED_DIR = DATA_ROOT / "normalized"
AGGREGATED_DIR = DATA_ROOT / "aggregated"
ALERTS_DIR = DATA_ROOT / "alerts"
INCIDENTS_DIR = DATA_ROOT / "incidents"
CMDB_DIR = DATA_ROOT / "cmdb"
SIMULATOR_DIR = DATA_ROOT / "simulator"

ASSETS_PATH = CMDB_DIR / "assets.json"

RAW_RETENTION_DAYS = int(os.getenv("RAW_RETENTION_DAYS", "14"))
RAW_MAX_FILES = int(os.getenv("RAW_MAX_FILES", "5000"))
RAW_CLEANUP_EVERY = int(os.getenv("RAW_CLEANUP_EVERY", "50"))

# Pipeline queue configuration
PIPELINE_QUEUE_SIZE = int(os.getenv("PIPELINE_QUEUE_SIZE", "1000"))
PIPELINE_WORKERS = int(os.getenv("PIPELINE_WORKERS", "1"))

# Security & CORS
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Интеграционный слой: webhook при создании инцидента (Telegram/Email/ServiceDesk)
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "").strip() or None