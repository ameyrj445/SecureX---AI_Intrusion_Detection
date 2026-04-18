"""
config.py — Centralized configuration for the AI-based IDS/IPS system.
All thresholds, paths, and service settings are defined here.
"""

import os

# ─── Base Paths ─────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR  = os.path.join(BASE_DIR, "logs")
MODEL_DIR = os.path.join(BASE_DIR, "ml", "models")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# ─── Database ────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(LOG_DIR, "ids_alerts.db")
LOG_FILE = os.path.join(LOG_DIR, "ids.log")

# ─── Packet Capture ──────────────────────────────────────────────────────────
CAPTURE_INTERFACE = None          # None = auto-select best interface
CAPTURE_FILTER    = "ip"          # BPF filter
CAPTURE_PROMISC   = True

# ─── Feature Engineering ─────────────────────────────────────────────────────
WINDOW_SIZE_SECONDS = 60          # Aggregation window
MIN_PACKETS_THRESHOLD = 5         # Min packets before scoring

# ─── Rule-Based Detection Thresholds ─────────────────────────────────────────
DDOS_REQUEST_RATE_THRESHOLD  = 500   # packets/minute from single IP
PORTSCAN_UNIQUE_PORTS        = 20    # unique ports → port scanning
BRUTEFORCE_ATTEMPT_THRESHOLD = 10    # repeated auth-port hits/min
BRUTEFORCE_PORTS             = {22, 21, 3389, 23, 25, 110, 143}  # Auth ports

# ─── ML Engine ───────────────────────────────────────────────────────────────
MODEL_PATH   = os.path.join(MODEL_DIR, "isolation_forest.pkl")
RF_MODEL_PATH = os.path.join(MODEL_DIR, "random_forest.pkl")
SCALER_PATH  = os.path.join(MODEL_DIR, "scaler.pkl")
FEATURES_PATH = os.path.join(MODEL_DIR, "feature_names.pkl")

ML_CONTAMINATION = 0.05           # Expected anomaly ratio
ML_N_ESTIMATORS  = 200
ML_RANDOM_STATE  = 42

# ─── Threat Scoring ──────────────────────────────────────────────────────────
# Weights for composite threat score (0-100)
RULE_WEIGHT  = 0.5
ML_WEIGHT    = 0.3
GEO_WEIGHT   = 0.2

# High-risk countries (ISO codes) - slightly bumps geo risk score
HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "NG", "UA", "RO"}

THREAT_LEVEL_LOW    = 30
THREAT_LEVEL_MEDIUM = 60
THREAT_LEVEL_HIGH   = 80

# ─── Auto-Blocking ───────────────────────────────────────────────────────────
AUTO_BLOCK_ENABLED     = True
BLOCK_THRESHOLD_SCORE  = 70       # Auto-block only when threat score exceeds 70
BLOCK_TTL_SECONDS      = 3600     # Auto-unblock after 1 hour (0 = permanent)
WHITELIST_IPS          = {         # Never block these
    "127.0.0.1",
    "::1",
    "192.168.1.1",
    "172.20.32.51",     # This machine (en8)
    "172.20.32.1",      # Default gateway
}

# ─── Geolocation ─────────────────────────────────────────────────────────────
GEO_API_URL   = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,query"
GEO_CACHE_TTL = 3600              # Cache geo lookups for 1 hour

# ─── Email Alerts ────────────────────────────────────────────────────────────
EMAIL_ENABLED   = False           # Set True and fill credentials to enable
SMTP_HOST       = "smtp.gmail.com"
SMTP_PORT       = 587
SMTP_USER       = "your_email@gmail.com"
SMTP_PASSWORD   = "your_app_password"
ALERT_RECIPIENTS = ["admin@example.com"]
EMAIL_THROTTLE_SECONDS = 300      # Don't send more than 1 email per IP per 5m

# ─── Dashboard ───────────────────────────────────────────────────────────────
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
DASHBOARD_DEBUG = False
SECRET_KEY = "ids-ips-secret-key-change-in-production"

# ─── Logging ─────────────────────────────────────────────────────────────────
LOG_LEVEL          = "INFO"
LOG_ROTATION_BYTES = 10 * 1024 * 1024   # 10 MB
LOG_BACKUP_COUNT   = 5
