# SecureX AI — Intrusion Detection & Prevention System

<div align="center">


**Real-time AI-powered Network Intrusion Detection & Prevention**

</div>

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Train the ML Model
```bash
# Using synthetic data (no dataset needed — great for testing):
python ml/train.py --synthetic

# Using CICIDS2017 dataset (best accuracy):
# 1. Download the datasets and trained models from the GitHub Releases page
# 2. Place the extracted CSV files in the data/ folder and .pkl files in ml/models/
# 3. Run:
python ml/train.py
```

### 3. Start the System
```bash
# Full system (live capture + dashboard):
python main.py

# Demo mode (synthetic traffic — no admin rights needed):
python main.py --demo

# Custom port:
python main.py --port 8080

# Disable auto-blocking (detection only):
python main.py --no-block
```

### 4. Open the Dashboard
```
http://localhost:5000
```

---

## 📁 Project Structure

```
AI-Based Intrusion Detection+Auto Blocking System/
│
├── main.py                     # 🚀 System entry point
├── config.py                   # ⚙️  All configuration settings
├── requirements.txt
│
├── core/                       # Core detection modules
│   ├── packet_capture.py       # 📡 Scapy live network capture
│   ├── feature_engineering.py  # 🔧 Per-IP sliding-window features
│   ├── rule_engine.py          # 📏 Rule-based detection (DDoS/portscan/etc)
│   ├── ml_engine.py            # 🤖 ML-based anomaly detection
│   ├── firewall.py             # 🛡️  Auto IP blocking (iptables/netsh)
│   ├── logger.py               # 📝 SQLite + rotating file logs
│   ├── geo_ip.py               # 🌍 IP geolocation
│   ├── threat_score.py         # 📊 Composite threat scoring (0-100)
│   └── alert_email.py          # 📧 SMTP email alerts
│
├── ml/                         # Machine learning pipeline
│   ├── train.py                # 🎓 Model training script
│   ├── preprocess.py           # 🔄 CICIDS2017 preprocessing
│   ├── evaluate.py             # 📈 Standalone evaluation
│   └── models/                 # Saved .pkl model files
│
├── dashboard/                  # Web dashboard
│   ├── app.py                  # Flask + Socket.IO server
│   ├── templates/index.html    # Dark-mode reactive UI
│   └── static/
│       ├── css/style.css
│       └── js/dashboard.js
│
├── data/                       # Dataset storage
│   └── README.md               # Dataset download instructions
│
└── logs/                       # Auto-created log files
    ├── ids.log                 # Rotating text log
    └── ids_alerts.db           # SQLite database
```

---

## 🔍 Detection Capabilities

### Rule-Based Detection
| Attack Type | Method | Threshold |
|-------------|--------|-----------|
| **DDoS** | Request rate > threshold | 500 pkts/min from single IP |
| **Port Scan** | Unique destination ports | 20+ ports in window |
| **Brute Force** | Auth-port repeated hits | 10+ hits/min (SSH/FTP/RDP) |
| **ICMP Flood** | High ICMP ratio + rate | >70% ICMP + >200 req/min |
| **UDP Flood** | High UDP ratio + rate | >80% UDP + >250 req/min |

### ML-Based Detection
- **IsolationForest** — Unsupervised anomaly detection on traffic feature vectors
- **RandomForestClassifier** — Supervised multi-class attack classification
- Trained on **CICIDS2017** dataset (2.8M+ labeled flow records)

### Threat Scoring (0–100)
```
score = (0.5 × rule_score) + (0.3 × ml_score) + (0.2 × geo_risk) × confidence
```
- Score ≥ 70 → **Auto-block**
- Score ≥ 80 → **CRITICAL** severity
- Score ≥ 60 → **HIGH** severity
- Score ≥ 30 → **MEDIUM** severity

---

## ⚙️ Configuration (`config.py`)

```python
# Detection thresholds
DDOS_REQUEST_RATE_THRESHOLD  = 500   # packets/min
PORTSCAN_UNIQUE_PORTS        = 20    # unique ports
BRUTEFORCE_ATTEMPT_THRESHOLD = 10    # auth hits/min

# Auto-blocking
AUTO_BLOCK_ENABLED    = True
BLOCK_THRESHOLD_SCORE = 70
BLOCK_TTL_SECONDS     = 3600         # Auto-unblock after 1 hour

# Email alerts
EMAIL_ENABLED  = False
SMTP_HOST      = "smtp.gmail.com"
SMTP_USER      = "your@gmail.com"
SMTP_PASSWORD  = "app_password"
ALERT_RECIPIENTS = ["admin@example.com"]

# Dashboard
DASHBOARD_PORT = 5000
```

---

## 📊 Dashboard Features

| Tab | Features |
|-----|----------|
| **Dashboard** | KPI cards, traffic chart, protocol donut, attack type chart, recent alerts |
| **Live Alerts** | Real-time alert table with filtering, threat score bar, geo info, block button |
| **Blocked IPs** | Active blocklist, unblock button, expiry times |
| **Traffic Analysis** | Packet rate chart, attack heatmap, top attacking IPs, severity distribution |
| **Threat Map** | Animated SVG world map with attack origin visualization |

---

## 🎯 CICIDS2017 Training Results (Expected)

| Metric | IsolationForest | RandomForest |
|--------|----------------|--------------|
| Accuracy | ~92% | ~97-99% |
| Precision | ~88% | ~96-98% |
| Recall | ~89% | ~97-99% |
| F1-Score | ~88% | ~97-98% |

*Results vary by dataset split and contamination ratio*

---

## 🔧 Advanced Usage

### Simulate an Attack (for testing)
```bash
# The demo mode automatically generates synthetic DDoS/portscan/bruteforce traffic
python main.py --demo
```

### Evaluate Trained Models
```bash
python ml/evaluate.py
```

### View Logs
```bash
# Real-time log tail
tail -f logs/ids.log

# Query SQLite database
sqlite3 logs/ids_alerts.db "SELECT * FROM alerts ORDER BY id DESC LIMIT 20"
sqlite3 logs/ids_alerts.db "SELECT * FROM blocked_ips WHERE active=1"
```

### Manually Block/Unblock an IP (API)
```bash
# Block
curl -X POST http://localhost:5000/api/block/10.0.0.5 \
     -H "Content-Type: application/json" \
     -d '{"reason": "Manual block"}'

# Unblock
curl -X POST http://localhost:5000/api/unblock/10.0.0.5
```

---

## 🛡️ OS-Specific Firewall Commands

**Linux (iptables):**
```bash
# Block inbound from attacker
iptables -I INPUT -s <IP> -j DROP
# Unblock
iptables -D INPUT -s <IP> -j DROP
```

**Windows (netsh):**
```cmd
netsh advfirewall firewall add rule name="IDS_BLOCK_<IP>" dir=in action=block remoteip=<IP>
netsh advfirewall firewall delete rule name="IDS_BLOCK_<IP>"
```

> **Note:** On Windows, run the application with Administrator privileges for firewall rules to work. On Linux, run with `sudo`.

---

## 📧 Email Alert Setup (Gmail)

1. Enable 2FA on your Google account
2. Generate an **App Password**: Google Account → Security → App Passwords
3. Update `config.py`:
```python
EMAIL_ENABLED    = True
SMTP_USER        = "your@gmail.com"
SMTP_PASSWORD    = "your_16char_app_password"
ALERT_RECIPIENTS = ["admin@company.com"]
```

---

## 📋 Requirements

- Python 3.10+
- Windows / Linux / macOS
- Administrator/root privileges for live packet capture and firewall rules
- 4 GB RAM recommended for CICIDS2017 training
- Internet connection for IP geolocation (ip-api.com)

---

## 🤝 License

This project is for educational and research purposes.
Built with ❤️ using Python, Scapy, scikit-learn, Flask, and Chart.js.
# SoftComputing_Project
