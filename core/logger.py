"""
core/logger.py — Centralized logging: SQLite alerts DB + rotating file log.
"""

import logging
import logging.handlers
import sqlite3
import threading
import json
import sys
import os
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


_lock = threading.Lock()

# ─── Python Logger Setup ─────────────────────────────────────────────────────

def get_logger(name: str = "IDS") -> logging.Logger:
    """Return a named logger with file + console handlers."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # Already configured

    logger.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Rotating file handler
    fh = logging.handlers.RotatingFileHandler(
        config.LOG_FILE,
        maxBytes=config.LOG_ROTATION_BYTES,
        backupCount=config.LOG_BACKUP_COUNT,
        encoding="utf-8"
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger


# ─── SQLite Database ─────────────────────────────────────────────────────────

def init_db():
    """Create DB tables if they don't exist."""
    conn = sqlite3.connect(config.DB_PATH)
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            src_ip      TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            severity    TEXT NOT NULL,
            threat_score REAL,
            details     TEXT,
            blocked     INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS blocked_ips (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT UNIQUE NOT NULL,
            blocked_at  TEXT NOT NULL,
            unblock_at  TEXT,
            reason      TEXT,
            active      INTEGER DEFAULT 1,
            country     TEXT,
            city        TEXT
        );

        CREATE TABLE IF NOT EXISTS traffic_stats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            total_packets INTEGER,
            alerts_count  INTEGER,
            blocked_count INTEGER,
            protocol_dist TEXT
        );
    """)
    conn.commit()
    conn.close()


def log_alert(
    src_ip: str,
    attack_type: str,
    severity: str,
    threat_score: float,
    details: dict = None,
    blocked: bool = False
) -> int:
    """Insert an alert record and return its ID."""
    with _lock:
        conn = sqlite3.connect(config.DB_PATH)
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO alerts (timestamp, src_ip, attack_type, severity,
               threat_score, details, blocked) VALUES (?,?,?,?,?,?,?)""",
            (
                datetime.utcnow().isoformat(),
                src_ip,
                attack_type,
                severity,
                threat_score,
                json.dumps(details or {}),
                1 if blocked else 0,
            )
        )
        row_id = cur.lastrowid
        conn.commit()
        conn.close()
    return row_id


def log_blocked_ip(
    ip: str,
    reason: str,
    unblock_at: str = None,
    country: str = None,
    city: str = None
):
    """Upsert a blocked IP record."""
    with _lock:
        conn = sqlite3.connect(config.DB_PATH)
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO blocked_ips (ip, blocked_at, unblock_at, reason, active, country, city)
               VALUES (?,?,?,?,1,?,?)
               ON CONFLICT(ip) DO UPDATE SET
                   blocked_at=excluded.blocked_at,
                   unblock_at=excluded.unblock_at,
                   reason=excluded.reason,
                   active=1,
                   country=excluded.country,
                   city=excluded.city""",
            (ip, datetime.utcnow().isoformat(), unblock_at, reason, country, city)
        )
        conn.commit()
        conn.close()


def unlog_blocked_ip(ip: str):
    """Mark an IP as unblocked in the DB."""
    with _lock:
        conn = sqlite3.connect(config.DB_PATH)
        cur = conn.cursor()
        cur.execute("UPDATE blocked_ips SET active=0 WHERE ip=?", (ip,))
        conn.commit()
        conn.close()


def get_recent_alerts(limit: int = 50) -> list:
    """Return the most recent alerts as a list of dicts."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_blocked_ips() -> list:
    """Return currently active blocked IPs."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM blocked_ips WHERE active=1 ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_traffic_stats(limit: int = 60) -> list:
    """Return recent traffic stats snapshots."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM traffic_stats ORDER BY id DESC LIMIT ?", (limit,)
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows[::-1]  # chronological order


def log_traffic_snapshot(total_packets: int, alerts_count: int,
                         blocked_count: int, protocol_dist: dict):
    """Insert a periodic traffic stats snapshot."""
    with _lock:
        conn = sqlite3.connect(config.DB_PATH)
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO traffic_stats
               (timestamp, total_packets, alerts_count, blocked_count, protocol_dist)
               VALUES (?,?,?,?,?)""",
            (
                datetime.utcnow().isoformat(),
                total_packets,
                alerts_count,
                blocked_count,
                json.dumps(protocol_dist)
            )
        )
        conn.commit()
        conn.close()


# Initialise DB on import
init_db()
