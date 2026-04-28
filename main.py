"""
main.py — SecureX AI IDS/IPS System Entry Point.

Orchestrates all modules:
  1. Packet capture (Scapy / synthetic)
  2. Feature aggregation (sliding window per IP)
  3. Rule-based detection
  4. ML-based detection
  5. Threat scoring + geolocation enrichment
  6. Auto-blocking (iptables / netsh)
  7. Logging (SQLite + file)
  8. Email alerts
  9. Flask + SocketIO dashboard

Usage:
  python main.py                  # Start the full system
  python main.py --no-block       # Run without auto-blocking
  python main.py --demo           # Force synthetic traffic mode
  python main.py --port 8080      # Change dashboard port
"""

import argparse
import queue
import sys
import os
import threading
import time
from datetime import datetime

# ─── Config ───────────────────────────────────────────────────────────────────
import config

# ─── Core Modules ─────────────────────────────────────────────────────────────
from core.logger import get_logger, log_alert, log_traffic_snapshot, init_db
from core.packet_capture import PacketCapture, packet_queue, get_stats as get_capture_stats
from core.feature_engineering import FeatureAggregator, feature_queue
from core.rule_engine import RuleEngine
from core.ml_engine import MLEngine
from core import geo_ip, threat_score, firewall
from core.alert_email import send_alert_email_async

# ─── Dashboard ────────────────────────────────────────────────────────────────
from dashboard.app import (
    push_alert,
    push_stats,
    update_live_stats,
    start_dashboard,
)

log = get_logger("Main")


# ─── Queues ───────────────────────────────────────────────────────────────────
alert_queue: queue.Queue = queue.Queue(maxsize=5000)
# ML gets a mirrored feature queue
ml_feature_queue: queue.Queue = queue.Queue(maxsize=5000)


# ─── Alert Coordinator ────────────────────────────────────────────────────────

def process_alert(alert: dict):
    """
    Full alert processing pipeline:
    1. Geo-enrich
    2. Threat score
    3. Log to DB
    4. Auto-block if score high enough
    5. Push to dashboard
    6. Send email (if enabled)
    """
    src_ip = alert.get("src_ip", "")

    # Skip whitelisted IPs
    if src_ip in config.WHITELIST_IPS:
        return

    # 1. Geo-enrichment (non-blocking cache-backed)
    try:
        geo_ip.enrich_alert(alert)
    except Exception as e:
        log.debug(f"[Main] Geo enrich failed: {e}")
        alert.setdefault("geo", {})

    # 2. Threat scoring
    try:
        threat_score.enrich_with_threat_score(alert)
    except Exception as e:
        log.debug(f"[Main] Threat score failed: {e}")
        alert.setdefault("threat_score", 50.0)

    ts = alert.get("threat_score", 0)
    severity = alert.get("severity", "LOW")

    # 3. Log to DB
    try:
        alert_id = log_alert(
            src_ip=src_ip,
            attack_type=alert.get("attack_type", "Unknown"),
            severity=severity,
            threat_score=ts,
            details=alert.get("details", {}),
            blocked=False,
        )
        alert["id"] = alert_id
    except Exception as e:
        log.error(f"[Main] DB log failed: {e}")

    # 4. Auto-block
    blocked = False
    if ts >= config.BLOCK_THRESHOLD_SCORE and not firewall.is_blocked(src_ip):
        geo = alert.get("geo", {})
        blocked = firewall.block_ip(
            ip=src_ip,
            reason=f"{alert.get('attack_type','?')} detected (score={ts:.0f})",
            ttl=config.BLOCK_TTL_SECONDS,
            country=geo.get("country"),
            city=geo.get("city"),
        )
        alert["blocked"] = blocked

    # 5. Push to dashboard
    try:
        push_alert(alert)
    except Exception as e:
        log.debug(f"[Main] Dashboard push failed: {e}")

    # 6. Email alert
    if severity in ("HIGH", "CRITICAL"):
        send_alert_email_async(alert)

    log.info(
        f"[Alert] {alert.get('attack_type')} | IP={src_ip} | "
        f"score={ts:.1f} | sev={severity} | blocked={blocked}"
    )


def alert_consumer_loop():
    """Drains the alert queue and processes each alert."""
    while True:
        try:
            alert = alert_queue.get(timeout=2.0)
            process_alert(alert)
        except queue.Empty:
            continue
        except Exception as e:
            log.error(f"[Main] Alert consumer error: {e}")


# ─── Feature Mirror (for ML engine) ──────────────────────────────────────────

def feature_mirror_loop():
    """
    Reads from feature_queue and mirrors to both:
      - rule_feature_queue (for RuleEngine)
      - ml_feature_queue (for MLEngine)
    We do this because the rule engine `get` consumes the item.
    """
    rule_q: queue.Queue = rule_engine_feature_queue
    while True:
        try:
            feat = feature_queue.get(timeout=1.0)
            # Send to rule engine
            try:
                rule_q.put_nowait(feat)
            except queue.Full:
                pass
            # Mirror to ML queue
            try:
                ml_feature_queue.put_nowait(dict(feat))
            except queue.Full:
                pass
        except queue.Empty:
            continue


# ─── Stats Reporter ───────────────────────────────────────────────────────────

def stats_reporter_loop(aggregator: FeatureAggregator):
    """Periodic stats snapshot + dashboard push every 5 seconds."""
    alert_count_snapshot = [0]

    while True:
        time.sleep(5)
        cap_stats = get_capture_stats()
        fw_metrics = firewall.get_metrics()

        stats = {
            "total_packets": cap_stats["total_packets"],
            "alerts_today": len([]),  # will be filled from DB
            "blocked_count": fw_metrics["currently_blocked"],
            "active_ips": aggregator.get_active_ip_count(),
            "uptime": cap_stats["uptime_seconds"],
            "protocol_dist": cap_stats["protocol_dist"],
        }
        update_live_stats(stats)
        push_stats(stats)

        # Log to DB
        try:
            log_traffic_snapshot(
                total_packets=cap_stats["total_packets"],
                alerts_count=0,
                blocked_count=fw_metrics["currently_blocked"],
                protocol_dist=cap_stats["protocol_dist"],
            )
        except Exception:
            pass


# ─── Main ─────────────────────────────────────────────────────────────────────

# Global (set in main so feature_mirror can access)
rule_engine_feature_queue: queue.Queue = queue.Queue(maxsize=5000)


def main():
    parser = argparse.ArgumentParser(description="SecureX AI IDS/IPS System")
    parser.add_argument("--no-block", action="store_true", help="Disable auto-blocking")
    parser.add_argument("--demo", action="store_true", help="Force synthetic traffic mode")
    parser.add_argument("--port", type=int, default=config.DASHBOARD_PORT, help="Dashboard port")
    parser.add_argument("--interface", default=None, help="Network interface to capture on")
    args = parser.parse_args()

    if args.no_block:
        config.AUTO_BLOCK_ENABLED = False
        log.info("[Main] Auto-blocking DISABLED")

    if args.port:
        config.DASHBOARD_PORT = args.port

    if args.interface:
        config.CAPTURE_INTERFACE = args.interface

    log.info("=" * 60)
    log.info("  SecureX AI — Intrusion Detection & Prevention System")
    log.info("  Starting all modules...")
    log.info("=" * 60)

    # ── 1. Feature Aggregator ─────────────────────────────────────────────────
    aggregator = FeatureAggregator(input_queue=packet_queue)
    aggregator.start()

    # ── 2. Rule Engine ────────────────────────────────────────────────────────
    rule_engine = RuleEngine(
        feature_q=rule_engine_feature_queue,
        alert_q=alert_queue,
    )
    rule_engine.start()

    # ── 3. ML Engine ─────────────────────────────────────────────────────────
    ml_engine = MLEngine(alert_q=alert_queue)
    ml_engine.start(ml_feature_queue)

    # ── 4. Alert Consumer ─────────────────────────────────────────────────────
    alert_thread = threading.Thread(
        target=alert_consumer_loop, daemon=True, name="AlertConsumer"
    )
    alert_thread.start()

    # ── 5. Feature Mirror ─────────────────────────────────────────────────────
    mirror_thread = threading.Thread(
        target=feature_mirror_loop, daemon=True, name="FeatureMirror"
    )
    mirror_thread.start()

    # ── 6. Stats Reporter ─────────────────────────────────────────────────────
    stats_thread = threading.Thread(
        target=stats_reporter_loop, args=[aggregator],
        daemon=True, name="StatsReporter"
    )
    stats_thread.start()

    # ── 7. Packet Capture ─────────────────────────────────────────────────────
    capture = PacketCapture(iface=config.CAPTURE_INTERFACE)
    if args.demo:
        capture._start_synthetic()
    else:
        capture.start()

    log.info(f"[Main] Dashboard → http://localhost:{config.DASHBOARD_PORT}")
    log.info("[Main] Press Ctrl+C to stop")

    # ── 8. Flask Dashboard (blocking) ─────────────────────────────────────────
    try:
        start_dashboard(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT)
    except KeyboardInterrupt:
        log.info("[Main] Shutting down...")
        capture.stop()
        aggregator.stop()
        rule_engine.stop()
        ml_engine.stop()


if __name__ == "__main__":
    main()

