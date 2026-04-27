"""
dashboard/app.py — Flask + Socket.IO web dashboard for the AI-based IDS/IPS.

Provides:
  - REST API endpoints for alerts, blocked IPs, and traffic stats
  - WebSocket (SocketIO) push for real-time alerts and stats
  - Management endpoints (manual unblock, clear alerts)
"""

import sys
import os
import json
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.logger import get_logger, get_recent_alerts, get_blocked_ips, get_traffic_stats
from core import firewall

# Replay engine (lazy import to avoid circular deps)
_replay_engine = None
_replay_lock = threading.Lock()

log = get_logger("Dashboard")

try:
    from flask import Flask, render_template, jsonify, request, abort
    from flask_socketio import SocketIO, emit
    _flask_ok = True
except ImportError as e:
    log.error(f"Flask/SocketIO not installed: {e}")
    _flask_ok = False

if not _flask_ok:
    raise SystemExit("Please install Flask and flask-socketio: pip install flask flask-socketio")

# ─── App Setup ───────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)
app.config["SECRET_KEY"] = config.SECRET_KEY

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    logger=False,
    engineio_logger=False,
)

# Global pushable state (set externally by main.py coordinator)
_alert_buffer = []  # Recent alerts for initial page load
_alert_lock = threading.Lock()
_live_stats = {
    "total_packets": 0,
    "alerts_today": 0,
    "blocked_count": 0,
    "active_ips": 0,
    "uptime": 0,
    "protocol_dist": {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0},
}
_stats_lock = threading.Lock()


def update_live_stats(stats: dict):
    with _stats_lock:
        _live_stats.update(stats)


def push_alert(alert: dict):
    """Called by coordinator to push a new alert to the dashboard."""
    # Sanitize for JSON
    clean = {k: v for k, v in alert.items() if k != "_features"}
    with _alert_lock:
        _alert_buffer.insert(0, clean)
        if len(_alert_buffer) > 500:
            _alert_buffer.pop()
    try:
        socketio.emit("new_alert", clean, namespace="/")
    except Exception:
        pass


def push_stats(stats: dict):
    """Push live stats update to all connected clients."""
    try:
        socketio.emit("stats_update", stats, namespace="/")
    except Exception:
        pass


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    limit = int(request.args.get("limit", 50))
    # Prefer in-memory buffer (real-time), fall back to DB
    with _alert_lock:
        data = _alert_buffer[:limit]
    if not data:
        data = get_recent_alerts(limit)
    return jsonify(data)


@app.route("/api/blocked")
def api_blocked():
    # Combine in-memory + DB blocked IPs
    mem = firewall.get_blocklist()
    if not mem:
        mem = get_blocked_ips()
    return jsonify(mem)


@app.route("/api/stats")
def api_stats():
    with _stats_lock:
        stats = dict(_live_stats)
    stats["blocked_count"] = firewall.get_metrics()["currently_blocked"]
    stats["traffic_history"] = get_traffic_stats(60)
    return jsonify(stats)


@app.route("/api/unblock/<ip>", methods=["POST"])
def api_unblock(ip):
    success = firewall.unblock_ip(ip)
    return jsonify({"success": success, "ip": ip})


@app.route("/api/block/<ip>", methods=["POST"])
def api_block(ip):
    reason = request.json.get("reason", "Manual block via dashboard") if request.is_json else "Manual block"
    success = firewall.block_ip(ip, reason=reason, ttl=0)
    return jsonify({"success": success, "ip": ip})


@app.route("/api/firewall/metrics")
def api_firewall_metrics():
    return jsonify(firewall.get_metrics())


@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "timestamp": time.time()})


# ─── SocketIO events ─────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    log.debug("[Dashboard] Client connected")
    # Send initial data
    with _alert_lock:
        recent = _alert_buffer[:20]
    with _stats_lock:
        stats = dict(_live_stats)
    emit("init_data", {"alerts": recent, "stats": stats})


@socketio.on("disconnect")
def on_disconnect():
    log.debug("[Dashboard] Client disconnected")


@socketio.on("request_stats")
def on_request_stats():
    with _stats_lock:
        stats = dict(_live_stats)
    stats["blocked_count"] = firewall.get_metrics()["currently_blocked"]
    emit("stats_update", stats)


# ─── Background stats-push thread ────────────────────────────────────────────

def _stats_push_loop():
    """Periodically push stats to all clients every 3 seconds."""
    while True:
        time.sleep(3)
        with _stats_lock:
            stats = dict(_live_stats)
        stats["blocked_count"] = firewall.get_metrics()["currently_blocked"]
        try:
            socketio.emit("stats_update", stats, namespace="/")
        except Exception:
            pass


def start_dashboard(host: str = config.DASHBOARD_HOST, port: int = config.DASHBOARD_PORT):
    # Start background stats push
    t = threading.Thread(target=_stats_push_loop, daemon=True, name="StatsPush")
    t.start()

    log.info(f"[Dashboard] Starting on http://{host}:{port}")
    socketio.run(
        app,
        host=host,
        port=port,
        debug=config.DASHBOARD_DEBUG,
        use_reloader=False,
        log_output=False,
        allow_unsafe_werkzeug=True,
    )


# ─── Replay API ─────────────────────────────────────────────────────────────

def _get_replay():
    """Lazy-init the replay engine."""
    global _replay_engine
    with _replay_lock:
        if _replay_engine is None:
            try:
                from ml.replay import DatasetReplayEngine
                _replay_engine = DatasetReplayEngine(
                    on_alert=push_alert,
                    on_stats=lambda s: socketio.emit("replay_stats", s, namespace="/"),
                    data_dir=os.path.join(
                        os.path.dirname(os.path.dirname(__file__)),
                        "data", "MachineLearningCSV", "MachineLearningCVE"
                    ),
                )
            except Exception as e:
                log.error(f"[Dashboard] Replay init failed: {e}")
                return None
    return _replay_engine


@app.route("/api/replay/start", methods=["POST"])
def api_replay_start():
    data   = request.get_json(silent=True) or {}
    speed  = float(data.get("speed", 1.0))
    attacks_only = bool(data.get("attacks_only", True))
    eng = _get_replay()
    if eng is None:
        return jsonify({"success": False, "error": "Replay engine unavailable"}), 500
    eng.speed = max(0.1, speed)
    eng.attacks_only = attacks_only
    if eng.get_stats()["status"] not in ("running", "paused"):
        eng.start()
    elif eng.get_stats()["status"] == "paused":
        eng.resume()
    socketio.emit("replay_status", eng.get_stats(), namespace="/")
    return jsonify({"success": True, "stats": eng.get_stats()})


@app.route("/api/replay/pause", methods=["POST"])
def api_replay_pause():
    eng = _get_replay()
    if eng:
        eng.pause()
        socketio.emit("replay_status", eng.get_stats(), namespace="/")
    return jsonify({"success": True})


@app.route("/api/replay/stop", methods=["POST"])
def api_replay_stop():
    global _replay_engine
    with _replay_lock:
        if _replay_engine:
            _replay_engine.stop()
            _replay_engine = None
    socketio.emit("replay_status", {"status": "idle"}, namespace="/")
    return jsonify({"success": True})


@app.route("/api/replay/speed", methods=["POST"])
def api_replay_speed():
    data  = request.get_json(silent=True) or {}
    speed = float(data.get("speed", 1.0))
    eng = _get_replay()
    if eng:
        eng.set_speed(speed)
    return jsonify({"success": True, "speed": speed})


@app.route("/api/replay/status")
def api_replay_status():
    eng = _get_replay()
    if eng is None:
        return jsonify({"status": "idle"})
    return jsonify(eng.get_stats())


if __name__ == "__main__":
    start_dashboard()

