"""
core/firewall.py — Automatic IP blocking via OS firewall rules.

Supports:
  - Linux: iptables
  - Windows: netsh advfirewall

Features:
  - Whitelist protection (never block safe IPs)
  - Auto-unblock via configurable TTL timer
  - Persistent blocklist tracking in the logger DB
  - Thread-safe operations
"""

import sys
import os
import platform
import subprocess
import threading
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.logger import get_logger, log_blocked_ip, unlog_blocked_ip

log = get_logger("Firewall")

_OS = platform.system()   # "Linux" | "Windows" | "Darwin"

# In-memory blocklist: ip -> {blocked_at, unblock_at, timer}
_blocklist: dict = {}
_blocklist_lock = threading.Lock()

# Metrics
_metrics = {"total_blocked": 0, "total_unblocked": 0}


# ─── OS-level commands ───────────────────────────────────────────────────────

def _run_cmd(cmd: list[str]) -> tuple[bool, str]:
    """Run a shell command. Returns (success, output)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            log.warning(f"[Firewall] Command failed: {' '.join(cmd)}\n{result.stderr}")
            return False, result.stderr
        return True, result.stdout
    except FileNotFoundError:
        log.warning(f"[Firewall] Command not found: {cmd[0]} — simulating block")
        return True, "(simulated)"
    except Exception as e:
        log.error(f"[Firewall] Command error: {e}")
        return False, str(e)


def _block_linux(ip: str) -> bool:
    ok, _ = _run_cmd(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    if ok:
        # Also block outbound
        _run_cmd(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"])
    return ok


def _unblock_linux(ip: str) -> bool:
    ok1, _ = _run_cmd(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    ok2, _ = _run_cmd(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
    return ok1 or ok2


def _block_windows(ip: str) -> bool:
    rule_name = f"IDS_BLOCK_{ip.replace('.', '_').replace(':', '_')}"
    ok, _ = _run_cmd([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in", "action=block",
        f"remoteip={ip}",
        "enable=yes"
    ])
    return ok


def _unblock_windows(ip: str) -> bool:
    rule_name = f"IDS_BLOCK_{ip.replace('.', '_').replace(':', '_')}"
    ok, _ = _run_cmd([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ])
    return ok


def _block_os(ip: str) -> bool:
    if _OS == "Linux":
        return _block_linux(ip)
    elif _OS == "Windows":
        return _block_windows(ip)
    else:
        log.info(f"[Firewall] Simulating block for {ip} (unsupported OS: {_OS})")
        return True


def _unblock_os(ip: str) -> bool:
    if _OS == "Linux":
        return _unblock_linux(ip)
    elif _OS == "Windows":
        return _unblock_windows(ip)
    else:
        log.info(f"[Firewall] Simulating unblock for {ip}")
        return True


# ─── Public API ──────────────────────────────────────────────────────────────

def block_ip(
    ip: str,
    reason: str = "Detected attack",
    ttl: int = config.BLOCK_TTL_SECONDS,
    country: str = None,
    city: str = None,
) -> bool:
    """
    Block an IP address with optional auto-unblock TTL.
    Returns True if successfully blocked.
    """
    if not config.AUTO_BLOCK_ENABLED:
        log.info(f"[Firewall] Auto-block disabled — skipping {ip}")
        return False

    if ip in config.WHITELIST_IPS:
        log.info(f"[Firewall] {ip} is whitelisted — skipping block")
        return False

    with _blocklist_lock:
        if ip in _blocklist:
            log.debug(f"[Firewall] {ip} already blocked")
            return True

    # Apply OS rule
    success = _block_os(ip)
    if not success:
        log.error(f"[Firewall] Failed to block {ip}")
        return False

    now = datetime.utcnow()
    unblock_at = (now + timedelta(seconds=ttl)).isoformat() if ttl > 0 else None

    # Set up auto-unblock timer
    timer = None
    if ttl > 0:
        timer = threading.Timer(ttl, _auto_unblock, args=[ip])
        timer.daemon = True
        timer.start()

    with _blocklist_lock:
        _blocklist[ip] = {
            "blocked_at": now.isoformat(),
            "unblock_at": unblock_at,
            "timer": timer,
            "reason": reason,
        }
        _metrics["total_blocked"] += 1

    log_blocked_ip(ip, reason, unblock_at, country, city)
    log.warning(
        f"[Firewall] 🚫 BLOCKED {ip} | reason={reason} | "
        f"TTL={ttl}s | country={country}"
    )
    return True


def unblock_ip(ip: str) -> bool:
    """Manually unblock an IP."""
    with _blocklist_lock:
        entry = _blocklist.pop(ip, None)

    if entry is None:
        log.warning(f"[Firewall] {ip} is not in blocklist")
        return False

    if entry.get("timer"):
        entry["timer"].cancel()

    success = _unblock_os(ip)
    if success:
        unlog_blocked_ip(ip)
        _metrics["total_unblocked"] += 1
        log.info(f"[Firewall] ✅ UNBLOCKED {ip}")
    return success


def _auto_unblock(ip: str):
    """Called by timer when TTL expires."""
    log.info(f"[Firewall] Auto-unblocking {ip} (TTL expired)")
    unblock_ip(ip)


def is_blocked(ip: str) -> bool:
    with _blocklist_lock:
        return ip in _blocklist


def get_blocklist() -> list[dict]:
    """Return a snapshot of the current in-memory blocklist."""
    with _blocklist_lock:
        return [
            {
                "ip": ip,
                "blocked_at": v["blocked_at"],
                "unblock_at": v["unblock_at"],
                "reason": v["reason"],
            }
            for ip, v in _blocklist.items()
        ]


def get_metrics() -> dict:
    with _blocklist_lock:
        return {
            "total_blocked": _metrics["total_blocked"],
            "total_unblocked": _metrics["total_unblocked"],
            "currently_blocked": len(_blocklist),
        }
