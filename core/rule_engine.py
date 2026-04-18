"""
core/rule_engine.py — Rule-based intrusion detection.

Evaluates feature vectors against configurable thresholds to detect:
 - DDoS attacks (high request rate)
 - Port scanning (many unique ports accessed)
 - Brute force (repeated auth-port hits)
 - Ping floods (high ICMP ratio + rate)
 - UDP floods
"""

import sys
import os
import queue
import threading
from datetime import datetime
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.logger import get_logger

log = get_logger("RuleEngine")


# ─── Alert Schema ─────────────────────────────────────────────────────────────

def make_alert(
    src_ip: str,
    attack_type: str,
    severity: str,
    confidence: float,
    details: dict,
    rule_score: float,
) -> dict:
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "src_ip": src_ip,
        "attack_type": attack_type,
        "severity": severity,          # LOW | MEDIUM | HIGH | CRITICAL
        "confidence": round(confidence, 3),
        "rule_score": round(rule_score, 2),  # 0-100 contribution from rules
        "details": details,
        "source": "rule",
    }


# ─── Individual Rules ─────────────────────────────────────────────────────────

def _check_ddos(f: dict) -> dict | None:
    rate = f.get("request_rate_per_min", 0)
    if rate >= config.DDOS_REQUEST_RATE_THRESHOLD:
        overshoot = min((rate / config.DDOS_REQUEST_RATE_THRESHOLD), 5.0)
        confidence = min(0.5 + overshoot * 0.1, 1.0)
        rule_score = min(50 + (overshoot - 1) * 10, 100)
        severity = "CRITICAL" if rate > config.DDOS_REQUEST_RATE_THRESHOLD * 3 else "HIGH"
        return make_alert(
            src_ip=f["src_ip"],
            attack_type="DDoS",
            severity=severity,
            confidence=confidence,
            details={
                "request_rate_per_min": rate,
                "threshold": config.DDOS_REQUEST_RATE_THRESHOLD,
                "udp_ratio": f.get("udp_ratio"),
                "total_packets": f.get("total_packets"),
            },
            rule_score=rule_score,
        )
    return None


def _check_port_scan(f: dict) -> dict | None:
    unique_ports = f.get("unique_dst_ports", 0)
    if unique_ports >= config.PORTSCAN_UNIQUE_PORTS:
        overshoot = unique_ports / config.PORTSCAN_UNIQUE_PORTS
        confidence = min(0.4 + overshoot * 0.15, 1.0)
        rule_score = min(40 + overshoot * 10, 100)
        severity = "HIGH" if unique_ports > config.PORTSCAN_UNIQUE_PORTS * 2 else "MEDIUM"
        return make_alert(
            src_ip=f["src_ip"],
            attack_type="Port Scan",
            severity=severity,
            confidence=confidence,
            details={
                "unique_ports_accessed": unique_ports,
                "threshold": config.PORTSCAN_UNIQUE_PORTS,
                "syn_ratio": f.get("syn_ratio"),
                "tcp_ratio": f.get("tcp_ratio"),
            },
            rule_score=rule_score,
        )
    return None


def _check_brute_force(f: dict) -> dict | None:
    auth_rate = f.get("auth_hit_rate", 0)
    auth_hits = f.get("auth_port_hits", 0)
    if auth_hits >= config.BRUTEFORCE_ATTEMPT_THRESHOLD:
        overshoot = auth_hits / config.BRUTEFORCE_ATTEMPT_THRESHOLD
        confidence = min(0.45 + overshoot * 0.1, 1.0)
        rule_score = min(45 + overshoot * 8, 100)
        severity = "HIGH" if auth_hits > config.BRUTEFORCE_ATTEMPT_THRESHOLD * 3 else "MEDIUM"
        return make_alert(
            src_ip=f["src_ip"],
            attack_type="Brute Force",
            severity=severity,
            confidence=confidence,
            details={
                "auth_port_hits": auth_hits,
                "auth_hit_rate_per_min": auth_rate,
                "threshold": config.BRUTEFORCE_ATTEMPT_THRESHOLD,
            },
            rule_score=rule_score,
        )
    return None


def _check_icmp_flood(f: dict) -> dict | None:
    icmp_ratio = f.get("icmp_ratio", 0)
    rate = f.get("request_rate_per_min", 0)
    if icmp_ratio > 0.7 and rate > 200:
        confidence = min(0.5 + icmp_ratio * 0.3, 1.0)
        rule_score = min(50 + rate / 20, 100)
        return make_alert(
            src_ip=f["src_ip"],
            attack_type="ICMP Flood",
            severity="HIGH",
            confidence=confidence,
            details={
                "icmp_ratio": icmp_ratio,
                "request_rate_per_min": rate,
            },
            rule_score=rule_score,
        )
    return None


def _check_udp_flood(f: dict) -> dict | None:
    udp_ratio = f.get("udp_ratio", 0)
    rate = f.get("request_rate_per_min", 0)
    if udp_ratio > 0.8 and rate > config.DDOS_REQUEST_RATE_THRESHOLD * 0.5:
        confidence = min(0.45 + udp_ratio * 0.25, 1.0)
        rule_score = min(45 + rate / 25, 100)
        return make_alert(
            src_ip=f["src_ip"],
            attack_type="UDP Flood",
            severity="HIGH",
            confidence=confidence,
            details={
                "udp_ratio": udp_ratio,
                "request_rate_per_min": rate,
            },
            rule_score=rule_score,
        )
    return None


# ─── Rule Engine ──────────────────────────────────────────────────────────────

RULES = [
    _check_ddos,
    _check_port_scan,
    _check_brute_force,
    _check_icmp_flood,
    _check_udp_flood,
]


class RuleEngine:
    """
    Reads feature vectors and applies all rule checks.
    Emits alerts to alert_queue and optionally calls a callback.
    """

    def __init__(
        self,
        feature_q: queue.Queue,
        alert_q: queue.Queue,
        on_alert: Callable[[dict], None] | None = None,
    ):
        self.feature_q = feature_q
        self.alert_q = alert_q
        self.on_alert = on_alert
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="RuleEngine"
        )
        self._thread.start()
        log.info("[RuleEngine] Started")

    def stop(self):
        self._running = False
        log.info("[RuleEngine] Stopped")

    def _run_loop(self):
        while self._running:
            try:
                features = self.feature_q.get(timeout=1.0)
                self._evaluate(features)
            except queue.Empty:
                continue
            except Exception as e:
                log.error(f"[RuleEngine] Error: {e}")

    def _evaluate(self, features: dict):
        for rule_fn in RULES:
            alert = rule_fn(features)
            if alert:
                # Attach raw features for ML engine to pick up
                alert["_features"] = features
                log.warning(
                    f"[RuleEngine] {alert['attack_type']} detected | "
                    f"IP={alert['src_ip']} | severity={alert['severity']} | "
                    f"confidence={alert['confidence']:.2f}"
                )
                try:
                    self.alert_q.put_nowait(alert)
                except queue.Full:
                    pass
                if self.on_alert:
                    try:
                        self.on_alert(alert)
                    except Exception as e:
                        log.error(f"[RuleEngine] on_alert callback error: {e}")
                # Only fire the most severe matching rule per feature vector per IP
                break
