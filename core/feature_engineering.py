"""
core/feature_engineering.py — Sliding-window per-IP feature aggregation.

Consumes raw packet records from packet_queue and produces feature vectors
suitable for both rule-based and ML-based detection.
"""

import sys
import os
import threading
import time
import queue
from collections import defaultdict, deque
from typing import Generator

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.logger import get_logger

log = get_logger("FeatureEng")

# Output queue of feature vectors ready for detection
feature_queue: queue.Queue = queue.Queue(maxsize=10000)


class IPTrafficWindow:
    """Holds raw packet records for a single source IP within a time window."""

    def __init__(self, window_seconds: int = config.WINDOW_SIZE_SECONDS):
        self.window = window_seconds
        self.records: deque = deque()
        self._lock = threading.Lock()

    def add(self, record: dict):
        with self._lock:
            self.records.append(record)
            cutoff = time.time() - self.window
            while self.records and self.records[0]["timestamp"] < cutoff:
                self.records.popleft()

    def compute_features(self, src_ip: str) -> dict | None:
        """Compute aggregated features over the current window."""
        with self._lock:
            records = list(self.records)

        if len(records) < config.MIN_PACKETS_THRESHOLD:
            return None

        now = time.time()
        window_secs = max(
            1,
            now - records[0]["timestamp"] if records else config.WINDOW_SIZE_SECONDS
        )

        total_pkts = len(records)
        sizes = [r["pkt_size"] for r in records]
        unique_dst_ports = set(r["dst_port"] for r in records)
        unique_dst_ips = set(r["dst_ip"] for r in records)

        size_mean = sum(sizes) / total_pkts
        size_var = sum((s - size_mean) ** 2 for s in sizes) / total_pkts if total_pkts > 1 else 0

        protocols = [r["protocol"] for r in records]
        syn_count = sum(1 for r in records if r.get("flags", 0) & 0x02)
        icmp_count = protocols.count("ICMP")
        udp_count = protocols.count("UDP")
        tcp_count = protocols.count("TCP")

        auth_ports = config.BRUTEFORCE_PORTS
        auth_hits = sum(1 for r in records if r["dst_port"] in auth_ports)

        request_rate = total_pkts / window_secs * 60  # per minute

        return {
            "src_ip": src_ip,
            "timestamp": now,
            "window_seconds": int(window_secs),
            # Volume features
            "total_packets": total_pkts,
            "request_rate_per_min": round(request_rate, 2),
            # Port features
            "unique_dst_ports": len(unique_dst_ports),
            "unique_dst_ips": len(unique_dst_ips),
            # Size features
            "pkt_size_mean": round(size_mean, 2),
            "pkt_size_variance": round(size_var, 2),
            "pkt_size_min": min(sizes),
            "pkt_size_max": max(sizes),
            # Protocol features
            "tcp_ratio": round(tcp_count / total_pkts, 3),
            "udp_ratio": round(udp_count / total_pkts, 3),
            "icmp_ratio": round(icmp_count / total_pkts, 3),
            "syn_ratio": round(syn_count / total_pkts, 3),
            # Auth features
            "auth_port_hits": auth_hits,
            "auth_hit_rate": round(auth_hits / window_secs * 60, 2),
            # Connection frequency
            "connection_freq": round(total_pkts / window_secs, 3),
        }


class FeatureAggregator:
    """
    Reads from packet_queue, aggregates per-IP sliding windows,
    and emits feature vectors to feature_queue at regular intervals.
    """

    def __init__(
        self,
        input_queue: queue.Queue,
        emit_interval: float = 2.0,  # seconds between feature emissions
        window_seconds: int = config.WINDOW_SIZE_SECONDS,
    ):
        self.input_queue = input_queue
        self.emit_interval = emit_interval
        self.window_seconds = window_seconds

        self._windows: dict[str, IPTrafficWindow] = defaultdict(
            lambda: IPTrafficWindow(self.window_seconds)
        )
        self._windows_lock = threading.Lock()
        self._running = False
        self._threads = []

    def start(self):
        self._running = True
        # Ingestion thread
        t1 = threading.Thread(target=self._ingest_loop, daemon=True, name="FE-Ingest")
        # Emission thread
        t2 = threading.Thread(target=self._emit_loop, daemon=True, name="FE-Emit")
        self._threads = [t1, t2]
        for t in self._threads:
            t.start()
        log.info(f"[FeatureAggregator] Started (window={self.window_seconds}s, emit_interval={self.emit_interval}s)")

    def stop(self):
        self._running = False
        log.info("[FeatureAggregator] Stopped")

    def _ingest_loop(self):
        while self._running:
            try:
                record = self.input_queue.get(timeout=1.0)
                src_ip = record.get("src_ip")
                if src_ip:
                    with self._windows_lock:
                        self._windows[src_ip].add(record)
            except queue.Empty:
                continue
            except Exception as e:
                log.error(f"[FeatureAggregator] Ingest error: {e}")

    def _emit_loop(self):
        """Periodically compute and emit feature vectors for all active IPs."""
        while self._running:
            time.sleep(self.emit_interval)
            with self._windows_lock:
                ips = list(self._windows.keys())

            for ip in ips:
                with self._windows_lock:
                    window = self._windows.get(ip)
                if not window:
                    continue
                features = window.compute_features(ip)
                if features:
                    try:
                        feature_queue.put_nowait(features)
                    except queue.Full:
                        pass

            # Prune stale windows (no traffic in last 2x window)
            cutoff = time.time() - (self.window_seconds * 2)
            with self._windows_lock:
                stale = [
                    ip for ip, w in self._windows.items()
                    if not w.records or w.records[-1]["timestamp"] < cutoff
                ]
                for ip in stale:
                    del self._windows[ip]

    def get_active_ip_count(self) -> int:
        with self._windows_lock:
            return len(self._windows)
