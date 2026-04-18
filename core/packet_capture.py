"""
core/packet_capture.py — Live packet capture using Scapy.

Captures IP packets and pushes extracted feature records to a shared queue.
Supports both live capture (Scapy AsyncSniffer) and synthetic demo mode.
"""

import queue
import threading
import time
import random
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.logger import get_logger

log = get_logger("PacketCapture")

# Shared queue for inter-module communication
packet_queue: queue.Queue = queue.Queue(maxsize=50000)

# Global stats
_stats = {
    "total_packets": 0,
    "protocol_dist": {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0},
    "start_time": time.time(),
}
_stats_lock = threading.Lock()


def _extract_packet_record(pkt) -> dict | None:
    """Extract a feature record from a Scapy packet."""
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore

        if not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        pkt_size = len(pkt)
        timestamp = time.time()

        protocol = "OTHER"
        src_port = 0
        dst_port = 0
        flags = 0

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            flags = int(tcp.flags)
            protocol = "TCP"
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            protocol = "UDP"
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "pkt_size": pkt_size,
            "flags": flags,
        }
    except Exception as e:
        log.debug(f"Packet extraction error: {e}")
        return None


def _packet_callback(pkt):
    """Scapy callback — extract record and enqueue."""
    record = _extract_packet_record(pkt)
    if record:
        with _stats_lock:
            _stats["total_packets"] += 1
            proto = record["protocol"]
            _stats["protocol_dist"][proto] = _stats["protocol_dist"].get(proto, 0) + 1
        try:
            packet_queue.put_nowait(record)
        except queue.Full:
            pass  # Drop if overwhelmed


class PacketCapture:
    """Live packet capture using Scapy AsyncSniffer."""

    def __init__(self, iface=None, bpf_filter: str = "ip"):
        self.iface = iface or config.CAPTURE_INTERFACE
        self.bpf_filter = bpf_filter
        self._sniffer = None
        self._running = False

    def start(self):
        """Start capturing in a background thread."""
        try:
            from scapy.all import AsyncSniffer  # type: ignore
            self._sniffer = AsyncSniffer(
                iface=self.iface,
                filter=self.bpf_filter,
                prn=_packet_callback,
                store=False,
            )
            self._sniffer.start()
            self._running = True
            log.info(f"[PacketCapture] Started on interface: {self.iface or 'auto'}")
        except Exception as e:
            log.error(f"[PacketCapture] Failed to start Scapy sniffer: {e}")
            log.warning("[PacketCapture] Falling back to SYNTHETIC traffic mode")
            self._start_synthetic()

    def _start_synthetic(self):
        """Generate realistic synthetic traffic for demo/testing."""
        self._running = True
        t = threading.Thread(target=self._synthetic_loop, daemon=True)
        t.start()
        log.info("[PacketCapture] Synthetic traffic generator started")

    def _synthetic_loop(self):
        """Injects synthetic normal + attack traffic into the queue."""
        benign_ips = [f"192.168.1.{i}" for i in range(2, 30)]
        attacker_ips = [f"10.0.0.{i}" for i in range(1, 10)]
        dst_ips = [f"192.168.1.{i}" for i in range(100, 105)]
        common_ports = [80, 443, 22, 8080, 3306, 5432, 25, 53, 21]
        all_ports = list(range(1, 65535))

        tick = 0
        while self._running:
            records = []
            # Normal benign traffic
            for _ in range(random.randint(5, 20)):
                src = random.choice(benign_ips)
                proto = random.choice(["TCP", "UDP", "ICMP"])
                rec = {
                    "timestamp": time.time(),
                    "src_ip": src,
                    "dst_ip": random.choice(dst_ips),
                    "protocol": proto,
                    "src_port": random.randint(1024, 65535),
                    "dst_port": random.choice(common_ports),
                    "pkt_size": random.randint(40, 1500),
                    "flags": 0x02,  # SYN
                }
                records.append(rec)

            # Simulate attacks every ~20 ticks
            if tick % 20 == 0:
                attack_type = random.choice(["ddos", "portscan", "bruteforce"])
                attacker = random.choice(attacker_ips)

                if attack_type == "ddos":
                    # High rate flood
                    for _ in range(random.randint(400, 800)):
                        records.append({
                            "timestamp": time.time(),
                            "src_ip": attacker,
                            "dst_ip": random.choice(dst_ips),
                            "protocol": "UDP",
                            "src_port": random.randint(1024, 65535),
                            "dst_port": 80,
                            "pkt_size": random.randint(64, 128),
                            "flags": 0,
                        })
                elif attack_type == "portscan":
                    # Many unique ports
                    for port in random.sample(all_ports, random.randint(25, 60)):
                        records.append({
                            "timestamp": time.time(),
                            "src_ip": attacker,
                            "dst_ip": random.choice(dst_ips),
                            "protocol": "TCP",
                            "src_port": random.randint(1024, 65535),
                            "dst_port": port,
                            "pkt_size": 40,
                            "flags": 0x02,  # SYN
                        })
                elif attack_type == "bruteforce":
                    # Repeated SSH hits
                    for _ in range(random.randint(20, 50)):
                        records.append({
                            "timestamp": time.time(),
                            "src_ip": attacker,
                            "dst_ip": random.choice(dst_ips),
                            "protocol": "TCP",
                            "src_port": random.randint(1024, 65535),
                            "dst_port": 22,
                            "pkt_size": random.randint(60, 100),
                            "flags": 0x02,
                        })

            for rec in records:
                with _stats_lock:
                    _stats["total_packets"] += 1
                    proto = rec["protocol"]
                    _stats["protocol_dist"][proto] = _stats["protocol_dist"].get(proto, 0) + 1
                try:
                    packet_queue.put_nowait(rec)
                except queue.Full:
                    pass

            tick += 1
            time.sleep(0.5)

    def stop(self):
        self._running = False
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        log.info("[PacketCapture] Stopped")


def get_stats() -> dict:
    """Return current capture stats (thread-safe copy)."""
    with _stats_lock:
        return {
            "total_packets": _stats["total_packets"],
            "protocol_dist": dict(_stats["protocol_dist"]),
            "uptime_seconds": int(time.time() - _stats["start_time"]),
        }
