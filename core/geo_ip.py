"""
core/geo_ip.py — IP Geolocation using ip-api.com (free, no API key needed).

Features:
- Async HTTP lookup
- In-memory LRU cache with TTL
- Private IP detection (skips lookup)
"""

import sys
import os
import time
import threading
import ipaddress
from functools import lru_cache

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.logger import get_logger

log = get_logger("GeoIP")

try:
    import requests
    _requests_available = True
except ImportError:
    _requests_available = False
    log.warning("[GeoIP] 'requests' not installed — geolocation disabled")

# ─── Cache ───────────────────────────────────────────────────────────────────
_cache: dict = {}          # ip -> {data, expires}
_cache_lock = threading.Lock()

# Private / reserved ranges
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


_PRIVATE_GEO = {
    "country": "Private",
    "countryCode": "XX",
    "city": "Local Network",
    "lat": 0.0,
    "lon": 0.0,
    "isp": "Local",
    "status": "private",
}


def lookup(ip: str) -> dict:
    """
    Look up geolocation for an IP address.
    Returns a dict with: country, countryCode, city, lat, lon, isp, status.
    """
    if _is_private(ip):
        return dict(_PRIVATE_GEO)

    # Check cache
    with _cache_lock:
        entry = _cache.get(ip)
        if entry and entry["expires"] > time.time():
            return entry["data"]

    if not _requests_available:
        return {"country": "Unknown", "countryCode": "??", "city": "Unknown",
                "lat": 0.0, "lon": 0.0, "isp": "Unknown", "status": "error"}

    try:
        url = config.GEO_API_URL.format(ip=ip)
        resp = requests.get(url, timeout=3)
        data = resp.json()
        if data.get("status") != "success":
            data = {"country": "Unknown", "countryCode": "??", "city": "Unknown",
                    "lat": 0.0, "lon": 0.0, "isp": "Unknown", "status": "fail"}
    except Exception as e:
        log.debug(f"[GeoIP] Lookup error for {ip}: {e}")
        data = {"country": "Unknown", "countryCode": "??", "city": "Unknown",
                "lat": 0.0, "lon": 0.0, "isp": "Unknown", "status": "error"}

    # Cache result
    with _cache_lock:
        _cache[ip] = {
            "data": data,
            "expires": time.time() + config.GEO_CACHE_TTL,
        }
        # Trim cache if too large
        if len(_cache) > 5000:
            oldest = sorted(_cache.keys(), key=lambda k: _cache[k]["expires"])[:500]
            for key in oldest:
                del _cache[key]

    return data


def get_country_risk_score(country_code: str) -> float:
    """Return a 0-1 geo risk modifier based on country."""
    if country_code in config.HIGH_RISK_COUNTRIES:
        return 0.8
    if country_code in {"XX", "??"}:
        return 0.5
    return 0.2


def enrich_alert(alert: dict) -> dict:
    """Add geo data to an alert dict in-place. Returns the alert."""
    ip = alert.get("src_ip", "")
    geo = lookup(ip) if ip else {}
    alert["geo"] = {
        "country": geo.get("country", "Unknown"),
        "country_code": geo.get("countryCode", "??"),
        "city": geo.get("city", "Unknown"),
        "lat": geo.get("lat", 0.0),
        "lon": geo.get("lon", 0.0),
        "isp": geo.get("isp", "Unknown"),
    }
    return alert
