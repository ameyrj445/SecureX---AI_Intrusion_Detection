"""
core/threat_score.py — Composite threat scoring system (0–100).

Combines:
  - Rule engine confidence score (weight: 50%)
  - ML anomaly score (weight: 30%)
  - Geo-risk modifier (weight: 20%)

Maps final score to severity level (LOW / MEDIUM / HIGH / CRITICAL).
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.logger import get_logger
from core import geo_ip

log = get_logger("ThreatScore")


def compute_threat_score(alert: dict) -> float:
    """
    Compute a composite 0–100 threat score for an alert.

    alert keys used:
      rule_score  (0-100)  — from rule engine
      ml_score    (0-100)  — from ML engine
      confidence  (0-1)    — detection confidence
      geo         (dict)   — geolocation (country_code)
    """
    rule_score = float(alert.get("rule_score", 0))
    ml_score = float(alert.get("ml_score", 0))
    confidence = float(alert.get("confidence", 0.5))

    # Geo risk
    geo = alert.get("geo", {})
    country_code = geo.get("country_code", "??")
    geo_risk = geo_ip.get_country_risk_score(country_code) * 100  # 0-100

    # If only rule fired (no ML score), use rule confidence to estimate ML contribution
    if ml_score == 0 and rule_score > 0:
        ml_score = rule_score * 0.8

    # Weighted composite
    composite = (
        config.RULE_WEIGHT * rule_score
        + config.ML_WEIGHT * ml_score
        + config.GEO_WEIGHT * geo_risk
    )

    # Boost by confidence
    composite = composite * (0.5 + 0.5 * confidence)

    return round(min(max(composite, 0.0), 100.0), 2)


def get_severity(score: float) -> str:
    """Map a 0-100 threat score to a severity label."""
    if score >= config.THREAT_LEVEL_HIGH:
        return "CRITICAL"
    elif score >= config.THREAT_LEVEL_MEDIUM:
        return "HIGH"
    elif score >= config.THREAT_LEVEL_LOW:
        return "MEDIUM"
    else:
        return "LOW"


def enrich_with_threat_score(alert: dict) -> dict:
    """
    Add 'threat_score' and update 'severity' in the alert dict.
    Expects 'geo' key to already be set (run geo_ip.enrich_alert first).
    """
    score = compute_threat_score(alert)
    alert["threat_score"] = score
    alert["severity"] = get_severity(score)
    return alert
