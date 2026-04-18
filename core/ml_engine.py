"""
core/ml_engine.py — ML-based anomaly detection using pre-trained models.

Loads:
  - IsolationForest (unsupervised anomaly detection)
  - RandomForestClassifier (supervised multi-class detection, if available)
  - StandardScaler (feature normalization)

Accepts feature vectors and returns anomaly predictions + threat contributions.
"""

import sys
import os
import pickle
import numpy as np
import queue
import threading
from datetime import datetime
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.logger import get_logger

log = get_logger("MLEngine")

# Feature columns expected by the model (must match training order)
DEFAULT_FEATURE_COLS = [
    "total_packets",
    "request_rate_per_min",
    "unique_dst_ports",
    "unique_dst_ips",
    "pkt_size_mean",
    "pkt_size_variance",
    "pkt_size_min",
    "pkt_size_max",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "syn_ratio",
    "auth_port_hits",
    "auth_hit_rate",
    "connection_freq",
]

# Attack label mapping from RF classifier
LABEL_MAP = {
    0: "BENIGN",
    1: "DDoS",
    2: "Port Scan",
    3: "Brute Force",
    4: "Web Attack",
    5: "Bot",
    6: "Infiltration",
    7: "DoS",
    8: "Heartbleed",
}


def _load_pickle(path: str):
    if os.path.exists(path):
        with open(path, "rb") as f:
            return pickle.load(f)
    return None


class MLEngine:
    """
    ML inference engine. Integrates with the detection pipeline.
    Reads from ml_feature_queue and emits ML alerts.
    """

    def __init__(
        self,
        alert_q: queue.Queue,
        on_alert: Callable[[dict], None] | None = None,
    ):
        self.alert_q = alert_q
        self.on_alert = on_alert
        self._running = False
        self._thread = None

        # Load models
        self.iso_forest = _load_pickle(config.MODEL_PATH)
        self.rf_classifier = _load_pickle(config.RF_MODEL_PATH)
        self.scaler = _load_pickle(config.SCALER_PATH)
        self.feature_names = _load_pickle(config.FEATURES_PATH) or DEFAULT_FEATURE_COLS

        if self.iso_forest:
            log.info("[MLEngine] IsolationForest model loaded")
        else:
            log.warning("[MLEngine] No IsolationForest model found — run ml/train.py first")

        if self.rf_classifier:
            log.info("[MLEngine] RandomForest classifier loaded")

    @property
    def is_ready(self) -> bool:
        return self.iso_forest is not None

    def predict(self, features: dict) -> dict | None:
        """
        Run ML inference on a feature vector dict.
        Returns a prediction dict or None if model not ready / benign.
        """
        if not self.is_ready:
            return None

        try:
            vec = np.array(
                [float(features.get(col, 0.0)) for col in self.feature_names],
                dtype=np.float32,
            ).reshape(1, -1)

            # Handle NaN / Inf
            vec = np.nan_to_num(vec, nan=0.0, posinf=1e6, neginf=-1e6)

            # Scale
            if self.scaler:
                vec_scaled = self.scaler.transform(vec)
            else:
                vec_scaled = vec

            # IsolationForest: returns -1 (anomaly) or 1 (normal)
            iso_pred = self.iso_forest.predict(vec_scaled)[0]
            # Raw anomaly score: more negative = more anomalous
            iso_score = self.iso_forest.score_samples(vec_scaled)[0]
            # Convert to 0-100 threat scale (lower score = higher threat)
            ml_threat = float(max(0, min(100, (-iso_score + 0.5) * 100)))

            if iso_pred == 1:
                return None  # Normal traffic

            # Supervised classification (if available)
            attack_type = "Anomaly"
            rf_confidence = 0.6
            if self.rf_classifier:
                rf_pred = self.rf_classifier.predict(vec_scaled)[0]
                rf_proba = self.rf_classifier.predict_proba(vec_scaled)[0]
                attack_type = LABEL_MAP.get(int(rf_pred), "Anomaly")
                rf_confidence = float(rf_proba.max())
                if attack_type == "BENIGN":
                    return None

            severity = (
                "CRITICAL" if ml_threat > 85 else
                "HIGH" if ml_threat > 65 else
                "MEDIUM"
            )

            return {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "src_ip": features["src_ip"],
                "attack_type": attack_type,
                "severity": severity,
                "confidence": rf_confidence,
                "ml_score": round(ml_threat, 2),
                "iso_score": round(float(iso_score), 4),
                "details": {
                    "isolation_forest_label": int(iso_pred),
                    "ml_threat_score": round(ml_threat, 2),
                    "top_features": {
                        col: float(features.get(col, 0))
                        for col in [
                            "request_rate_per_min", "unique_dst_ports",
                            "auth_port_hits", "udp_ratio", "syn_ratio"
                        ]
                    },
                },
                "_features": features,
                "source": "ml",
            }

        except Exception as e:
            log.error(f"[MLEngine] Prediction error: {e}")
            return None

    def start(self, feature_q: queue.Queue):
        """Start background thread consuming from feature_q."""
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            args=(feature_q,),
            daemon=True,
            name="MLEngine",
        )
        self._thread.start()
        log.info("[MLEngine] Started background inference thread")

    def stop(self):
        self._running = False
        log.info("[MLEngine] Stopped")

    def _run_loop(self, feature_q: queue.Queue):
        # ML runs on a duplicate of feature vectors (rule engine already consumes them)
        ml_local_q: queue.Queue = queue.Queue(maxsize=5000)
        feature_q._ml_mirror = ml_local_q  # We'll mirror via the coordinator

        while self._running:
            try:
                features = ml_local_q.get(timeout=1.0)
                result = self.predict(features)
                if result:
                    log.warning(
                        f"[MLEngine] {result['attack_type']} | "
                        f"IP={result['src_ip']} | score={result['ml_score']:.1f}"
                    )
                    try:
                        self.alert_q.put_nowait(result)
                    except queue.Full:
                        pass
                    if self.on_alert:
                        try:
                            self.on_alert(result)
                        except Exception as e:
                            log.error(f"[MLEngine] on_alert error: {e}")
            except queue.Empty:
                continue
            except Exception as e:
                log.error(f"[MLEngine] Loop error: {e}")
