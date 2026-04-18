"""
ml/replay.py — Dataset Replay Engine for AI-based IDS/IPS.

Streams rows from CICIDS2017 CSV files through the trained ML models
and pushes detections to the dashboard in real time — perfect for demos.
"""

import sys
import os
import glob
import time
import threading
import queue
import random
import pickle
import numpy as np
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.logger import get_logger

log = get_logger("Replay")

LABEL_MAP = {
    0: "BENIGN", 1: "DDoS", 2: "Port Scan", 3: "Brute Force",
    4: "Web Attack", 5: "Bot", 6: "Infiltration", 7: "DoS", 8: "Heartbleed",
}

ATTACK_LABEL_MAP = {
    "benign": 0, "normal": 0,
    "ddos": 1,
    "dos hulk": 7, "dos goldeneye": 7, "dos slowloris": 7, "dos slowhttptest": 7,
    "heartbleed": 8,
    "web attack \u2013 brute force": 3, "web attack \u2013 xss": 4,
    "web attack \u2013 sql injection": 4,
    "web attack brute force": 3, "web attack xss": 4, "web attack sql injection": 4,
    "ftp-patator": 3, "ssh-patator": 3,
    "infiltration": 6, "bot": 5, "portscan": 2,
}

# Fake IP pools for demo
BENIGN_IPS  = [f"192.168.1.{i}" for i in range(10, 50)]
ATTACK_IPS  = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
               for _ in range(80)]


def _fake_ip(label_int: int) -> str:
    if label_int == 0:
        return random.choice(BENIGN_IPS)
    return random.choice(ATTACK_IPS)


def _load_pickle(path):
    if os.path.exists(path):
        with open(path, "rb") as f:
            return pickle.load(f)
    return None


def _normalize_col(col: str) -> str:
    return col.strip().lower().replace(" ", "_").replace("/", "_").replace("-", "_")


def _map_label(label) -> int:
    if isinstance(label, (int, float)):
        return int(label)
    clean = str(label).strip().lower()
    if clean.isdigit():
        return int(clean)
    return ATTACK_LABEL_MAP.get(clean, 1)


class DatasetReplayEngine:
    """
    Reads CICIDS2017 CSV rows, runs them through the trained ML models,
    and emits alert dicts via a callback — at a configurable speed.
    """

    def __init__(self, on_alert, on_stats=None, data_dir: str = None,
                 speed: float = 1.0, attacks_only: bool = False):
        """
        Args:
            on_alert: callable(alert_dict) — called for each detected event
            on_stats:  callable(stats_dict) — called every second with replay stats
            data_dir:  path to CICIDS2017 CSVs
            speed:     rows-per-second multiplier (1.0 = 50 rows/s, 5.0 = 250/s)
            attacks_only: if True, skip BENIGN rows (faster demo)
        """
        self.on_alert = on_alert
        self.on_stats = on_stats
        self.data_dir = data_dir or config.DATA_DIR
        self.speed = max(0.1, speed)
        self.attacks_only = attacks_only

        self._running = False
        self._paused = False
        self._thread = None
        self._lock = threading.Lock()

        # Stats
        self.stats = {
            "status": "idle",
            "rows_processed": 0,
            "attacks_found": 0,
            "benign_found": 0,
            "current_file": "",
            "progress_pct": 0,
            "speed": speed,
            "attacks_only": attacks_only,
        }

        # Load models
        self.scaler       = _load_pickle(config.SCALER_PATH)
        self.feature_names = _load_pickle(config.FEATURES_PATH) or []
        self.rf_model     = _load_pickle(config.RF_MODEL_PATH)
        self.iso_model    = _load_pickle(config.MODEL_PATH)

        if not self.rf_model and not self.iso_model:
            raise RuntimeError("No trained models found — run ml/train.py first")

    # ── Public control API ────────────────────────────────────────────────────

    def start(self):
        if self._running:
            return
        self._running = True
        self._paused  = False
        self._thread  = threading.Thread(target=self._run, daemon=True, name="Replay")
        self._thread.start()
        log.info("[Replay] Dataset replay started")

    def pause(self):
        self._paused = True
        self._update_stats(status="paused")
        log.info("[Replay] Paused")

    def resume(self):
        self._paused = False
        self._update_stats(status="running")
        log.info("[Replay] Resumed")

    def stop(self):
        self._running = False
        self._paused  = False
        self._update_stats(status="idle")
        log.info("[Replay] Stopped")

    def set_speed(self, speed: float):
        self.speed = max(0.1, speed)
        self._update_stats(speed=self.speed)

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self.stats)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _update_stats(self, **kwargs):
        with self._lock:
            self.stats.update(kwargs)

    def _run(self):
        csv_files = glob.glob(os.path.join(self.data_dir, "*.csv"))
        if not csv_files:
            log.error(f"[Replay] No CSV files found in {self.data_dir}")
            self._update_stats(status="error")
            return

        # Prioritise attack-heavy files first for a good demo
        priority = ["DDos", "PortScan", "Tuesday", "Wednesday", "Thursday"]
        def sort_key(f):
            name = os.path.basename(f)
            for i, p in enumerate(priority):
                if p.lower() in name.lower():
                    return i
            return len(priority)
        csv_files.sort(key=sort_key)

        self._update_stats(status="running")
        BASE_ROWS_PER_SEC = 50  # at speed=1.0

        for csv_path in csv_files:
            if not self._running:
                break

            fname = os.path.basename(csv_path)
            self._update_stats(current_file=fname, rows_processed=0, progress_pct=0)
            log.info(f"[Replay] Processing: {fname}")

            try:
                df = pd.read_csv(csv_path, low_memory=False, encoding="latin-1")
                df.columns = [_normalize_col(c) for c in df.columns]
            except Exception as e:
                log.error(f"[Replay] Failed to load {fname}: {e}")
                continue

            # Find label column
            label_col = next((c for c in ["label", "attack_type", "class"] if c in df.columns), None)
            if not label_col:
                continue

            total_rows = len(df)
            rows_done  = 0
            batch_size = max(1, int(BASE_ROWS_PER_SEC * self.speed))

            idx = 0
            while idx < total_rows and self._running:
                # Pause support
                while self._paused and self._running:
                    time.sleep(0.2)

                batch = df.iloc[idx: idx + batch_size]
                idx  += batch_size

                for _, row in batch.iterrows():
                    if not self._running:
                        break

                    label_raw = row.get(label_col, "BENIGN")
                    label_int = _map_label(label_raw)

                    if self.attacks_only and label_int == 0:
                        continue

                    result = self._score_row(row, label_int, label_raw)
                    if result:
                        if self.on_alert:
                            try:
                                self.on_alert(result)
                            except Exception as e:
                                log.error(f"[Replay] on_alert error: {e}")

                rows_done += len(batch)
                pct = min(100, int(rows_done / total_rows * 100))
                with self._lock:
                    self.stats["rows_processed"] += len(batch)
                    self.stats["progress_pct"] = pct
                    if self.on_stats:
                        try:
                            self.on_stats(dict(self.stats))
                        except Exception:
                            pass

                time.sleep(1.0)  # 1 batch per second

        self._update_stats(status="done", progress_pct=100)
        log.info("[Replay] Replay complete")

    def _score_row(self, row: pd.Series, label_int: int, label_raw) -> dict | None:
        """Score a single CSV row through the ML models."""
        try:
            # Build feature vector
            vec = np.array(
                [float(row.get(col, 0.0)) if col in row.index else 0.0
                 for col in self.feature_names],
                dtype=np.float32,
            ).reshape(1, -1)
            vec = np.nan_to_num(vec, nan=0.0, posinf=1e6, neginf=-1e6)

            if self.scaler:
                vec_scaled = self.scaler.transform(vec)
            else:
                vec_scaled = vec

            # Get RF prediction
            attack_type = LABEL_MAP.get(label_int, str(label_raw))
            confidence  = 0.95
            rf_pred_int = label_int

            if self.rf_model:
                rf_pred_int = int(self.rf_model.predict(vec_scaled)[0])
                rf_proba    = self.rf_model.predict_proba(vec_scaled)[0]
                confidence  = float(rf_proba.max())
                attack_type = LABEL_MAP.get(rf_pred_int, "Anomaly")

            # IsolationForest score
            ml_score = 50.0
            if self.iso_model:
                iso_s    = float(self.iso_model.score_samples(vec_scaled)[0])
                ml_score = float(max(0, min(100, (-iso_s + 0.5) * 100)))

            # Skip genuine benign predictions
            if rf_pred_int == 0 and label_int == 0:
                with self._lock:
                    self.stats["benign_found"] += 1
                return None

            # Build alert
            severity = (
                "CRITICAL" if ml_score > 85 or label_int in [1, 7] else
                "HIGH"     if ml_score > 65 or label_int in [2, 3] else
                "MEDIUM"
            )

            src_ip = _fake_ip(label_int)

            with self._lock:
                self.stats["attacks_found"] += 1

            return {
                "timestamp":   pd.Timestamp.utcnow().isoformat() + "Z",
                "src_ip":      src_ip,
                "attack_type": attack_type,
                "severity":    severity,
                "confidence":  round(confidence, 3),
                "ml_score":    round(ml_score, 2),
                "source":      "replay",
                "details": {
                    "true_label":   str(label_raw),
                    "rf_predicted": attack_type,
                    "ml_score":     round(ml_score, 2),
                },
            }

        except Exception as e:
            log.error(f"[Replay] Score error: {e}")
            return None
