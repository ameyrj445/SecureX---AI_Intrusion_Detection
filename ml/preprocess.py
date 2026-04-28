"""
ml/preprocess.py — CICIDS2017 dataset preprocessing pipeline.

Steps:
  1. Load all CSV files from data/ directory
  2. Remove null values and infinite values
  3. Encode categorical columns
  4. Drop low-variance / redundant columns
  5. Normalize numerical features (StandardScaler)
  6. Split into train/test sets
  7. Return (X_train, X_test, y_train, y_test, scaler, feature_names, label_encoder)
"""

import sys
import os
import glob
import pickle
import warnings
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import VarianceThreshold

warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.logger import get_logger

log = get_logger("Preprocess")


# ─── Column name normalization ────────────────────────────────────────────────
def _normalize_col(col: str) -> str:
    return col.strip().lower().replace(" ", "_").replace("/", "_").replace("-", "_")


# ─── Label binarizer ─────────────────────────────────────────────────────────
ATTACK_LABEL_MAP = {
    "benign": 0,
    "normal": 0,
    "ddos": 1,
    "dos hulk": 7,
    "dos goldeneye": 7,
    "dos slowloris": 7,
    "dos slowhttptest": 7,
    "heartbleed": 8,
    "web attack – brute force": 3,
    "web attack – xss": 4,
    "web attack – sql injection": 4,
    "web attack brute force": 3,
    "web attack xss": 4,
    "web attack sql injection": 4,
    "ftp-patator": 3,
    "ssh-patator": 3,
    "infiltration": 6,
    "bot": 5,
    "portscan": 2,
}


def map_label(label) -> int:
    # If already an integer (e.g. from synthetic data), return directly
    if isinstance(label, (int, float)):
        return int(label)
    clean = str(label).strip().lower()
    # If it's a digit string, parse directly
    if clean.isdigit():
        return int(clean)
    return ATTACK_LABEL_MAP.get(clean, 1)  # default unknown = 1 (attack)


# ─── Feature columns used for training ───────────────────────────────────────
SELECTED_FEATURES = [
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_of_fwd_packets",
    "flow_duration",
    "flow_bytes_s",
    "flow_packets_s",
    "fwd_packet_length_max",
    "fwd_packet_length_min",
    "fwd_packet_length_mean",
    "fwd_packet_length_std",
    "bwd_packet_length_max",
    "bwd_packet_length_min",
    "bwd_packet_length_mean",
    "bwd_packet_length_std",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_total",
    "fwd_iat_mean",
    "bwd_iat_total",
    "bwd_iat_mean",
    "fwd_psh_flags",
    "bwd_psh_flags",
    "fwd_urg_flags",
    "bwd_urg_flags",
    "fwd_header_length",
    "bwd_header_length",
    "fwd_packets_s",
    "bwd_packets_s",
    "min_packet_length",
    "max_packet_length",
    "packet_length_mean",
    "packet_length_std",
    "packet_length_variance",
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    "cwe_flag_count",
    "ece_flag_count",
    "down_up_ratio",
    "average_packet_size",
    "avg_fwd_segment_size",
    "avg_bwd_segment_size",
    "init_win_bytes_forward",
    "init_win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "active_mean",
    "active_std",
    "active_max",
    "active_min",
    "idle_mean",
    "idle_std",
    "idle_max",
    "idle_min",
]


def load_cicids2017(data_dir: str = None) -> pd.DataFrame | None:
    """Load all CICIDS2017 CSVs from data_dir. Returns None if no files found."""
    data_dir = data_dir or config.DATA_DIR
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    if not csv_files:
        log.warning(f"[Preprocess] No CSV files found in {data_dir}")
        return None

    log.info(f"[Preprocess] Loading {len(csv_files)} CSV file(s)...")
    dfs = []
    for f in csv_files:
        try:
            df = pd.read_csv(f, low_memory=False, encoding="latin-1")
            df.columns = [_normalize_col(c) for c in df.columns]
            dfs.append(df)
            log.info(f"  Loaded: {os.path.basename(f)} ({len(df):,} rows)")
        except Exception as e:
            log.error(f"  Failed to load {f}: {e}")

    if not dfs:
        return None

    combined = pd.concat(dfs, ignore_index=True)
    log.info(f"[Preprocess] Total rows: {len(combined):,}")
    return combined


def preprocess(
    df: pd.DataFrame,
    test_size: float = 0.2,
    random_state: int = config.ML_RANDOM_STATE,
):
    """
    Full preprocessing pipeline.
    Returns: (X_train, X_test, y_train, y_test, scaler, feature_names, le)
    """
    log.info("[Preprocess] Starting preprocessing pipeline...")

    # ── 1. Find label column ──────────────────────────────────────────────────
    label_col = None
    for candidate in ["label", "attack_type", "class", "attack"]:
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        raise ValueError("Could not find label column in dataset")
    log.info(f"[Preprocess] Label column: '{label_col}'")
    log.info(f"[Preprocess] Label distribution:\n{df[label_col].value_counts().head(15)}")

    # ── 2. Encode labels ──────────────────────────────────────────────────────
    y = df[label_col].astype(str).apply(map_label).values
    log.info(f"[Preprocess] Class distribution after mapping: {dict(zip(*np.unique(y, return_counts=True)))}")

    # ── 3. Select features ────────────────────────────────────────────────────
    # Try CICIDS2017-specific columns first; fall back to all numerics
    available = [c for c in SELECTED_FEATURES if c in df.columns]
    if len(available) < 10:
        log.warning("[Preprocess] Few CICIDS features found — using all numeric columns")
        available = [
            c for c in df.columns
            if c != label_col and df[c].dtype in [np.float64, np.float32, np.int64, np.int32]
        ]

    X = df[available].copy()
    log.info(f"[Preprocess] Using {len(available)} features")

    # ── 4. Clean data ─────────────────────────────────────────────────────────
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    null_before = X.isnull().sum().sum()
    X.fillna(X.median(numeric_only=True), inplace=True)
    log.info(f"[Preprocess] Filled {null_before:,} null/inf values")

    # ── 5. Remove zero-variance columns ──────────────────────────────────────
    selector = VarianceThreshold(threshold=0.0)
    X_sel = selector.fit_transform(X)
    feature_names = np.array(available)[selector.get_support()].tolist()
    log.info(f"[Preprocess] After variance threshold: {len(feature_names)} features")

    # ── 6. Scale ──────────────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_sel)

    # ── 7. Train/test split ───────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )
    log.info(
        f"[Preprocess] Train: {X_train.shape}, Test: {X_test.shape} | "
        f"Classes: {np.unique(y_train)}"
    )

    return X_train, X_test, y_train, y_test, scaler, feature_names


def generate_synthetic_data(n_samples: int = 50000):
    """
    Generate synthetic data shaped like CICIDS2017 for testing when no dataset available.
    80% benign, 20% various attacks.
    """
    log.info(f"[Preprocess] Generating {n_samples:,} synthetic samples...")
    np.random.seed(config.ML_RANDOM_STATE)

    n_features = len(SELECTED_FEATURES)
    X = np.random.randn(n_samples, n_features).astype(np.float32)

    labels = np.zeros(n_samples, dtype=int)
    # 20% attacks
    attack_idx = np.random.choice(n_samples, size=int(n_samples * 0.20), replace=False)

    attack_types = [1, 2, 3, 4, 5, 7]
    for i, idx in enumerate(attack_idx):
        atype = attack_types[i % len(attack_types)]
        labels[idx] = atype
        # Add distinguishing signal patterns
        if atype == 1:   # DDoS: high packet rate
            X[idx, 1:3] += 10
        elif atype == 2: # Port scan: many unique ports
            X[idx, 0] += 5
        elif atype == 3: # Brute force: auth ports
            X[idx, 5] += 7
        elif atype == 7: # DoS: large flow duration spike
            X[idx, 3] += 8

    # Create DataFrame
    df = pd.DataFrame(X, columns=SELECTED_FEATURES)
    df["label"] = labels
    log.info(f"[Preprocess] Synthetic data created: {dict(zip(*np.unique(labels, return_counts=True)))}")
    return df
