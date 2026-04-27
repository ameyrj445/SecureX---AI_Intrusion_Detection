"""
ml/train.py — Model training script for the AI-based IDS/IPS.

Trains:
  1. IsolationForest — unsupervised anomaly detection
  2. RandomForestClassifier — supervised multi-class attack classification

Usage:
  python ml/train.py                    # Use CICIDS2017 CSVs in data/
  python ml/train.py --synthetic        # Generate synthetic data (no dataset needed)
  python ml/train.py --data /path/to/   # Custom data directory
  python ml/train.py --evaluate         # Run evaluation report after training
"""

import sys
import os
import argparse
import pickle
import time
import warnings

warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.logger import get_logger
from ml.preprocess import load_cicids2017, preprocess, generate_synthetic_data

log = get_logger("Train")


def save_model(obj, path: str, name: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(obj, f, protocol=pickle.HIGHEST_PROTOCOL)
    log.info(f"[Train] {name} saved → {path}")


def train_isolation_forest(X_train, contamination: float = config.ML_CONTAMINATION):
    from sklearn.ensemble import IsolationForest
    log.info(f"[Train] Training IsolationForest (n_estimators={config.ML_N_ESTIMATORS}, contamination={contamination})...")
    t0 = time.time()
    model = IsolationForest(
        n_estimators=config.ML_N_ESTIMATORS,
        contamination=contamination,
        random_state=config.ML_RANDOM_STATE,
        n_jobs=1,
        max_samples="auto",
    )
    model.fit(X_train)
    log.info(f"[Train] IsolationForest trained in {time.time()-t0:.1f}s")
    return model


def train_random_forest(X_train, y_train):
    from sklearn.ensemble import RandomForestClassifier
    log.info("[Train] Training RandomForestClassifier...")
    t0 = time.time()
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=5,
        n_jobs=1,
        random_state=config.ML_RANDOM_STATE,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)
    log.info(f"[Train] RandomForest trained in {time.time()-t0:.1f}s")
    return model


def evaluate(iso_model, rf_model, X_test, y_test, feature_names):
    from sklearn.metrics import (
        classification_report, accuracy_score,
        precision_score, recall_score, f1_score,
        confusion_matrix, roc_auc_score
    )
    import numpy as np

    print("\n" + "="*70)
    print("  ISOLATION FOREST EVALUATION")
    print("="*70)
    # IF predicts -1 (anomaly) or 1 (normal)
    if_preds = iso_model.predict(X_test)
    # Map: -1 → attack (1), 1 → benign (0)
    if_binary = np.where(if_preds == -1, 1, 0)
    y_binary = np.where(y_test > 0, 1, 0)

    acc = accuracy_score(y_binary, if_binary)
    prec = precision_score(y_binary, if_binary, zero_division=0)
    rec = recall_score(y_binary, if_binary, zero_division=0)
    f1 = f1_score(y_binary, if_binary, zero_division=0)

    print(f"  Accuracy:  {acc*100:.2f}%")
    print(f"  Precision: {prec*100:.2f}%")
    print(f"  Recall:    {rec*100:.2f}%")
    print(f"  F1-Score:  {f1*100:.2f}%")
    print(f"\n  Confusion Matrix (binary: normal=0, attack=1):")
    cm = confusion_matrix(y_binary, if_binary)
    print(f"  {cm}")

    if rf_model is not None:
        print("\n" + "="*70)
        print("  RANDOM FOREST CLASSIFIER EVALUATION")
        print("="*70)
        rf_preds = rf_model.predict(X_test)
        # Only include labels that appear in test set
        present_labels = sorted(np.unique(np.concatenate([y_test, rf_preds])))
        ALL_NAMES = {0:"BENIGN",1:"DDoS",2:"PortScan",3:"BruteForce",
                     4:"WebAtk",5:"Bot",6:"Infiltration",7:"DoS",8:"Heartbleed"}
        label_tnames = [ALL_NAMES.get(l, f"Class{l}") for l in present_labels]
        print(classification_report(
            y_test, rf_preds,
            labels=present_labels,
            target_names=label_tnames,
            zero_division=0
        ))
        rf_acc = accuracy_score(y_test, rf_preds)
        print(f"  Overall Accuracy: {rf_acc*100:.2f}%")

        # Top feature importances
        importances = rf_model.feature_importances_
        top_idx = importances.argsort()[::-1][:10]
        print("\n  Top 10 Important Features:")
        for i, idx in enumerate(top_idx):
            print(f"    {i+1:2d}. {feature_names[idx]:<40s} {importances[idx]:.4f}")

    print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="IDS/IPS Model Trainer")
    parser.add_argument("--synthetic", action="store_true",
                        help="Use synthetic data (no dataset files needed)")
    parser.add_argument("--data", default=None, help="Path to data directory")
    parser.add_argument("--evaluate", action="store_true", help="Run evaluation after training")
    parser.add_argument("--contamination", type=float, default=config.ML_CONTAMINATION,
                        help="IsolationForest contamination ratio (default: 0.05)")
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("  AI-Based IDS/IPS — Model Training")
    log.info("=" * 60)

    # ── Load Data ─────────────────────────────────────────────────────────────
    if args.synthetic:
        log.info("[Train] Using synthetic dataset...")
        df = generate_synthetic_data(n_samples=100000)
    else:
        df = load_cicids2017(args.data)
        if df is None:
            log.warning("[Train] No CICIDS2017 data found. Falling back to synthetic.")
            df = generate_synthetic_data(n_samples=100000)

    # ── Preprocess ────────────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test, scaler, feature_names = preprocess(df)

    # ── Train IsolationForest ─────────────────────────────────────────────────
    iso_model = train_isolation_forest(X_train, args.contamination)
    save_model(iso_model, config.MODEL_PATH, "IsolationForest")

    # ── Train RandomForest ────────────────────────────────────────────────────
    rf_model = None
    try:
        rf_model = train_random_forest(X_train, y_train)
        save_model(rf_model, config.RF_MODEL_PATH, "RandomForest")
    except Exception as e:
        log.error(f"[Train] RandomForest training failed: {e}")

    # ── Save scaler + feature list ────────────────────────────────────────────
    save_model(scaler, config.SCALER_PATH, "StandardScaler")
    save_model(feature_names, config.FEATURES_PATH, "FeatureNames")

    log.info(f"[Train] Feature names saved: {feature_names[:5]}... ({len(feature_names)} total)")

    # ── Evaluate ──────────────────────────────────────────────────────────────
    if args.evaluate or True:  # Always evaluate
        evaluate(iso_model, rf_model, X_test, y_test, feature_names)

    log.info("[Train] ✅ All models saved to ml/models/")
    log.info("[Train] Run 'python main.py' to start the IDS/IPS system")


if __name__ == "__main__":
    main()

