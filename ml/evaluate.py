"""ml/evaluate.py — Standalone model evaluation script."""

import sys
import os
import pickle
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.logger import get_logger
from ml.preprocess import load_cicids2017, preprocess, generate_synthetic_data

log = get_logger("Evaluate")


def load_model(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return pickle.load(f)


def main():
    log.info("[Evaluate] Loading saved models...")
    iso  = load_model(config.MODEL_PATH)
    rf   = load_model(config.RF_MODEL_PATH)
    scaler = load_model(config.SCALER_PATH)
    feat_names = load_model(config.FEATURES_PATH)

    if not iso:
        log.error("[Evaluate] No trained models found. Run ml/train.py first.")
        return

    log.info("[Evaluate] Loading test data (synthetic)...")
    df = generate_synthetic_data(10000)
    X_train, X_test, y_train, y_test, _, _ = preprocess(df)

    from sklearn.metrics import (
        classification_report, accuracy_score,
        precision_score, recall_score, f1_score
    )

    # Isolation Forest
    if_preds = iso.predict(X_test)
    if_binary = np.where(if_preds == -1, 1, 0)
    y_binary  = np.where(y_test > 0, 1, 0)

    print("\n" + "="*60)
    print("  ISOLATION FOREST — Binary Detection Report")
    print("="*60)
    print(f"  Accuracy:  {accuracy_score(y_binary, if_binary)*100:.2f}%")
    print(f"  Precision: {precision_score(y_binary, if_binary, zero_division=0)*100:.2f}%")
    print(f"  Recall:    {recall_score(y_binary, if_binary, zero_division=0)*100:.2f}%")
    print(f"  F1-Score:  {f1_score(y_binary, if_binary, zero_division=0)*100:.2f}%")

    if rf:
        print("\n" + "="*60)
        print("  RANDOM FOREST — Multi-Class Report")
        print("="*60)
        rf_preds = rf.predict(X_test)
        print(classification_report(y_test, rf_preds, zero_division=0))

    print("="*60 + "\n")


if __name__ == "__main__":
    main()
