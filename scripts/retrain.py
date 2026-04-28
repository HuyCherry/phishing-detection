"""
retrain.py — Train Ensemble ML model (RF + XGBoost + LightGBM).
"""
import os
import sys
import json
import pickle
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, roc_auc_score, precision_score, recall_score, f1_score,
)
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
from config import DATA_DIR, MODEL_DIR, MODEL_PATH


def load_best_dataset():
    """Ưu tiên dataset_from_feeds.csv, fallback phishing_dataset.csv."""
    ds_path = DATA_DIR / "dataset_from_feeds.csv"
    if not ds_path.exists():
        print(f"  {ds_path.name} not found, fallback to phishing_dataset.csv")
        ds_path = DATA_DIR / "phishing_dataset.csv"
    if not ds_path.exists():
        print("ERROR: No dataset found. Run fetch_feeds.py + build_dataset.py first.")
        sys.exit(1)
    print(f"  Loading {ds_path.name}...")
    df = pd.read_csv(ds_path)
    if 'id' in df.columns:
        df = df.drop(columns=['id'])
    if 'CLASS_LABEL' not in df.columns:
        print("ERROR: CLASS_LABEL column not found.")
        sys.exit(1)
    return df


def train(df):
    """Train ensemble model, return (model, feature_names, metrics)."""
    X = df.drop(columns=['CLASS_LABEL'])
    y = df['CLASS_LABEL']
    feature_names = X.columns.tolist()
    print(f"  Shape: {X.shape}, Features: {len(feature_names)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42,
    )

    print("  Building ensemble (RF + XGBoost + LightGBM)...")
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=20, random_state=42, n_jobs=-1,
    )
    xgb = XGBClassifier(
        n_estimators=200, max_depth=8, learning_rate=0.05,
        eval_metric='logloss', random_state=42,
    )
    lgbm = LGBMClassifier(
        n_estimators=200, max_depth=8, learning_rate=0.05,
        random_state=42, verbose=-1,
    )
    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('xgb', xgb), ('lgbm', lgbm)],
        voting='soft',
    )

    print("  Training...")
    ensemble.fit(X_train, y_train)

    print("  Evaluating...")
    y_pred = ensemble.predict(X_test)
    y_prob = ensemble.predict_proba(X_test)[:, 1]

    metrics = {
        'accuracy': round(accuracy_score(y_test, y_pred), 4),
        'auc': round(roc_auc_score(y_test, y_prob), 4),
        'precision': round(precision_score(y_test, y_pred), 4),
        'recall': round(recall_score(y_test, y_pred), 4),
        'f1': round(f1_score(y_test, y_pred), 4),
    }
    for k, v in metrics.items():
        print(f"  {k:12s}: {v:.4f}")

    # Top 10 feature importance
    print("\n  Top 10 Feature Importance (RandomForest):")
    rf_fitted = ensemble.named_estimators_['rf']
    importances = rf_fitted.feature_importances_
    indices = np.argsort(importances)[::-1][:10]
    for rank, idx in enumerate(indices, 1):
        print(f"    {rank:2d}. {feature_names[idx]:30s}  {importances[idx]:.4f}")

    return ensemble, feature_names, metrics


def validate_and_deploy(model, feature_names, metrics, dataset_size):
    """Lưu model nếu AUC không giảm quá 0.005."""
    history_file = MODEL_DIR / "model_history.json"
    history = []
    old_auc = 0.0

    if history_file.exists():
        try:
            with open(history_file, "r") as f:
                history = json.load(f)
            if history:
                old_auc = history[-1].get("auc", 0.0)
        except Exception:
            pass

    print(f"\n  Previous AUC: {old_auc:.4f}")
    auc = metrics['auc']

    if auc >= old_auc - 0.005 or len(history) == 0:
        print("  -> Deploying new model...")
        with open(MODEL_PATH, "wb") as f:
            pickle.dump({'model': model, 'feature_names': feature_names}, f)
        size_kb = os.path.getsize(MODEL_PATH) / 1024
        print(f"  -> Saved {MODEL_PATH.name} ({size_kb:.1f} KB)")

        history.append({
            "trained_at": str(pd.Timestamp.now()),
            **metrics,
            "model_size_kb": round(size_kb, 1),
            "dataset_size": dataset_size,
        })
        with open(history_file, "w") as f:
            json.dump(history, f, indent=4)
    else:
        print("  -> Model did NOT improve. Discarding.")


if __name__ == "__main__":
    print("=" * 50)
    print("RETRAIN MODEL - START")
    print("=" * 50)

    df = load_best_dataset()
    model, feature_names, metrics = train(df)
    validate_and_deploy(model, feature_names, metrics, len(df))

    print("=" * 50)
    print("RETRAIN MODEL - COMPLETE")
    print("=" * 50)
