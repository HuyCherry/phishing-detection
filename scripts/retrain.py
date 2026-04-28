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
from sklearn.metrics import accuracy_score, roc_auc_score, precision_score, recall_score, f1_score
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "model"
MODEL_DIR.mkdir(parents=True, exist_ok=True)


if __name__ == "__main__":
    print("=" * 50)
    print("RETRAIN MODEL - START")
    print("=" * 50)

    # --- Load dataset ---
    ds_path = DATA_DIR / "dataset_from_feeds.csv"
    if not ds_path.exists():
        print(f"  {ds_path.name} not found, fallback to phishing_dataset.csv")
        ds_path = DATA_DIR / "phishing_dataset.csv"

    if not ds_path.exists():
        print("ERROR: No dataset found.")
        sys.exit(1)

    print(f"  Loading {ds_path.name}...")
    df = pd.read_csv(ds_path)

    if 'id' in df.columns:
        df = df.drop(columns=['id'])

    if 'CLASS_LABEL' not in df.columns:
        print("ERROR: CLASS_LABEL column not found.")
        sys.exit(1)

    X = df.drop(columns=['CLASS_LABEL'])
    y = df['CLASS_LABEL']
    feature_names = X.columns.tolist()

    print(f"  Shape: {X.shape}, Features: {len(feature_names)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # --- Build ensemble ---
    print("  Building ensemble (RF + XGBoost + LightGBM)...")
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=20, random_state=42, n_jobs=-1
    )
    xgb = XGBClassifier(
        n_estimators=200, max_depth=8, learning_rate=0.05,
        eval_metric='logloss', random_state=42
    )
    lgbm = LGBMClassifier(
        n_estimators=200, max_depth=8, learning_rate=0.05,
        random_state=42, verbose=-1
    )

    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('xgb', xgb), ('lgbm', lgbm)],
        voting='soft'
    )

    print("  Training...")
    ensemble.fit(X_train, y_train)

    # --- Evaluate ---
    print("  Evaluating...")
    y_pred = ensemble.predict(X_test)
    y_prob = ensemble.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f"  Accuracy  : {acc:.4f}")
    print(f"  AUC       : {auc:.4f}")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1        : {f1:.4f}")

    # --- Top 10 feature importance (from RF) ---
    print("\n  Top 10 Feature Importance (RandomForest):")
    rf_fitted = ensemble.named_estimators_['rf']
    importances = rf_fitted.feature_importances_
    indices = np.argsort(importances)[::-1][:10]
    for rank, idx in enumerate(indices, 1):
        print(f"    {rank:2d}. {feature_names[idx]:30s}  {importances[idx]:.4f}")

    # --- Check if should deploy ---
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

    if auc >= old_auc - 0.005 or len(history) == 0:
        print("  -> Deploying new model...")
        model_path = MODEL_DIR / "phishing_model.pkl"
        with open(model_path, "wb") as f:
            pickle.dump({'model': ensemble, 'feature_names': feature_names}, f)

        size_kb = os.path.getsize(model_path) / 1024
        print(f"  -> Saved {model_path.name} ({size_kb:.1f} KB)")

        history.append({
            "trained_at": str(pd.Timestamp.now()),
            "accuracy": round(acc, 4),
            "auc": round(auc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "model_size_kb": round(size_kb, 1),
        })
        with open(history_file, "w") as f:
            json.dump(history, f, indent=4)
    else:
        print("  -> Model did NOT improve. Discarding.")

    print("=" * 50)
    print("RETRAIN MODEL - COMPLETE")
    print("=" * 50)
