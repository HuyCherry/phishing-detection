import os
import json
import pickle
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, roc_auc_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from xgboost import XGBClassifier

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "model"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

if __name__ == "__main__":
    print("=== STARTING MODEL RETRAIN ===")
    
    dataset_path = DATA_DIR / "dataset_from_feeds.csv"
    if not dataset_path.exists():
        print(f"{dataset_path.name} not found. Fallback to phishing_dataset.csv")
        dataset_path = DATA_DIR / "phishing_dataset.csv"
        
    if not dataset_path.exists():
        print("No dataset found. Please provide dataset.")
        exit(1)
        
    print(f"Loading data from {dataset_path.name}...")
    df = pd.read_csv(dataset_path)
    
    if 'id' in df.columns:
        df = df.drop(columns=['id'])
        
    if 'CLASS_LABEL' not in df.columns:
        print("Error: CLASS_LABEL column not found.")
        exit(1)
        
    X = df.drop(columns=['CLASS_LABEL'])
    y = df['CLASS_LABEL']
    
    feature_names = X.columns.tolist()
    
    print(f"Data shape: {X.shape}, Features: {len(feature_names)}")
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Initializing models...")
    rf = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
    xgb = XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.05, eval_metric='logloss', random_state=42)
    gb = GradientBoostingClassifier(n_estimators=100, max_depth=6, random_state=42)
    
    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('xgb', xgb), ('gb', gb)],
        voting='soft'
    )
    
    print("Training ensemble model...")
    ensemble.fit(X_train, y_train)
    
    print("Evaluating model...")
    y_pred = ensemble.predict(X_test)
    y_prob = ensemble.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    
    print(f"New Model Accuracy: {acc:.4f}")
    print(f"New Model AUC     : {auc:.4f}")
    
    history_file = MODEL_DIR / "model_history.json"
    old_auc = 0.0
    history = []
    
    if history_file.exists():
        try:
            with open(history_file, "r") as f:
                history = json.load(f)
                if history:
                    old_auc = history[-1].get("auc", 0.0)
        except Exception as e:
            print(f"Warning: Could not read model history: {e}")
            
    print(f"Previous AUC      : {old_auc:.4f}")
    
    if auc >= old_auc - 0.005 or len(history) == 0:
        print("Model improved or condition met. Saving new model...")
        model_path = MODEL_DIR / "phishing_model.pkl"
        
        model_data = {
            'model': ensemble,
            'feature_names': feature_names
        }
        
        with open(model_path, "wb") as f:
            pickle.dump(model_data, f)
            
        model_size_kb = os.path.getsize(model_path) / 1024
        print(f"Model saved to {model_path.name} ({model_size_kb:.1f} KB)")
        
        history.append({
            "trained_at": str(pd.Timestamp.now()),
            "accuracy": acc,
            "auc": auc,
            "model_size_kb": model_size_kb
        })
        
        with open(history_file, "w") as f:
            json.dump(history, f, indent=4)
    else:
        print("Model did not improve sufficiently. Discarding new model.")
        
    print("=== RETRAIN COMPLETE ===")
