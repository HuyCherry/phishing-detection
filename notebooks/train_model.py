"""
train_model.py — Quick training script (same logic as scripts/retrain.py).
Can be run from notebooks/ or as standalone.
"""
from pathlib import Path
import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

BASE_DIR = Path(__file__).resolve().parent.parent

# Try feeds dataset first, fallback to original
ds_path = BASE_DIR / "data" / "dataset_from_feeds.csv"
if not ds_path.exists():
    ds_path = BASE_DIR / "data" / "phishing_dataset.csv"

df = pd.read_csv(ds_path)
print(f"Shape: {df.shape}")
print(f"Columns: {df.columns.tolist()[:10]}...")

if 'id' in df.columns:
    X = df.drop(['CLASS_LABEL', 'id'], axis=1)
else:
    X = df.drop(['CLASS_LABEL'], axis=1)
y = df['CLASS_LABEL']

feature_names = X.columns.tolist()
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

rf = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
xgb = XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.05,
                     eval_metric='logloss', random_state=42)
lgbm = LGBMClassifier(n_estimators=200, max_depth=8, learning_rate=0.05,
                       random_state=42, verbose=-1)

ensemble = VotingClassifier(
    estimators=[('rf', rf), ('xgb', xgb), ('lgbm', lgbm)],
    voting='soft'
)
print("Training ensemble model...")
ensemble.fit(X_train, y_train)

y_pred = ensemble.predict(X_test)
y_prob = ensemble.predict_proba(X_test)[:, 1]
print(f"Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
print(f"AUC: {roc_auc_score(y_test, y_prob):.4f}")
print(classification_report(y_test, y_pred))

model_path = BASE_DIR / "model" / "phishing_model.pkl"
model_path.parent.mkdir(exist_ok=True)
with open(model_path, 'wb') as f:
    pickle.dump({'model': ensemble, 'feature_names': feature_names}, f)
print(f"Saved: {model_path}  ({model_path.stat().st_size/1024:.1f} KB)")