from pathlib import Path
import pandas as pd, pickle, os
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier

BASE_DIR = Path(__file__).resolve().parent.parent
df = pd.read_csv(BASE_DIR / "data" / "clean_data.csv")
print(f"Shape: {df.shape}")
print(f"Columns: {df.columns.tolist()[:10]}...")

if 'id' in df.columns:
    X = df.drop(['CLASS_LABEL', 'id'], axis=1)
else:
    X = df.drop(['CLASS_LABEL'], axis=1)
y = df['CLASS_LABEL']

feature_names = X.columns.tolist()
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Ensemble 3 model mạnh hơn
rf  = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
xgb = XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.05,
                    eval_metric='logloss', random_state=42)
gb  = GradientBoostingClassifier(n_estimators=100, max_depth=6, random_state=42)

ensemble = VotingClassifier(
    estimators=[('rf', rf), ('xgb', xgb), ('gb', gb)],
    voting='soft'
)
print("Training ensemble model...")
ensemble.fit(X_train, y_train)

y_pred = ensemble.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
print(classification_report(y_test, y_pred))

model_path = BASE_DIR / "model" / "phishing_model.pkl"
model_path.parent.mkdir(exist_ok=True)
with open(model_path, 'wb') as f:
    pickle.dump({'model': ensemble, 'feature_names': feature_names}, f)
print(f"Saved: {model_path}  ({model_path.stat().st_size/1024:.1f} KB)")