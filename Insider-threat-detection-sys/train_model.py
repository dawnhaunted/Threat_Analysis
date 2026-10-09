"""Optional baseline anomaly model for the synthetic activity dataset.

The dashboard currently uses the transparent rule engine. This script trains an
Isolation Forest as an experimental, unsupervised baseline; it is not a
validated detector and should not be used for employment decisions.
"""
from pathlib import Path
import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "sample_activity.csv"
MODEL_DIR = ROOT / "model"
MODEL_PATH = MODEL_DIR / "isolation_forest.joblib"

NUMERIC = ["data_volume_mb", "failed_logins"]
CATEGORICAL = ["department", "event_type", "device_trust", "after_hours"]

def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)
    missing = set(NUMERIC + CATEGORICAL) - set(df.columns)
    if missing:
        raise ValueError(f"Dataset missing columns: {sorted(missing)}")
    features = df[NUMERIC + CATEGORICAL].copy()
    features["after_hours"] = features["after_hours"].astype(str)
    preprocess = ColumnTransformer([
        ("numeric", StandardScaler(), NUMERIC),
        ("categorical", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL),
    ])
    pipeline = Pipeline([
        ("preprocess", preprocess),
        ("detector", IsolationForest(n_estimators=200, contamination=0.08, random_state=42)),
    ])
    pipeline.fit(features)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    print(f"Saved experimental anomaly model to: {MODEL_PATH}")

if __name__ == "__main__":
    main()
