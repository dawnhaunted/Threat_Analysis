"""Transparent rule-based risk scoring for security activity events."""
from __future__ import annotations
import pandas as pd

REQUIRED_COLUMNS = {
    "timestamp", "user_id", "department", "event_type", "device_trust",
    "after_hours", "data_volume_mb", "failed_logins"
}

def risk_band(score: float) -> str:
    """Map a 0–100 score to a readable severity band."""
    score = float(score)
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"

def score_event(row) -> tuple[int, list[str]]:
    """Return an explainable score and the triggered risk indicators."""
    score, reasons = 0, []
    event = str(row["event_type"]).strip().lower()
    trust = str(row["device_trust"]).strip().lower()
    after_hours = str(row["after_hours"]).strip().lower() in {"true", "1", "yes"}
    volume = max(0.0, float(row["data_volume_mb"]))
    failed = max(0, int(row["failed_logins"]))

    if event in {"mass_download", "bulk_export"}:
        score += 35
        reasons.append("bulk data transfer")
    elif event in {"file_download", "file_access"}:
        score += 10
        reasons.append("file activity")

    if trust in {"untrusted", "unknown", "low"}:
        score += 20
        reasons.append("untrusted device")

    if after_hours:
        score += 15
        reasons.append("after-hours activity")

    if volume >= 500:
        score += 25
        reasons.append("very high data volume")
    elif volume >= 100:
        score += 12
        reasons.append("elevated data volume")

    if failed >= 5:
        score += 15
        reasons.append("repeated failed logins")
    elif failed >= 2:
        score += 7
        reasons.append("multiple failed logins")

    return min(100, score), reasons or ["no configured indicators triggered"]

def add_risk_assessment(data: pd.DataFrame) -> pd.DataFrame:
    """Validate input and return a copy enriched with risk_score, risk_band, risk_reasons."""
    missing = REQUIRED_COLUMNS - set(data.columns)
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(sorted(missing))}")
    df = data.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if df["timestamp"].isna().any():
        raise ValueError("Column 'timestamp' contains invalid or empty timestamps.")
    df["user_id"] = df["user_id"].astype(str).str.strip()
    df["department"] = df["department"].astype(str).str.strip()
    if (df["user_id"] == "").any():
        raise ValueError("Column 'user_id' cannot contain empty values.")
    df["data_volume_mb"] = pd.to_numeric(df["data_volume_mb"], errors="coerce")
    df["failed_logins"] = pd.to_numeric(df["failed_logins"], errors="coerce")
    if df[["data_volume_mb", "failed_logins"]].isna().any().any():
        raise ValueError("data_volume_mb and failed_logins must contain numeric values.")
    if (df["data_volume_mb"] < 0).any() or (df["failed_logins"] < 0).any():
        raise ValueError("Data volume and failed login counts cannot be negative.")
    scores = df.apply(score_event, axis=1)
    df["risk_score"] = scores.apply(lambda result: result[0])
    df["risk_reasons"] = scores.apply(lambda result: result[1])
    df["risk_band"] = df["risk_score"].apply(risk_band)
    return df
