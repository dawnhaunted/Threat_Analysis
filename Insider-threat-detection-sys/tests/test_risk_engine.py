import pandas as pd
import pytest
from risk_engine import add_risk_assessment, risk_band, score_event

def event(**overrides):
    row = {
        "timestamp": "2026-01-01 09:00:00", "user_id": "EMP-001",
        "department": "IT", "event_type": "login", "device_trust": "trusted",
        "after_hours": False, "data_volume_mb": 10, "failed_logins": 0,
    }
    row.update(overrides)
    return row

def test_risk_bands():
    assert risk_band(0) == "Low"
    assert risk_band(40) == "Medium"
    assert risk_band(70) == "High"
    assert risk_band(85) == "Critical"

def test_high_risk_event_has_explanations():
    score, reasons = score_event(event(event_type="bulk_export", device_trust="untrusted",
        after_hours=True, data_volume_mb=800, failed_logins=6))
    assert score == 100
    assert len(reasons) >= 4

def test_assessment_adds_columns():
    result = add_risk_assessment(pd.DataFrame([event()]))
    assert {"risk_score", "risk_band", "risk_reasons"} <= set(result.columns)
    assert result.iloc[0]["risk_band"] == "Low"

def test_missing_column_fails():
    with pytest.raises(ValueError, match="Missing required columns"):
        add_risk_assessment(pd.DataFrame([{"user_id": "EMP-001"}]))

def test_negative_volume_fails():
    with pytest.raises(ValueError, match="cannot be negative"):
        add_risk_assessment(pd.DataFrame([event(data_volume_mb=-1)]))
