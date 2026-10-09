"""Generate a reproducible synthetic activity dataset for demos and tests."""
from pathlib import Path
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "sample_activity.csv"

def generate(n: int = 600, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    users = [f"EMP-{i:03d}" for i in range(1, 61)]
    departments = ["Engineering", "Finance", "HR", "Operations", "Sales", "IT"]
    event_types = ["login", "file_access", "file_download", "email_access", "mass_download", "bulk_export"]
    rows = []
    start = np.datetime64("2026-01-01T00:00")
    for i in range(n):
        suspicious = rng.random() < 0.09
        event = rng.choice(event_types, p=[.32,.27,.18,.12,.07,.04])
        if suspicious and rng.random() < .6:
            event = rng.choice(["mass_download", "bulk_export"])
        volume = float(rng.lognormal(2.8, .7))
        if suspicious:
            volume = float(rng.uniform(150, 1200))
        failed = int(rng.choice([0,1,2,3,5,7], p=[.64,.15,.1,.05,.04,.02]))
        if suspicious and rng.random() < .4:
            failed = int(rng.integers(5, 10))
        rows.append({
            "timestamp": str(start + np.timedelta64(int(rng.integers(0, 90*24*60)), "m")),
            "user_id": str(rng.choice(users)),
            "department": str(rng.choice(departments)),
            "event_type": str(event),
            "device_trust": str(rng.choice(["trusted","trusted","trusted","unknown","untrusted"] if not suspicious else ["trusted","unknown","untrusted"])),
            "after_hours": bool(rng.random() < (.55 if suspicious else .16)),
            "data_volume_mb": round(volume, 2),
            "failed_logins": failed,
        })
    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)

if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    generate().to_csv(OUT, index=False)
    print(f"Wrote {OUT}")
