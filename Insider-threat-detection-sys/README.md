<div align="center">

# 🛡️ Sentinel — Insider Threat Detection & Risk Prioritization

**An explainable security analytics prototype for exploring unusual workforce activity.**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B?logo=streamlit&logoColor=white)
![Status](https://img.shields.io/badge/Status-Portfolio%20Prototype-blue)
![Data](https://img.shields.io/badge/Dataset-Synthetic-lightgrey)

</div>

---

## Overview

Sentinel is a small, reproducible portfolio project that demonstrates how security activity records can be transformed into an explainable review queue. It includes a Streamlit dashboard, a transparent rule-based risk engine, synthetic demonstration data, an optional unsupervised anomaly-detection baseline, and unit tests.

> **Important:** This is a learning/demo project. The included data is synthetic. Risk scores are heuristic indicators—not probabilities, proof of malicious intent, or a validated production security control.

## Features

- **Interactive dashboard** with event and user summaries.
- **Explainable risk scoring** with a list of indicators behind every score.
- **Risk bands**: Low, Medium, High, and Critical.
- **Review queue** with filters and CSV export.
- **Synthetic dataset generator** for repeatable demos.
- **Optional Isolation Forest baseline** for unsupervised anomaly exploration.
- **Input validation and unit tests** for the rule engine.

## Preview

Run the app locally to view the dashboard. Add a screenshot of the running app to `docs/dashboard.png` and embed it here when available:

```md
![Sentinel dashboard](docs/dashboard.png)
```

## Architecture

```text
insider-threat-detection-sys/
├── app.py                     # Streamlit dashboard
├── risk_engine.py             # Validation, scoring, explanations
├── train_model.py             # Optional Isolation Forest baseline
├── data/
│   ├── generate_sample_data.py
│   └── sample_activity.csv     # Synthetic demo data
├── model/                     # Locally generated model artifacts
├── tests/
│   └── test_risk_engine.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Quick start

### 1. Clone and enter the repository

```bash
git clone https://github.com/<your-username>/insider-threat-detection-sys.git
cd insider-threat-detection-sys
```

### 2. Create a virtual environment

**Windows (PowerShell):**
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies and launch

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Streamlit prints a local URL, usually `http://localhost:8501`.

## Regenerate the demo data

```bash
python data/generate_sample_data.py
```

The generator uses a fixed random seed by default, making the sample data reproducible.

## Train the optional anomaly baseline

```bash
python train_model.py
```

The script saves `model/isolation_forest.joblib`. This model is an experimental unsupervised baseline and is **not used by the current dashboard**. The primary dashboard score comes from the rule-based engine so each alert has human-readable reasons.

## Run tests

```bash
pytest -q
```

## Input CSV schema

For an uploaded CSV, provide these columns:

| Column | Type | Description |
|---|---|---|
| `timestamp` | datetime | Event timestamp |
| `user_id` | string | Pseudonymous employee identifier |
| `department` | string | Department or business unit |
| `event_type` | string | For example `login`, `file_access`, `mass_download`, `bulk_export` |
| `device_trust` | string | `trusted`, `unknown`, or `untrusted` |
| `after_hours` | boolean | Whether activity occurred outside normal hours |
| `data_volume_mb` | number | Data volume associated with the event, in MB |
| `failed_logins` | integer | Failed login count associated with the event |

## Risk scoring logic

The rule engine adds weighted indicators and caps the result at 100:

| Indicator | Points |
|---|---:|
| Bulk download/export | +35 |
| File activity | +10 |
| Untrusted/unknown device | +20 |
| After-hours activity | +15 |
| Data volume ≥ 500 MB | +25 |
| Data volume ≥ 100 MB | +12 instead |
| 5+ failed logins | +15 |
| 2–4 failed logins | +7 instead |

Bands: **Low** (0–39), **Medium** (40–69), **High** (70–84), **Critical** (85–100).

These are illustrative engineering assumptions, not industry-standard thresholds. The score is not calibrated as a probability.

## Responsible use and limitations

Insider-threat monitoring can affect privacy, employment, and civil liberties. Before any real-world use:

- Obtain legal, privacy, HR, and security approval for the intended purpose.
- Minimize collected data and use pseudonymous identifiers where practical.
- Restrict access, encrypt data, define retention periods, and audit access to alerts.
- Validate the approach against representative, authorized data and measure false positives.
- Evaluate disparate impact and document thresholds and limitations.
- Require qualified human review and corroborating evidence before any action.
- Never use this prototype to automatically discipline, rank, or terminate employees.

## Roadmap

- [ ] Add a documented, authorized real dataset and provenance.
- [ ] Add time-window baselines per user and role.
- [ ] Add model evaluation with precision/recall where labels exist.
- [ ] Add structured logging, configuration, and CI checks.
- [ ] Add a screenshot/GIF of the dashboard to the repository.

## Tech stack

Python · Pandas · NumPy · Streamlit · Plotly · scikit-learn · pytest

## License

Choose a license before public release. If you want others to reuse and modify the project, the MIT License is a common permissive option; make sure you understand its terms before adding it.
