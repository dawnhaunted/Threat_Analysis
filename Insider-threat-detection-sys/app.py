from pathlib import Path
import pandas as pd
import streamlit as st
import plotly.express as px

from risk_engine import add_risk_assessment, risk_band

st.set_page_config(page_title="Sentinel | Insider Threat Monitor", page_icon="🛡️", layout="wide")

ROOT = Path(__file__).resolve().parent
DEFAULT_DATA = ROOT / "data" / "sample_activity.csv"

st.markdown("""
<style>
    .block-container {padding-top: 1.6rem; padding-bottom: 2rem;}
    [data-testid="stMetric"] {background: #111827; border: 1px solid #253247; padding: 16px; border-radius: 12px;}
    div[data-testid="stMetricLabel"] {color: #9ca3af;}
    .hero {padding: 1.2rem 1.4rem; border-radius: 14px; background: linear-gradient(120deg,#111827,#172554); border: 1px solid #263449; margin-bottom: 1rem;}
    .muted {color: #9ca3af;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="hero"><h1>🛡️ Sentinel</h1><p class="muted">Insider Threat Detection & Risk Prioritization</p><p>Explore synthetic workforce activity, identify unusual behavior patterns, and prioritize events for human review.</p></div>', unsafe_allow_html=True)

@st.cache_data
def load_data(file_bytes=None):
    if file_bytes:
        from io import BytesIO
        return pd.read_csv(BytesIO(file_bytes))
    return pd.read_csv(DEFAULT_DATA)

with st.sidebar:
    st.header("Controls")
    uploaded = st.file_uploader("Upload activity CSV", type=["csv"], help="Use the schema documented in README.md.")
    st.caption("The bundled dataset is synthetic and contains no real employee data.")
    st.divider()
    threshold = st.slider("High-risk threshold", 0, 100, 70, 5)
    band_filter = st.multiselect("Risk bands", ["Low", "Medium", "High", "Critical"], default=["Medium", "High", "Critical"])

try:
    raw = load_data(uploaded.getvalue() if uploaded else None)
    assessed = add_risk_assessment(raw)
except Exception as exc:
    st.error(f"Could not load or assess the dataset: {exc}")
    st.info("Check that the CSV contains the required columns listed in the README.")
    st.stop()

required_display = ["timestamp", "user_id", "department", "event_type", "device_trust", "after_hours", "data_volume_mb", "failed_logins", "risk_score", "risk_band", "risk_reasons"]
missing = [c for c in required_display if c not in assessed.columns]
if missing:
    st.error(f"Missing required fields after assessment: {', '.join(missing)}")
    st.stop()

filtered = assessed[assessed["risk_band"].isin(band_filter)].copy()
filtered = filtered[filtered["risk_score"] >= threshold] if threshold > 0 else filtered

total_events = len(assessed)
high_risk = int((assessed["risk_score"] >= 70).sum())
critical = int((assessed["risk_band"] == "Critical").sum())
unique_users = int(assessed["user_id"].nunique())

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analyzed", f"{total_events:,}")
c2.metric("High-risk events", f"{high_risk:,}", help="Risk score ≥ 70; rule-based, not a probability.")
c3.metric("Critical events", f"{critical:,}")
c4.metric("Unique users", f"{unique_users:,}")

left, right = st.columns([1.25, 1])
with left:
    st.subheader("Risk distribution")
    counts = assessed["risk_band"].value_counts().reindex(["Low", "Medium", "High", "Critical"], fill_value=0).rename_axis("Risk band").reset_index(name="Events")
    fig = px.bar(counts, x="Risk band", y="Events", color="Risk band",
                 color_discrete_map={"Low":"#16a34a","Medium":"#eab308","High":"#f97316","Critical":"#dc2626"})
    fig.update_layout(template="plotly_dark", showlegend=False, margin=dict(l=10,r=10,t=20,b=10), height=320)
    st.plotly_chart(fig, use_container_width=True)
with right:
    st.subheader("Events by department")
    dept = assessed.groupby("department", as_index=False).agg(events=("user_id","size"), mean_risk=("risk_score","mean"))
    fig2 = px.bar(dept, x="department", y="events", color="mean_risk", color_continuous_scale="OrRd",
                  labels={"department":"Department","events":"Events","mean_risk":"Mean risk score"})
    fig2.update_layout(template="plotly_dark", margin=dict(l=10,r=10,t=20,b=10), height=320)
    st.plotly_chart(fig2, use_container_width=True)

st.subheader("Activity review queue")
st.caption("Scores are transparent heuristics intended to prioritize review—not proof of malicious intent.")
show_cols = ["timestamp", "user_id", "department", "event_type", "risk_score", "risk_band", "risk_reasons"]
table = filtered.sort_values("risk_score", ascending=False)[show_cols].copy()
table["risk_reasons"] = table["risk_reasons"].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)
st.dataframe(table, use_container_width=True, hide_index=True, height=360)

csv = filtered.to_csv(index=False).encode("utf-8")
st.download_button("Download filtered review queue (CSV)", csv, "sentinel_review_queue.csv", "text/csv")

st.subheader("User-level overview")
user_summary = assessed.groupby(["user_id", "department"], as_index=False).agg(
    events=("risk_score", "size"), max_risk=("risk_score", "max"), avg_risk=("risk_score", "mean"),
    after_hours_events=("after_hours", "sum")
).sort_values(["max_risk", "events"], ascending=False)
st.dataframe(user_summary, use_container_width=True, hide_index=True)

with st.expander("Methodology & responsible use"):
    st.markdown("""
    - Risk scores are generated by an explainable, configurable rule engine.
    - All included activity records are synthetic demonstration data.
    - A high score is an alert for contextual review, not a conclusion about a person.
    - Production use requires lawful authorization, data minimization, access controls, retention limits,
      documented validation, bias assessment, and a human investigation process.
    - Do not use this prototype to automatically discipline, rank, or terminate employees.
    """)
st.caption("Sentinel • Portfolio prototype • Privacy-aware security analytics")
