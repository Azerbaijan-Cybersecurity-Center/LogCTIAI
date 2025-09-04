import json
from pathlib import Path

import pandas as pd
import streamlit as st


st.set_page_config(page_title="LogCTI Dashboard", page_icon="🛡️", layout="wide")
st.title("Log + CTI Dashboard 🛡️")


@st.cache_data(show_spinner=False)
def load_jsonl(path: Path) -> pd.DataFrame:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return pd.DataFrame(rows)


def list_processed_files(base: Path) -> list[Path]:
    if not base.exists():
        return []
    return sorted([p for p in base.glob("*.jsonl")], key=lambda p: p.stat().st_mtime, reverse=True)


col1, col2 = st.columns([2, 1])
with col2:
    base_dir = st.text_input("Processed dir", value=str(Path("data/processed").resolve()))
    base_path = Path(base_dir)
    files = list_processed_files(base_path)
    file_names = [f.name for f in files]
    selected = st.selectbox("Enriched file", options=file_names) if files else None
    uploaded = st.file_uploader("...or upload enriched .jsonl", type=["jsonl"])  # optional

df = pd.DataFrame()
if uploaded is not None:
    df = pd.DataFrame([json.loads(l) for l in uploaded.getvalue().decode("utf-8").splitlines() if l.strip()])
elif selected:
    df = load_jsonl(base_path / selected)

if df.empty:
    st.info("Select or upload an enriched JSONL file to explore results.")
    st.stop()

# Metrics
total_requests = len(df)
unique_ips = df["ip"].nunique() if "ip" in df.columns else 0
status_counts = df["status"].astype(str).value_counts() if "status" in df.columns else pd.Series(dtype=int)

with col1:
    m1, m2, m3 = st.columns(3)
    m1.metric("Total requests", f"{total_requests}")
    m2.metric("Unique IPs", f"{unique_ips}")
    if not status_counts.empty:
        m3.metric("Top status", f"{status_counts.index[0]}: {int(status_counts.iloc[0])}")

st.subheader("Status distribution")
if not status_counts.empty:
    st.bar_chart(status_counts)
else:
    st.write("No status data available.")

# Suspicious IPs table (if present in records as enriched by pipeline)
cols = [
    "ip",
    "severity",
    "status",
    "path",
    "ua",
    "rationale",
]
present_cols = [c for c in cols if c in df.columns]
st.subheader("Sample of enriched events")
st.dataframe(df[present_cols].head(100), use_container_width=True)

# Aggregate suspicious overview from records if they contain CTI annotations
cti_cols = [
    "ip",
    "risk",
    "abuse_confidence_score",
    "total_reports",
    "country",
    "talos_reputation",
    "vt_malicious",
    "vt_suspicious",
]
present_cti = [c for c in cti_cols if c in df.columns]
if present_cti:
    st.subheader("CTI Signals (per record view)")
    st.dataframe(df[present_cti].dropna(how="all").head(200), use_container_width=True)

st.caption("Tip: generate enriched JSONL via `python -m src.cli <log> --out data/processed`.")

