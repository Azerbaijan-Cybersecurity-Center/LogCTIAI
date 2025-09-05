import json
from pathlib import Path

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh


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


def tail_jsonl(path: Path, start_pos: int = 0, max_lines: int = 2000) -> tuple[list[dict], int]:
    rows: list[dict] = []
    try:
        with path.open("rb") as f:
            f.seek(start_pos)
            for i, line in enumerate(f):
                if i > max_lines:
                    break
                try:
                    rows.append(json.loads(line.decode("utf-8", errors="ignore")))
                except Exception:
                    continue
            pos = f.tell()
    except FileNotFoundError:
        return [], 0
    return rows, pos


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
    refresh_ms = st.slider("Auto-refresh (ms)", min_value=0, max_value=10000, step=500, value=2000,
                           help="Set to 0 to disable auto-refresh")
    if refresh_ms > 0:
        st_autorefresh(interval=refresh_ms, key="auto_refresh")

df = pd.DataFrame()
if uploaded is not None:
    df = pd.DataFrame([json.loads(l) for l in uploaded.getvalue().decode("utf-8").splitlines() if l.strip()])
elif selected:
    # Use tailing for scalability and near real-time updates
    file_path = base_path / selected
    if "_tail_pos" not in st.session_state or st.session_state.get("_tail_file") != str(file_path):
        st.session_state["_tail_pos"] = 0
        st.session_state["_tail_file"] = str(file_path)
    new_rows, new_pos = tail_jsonl(file_path, st.session_state["_tail_pos"], max_lines=5000)
    st.session_state["_tail_pos"] = new_pos
    df = pd.DataFrame(new_rows) if new_rows else load_jsonl(file_path)

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
st.subheader("Latest enriched events (tail)")
st.dataframe(df[present_cols].tail(200), use_container_width=True)

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
    st.dataframe(df[present_cti].dropna(how="all").tail(300), use_container_width=True)

st.caption("Tip: generate enriched JSONL via `python -m src.cli <log> --out data/processed`. The dashboard will auto-refresh.")
