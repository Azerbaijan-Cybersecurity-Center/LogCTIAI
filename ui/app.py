import json
import os
import subprocess
from pathlib import Path

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from dotenv import dotenv_values, set_key


st.set_page_config(page_title="LogCTI Dashboard", page_icon="🛡️", layout="wide")

# Header with branding and GitHub link
hdr_l, hdr_c, hdr_r = st.columns([3, 2, 2])
with hdr_l:
    st.markdown("""
    <div style='padding:6px 0;'>
      <span style='font-size:28px; font-weight:700;'>PierringShot Electronics</span>
      <span style='padding:0 10px;'>×</span>
      <span style='font-size:28px; font-weight:700;'>Azerbaijan Cybersecurity Center</span>
      <div style='color:#6c757d;'>Log + CTI Interactive Dashboard</div>
    </div>
    """, unsafe_allow_html=True)
with hdr_r:
    repo_url = "https://github.com/Azerbaijan-Cybersecurity-Center/LogCTIAI"
    if hasattr(st, "link_button"):
        st.link_button("GitHub Repo ⭐", repo_url, type="primary")
    else:  # fallback
        st.markdown(f"[![GitHub](https://img.shields.io/badge/GitHub-Repo-black?logo=github)]({repo_url})", unsafe_allow_html=True)


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


def severity_badge(row: dict) -> str:
    sev = str(row.get("severity") or row.get("risk") or "unknown").lower()
    if sev in ("high", "malicious"):
        return "🔴 High"
    if sev == "medium":
        return "🟠 Medium"
    if sev == "low":
        return "🟡 Low"
    return "⚪ Unknown"


def run_cli_stream(args: list[str], workdir: Path | None = None):
    proc = subprocess.Popen(
        args,
        cwd=str(workdir or Path.cwd()),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        universal_newlines=True,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        yield line.rstrip("\n")
    proc.wait()
    return proc.returncode


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

with st.sidebar:
    st.header("Run Pipeline")
    inp = st.text_input("Input file path", value=str(Path("data/raw/access_log.txt").resolve()))
    out_dir = st.text_input("Output dir", value=str(Path("data/processed").resolve()))
    colv1, colv2 = st.columns(2)
    with colv1:
        verbose = st.selectbox("Verbose", options=["quiet", "normal", "max"], index=2)
    with colv2:
        color = st.selectbox("Color", options=["auto", "always", "never"], index=0)
    no_llm = st.checkbox("Disable LLM", value=False)
    limit = st.number_input("Limit records", min_value=0, value=0, step=100)
    summary = st.checkbox("Print summary", value=True)
    preview = st.number_input("Preview N records", min_value=0, value=10, step=10)
    fmt = st.selectbox("Output format", options=["jsonl", "csv"], index=0)
    st.divider()
    st.caption("LLM controls")
    llm_sample = st.number_input("LLM sample groups (0=all)", min_value=0, value=200)
    llm_group_by = st.selectbox("Group by", options=["ip", "signature", "none"], index=0)
    group_window = st.number_input("Group window (sec)", min_value=0, value=0)
    gate_4xx = st.number_input("LLM gate 4xx >=", min_value=0, value=0)
    gate_ua = st.checkbox("LLM gate suspicious UA", value=False)
    st.divider()
    st.caption("CTI controls")
    cti_scope = st.selectbox("CTI scope", options=["suspicious", "all"], index=0)
    cti_max = st.number_input("CTI max lookups (0=unlimited)", min_value=0, value=100)
    cti_batch_size = st.number_input("CTI batch size (0=off)", min_value=0, value=0)
    cti_batch_pause = st.number_input("CTI batch pause (sec)", min_value=0.0, value=0.0, step=0.1)
    ai_mal = st.checkbox("AI malicious report", value=False)
    run_btn = st.button("Run ▶", type="primary", use_container_width=True)

    st.header("Edit .env")
    env_path = Path(".env")
    current_env = dotenv_values(env_path) if env_path.exists() else {}
    groq_keys = st.text_area("GROQ_API_KEYS (comma-separated)", value=current_env.get("GROQ_API_KEYS", ""))
    groq_model = st.text_input("GROQ_MODEL", value=current_env.get("GROQ_MODEL", "llama3-8b-8192"))
    risk_4xx = st.text_input("RISK_4XX_THRESHOLD", value=current_env.get("RISK_4XX_THRESHOLD", "5"))
    ua_regex = st.text_input("SUSPICIOUS_UA_REGEX", value=current_env.get("SUSPICIOUS_UA_REGEX", ""))
    vt_key = st.text_input("VT_API_KEY", value=current_env.get("VT_API_KEY", ""))
    otx_key = st.text_input("OTX_API_KEY", value=current_env.get("OTX_API_KEY", ""))
    gn_key = st.text_input("GREYNOISE_API_KEY", value=current_env.get("GREYNOISE_API_KEY", ""))
    ipinfo = st.text_input("IPINFO_TOKEN", value=current_env.get("IPINFO_TOKEN", ""))
    off_block = st.text_input("OFFLINE_IP_BLOCKLIST", value=current_env.get("OFFLINE_IP_BLOCKLIST", ""))
    if st.button("Save .env", use_container_width=True):
        env_path.touch(exist_ok=True)
        set_key(str(env_path), "GROQ_API_KEYS", groq_keys)
        set_key(str(env_path), "GROQ_MODEL", groq_model)
        set_key(str(env_path), "RISK_4XX_THRESHOLD", risk_4xx)
        set_key(str(env_path), "SUSPICIOUS_UA_REGEX", ua_regex)
        set_key(str(env_path), "VT_API_KEY", vt_key)
        set_key(str(env_path), "OTX_API_KEY", otx_key)
        set_key(str(env_path), "GREYNOISE_API_KEY", gn_key)
        set_key(str(env_path), "IPINFO_TOKEN", ipinfo)
        set_key(str(env_path), "OFFLINE_IP_BLOCKLIST", off_block)
        st.success(".env saved ✔")

if run_btn:
    st.session_state["_tail_pos"] = 0  # reset tail to show fresh lines
    cmd = [
        "python", "-m", "src.cli", inp,
        "--out", out_dir,
        "--verbose", verbose,
        "--color", color,
        "--format", fmt,
        "--llm-group-by", llm_group_by,
    ]
    if no_llm:
        cmd.append("--no-llm")
    if summary:
        cmd.append("--summary")
    if preview and int(preview) > 0:
        cmd.extend(["--preview", str(int(preview))])
    if limit and int(limit) > 0:
        cmd.extend(["--limit", str(int(limit))])
    if int(llm_sample) >= 0:
        cmd.extend(["--llm-sample", str(int(llm_sample))])
    if int(group_window) > 0:
        cmd.extend(["--group-window", str(int(group_window))])
    if int(gate_4xx) > 0:
        cmd.extend(["--llm-gate-4xx", str(int(gate_4xx))])
    if gate_ua:
        cmd.append("--llm-gate-ua")
    cmd.extend(["--cti-scope", cti_scope])
    if int(cti_max) >= 0:
        cmd.extend(["--cti-max", str(int(cti_max))])
    if int(cti_batch_size) > 0:
        cmd.extend(["--cti-batch-size", str(int(cti_batch_size))])
    if float(cti_batch_pause) > 0:
        cmd.extend(["--cti-batch-pause", str(float(cti_batch_pause))])
    if ai_mal:
        cmd.append("--ai-malicious-report")

    st.info("Running pipeline... logs will stream below.")
    log_box = st.empty()
    log_lines = []
    for ln in run_cli_stream(cmd):
        log_lines.append(ln)
        # Keep only last few hundred lines for performance
        log_box.code("\n".join(log_lines[-400:]), language="bash")
    st.success("Pipeline finished. Refresh the table if needed.")

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

# Latest enriched events with colored severity badges
st.subheader("Latest enriched events (tail)")
df_display = df.copy()
df_display["severity_badge"] = [severity_badge(row) for row in df_display.to_dict(orient="records")]
cols = [c for c in ["ip", "severity_badge", "status", "path", "ua", "rationale"] if c in df_display.columns]
st.dataframe(df_display[cols].tail(200), use_container_width=True)

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
