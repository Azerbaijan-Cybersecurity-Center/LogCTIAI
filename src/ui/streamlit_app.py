from __future__ import annotations

import io
import os
from pathlib import Path
from typing import List

import pandas as pd
import streamlit as st

from src.core.scanner import ScanOptions, parse_ips, scan_ips_enrich
from src.report.pdf_report import PDFReport


def country_flag(code: str | None) -> str:
    if not code:
        return ""
    code = code.upper()
    if len(code) != 2 or not code.isalpha():
        return code
    # Regional indicator symbols start at 0x1F1E6 for 'A'
    try:
        return chr(0x1F1E6 + ord(code[0]) - ord('A')) + chr(0x1F1E6 + ord(code[1]) - ord('A'))
    except Exception:
        return code


st.set_page_config(page_title="LogCTIAI – IP Scanner", layout="wide")
st.title("🔎 IP Scanner – CTI Enriched Report")
st.write("Upload IP list, enrich with VirusTotal, and download a PDF report.")

with st.sidebar:
    st.header("Settings")
    vt_key = st.text_input("VirusTotal API Key", type="password", help="Used only for this session")
    abip_key = st.text_input("AbuseIPDB API Key", type="password", help="Optional; improves detection")
    include_susp = st.checkbox("Include suspicious in report", value=False)
    cti_max_all = st.checkbox("Scan all IPs (no cap)", value=False)
    cti_max = -1 if cti_max_all else st.slider("CTI max lookups", min_value=10, max_value=1000, value=200, step=10)
    use_cache = st.checkbox("Use cache", value=True)
    no_cti = st.checkbox("Disable CTI (offline)", value=False)
    out_dir = st.text_input("Output directory", value="data/processed")

uploaded = st.file_uploader("Upload .txt with one IP per line", type=["txt"]) 
text_ips = st.text_area("…or paste IPs (one per line)")

def gather_ips() -> List[str]:
    lines: List[str] = []
    if uploaded is not None:
        content = uploaded.read().decode("utf-8", errors="ignore")
        lines.extend(content.splitlines())
    if text_ips.strip():
        lines.extend(text_ips.splitlines())
    return parse_ips(lines)


col_run, col_info = st.columns([1, 3])
with col_run:
    run = st.button("Run Scan", type="primary")
with col_info:
    st.info("Tip: Cache avoids repeated VT queries. Use 'Scan all' carefully due to rate limits.")

if run:
    ips = gather_ips()
    if not ips:
        st.warning("No valid IPs provided.")
        st.stop()

    if vt_key:
        os.environ["VT_API_KEY"] = vt_key
    if abip_key:
        os.environ["ABUSEIPDB_API_KEY"] = abip_key

    opts = ScanOptions(cti_max=cti_max, use_cache=use_cache, no_cti=no_cti)

    progress = st.progress(0)
    status = st.empty()

    def on_prog(i: int, t: int) -> None:
        progress.progress(min(1.0, i / max(1, t)))
        status.write(f"Scanning {i}/{t}")

    rows, summary, errors = scan_ips_enrich(ips, opts, on_progress=on_prog)

    st.success(f"Scanned {summary['total']} IPs • Malicious: {summary['malicious']} • Suspicious: {summary['suspicious']}")
    if errors:
        with st.expander("Show errors"):
            st.write("\n".join(errors))

    # Filter rows
    rows = [r for r in rows if r["classification"] in ("malicious", "suspicious" if include_susp else "malicious")]

    if rows:
        df = pd.DataFrame([{**r, "flag": country_flag(r.get("country"))} for r in rows])
        agg = pd.DataFrame(
            {
                "class": ["malicious", "suspicious", "harmless"],
                "count": [summary["malicious"], summary["suspicious"], summary["harmless"]],
            }
        )

        a, b = st.columns([1, 2])
        with a:
            st.subheader("Summary")
            st.metric("IPs", summary["total"])
            st.metric("Malicious", summary["malicious"])
            st.metric("Suspicious", summary["suspicious"])
        with b:
            st.subheader("Distribution")
            st.bar_chart(agg.set_index("class"))

        st.subheader("Findings")
        st.dataframe(df[["flag", "ip", "classification", "country", "malicious", "suspicious", "harmless", "as_owner"]], use_container_width=True)

        # Generate PDF
        pdf = PDFReport()
        blob = pdf.build(
            malicious_rows=[
                {
                    "ip": r["ip"],
                    "classification": r["classification"],
                    "country": r["country"],
                    "malicious": str(r["malicious"]),
                    "suspicious": str(r["suspicious"]),
                    "harmless": str(r["harmless"]),
                    "as_owner": r["as_owner"],
                }
                for r in rows
            ],
            summary=summary,
        )

        st.download_button("Download PDF report", data=blob, file_name="ip_threat_report.pdf", mime="application/pdf")

        # Optionally write to disk
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        with (out_path / "ip_threat_report.pdf").open("wb") as f:
            f.write(blob)
    else:
        st.info("No malicious findings. Use 'Include suspicious' to broaden the view.")
