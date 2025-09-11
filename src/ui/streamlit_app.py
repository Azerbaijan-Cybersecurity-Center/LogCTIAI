from __future__ import annotations

import io
import os
from pathlib import Path
from typing import List

import pandas as pd
import streamlit as st

from src.core.scanner import ScanOptions, parse_ips, scan_ips_enrich
from src.report.pdf_report import PDFReport
from src.groq_client import GroqRotatingClient


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
st.write("Upload IP list, enrich with CTI, and download a clean PDF report.")

with st.sidebar:
    st.header("Settings")
    vt_key = st.text_input("VirusTotal API Key", type="password", help="Used only for this session")
    abip_key = st.text_input("AbuseIPDB API Key", type="password", help="Optional; improves detection")
    include_susp = st.checkbox("Include suspicious in report", value=False)
    use_ai = st.checkbox("AI executive summary in PDF", value=False, help="Uses GROQ keys from .env if configured")

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
    st.info("Tip: VT/AbuseIPDB keys improve accuracy. AI summary is optional.")

if run:
    ips = gather_ips()
    if not ips:
        st.warning("No valid IPs provided.")
        st.stop()

    if vt_key:
        os.environ["VT_API_KEY"] = vt_key
    if abip_key:
        os.environ["ABUSEIPDB_API_KEY"] = abip_key

    # Keep options simple and sensible by default
    opts = ScanOptions(cti_max=200, use_cache=True, no_cti=False)

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

        # Optional AI executive summary via GROQ
        ai_summary: str | None = None
        if use_ai:
            with st.spinner("Generating AI executive summary…"):
                try:
                    client = GroqRotatingClient()
                    # Keep prompt compact: provide summary and up to 20 top rows
                    sample_rows = [
                        {k: r[k] for k in ("ip", "classification", "country", "malicious", "suspicious", "harmless", "as_owner")}
                        for r in rows[:20]
                    ]
                    user = (
                        "Write a concise 80-120 word executive summary for a security PDF report. "
                        "Highlight overall risk level, notable patterns (countries/ASNs), and clear next steps.\n"
                        f"SUMMARY: {summary}\nROWS: {sample_rows}"
                    )
                    ai_summary = client.chat([
                        {"role": "system", "content": "You are a senior SOC analyst writing executive summaries for CISOs."},
                        {"role": "user", "content": user},
                    ])
                except Exception as e:
                    st.info(f"AI summary unavailable: {e}")

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
            ai_summary=ai_summary,
        )

        st.download_button("Download PDF report", data=blob, file_name="ip_threat_report.pdf", mime="application/pdf")

        # Save to default processed directory
        out_path = Path("data/processed")
        out_path.mkdir(parents=True, exist_ok=True)
        with (out_path / "ip_threat_report.pdf").open("wb") as f:
            f.write(blob)
    else:
        st.info("No malicious findings. Use 'Include suspicious' to broaden the view.")
