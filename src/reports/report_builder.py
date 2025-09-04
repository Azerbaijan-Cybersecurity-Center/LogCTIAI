from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional


def _md_row(cells: List[str]) -> str:
    return "| " + " | ".join(cells) + " |\n"


def build_markdown_report(
    out_dir: Path,
    suspicious: List[Dict[str, object]],
    overall_stats: Dict[str, object],
    ai_insight: Optional[str],
    title: str = "Log Analysis + CTI Report",
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.md"
    lines: List[str] = []
    lines.append(f"# {title}\n\n")
    lines.append("## Overview\n")
    lines.append(f"- Total requests: {overall_stats.get('total_requests')}\n")
    lines.append(f"- Unique IPs: {overall_stats.get('unique_ips')}\n")
    lines.append(f"- 404/200 ratio: {overall_stats.get('ratio_404_200')}\n\n")

    if ai_insight:
        lines.append("## AI Anomaly Insight\n")
        lines.append(ai_insight.strip() + "\n\n")

    lines.append("## Suspicious IPs\n")
    if not suspicious:
        lines.append("No suspicious IPs identified.\n")
    else:
        lines.append(_md_row(["IP", "Risk", "Abuse Score", "Total Reports", "Country", "Requests", "4xx", "Suspicious UA", "Talos", "VT (mal/susp)", "One-line Explain"]))
        lines.append(_md_row(["---"] * 11))
        for s in suspicious:
            lines.append(
                _md_row([
                    str(s.get("ip", "")),
                    str(s.get("risk", "unknown")),
                    str(s.get("abuse_confidence_score", "")),
                    str(s.get("total_reports", "")),
                    str(s.get("country", "")),
                    str(s.get("requests", "")),
                    str(s.get("errors_4xx", "")),
                    "yes" if s.get("ua_suspicious") else "no",
                    str(s.get("talos_reputation", "")),
                    f"{s.get('vt_malicious','')}/{s.get('vt_suspicious','')}",
                    str(s.get("ai_one_liner", "")),
                ])
            )

    path.write_text("".join(lines), encoding="utf-8")
    return path


def build_text_report(
    out_dir: Path,
    suspicious: List[Dict[str, object]],
    overall_stats: Dict[str, object],
    ai_insight: Optional[str],
    title: str = "Log Analysis + CTI Report",
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.txt"
    lines: List[str] = []
    lines.append(f"{title}\n")
    lines.append("=" * len(title) + "\n\n")
    lines.append("Overview\n")
    lines.append(f"- Total requests: {overall_stats.get('total_requests')}\n")
    lines.append(f"- Unique IPs: {overall_stats.get('unique_ips')}\n")
    lines.append(f"- 404/200 ratio: {overall_stats.get('ratio_404_200')}\n\n")
    if ai_insight:
        lines.append("AI Anomaly Insight\n")
        lines.append(ai_insight.strip() + "\n\n")
    lines.append("Suspicious IPs\n")
    if not suspicious:
        lines.append("- None\n")
    else:
        for s in suspicious:
            lines.append(
                f"- {s.get('ip')} | risk={s.get('risk')} | score={s.get('abuse_confidence_score')} | "
                f"reports={s.get('total_reports')} | country={s.get('country')} | req={s.get('requests')} | "
                f"4xx={s.get('errors_4xx')} | UA suspicious={'yes' if s.get('ua_suspicious') else 'no'} | "
                f"talos={s.get('talos_reputation')} | vt={s.get('vt_malicious')}/{s.get('vt_suspicious')}\n"
            )
            if s.get("ai_one_liner"):
                lines.append(f"  AI: {s.get('ai_one_liner')}\n")

    path.write_text("".join(lines), encoding="utf-8")
    return path


def build_malicious_ai_report(
    out_dir: Path,
    content: str,
    *,
    title: str = "Malicious Activity AI Report",
) -> tuple[Path, Path]:
    """Write a detailed AI-written malicious activity report to txt and md.

    Returns: (txt_path, md_path)
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    txt_path = out_dir / "malicious_ai_report.txt"
    md_path = out_dir / "malicious_ai_report.md"

    # Text version
    lines_txt: List[str] = []
    lines_txt.append(f"{title}\n")
    lines_txt.append("=" * len(title) + "\n\n")
    lines_txt.append(content.strip() + "\n")
    txt_path.write_text("".join(lines_txt), encoding="utf-8")

    # Markdown version
    lines_md: List[str] = []
    lines_md.append(f"# {title}\n\n")
    lines_md.append(content.strip() + "\n")
    md_path.write_text("".join(lines_md), encoding="utf-8")

    return txt_path, md_path
