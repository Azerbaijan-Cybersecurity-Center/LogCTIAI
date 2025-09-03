from pathlib import Path

from src.reports.report_builder import build_text_report, build_markdown_report


def test_build_reports(tmp_path: Path):
    suspicious = [
        {
            "ip": "1.2.3.4",
            "risk": "high",
            "abuse_confidence_score": 80,
            "total_reports": 120,
            "country": "US",
            "requests": 42,
            "errors_4xx": 5,
            "ua_suspicious": True,
            "ai_one_liner": "High risk due to multiple 4xx and CTI reports.",
        }
    ]
    overall = {"total_requests": 100, "unique_ips": 10, "ratio_404_200": 0.5}
    txt = build_text_report(tmp_path, suspicious, overall, ai_insight="Spike detected")
    md = build_markdown_report(tmp_path, suspicious, overall, ai_insight="Spike detected")
    assert txt.exists() and txt.stat().st_size > 0
    assert md.exists() and md.stat().st_size > 0

