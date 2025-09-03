from pathlib import Path

from src.cli import summarize_and_cti, process_log


def test_summarize_and_cti_offline():
    # Two IPs, one with many 4xx and suspicious UA
    records = [
        {"ip": "1.1.1.1", "status": 200, "ua": "Mozilla/5.0"},
        {"ip": "1.1.1.1", "status": 404, "ua": "sqlmap/1.7"},
        {"ip": "1.1.1.1", "status": 404, "ua": "sqlmap/1.7"},
        {"ip": "2.2.2.2", "status": 200, "ua": "curl/8.0"},
        {"ip": "1.1.1.1", "status": 404, "ua": "sqlmap/1.7"},
        {"ip": "1.1.1.1", "status": 404, "ua": "sqlmap/1.7"},
        {"ip": "1.1.1.1", "status": 404, "ua": "sqlmap/1.7"},
    ]
    overall, suspicious, insight = summarize_and_cti(records, use_llm=False, with_cti=False)
    assert overall["total_requests"] == len(records)
    assert overall["unique_ips"] == 2
    # At least 1 suspicious row (due to 4xx>=5 and UA)
    assert any(r["ip"] == "1.1.1.1" and r["ua_suspicious"] for r in suspicious)
    assert insight is None


def test_process_log_offline(tmp_path: Path):
    log = tmp_path / "access_log.txt"
    log.write_text(
        '\n'.join([
            '10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /a HTTP/1.1" 200 123 "-" "Mozilla/5.0"',
            '10.0.0.1 - - [10/Oct/2000:13:55:40 -0700] "GET /b HTTP/1.1" 404 0 "-" "sqlmap/1.7"',
        ]),
        encoding="utf-8",
    )
    out = process_log(log, tmp_path, use_llm=False, limit=None, out_format="jsonl", with_cti=False, build_reports=True)
    assert out.exists()
    # Reports directory exists
    assert (tmp_path / "reports" / "report.txt").exists()
    assert (tmp_path / "reports" / "report.md").exists()

