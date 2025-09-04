import os
from pathlib import Path

from src import cli


class DummyGroq:
    def chat(self, messages):
        return "DUMMY MALICIOUS REPORT"


def test_ai_malicious_report_offline_blocklist(tmp_path, monkeypatch):
    # Prepare a log with one IP that will be escalated via offline blocklist
    log = tmp_path / "access_log.txt"
    log.write_text(
        '\n'.join([
            '10.9.9.9 - - [10/Oct/2000:13:55:36 -0700] "GET /a HTTP/1.1" 404 0 "-" "sqlmap/1.7"',
            '10.9.9.9 - - [10/Oct/2000:13:55:40 -0700] "GET /b HTTP/1.1" 404 0 "-" "sqlmap/1.7"',
        ]),
        encoding="utf-8",
    )
    # Create offline blocklist and point env var to it so risk escalates to high
    bl = tmp_path / "blocklist.txt"
    bl.write_text("10.9.9.9\n", encoding="utf-8")
    monkeypatch.setenv("OFFLINE_IP_BLOCKLIST", str(bl))
    # Ensure LLM path is taken; set a dummy key and monkeypatch client
    monkeypatch.setenv("GROQ_API_KEYS", "dummy-key")
    monkeypatch.setattr(cli, "GroqRotatingClient", lambda: DummyGroq())

    rc = cli.main([
        str(log),
        "--out", str(tmp_path),
        "--no-cti",  # avoid live CTI calls
        "--ai-malicious-report",
        "--color", "never",
    ])
    assert rc == 0
    rpt = tmp_path / "reports" / "malicious_ai_report.txt"
    assert rpt.exists()
    assert "DUMMY MALICIOUS REPORT" in rpt.read_text(encoding="utf-8")

