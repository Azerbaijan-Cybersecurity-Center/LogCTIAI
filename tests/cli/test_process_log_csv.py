from pathlib import Path

from src.cli import process_log


def test_process_log_csv_output(tmp_path: Path):
    log = tmp_path / "access_log.txt"
    log.write_text('127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /a HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n', encoding="utf-8")
    out = process_log(log, tmp_path, use_llm=False, limit=None, out_format="csv", with_cti=False, build_reports=False)
    assert out.suffix == ".csv" and out.exists()

