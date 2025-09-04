from pathlib import Path

from src import cli


def test_cli_main_access_log(tmp_path: Path):
    log = tmp_path / "access_log.txt"
    log.write_text('127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /a HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n', encoding="utf-8")
    rc = cli.main([
        str(log),
        "--out", str(tmp_path),
        "--no-llm", "--no-cti", "--no-reports",
        "--summary", "--preview", "1",
        "--color", "never",
    ])
    assert rc == 0


def test_cli_main_txt_branch(tmp_path: Path):
    txt = tmp_path / "notes.txt"
    txt.write_text("hello", encoding="utf-8")
    rc = cli.main([str(txt), "--out", str(tmp_path), "--no-llm", "--no-cti", "--no-reports"])
    assert rc == 0


def test_cli_main_unsupported(tmp_path: Path):
    p = tmp_path / "data.bin"
    p.write_bytes(b"\x00\x01")
    rc = cli.main([str(p), "--out", str(tmp_path), "--no-llm", "--no-cti", "--no-reports"])
    assert rc == 2


def test_cli_main_txt_log_autodetect(tmp_path: Path):
    txt_log = tmp_path / "new_log.txt"
    txt_log.write_text('127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /a HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n', encoding="utf-8")
    rc = cli.main([
        str(txt_log),
        "--out", str(tmp_path),
        "--no-llm", "--no-cti", "--no-reports",
        "--color", "never",
    ])
    assert rc == 0
    # Confirm log output exists
    out_jsonl = tmp_path / "new_log.jsonl"
    assert out_jsonl.exists()
