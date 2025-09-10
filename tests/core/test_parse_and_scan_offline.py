from pathlib import Path

from src.core.scanner import ScanOptions, parse_ips, scan_ips_list


def test_parse_ips_filters_invalid():
    ips = parse_ips(["8.8.8.8", "not-an-ip", "1.1.1.1", "#comment", " "])
    assert ips == ["8.8.8.8", "1.1.1.1"]


def test_scan_offline_counts(tmp_path: Path):
    ips = ["8.8.8.8", "1.1.1.1", "8.8.8.8"]
    opts = ScanOptions(cti_max=-1, no_cti=True)
    results, summary, errors = scan_ips_list(ips, opts)
    assert summary["total"] == 2
    assert summary["malicious"] == 0
    assert summary["suspicious"] == 0
    assert isinstance(errors, list)

