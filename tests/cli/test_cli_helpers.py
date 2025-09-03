from src.cli import _print_summary, _preview_records


def test_cli_helpers_do_not_crash():
    records = [
        {"ip": "1.1.1.1", "status": 200, "method": "GET", "severity": "low"},
        {"ip": "2.2.2.2", "status": 404, "method": "POST", "severity": "high", "rationale": "Test"},
    ]
    # Functions should run without raising; visual output is not asserted
    _print_summary(records)
    _preview_records(records, 2)

