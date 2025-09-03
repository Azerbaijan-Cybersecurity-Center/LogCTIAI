from pathlib import Path

import pytest

from src.enrichers import cti_service as svc


class DummyAbuseResult:
    def __init__(self, ip: str, score: int | None, reports: int | None, country: str | None):
        self.ip = ip
        self.abuse_confidence_score = score
        self.total_reports = reports
        self.country = country
        self.url = f"https://www.abuseipdb.com/check/{ip}"


def test_cti_risk_mapping_and_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Monkeypatch provider to avoid network
    calls: list[str] = []

    def fake_fetch(ip: str):
        calls.append(ip)
        if ip == "1.2.3.4":
            return DummyAbuseResult(ip, score=80, reports=150, country="US")
        if ip == "5.6.7.8":
            return DummyAbuseResult(ip, score=30, reports=12, country="DE")
        return DummyAbuseResult(ip, score=None, reports=None, country=None)

    # Patch the name used inside cti_service
    monkeypatch.setattr("src.enrichers.cti_service.fetch_abuseipdb", fake_fetch)

    cache_path = tmp_path / "cti.json"
    out = svc.cti_for_ips(["1.2.3.4", "5.6.7.8"], cache_path=cache_path)

    assert out["1.2.3.4"].risk == "high"
    assert out["5.6.7.8"].risk == "medium"

    # Second run should use cache; provider not called again
    calls.clear()
    out2 = svc.cti_for_ips(["1.2.3.4", "5.6.7.8"], cache_path=cache_path)
    assert calls == []
    assert out2["1.2.3.4"].abuse_confidence_score == 80
