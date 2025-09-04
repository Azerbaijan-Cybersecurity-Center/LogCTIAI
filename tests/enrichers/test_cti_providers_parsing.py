import types

import pytest

from src.enrichers.cti_providers import (
    fetch_abuseipdb,
    fetch_talos,
    fetch_virustotal,
)


class _Resp:
    def __init__(self, text: str = "", status: int = 200, json_data=None):
        self.text = text
        self.status_code = status
        self._json = json_data or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")

    def json(self):
        return self._json


class _Client:
    def __init__(self, *, text: str = "", status: int = 200, json_data=None, **_: object):
        self._resp = _Resp(text=text, status=status, json_data=json_data)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url: str):  # noqa: ARG002 - exercised by provider code
        return self._resp


def test_fetch_abuseipdb_parses_html(monkeypatch):
    html = """
    <html><body>
      <div>Abuse Confidence Score: 90</div>
      <div>Total Reports: 123</div>
      <div>Country: United States</div>
    </body></html>
    """

    # Patch httpx.Client to our stub
    import httpx  # type: ignore

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: _Client(text=html))

    res = fetch_abuseipdb("1.2.3.4")
    assert res.ip == "1.2.3.4"
    assert res.abuse_confidence_score == 90
    assert res.total_reports == 123
    assert res.country == "United States"
    assert "abuseipdb" in res.url


def test_fetch_talos_parses_html(monkeypatch):
    html = """
    <html><body>
      <div>Web Reputation: Malicious</div>
      <div>Owner: Example ISP, Inc.</div>
    </body></html>
    """
    import httpx  # type: ignore

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: _Client(text=html))

    res = fetch_talos("5.6.7.8")
    assert res.ip == "5.6.7.8"
    assert res.reputation == "Malicious"
    assert res.owner == "Example ISP, Inc."
    assert "talos" in res.url


def test_fetch_virustotal_parses_json(monkeypatch):
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 2, "suspicious": 3}
            }
        }
    }

    import httpx  # type: ignore

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: _Client(json_data=payload))

    res = fetch_virustotal("9.9.9.9", api_key="dummy")
    assert res.ip == "9.9.9.9"
    assert res.malicious == 2
    assert res.suspicious == 3
    assert "virustotal" in res.url

