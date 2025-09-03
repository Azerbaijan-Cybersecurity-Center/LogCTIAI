import json

from src.enrichers import llm_enricher as le


class DummyClient:
    def __init__(self):
        self.calls = 0

    def chat(self, messages):
        self.calls += 1
        # Return valid JSON once, then invalid to hit fallback path
        if self.calls == 1:
            return json.dumps({"severity": "low", "iocs": ["1.1.1.1"], "rationale": "Looks benign"})
        return "not-json"


def test_enrich_log_records_llm_mock(monkeypatch):
    # Monkeypatch the client class used inside module
    monkeypatch.setattr(le, "GroqRotatingClient", lambda: DummyClient())
    records = [
        {"ip": "1.1.1.1", "status": 200, "path": "/", "method": "GET", "proto": "HTTP/1.1"},
        {"ip": "2.2.2.2", "status": 404, "path": "/x", "method": "GET", "proto": "HTTP/1.1"},
    ]
    out = le.enrich_log_records(records, use_llm=True)
    assert len(out) == 2
    assert out[0]["severity"] == "low"
    assert out[1]["severity"] == "unknown"  # second call returns non-JSON

