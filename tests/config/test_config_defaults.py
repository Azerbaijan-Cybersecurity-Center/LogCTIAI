from src.config import get_settings


def test_get_settings_defaults_no_env(monkeypatch):
    # Ensure no env vars
    monkeypatch.delenv("GROQ_API_KEYS", raising=False)
    monkeypatch.delenv("GROQ_MODEL", raising=False)
    s = get_settings()
    assert isinstance(s.groq_api_keys, list)
    assert s.groq_model

