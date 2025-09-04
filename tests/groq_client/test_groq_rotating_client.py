from types import SimpleNamespace

import pytest

import src.groq_client as gc


class FakeCompletions:
    def __init__(self, content: str):
        self._content = content

    def create(self, model, messages, temperature):  # noqa: ARG002
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=self._content))])


class FakeChat:
    def __init__(self, content: str):
        self.completions = FakeCompletions(content)


class FakeGroq:
    def __init__(self, api_key: str):
        # Expose api_key for assertions via _next_client
        self.api_key = api_key
        self.chat = FakeChat("ok")


def test_next_client_rotates(monkeypatch):
    # Patch Groq class to our fake
    monkeypatch.setattr(gc, "Groq", FakeGroq)
    client = gc.GroqRotatingClient(api_keys=["k1", "k2"], model="m")

    c1 = client._next_client()
    c2 = client._next_client()
    c3 = client._next_client()
    assert getattr(c1, "api_key", None) == "k1"
    assert getattr(c2, "api_key", None) == "k2"
    assert getattr(c3, "api_key", None) == "k1"


def test_chat_success_path(monkeypatch):
    monkeypatch.setattr(gc, "Groq", FakeGroq)
    client = gc.GroqRotatingClient(api_keys=["kX"], model="m")
    out = client.chat([
        {"role": "system", "content": "s"},
        {"role": "user", "content": "u"},
    ])
    assert out == "ok"

