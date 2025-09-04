from __future__ import annotations

import random
import time
from typing import Dict, List, Optional
import os

from groq import Groq
from rich.console import Console

from .config import get_settings


console = Console()


class GroqRotatingClient:
    def __init__(self, api_keys: Optional[List[str]] = None, model: Optional[str] = None):
        settings = get_settings()
        self.keys = api_keys if api_keys is not None else settings.groq_api_keys
        self.model = model or settings.groq_model
        self._clients = [Groq(api_key=k) for k in self.keys]
        self._index = 0
        # Simple token budget guard (approximate tokens via chars/4)
        try:
            self._budget = int(os.getenv("GROQ_TOKENS_BUDGET", "0")) or None
        except ValueError:
            self._budget = None
        self._used = 0

    def _next_client(self) -> Groq:
        if not self._clients:
            raise RuntimeError("No GROQ_API_KEYS configured. Add keys to .env or pass explicitly.")
        client = self._clients[self._index % len(self._clients)]
        self._index = (self._index + 1) % len(self._clients)
        return client

    def chat(self, messages: List[Dict[str, str]],
             model: Optional[str] = None,
             max_retries: int = 5,
             base_delay: float = 1.0) -> str:
        """Send a chat completion request with polite rotation and backoff.

        - Rotates keys between attempts
        - Exponential backoff with jitter for 429/5xx
        """
        last_error: Optional[Exception] = None
        m = model or self.model
        # pre-check budget
        if self._budget is not None:
            approx_tokens = sum(len(m.get("content", "")) for m in messages) // 4 + 32
            if self._used + approx_tokens > self._budget:
                raise RuntimeError("LLM budget exhausted; set GROQ_TOKENS_BUDGET higher or reduce --llm-sample")
        for attempt in range(max_retries):
            client = self._next_client()
            try:
                resp = client.chat.completions.create(
                    model=m,
                    messages=messages,
                    temperature=0.2,
                )
                # book tokens used (approx)
                if self._budget is not None:
                    approx_tokens = sum(len(m.get("content", "")) for m in messages) // 4 + 32
                    self._used += approx_tokens
                return resp.choices[0].message.content or ""
            except Exception as e:  # pragma: no cover - network specific
                last_error = e
                # Backoff for transient errors, otherwise raise immediately
                msg = str(e)
                if any(code in msg for code in ["429", "5", "Rate limit", "rate"]):
                    delay = base_delay * (2 ** attempt) * (1 + random.random() * 0.25)
                    console.log(f"Transient error: {e}. Retrying in {delay:.2f}s...")
                    time.sleep(delay)
                    continue
                raise
        raise RuntimeError(f"Groq chat failed after {max_retries} attempts: {last_error}")
