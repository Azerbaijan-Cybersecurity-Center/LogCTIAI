from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional


def _normalize_proxy_url(s: str) -> Optional[str]:
    s = s.strip()
    if not s:
        return None
    if "://" not in s:
        # Default to http if scheme omitted
        s = f"http://{s}"
    return s


@dataclass
class ProxyConfig:
    urls: List[str]

    @classmethod
    def from_env(cls) -> "ProxyConfig":
        raw = os.getenv("PROXY_LIST", "").strip()
        urls = []
        if raw:
            for part in raw.split(","):
                url = _normalize_proxy_url(part)
                if url:
                    urls.append(url)
        # Fallback to traditional env if set (single proxy)
        if not urls:
            http = os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
            https = os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")
            if http or https:
                # Use https if provided, else http
                url = _normalize_proxy_url(https or http)
                if url:
                    urls = [url]
        return cls(urls=urls)


class ProxyRotator:
    """Thread-safe rotator for outbound proxies for requests.

    Note: Proxies are for network resiliency. They must not be used to
    bypass provider Terms or rate limits attached to your API keys.
    """

    def __init__(self, cfg: Optional[ProxyConfig] = None) -> None:
        self.cfg = cfg or ProxyConfig.from_env()
        self._i = 0
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls) -> "ProxyRotator":
        return cls(ProxyConfig.from_env())

    def enabled(self) -> bool:
        return bool(self.cfg.urls)

    def _current_url(self) -> Optional[str]:
        if not self.cfg.urls:
            return None
        return self.cfg.urls[self._i % len(self.cfg.urls)]

    def rotate(self) -> None:
        with self._lock:
            if self.cfg.urls:
                self._i = (self._i + 1) % len(self.cfg.urls)

    def get(self) -> Optional[Dict[str, str]]:
        """Return a requests-compatible proxies mapping for the current proxy.

        Example: {"http": "http://host:port", "https": "http://host:port"}
        """
        with self._lock:
            url = self._current_url()
        if not url:
            return None
        return {"http": url, "https": url}

