from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from .ratelimit import RateLimitConfig, RateLimiter
from src.net.proxy import ProxyRotator


@dataclass
class AbuseIPDBResult:
    ip: str
    abuse_confidence: int
    total_reports: int
    country_code: Optional[str]
    isp: Optional[str]
    usage_type: Optional[str]
    domain: Optional[str]
    last_reported_at: Optional[str]
    link: Optional[str]

    def is_malicious(self, threshold: int = 50) -> bool:
        try:
            return int(self.abuse_confidence) >= int(threshold)
        except Exception:
            return False


class AbuseIPDBClient:
    """Minimal AbuseIPDB v2 client for IP check.

    Reads API key from env var ABUSEIPDB_API_KEY.
    """

    BASE = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 15.0,
        rate: Optional[RateLimitConfig] = None,
        proxies: Optional[ProxyRotator] = None,
    ):
        # Support single or multiple keys via env
        env_multi = os.getenv("ABUSEIPDB_API_KEYS", "").strip()
        if env_multi:
            self.api_keys = [k.strip() for k in env_multi.split(",") if k.strip()]
        else:
            single = api_key or os.getenv("ABUSEIPDB_API_KEY")
            self.api_keys = [single] if single else []
        self._key_index = 0
        self.timeout = timeout
        self.ratelimiter = RateLimiter(rate or RateLimitConfig(per_second=1.0, burst=1))
        self.session = requests.Session()
        self.proxies = proxies or ProxyRotator.from_env()

    def enabled(self) -> bool:
        return bool(self.api_keys)

    def fetch(self, ip: str) -> Optional[AbuseIPDBResult]:
        if not self.enabled():
            return None
        params = {"ipAddress": ip, "maxAgeInDays": 365}
        # Use current key; rotate between attempts if multiple keys are configured
        for attempt in range(4):
            try:
                self.ratelimiter.acquire()
                key = self.api_keys[self._key_index % max(1, len(self.api_keys))] if self.api_keys else None
                headers = {"Key": key or "", "Accept": "application/json"}
                resp = self.session.get(
                    self.BASE,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                    proxies=(self.proxies.get() if self.proxies.enabled() else None),
                )
                if resp.status_code == 200:
                    return self._parse(resp.json(), ip)
                if resp.status_code in (429, 500, 502, 503):
                    retry_after = resp.headers.get("Retry-After")
                    sleep_s = float(retry_after) if retry_after and retry_after.isdigit() else 2 ** attempt
                    time.sleep(sleep_s)
                    # If multiple keys are configured, rotate to distribute load
                    if len(self.api_keys) > 1 and resp.status_code == 429:
                        self._key_index = (self._key_index + 1) % len(self.api_keys)
                    continue
                if resp.status_code == 403:
                    # Forbidden (possibly IP-level). Rotate proxy if configured; if multiple keys, rotate key as well.
                    if self.proxies.enabled():
                        self.proxies.rotate()
                    if len(self.api_keys) > 1:
                        self._key_index = (self._key_index + 1) % len(self.api_keys)
                    time.sleep(2 ** attempt)
                    continue
                try:
                    err = resp.json()
                except json.JSONDecodeError:
                    err = {"error": resp.text}
                raise RuntimeError(f"AbuseIPDB error {resp.status_code}: {err}")
            except requests.RequestException as e:
                if attempt == 3:
                    raise
                time.sleep(2 ** attempt)
        return None

    @staticmethod
    def _parse(data: Dict[str, Any], ip: str) -> AbuseIPDBResult:
        d = data.get("data", {})
        return AbuseIPDBResult(
            ip=ip,
            abuse_confidence=int(d.get("abuseConfidenceScore", 0) or 0),
            total_reports=int(d.get("totalReports", 0) or 0),
            country_code=d.get("countryCode"),
            isp=d.get("isp"),
            usage_type=d.get("usageType"),
            domain=d.get("domain"),
            last_reported_at=d.get("lastReportedAt"),
            link=f"https://www.abuseipdb.com/check/{ip}",
        )
