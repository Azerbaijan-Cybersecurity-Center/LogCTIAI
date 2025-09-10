from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from .ratelimit import RateLimitConfig, RateLimiter


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
    ):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.timeout = timeout
        self.ratelimiter = RateLimiter(rate or RateLimitConfig(per_second=1.0, burst=1))
        self.session = requests.Session()

    def enabled(self) -> bool:
        return bool(self.api_key)

    def fetch(self, ip: str) -> Optional[AbuseIPDBResult]:
        if not self.enabled():
            return None
        params = {"ipAddress": ip, "maxAgeInDays": 365}
        headers = {"Key": self.api_key, "Accept": "application/json"}
        for attempt in range(4):
            try:
                self.ratelimiter.acquire()
                resp = self.session.get(self.BASE, params=params, headers=headers, timeout=self.timeout)
                if resp.status_code == 200:
                    return self._parse(resp.json(), ip)
                if resp.status_code in (429, 500, 502, 503):
                    retry_after = resp.headers.get("Retry-After")
                    sleep_s = float(retry_after) if retry_after and retry_after.isdigit() else 2 ** attempt
                    time.sleep(sleep_s)
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

