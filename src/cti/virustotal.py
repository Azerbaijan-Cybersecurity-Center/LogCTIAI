from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from .ratelimit import RateLimitConfig, RateLimiter

@dataclass
class VTResult:
    ip: str
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    last_analysis_date: Optional[int]
    asn: Optional[int]
    as_owner: Optional[str]
    country: Optional[str]
    link: Optional[str]

    @property
    def is_malicious(self) -> bool:
        return self.malicious > 0


class VirusTotalClient:
    """Minimal VirusTotal v3 client for IP lookups with simple backoff.

    Reads API key from env var VT_API_KEY.
    """

    BASE = "https://www.virustotal.com/api/v3/ip_addresses/"

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 15.0,
        rate: Optional[RateLimitConfig] = None,
    ):
        self.api_key = api_key or os.getenv("VT_API_KEY")
        self.timeout = timeout
        self.ratelimiter = RateLimiter(rate or RateLimitConfig(per_second=1.0, burst=1))
        self.session = requests.Session()

    def enabled(self) -> bool:
        return bool(self.api_key)

    def fetch(self, ip: str) -> Optional[VTResult]:
        if not self.enabled():
            return None
        url = self.BASE + ip
        headers = {"x-apikey": self.api_key}
        for attempt in range(4):
            try:
                self.ratelimiter.acquire()
                resp = self.session.get(url, headers=headers, timeout=self.timeout)
                if resp.status_code == 200:
                    return self._parse(resp.json(), ip)
                if resp.status_code == 404:
                    return VTResult(
                        ip=ip,
                        malicious=0,
                        suspicious=0,
                        harmless=0,
                        undetected=0,
                        last_analysis_date=None,
                        asn=None,
                        as_owner=None,
                        country=None,
                        link=None,
                    )
                if resp.status_code in (429, 500, 502, 503):
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after:
                        try:
                            sleep_s = float(retry_after)
                        except ValueError:
                            sleep_s = 2 ** attempt
                    else:
                        sleep_s = 2 ** attempt
                    time.sleep(sleep_s)
                    continue
                # Other errors: try to parse message for context
                try:
                    err = resp.json()
                except json.JSONDecodeError:
                    err = {"error": resp.text}
                raise RuntimeError(f"VT error {resp.status_code}: {err}")
            except requests.RequestException as e:
                if attempt == 3:
                    raise
                time.sleep(2 ** attempt)
        return None

    @staticmethod
    def _parse(data: Dict[str, Any], ip: str) -> VTResult:
        d = data.get("data", {})
        attrs = d.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return VTResult(
            ip=ip,
            malicious=int(stats.get("malicious", 0) or 0),
            suspicious=int(stats.get("suspicious", 0) or 0),
            harmless=int(stats.get("harmless", 0) or 0),
            undetected=int(stats.get("undetected", 0) or 0),
            last_analysis_date=attrs.get("last_analysis_date"),
            asn=attrs.get("asn"),
            as_owner=attrs.get("as_owner"),
            country=attrs.get("country"),
            link=d.get("links", {}).get("self"),
        )
