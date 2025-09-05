from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Dict


@dataclass
class OTXResult:
    ip: str
    pulse_count: Optional[int]
    reputation: Optional[int]
    url: str


@dataclass
class GreyNoiseResult:
    ip: str
    classification: Optional[str]  # benign|malicious|unknown
    name: Optional[str]
    url: str


@dataclass
class ThreatFoxResult:
    ip: str
    matches: Optional[int]
    url: str


@dataclass
class IPInfoResult:
    ip: str
    org: Optional[str]
    country: Optional[str]
    city: Optional[str]
    url: str


def fetch_otx(ip: str, api_key: Optional[str], timeout: float = 15.0) -> OTXResult:
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    if not api_key:
        return OTXResult(ip=ip, pulse_count=None, reputation=None, url=url)
    try:
        import httpx  # type: ignore
    except Exception:  # pragma: no cover
        return OTXResult(ip=ip, pulse_count=None, reputation=None, url=url)
    try:
        with httpx.Client(timeout=timeout, headers={"X-OTX-API-KEY": api_key}) as client:
            r = client.get(url)
            if r.status_code >= 400:
                return OTXResult(ip=ip, pulse_count=None, reputation=None, url=url)
            data = r.json()
            pulse_info = data.get("pulse_info", {})
            count = int(pulse_info.get("count") or 0)
            rep = data.get("reputation")
            try:
                rep = int(rep) if rep is not None else None
            except Exception:
                rep = None
            return OTXResult(ip=ip, pulse_count=count, reputation=rep, url=url)
    except Exception:  # pragma: no cover
        return OTXResult(ip=ip, pulse_count=None, reputation=None, url=url)


def fetch_greynoise(ip: str, api_key: Optional[str], timeout: float = 15.0) -> GreyNoiseResult:
    url = f"https://api.greynoise.io/v3/community/{ip}"
    if not api_key:
        return GreyNoiseResult(ip=ip, classification=None, name=None, url=url)
    try:
        import httpx  # type: ignore
    except Exception:  # pragma: no cover
        return GreyNoiseResult(ip=ip, classification=None, name=None, url=url)
    try:
        with httpx.Client(timeout=timeout, headers={"key": api_key}) as client:
            r = client.get(url)
            if r.status_code >= 400:
                return GreyNoiseResult(ip=ip, classification=None, name=None, url=url)
            data = r.json()
            return GreyNoiseResult(
                ip=ip,
                classification=data.get("classification"),
                name=data.get("name"),
                url=url,
            )
    except Exception:  # pragma: no cover
        return GreyNoiseResult(ip=ip, classification=None, name=None, url=url)


def fetch_threatfox(ip: str, timeout: float = 15.0) -> ThreatFoxResult:
    url = "https://threatfox-api.abuse.ch/api/v1/"
    try:
        import httpx  # type: ignore
    except Exception:  # pragma: no cover
        return ThreatFoxResult(ip=ip, matches=None, url=url)
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.post(url, json={"query": "search_ioc", "search_term": ip})
            if r.status_code >= 400:
                return ThreatFoxResult(ip=ip, matches=None, url=url)
            data = r.json()
            # Response has { query_status, data: [ ... ] }
            arr: List[Dict[str, object]] = data.get("data") or []
            return ThreatFoxResult(ip=ip, matches=len(arr) if isinstance(arr, list) else 0, url=url)
    except Exception:  # pragma: no cover
        return ThreatFoxResult(ip=ip, matches=None, url=url)


def fetch_ipinfo(ip: str, token: Optional[str], timeout: float = 10.0) -> IPInfoResult:
    url = f"https://ipinfo.io/{ip}/json"
    # IPInfo allows limited anonymous queries; token improves reliability
    try:
        import httpx  # type: ignore
    except Exception:  # pragma: no cover
        return IPInfoResult(ip=ip, org=None, country=None, city=None, url=url)
    try:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        with httpx.Client(timeout=timeout, headers=headers) as client:
            r = client.get(url)
            if r.status_code >= 400:
                return IPInfoResult(ip=ip, org=None, country=None, city=None, url=url)
            data = r.json()
            return IPInfoResult(
                ip=ip,
                org=data.get("org"),
                country=data.get("country"),
                city=data.get("city"),
                url=url,
            )
    except Exception:  # pragma: no cover
        return IPInfoResult(ip=ip, org=None, country=None, city=None, url=url)

