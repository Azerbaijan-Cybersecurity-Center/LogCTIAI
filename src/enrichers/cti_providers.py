from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class AbuseIPDBResult:
    ip: str
    abuse_confidence_score: Optional[int]
    total_reports: Optional[int]
    country: Optional[str]
    url: str


@dataclass
class TalosResult:
    ip: str
    reputation: Optional[str]
    owner: Optional[str]
    url: str


@dataclass
class VirusTotalResult:
    ip: str
    malicious: Optional[int]
    suspicious: Optional[int]
    url: str


def fetch_abuseipdb(ip: str, timeout: float = 15.0) -> AbuseIPDBResult:
    # Lazy imports to keep tests independent of optional deps
    try:
        import httpx  # type: ignore
    except Exception:  # pragma: no cover - env specific
        httpx = None  # type: ignore
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception:  # pragma: no cover - env specific
        BeautifulSoup = None  # type: ignore

    url = f"https://www.abuseipdb.com/check/{ip}"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    # If dependencies are unavailable, return empty info gracefully
    if httpx is None or BeautifulSoup is None:  # pragma: no cover - env specific
        return AbuseIPDBResult(ip=ip, abuse_confidence_score=None, total_reports=None, country=None, url=url)

    try:
        with httpx.Client(headers=headers, follow_redirects=True, timeout=timeout) as client:
            resp = client.get(url)
            resp.raise_for_status()
            html = resp.text
    except Exception:  # pragma: no cover - network specific
        return AbuseIPDBResult(ip=ip, abuse_confidence_score=None, total_reports=None, country=None, url=url)

    soup = BeautifulSoup(html, "html.parser")

    def _extract_text(patterns):
        txt = soup.get_text(" ", strip=True)
        for pat in patterns:
            m = re.search(pat, txt, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    # Try to find values using robust text search as the DOM may change.
    score_txt = _extract_text([
        r"Abuse Confidence Score\s*:?\s*(\d{1,3})",
        r"Confidence of Abuse\s*:?\s*(\d{1,3})",
    ])
    total_reports_txt = _extract_text([
        r"Total Reports\s*:?\s*(\d+)",
        r"Reports\s*:?\s*(\d+)",
    ])
    country_txt = _extract_text([
        r"Country\s*:?\s*([A-Za-z\s]+)",
        r"Geolocation\s*:?\s*([A-Za-z\s]+)",
    ])

    score = int(score_txt) if score_txt and score_txt.isdigit() else None
    total_reports = int(total_reports_txt) if total_reports_txt and total_reports_txt.isdigit() else None
    country = country_txt.strip() if country_txt else None

    return AbuseIPDBResult(
        ip=ip,
        abuse_confidence_score=score,
        total_reports=total_reports,
        country=country,
        url=url,
    )


def fetch_talos(ip: str, timeout: float = 15.0) -> TalosResult:
    try:
        import httpx  # type: ignore
    except Exception:  # pragma: no cover
        httpx = None  # type: ignore
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception:  # pragma: no cover
        BeautifulSoup = None  # type: ignore

    url = f"https://talosintelligence.com/reputation_center/lookup?search={ip}"
    if httpx is None or BeautifulSoup is None:  # pragma: no cover
        return TalosResult(ip=ip, reputation=None, owner=None, url=url)
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout) as client:
            resp = client.get(url)
            resp.raise_for_status()
            html = resp.text
    except Exception:  # pragma: no cover
        return TalosResult(ip=ip, reputation=None, owner=None, url=url)
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)
    rep = None
    owner = None
    # Heuristic patterns
    m = re.search(r"Web Reputation\s*:?\s*([A-Za-z]+)", text, re.IGNORECASE)
    if m:
        rep = m.group(1).strip()
    m = re.search(r"Owner\s*:?\s*([\w\s\-\.,]+)", text, re.IGNORECASE)
    if m:
        owner = m.group(1).strip()
    return TalosResult(ip=ip, reputation=rep, owner=owner, url=url)


def fetch_virustotal(ip: str, api_key: Optional[str], timeout: float = 15.0) -> VirusTotalResult:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    if not api_key:  # pragma: no cover
        return VirusTotalResult(ip=ip, malicious=None, suspicious=None, url=url)
    try:
        import httpx  # type: ignore
    except Exception:  # pragma: no cover
        return VirusTotalResult(ip=ip, malicious=None, suspicious=None, url=url)
    try:
        with httpx.Client(timeout=timeout, headers={"x-apikey": api_key}) as client:
            r = client.get(url)
            if r.status_code >= 400:
                return VirusTotalResult(ip=ip, malicious=None, suspicious=None, url=url)
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal = stats.get("malicious")
            susp = stats.get("suspicious")
            return VirusTotalResult(ip=ip, malicious=mal, suspicious=susp, url=url)
    except Exception:  # pragma: no cover
        return VirusTotalResult(ip=ip, malicious=None, suspicious=None, url=url)
