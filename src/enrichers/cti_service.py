from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Iterable, Optional
from pathlib import Path
import json

from .cti_providers import (
    fetch_abuseipdb,
    AbuseIPDBResult,
    fetch_talos,
    TalosResult,
    fetch_virustotal,
    VirusTotalResult,
)


@dataclass
class CTIRecord:
    ip: str
    source: str
    abuse_confidence_score: Optional[int] = None
    total_reports: Optional[int] = None
    country: Optional[str] = None
    url: Optional[str] = None
    risk: str = "unknown"  # low/medium/high/unknown
    # Talos
    talos_reputation: Optional[str] = None
    talos_owner: Optional[str] = None
    talos_url: Optional[str] = None
    # VirusTotal
    vt_malicious: Optional[int] = None
    vt_suspicious: Optional[int] = None
    vt_url: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _score_to_risk(score: Optional[int], reports: Optional[int]) -> str:
    if score is None and reports is None:
        return "unknown"
    s = score or 0
    r = reports or 0
    if s >= 70 or r >= 100:
        return "high"
    if s >= 25 or r >= 10:
        return "medium"
    return "low"


def _merge_risk(base: str, talos_rep: Optional[str], vt_mal: Optional[int], vt_susp: Optional[int]) -> str:
    # Upgrade risk based on Talos/VirusTotal signals
    r = base
    rep = (talos_rep or "").lower()
    if rep in {"untrusted", "malicious"}:
        r = "high"
    elif rep in {"questionable"} and r == "low":
        r = "medium"
    mal = vt_mal or 0
    susp = vt_susp or 0
    if mal >= 5:
        r = "high"
    elif mal >= 1 or susp >= 3:
        if r == "low":
            r = "medium"
    return r


def _load_cache(path: Path) -> Dict[str, Dict[str, object]]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _save_cache(path: Path, data: Dict[str, Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def cti_for_ips(
    ips: Iterable[str],
    providers: Iterable[str] = ("abuseipdb", "talos", "virustotal"),
    cache_path: Path | None = Path("data/cache/cti_cache.json"),
    force_refresh: bool = False,
    virustotal_api_key: Optional[str] = None,
    *,
    batch_size: int | None = None,
    pause_seconds: float = 0.0,
    cache_flush_every: int = 10,
) -> Dict[str, CTIRecord]:
    results: Dict[str, CTIRecord] = {}
    unique_ips = list(dict.fromkeys(i for i in ips if i))
    cache: Dict[str, Dict[str, object]] = {}
    if cache_path:
        cache = _load_cache(cache_path)
    processed = 0
    for ip in unique_ips:
        cached = cache.get(ip, {}) if cache_path else {}
        # Start from cached/base
        rec = CTIRecord(
            ip=ip,
            source="multi",
            abuse_confidence_score=cached.get("abuse_confidence_score"),
            total_reports=cached.get("total_reports"),
            country=cached.get("country"),
            url=cached.get("url"),
            talos_reputation=cached.get("talos_reputation"),
            talos_owner=cached.get("talos_owner"),
            talos_url=cached.get("talos_url"),
            vt_malicious=cached.get("vt_malicious"),
            vt_suspicious=cached.get("vt_suspicious"),
            vt_url=cached.get("vt_url"),
        )
        # Fetch live if force or missing
        if force_refresh or rec.abuse_confidence_score is None and ("abuseipdb" in providers):
            a: AbuseIPDBResult = fetch_abuseipdb(ip)
            rec.abuse_confidence_score = a.abuse_confidence_score
            rec.total_reports = a.total_reports
            rec.country = a.country
            rec.url = a.url
        if force_refresh or rec.talos_reputation is None and ("talos" in providers):
            t: TalosResult = fetch_talos(ip)
            rec.talos_reputation = t.reputation
            rec.talos_owner = t.owner
            rec.talos_url = t.url
        if force_refresh or rec.vt_malicious is None and ("virustotal" in providers):
            v: VirusTotalResult = fetch_virustotal(ip, virustotal_api_key)
            rec.vt_malicious = v.malicious
            rec.vt_suspicious = v.suspicious
            rec.vt_url = v.url
        # Compute risk
        base = _score_to_risk(rec.abuse_confidence_score, rec.total_reports)
        rec.risk = _merge_risk(base, rec.talos_reputation, rec.vt_malicious, rec.vt_suspicious)
        results[ip] = rec
        if cache_path:
            cache[ip] = {
                "abuse_confidence_score": rec.abuse_confidence_score,
                "total_reports": rec.total_reports,
                "country": rec.country,
                "url": rec.url,
                "talos_reputation": rec.talos_reputation,
                "talos_owner": rec.talos_owner,
                "talos_url": rec.talos_url,
                "vt_malicious": rec.vt_malicious,
                "vt_suspicious": rec.vt_suspicious,
                "vt_url": rec.vt_url,
            }
        processed += 1
        # Optional pause and periodic cache flush for resiliency on large batches
        if cache_path and processed % max(1, cache_flush_every) == 0:
            _save_cache(cache_path, cache)
        if batch_size and (processed % batch_size == 0) and pause_seconds > 0:
            import time as _t
            _t.sleep(pause_seconds)
    if cache_path:
        _save_cache(cache_path, cache)
    return results
