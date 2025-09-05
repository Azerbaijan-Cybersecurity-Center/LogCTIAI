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
from .cti_providers_ext import (
    fetch_otx,
    OTXResult,
    fetch_greynoise,
    GreyNoiseResult,
    fetch_threatfox,
    ThreatFoxResult,
    fetch_ipinfo,
    IPInfoResult,
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
    # OTX
    otx_pulse_count: Optional[int] = None
    otx_reputation: Optional[int] = None
    otx_url: Optional[str] = None
    # GreyNoise
    greynoise_classification: Optional[str] = None
    greynoise_name: Optional[str] = None
    greynoise_url: Optional[str] = None
    # ThreatFox
    threatfox_matches: Optional[int] = None
    threatfox_url: Optional[str] = None
    # IPInfo (enrichment only)
    ipinfo_org: Optional[str] = None
    ipinfo_country: Optional[str] = None
    ipinfo_city: Optional[str] = None
    ipinfo_url: Optional[str] = None

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


def _merge_risk_ext(current: str,
                    otx_pulses: Optional[int],
                    greynoise_cls: Optional[str],
                    threatfox_matches: Optional[int]) -> str:
    r = current
    if greynoise_cls and greynoise_cls.lower() == "malicious":
        r = "high"
    if (otx_pulses or 0) >= 3 and r == "low":
        r = "medium"
    if (threatfox_matches or 0) >= 1:
        r = "high"
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
    providers: Iterable[str] = ("abuseipdb", "talos", "virustotal", "otx", "greynoise", "threatfox", "ipinfo"),
    cache_path: Path | None = Path("data/cache/cti_cache.json"),
    force_refresh: bool = False,
    virustotal_api_key: Optional[str] = None,
    otx_api_key: Optional[str] = None,
    greynoise_api_key: Optional[str] = None,
    ipinfo_token: Optional[str] = None,
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
            otx_pulse_count=cached.get("otx_pulse_count"),
            otx_reputation=cached.get("otx_reputation"),
            otx_url=cached.get("otx_url"),
            greynoise_classification=cached.get("greynoise_classification"),
            greynoise_name=cached.get("greynoise_name"),
            greynoise_url=cached.get("greynoise_url"),
            threatfox_matches=cached.get("threatfox_matches"),
            threatfox_url=cached.get("threatfox_url"),
            ipinfo_org=cached.get("ipinfo_org"),
            ipinfo_country=cached.get("ipinfo_country"),
            ipinfo_city=cached.get("ipinfo_city"),
            ipinfo_url=cached.get("ipinfo_url"),
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
        if force_refresh or rec.otx_pulse_count is None and ("otx" in providers):
            o: OTXResult = fetch_otx(ip, otx_api_key)
            rec.otx_pulse_count = o.pulse_count
            rec.otx_reputation = o.reputation
            rec.otx_url = o.url
        if force_refresh or rec.greynoise_classification is None and ("greynoise" in providers):
            g: GreyNoiseResult = fetch_greynoise(ip, greynoise_api_key)
            rec.greynoise_classification = g.classification
            rec.greynoise_name = g.name
            rec.greynoise_url = g.url
        if force_refresh or rec.threatfox_matches is None and ("threatfox" in providers):
            tf: ThreatFoxResult = fetch_threatfox(ip)
            rec.threatfox_matches = tf.matches
            rec.threatfox_url = tf.url
        if force_refresh or rec.ipinfo_org is None and ("ipinfo" in providers):
            ii: IPInfoResult = fetch_ipinfo(ip, ipinfo_token)
            rec.ipinfo_org = ii.org
            rec.ipinfo_country = ii.country
            rec.ipinfo_city = ii.city
            rec.ipinfo_url = ii.url
        # Compute risk
        base = _score_to_risk(rec.abuse_confidence_score, rec.total_reports)
        rec.risk = _merge_risk(base, rec.talos_reputation, rec.vt_malicious, rec.vt_suspicious)
        rec.risk = _merge_risk_ext(rec.risk, rec.otx_pulse_count, rec.greynoise_classification, rec.threatfox_matches)
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
                "otx_pulse_count": rec.otx_pulse_count,
                "otx_reputation": rec.otx_reputation,
                "otx_url": rec.otx_url,
                "greynoise_classification": rec.greynoise_classification,
                "greynoise_name": rec.greynoise_name,
                "greynoise_url": rec.greynoise_url,
                "threatfox_matches": rec.threatfox_matches,
                "threatfox_url": rec.threatfox_url,
                "ipinfo_org": rec.ipinfo_org,
                "ipinfo_country": rec.ipinfo_country,
                "ipinfo_city": rec.ipinfo_city,
                "ipinfo_url": rec.ipinfo_url,
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
