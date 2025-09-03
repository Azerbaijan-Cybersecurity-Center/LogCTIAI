from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Iterable, Optional
from pathlib import Path
import json

from .cti_providers import fetch_abuseipdb, AbuseIPDBResult


@dataclass
class CTIRecord:
    ip: str
    source: str
    abuse_confidence_score: Optional[int] = None
    total_reports: Optional[int] = None
    country: Optional[str] = None
    url: Optional[str] = None
    risk: str = "unknown"  # low/medium/high/unknown

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
    provider: str = "abuseipdb",
    cache_path: Path | None = Path("data/cache/cti_cache.json"),
    force_refresh: bool = False,
) -> Dict[str, CTIRecord]:
    results: Dict[str, CTIRecord] = {}
    unique_ips = list(dict.fromkeys(i for i in ips if i))
    cache: Dict[str, Dict[str, object]] = {}
    if cache_path:
        cache = _load_cache(cache_path)
    if provider == "abuseipdb":
        for ip in unique_ips:
            if not force_refresh and ip in cache:
                cached = cache[ip]
                rec = CTIRecord(
                    ip=ip,
                    source="abuseipdb",
                    abuse_confidence_score=cached.get("abuse_confidence_score"),
                    total_reports=cached.get("total_reports"),
                    country=cached.get("country"),
                    url=cached.get("url"),
                )
            else:
                r: AbuseIPDBResult = fetch_abuseipdb(ip)
                rec = CTIRecord(
                    ip=ip,
                    source="abuseipdb",
                    abuse_confidence_score=r.abuse_confidence_score,
                    total_reports=r.total_reports,
                    country=r.country,
                    url=r.url,
                )
                if cache_path:
                    cache[ip] = {
                        "abuse_confidence_score": rec.abuse_confidence_score,
                        "total_reports": rec.total_reports,
                        "country": rec.country,
                        "url": rec.url,
                    }
            rec = CTIRecord(
                ip=rec.ip,
                source=rec.source,
                abuse_confidence_score=rec.abuse_confidence_score,
                total_reports=rec.total_reports,
                country=rec.country,
                url=rec.url,
            )
            rec.risk = _score_to_risk(rec.abuse_confidence_score, rec.total_reports)
            results[ip] = rec
        if cache_path:
            _save_cache(cache_path, cache)
    else:
        raise ValueError(f"Unsupported CTI provider: {provider}")
    return results
