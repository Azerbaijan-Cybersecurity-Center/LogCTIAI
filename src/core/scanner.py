from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from dotenv import load_dotenv

from src.cache.cti_cache import DEFAULT_CACHE, get_cached, load_cache, save_cache, set_cached
from src.cti import VirusTotalClient, VTResult, AbuseIPDBClient, AbuseIPDBResult
from src.cti.ratelimit import RateLimitConfig


ProgressCb = Optional[Callable[[int, int], None]]


@dataclass
class ScanOptions:
    cti_max: int = 200
    use_cache: bool = True
    no_cti: bool = False
    offline_blocklist: Optional[Set[str]] = None
    cti_rate_per_sec: float = 1.0
    cti_burst: int = 1
    save_every: int = 50  # persist cache every N updates
    abuseipdb: bool = True
    abuseipdb_threshold: int = 50
    abuseipdb_rate_per_sec: float = 0.8
    abuseipdb_burst: int = 1


def parse_ips(lines: Iterable[str]) -> List[str]:
    ips: List[str] = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        try:
            ipaddress.ip_address(s)
            ips.append(s)
        except ValueError:
            continue
    return list(dict.fromkeys(ips))


def scan_ips_list(
    ips: List[str],
    options: ScanOptions,
    on_progress: ProgressCb = None,
) -> Tuple[List[VTResult], Dict[str, int], List[str]]:
    """Scan IP addresses via VT, honoring caching and limits.

    Returns (results, summary, errors).
    """
    load_dotenv()

    unique_ips = list(dict.fromkeys(ips))
    cache = load_cache(DEFAULT_CACHE) if options.use_cache else {}
    offline_bad = options.offline_blocklist or set()
    vt = VirusTotalClient(rate=RateLimitConfig(per_second=options.cti_rate_per_sec, burst=options.cti_burst))
    abip = AbuseIPDBClient(rate=RateLimitConfig(per_second=options.abuseipdb_rate_per_sec, burst=options.abuseipdb_burst))

    errors: List[str] = []
    results: List[VTResult] = []

    to_query = [ip for ip in unique_ips if ip not in offline_bad]
    if not options.no_cti and options.cti_max >= 0:
        to_query = to_query[: options.cti_max]

    total = len(unique_ips)
    save_counter = 0
    for idx, ip in enumerate(unique_ips, 1):
        vt_result: Optional[VTResult] = None
        try:
            if ip in offline_bad:
                vt_result = VTResult(
                    ip=ip,
                    malicious=1,
                    suspicious=0,
                    harmless=0,
                    undetected=0,
                    last_analysis_date=None,
                    asn=None,
                    as_owner="OFFLINE_BLOCKLIST",
                    country=None,
                    link=None,
                )
            else:
                cached = get_cached(cache, f"vt:{ip}") if options.use_cache else None
                if cached is not None:
                    vt_result = VTResult(**cached)
                elif not options.no_cti and ip in to_query and vt.enabled():
                    vt_result = vt.fetch(ip)
                    if vt_result and options.use_cache:
                        set_cached(cache, f"vt:{ip}", vt_result.__dict__)
                        save_counter += 1
                        if save_counter >= max(1, options.save_every):
                            save_cache(cache, DEFAULT_CACHE)
                            save_counter = 0

            # Optionally fetch AbuseIPDB
            if options.abuseipdb and not options.no_cti and abip.enabled() and ip not in offline_bad:
                ab_cached = get_cached(cache, f"abip:{ip}") if options.use_cache else None
                if ab_cached is None:
                    ab_res = abip.fetch(ip)
                    if ab_res and options.use_cache:
                        set_cached(cache, f"abip:{ip}", ab_res.__dict__)
                        save_counter += 1
                        if save_counter >= max(1, options.save_every):
                            save_cache(cache, DEFAULT_CACHE)
                            save_counter = 0
                else:
                    # cached; do nothing (consumed later by reporters if needed)
                    pass

            # Ensure we always have a VTResult, even if no CTI performed
            if vt_result is None:
                vt_result = VTResult(
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
        except Exception as e:
            errors.append(f"{ip}: {e}")
            vt_result = VTResult(
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

        results.append(vt_result)
        if on_progress:
            try:
                on_progress(idx, total)
            except Exception:
                pass

    if options.use_cache:
        save_cache(cache, DEFAULT_CACHE)

    malicious = sum(1 for r in results if r.malicious > 0)
    suspicious = sum(1 for r in results if (r.malicious == 0 and r.suspicious > 0))
    harmless = sum(1 for r in results if (r.malicious == 0 and r.suspicious == 0 and r.harmless > 0))

    summary = {
        "total": len(results),
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "errors": len(errors),
    }
    return results, summary, errors


def scan_ips_enrich(
    ips: List[str],
    options: ScanOptions,
    on_progress: ProgressCb = None,
):
    """Scan IPs with VT and AbuseIPDB and return ready-to-report rows.

    Returns (rows, summary, errors).
    """
    results, summary, errors = scan_ips_list(ips, options, on_progress)
    cache = load_cache(DEFAULT_CACHE) if options.use_cache else {}

    rows = []
    for r in results:
        ip = r.ip
        ab: Optional[AbuseIPDBResult] = None
        ab_raw = get_cached(cache, f"abip:{ip}") if options.use_cache else None
        if ab_raw:
            try:
                ab = AbuseIPDBResult(**ab_raw)
            except Exception:
                ab = None
        is_mal = (r.malicious > 0) or (ab.is_malicious(options.abuseipdb_threshold) if ab else False)
        is_susp = (not is_mal and r.suspicious > 0)
        label = "malicious" if is_mal else ("suspicious" if is_susp else "clean")
        country = (r.country or (ab.country_code if ab else None) or "")
        owner = (r.as_owner or (ab.isp if ab else None) or "")
        rows.append(
            {
                "ip": ip,
                "classification": label,
                "country": country,
                "malicious": str(r.malicious),
                "suspicious": str(r.suspicious),
                "harmless": str(r.harmless),
                "as_owner": owner,
            }
        )
    # Recompute counts from rows for correctness
    total = len(rows)
    malicious = sum(1 for x in rows if x["classification"] == "malicious")
    suspicious = sum(1 for x in rows if x["classification"] == "suspicious")
    harmless = total - malicious - suspicious
    summary.update({"total": total, "malicious": malicious, "suspicious": suspicious, "harmless": harmless})
    return rows, summary, errors
