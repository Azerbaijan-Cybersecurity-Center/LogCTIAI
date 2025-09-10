from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from dotenv import load_dotenv

from src.cache.cti_cache import DEFAULT_CACHE, get_cached, load_cache, save_cache, set_cached
from src.cti import VirusTotalClient, VTResult
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
                else:
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
