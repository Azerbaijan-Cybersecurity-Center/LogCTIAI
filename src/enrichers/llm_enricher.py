from __future__ import annotations

import json
from typing import Dict, List, Iterable, Tuple, Optional
from datetime import datetime
from ..parsers.ua_analysis import detect_suspicious_user_agent
from ..config import get_settings

from ..groq_client import GroqRotatingClient


SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. Given a log record, "
    "classify severity (low, medium, high), extract any indicators of compromise (IPs, URLs), "
    "and provide a one-sentence rationale. Return strict JSON with keys: severity, iocs (list), rationale."
)


def enrich_log_records(
    records: List[Dict[str, object]],
    use_llm: bool = True,
    *,
    llm_sample: Optional[int] = None,
    group_by: Optional[List[str]] = None,
    group_window_sec: Optional[int] = None,
    llm_gate_min_4xx: Optional[int] = None,
    llm_gate_ua: bool = False,
) -> List[Dict[str, object]]:
    """Enrich records using LLM with optional grouping and sampling to reduce requests.

    - When ``use_llm`` is False, returns pass-through annotations.
    - If ``group_by`` is provided, records are grouped by the tuple of those fields and a single
      representative from each group is sent to the LLM; the response is propagated to the group.
    - If ``llm_sample`` is provided, only that many groups are sent to the LLM and the rest are
      annotated with defaults (severity=unknown, rationale="LLM sampled out").
    """
    if not use_llm:
        return [
            {**r, "severity": "unknown", "iocs": [r.get("ip")] if r.get("ip") else [], "rationale": "LLM disabled"}
            for r in records
        ]

    # Helper to build group key
    def _parse_time_bucket(rec: Dict[str, object]) -> Optional[int]:
        if not group_window_sec:
            return None
        raw = str(rec.get("time") or rec.get("timestamp") or "").strip()
        if not raw:
            return None
        # Try common formats
        for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
            try:
                dt = datetime.strptime(raw, fmt)
                return int(dt.timestamp()) // int(group_window_sec)
            except Exception:
                continue
        return None

    def _key(rec: Dict[str, object]) -> Tuple[object, ...]:
        if not group_by:
            return (id(rec),)  # unique per record so it behaves like "no grouping"
        bucket = _parse_time_bucket(rec)
        base = tuple(rec.get(k) for k in group_by)
        return base + ((bucket,) if bucket is not None else tuple())

    # Build groups: key -> list of indices
    groups: Dict[Tuple[object, ...], List[int]] = {}
    per_group_stats: Dict[Tuple[object, ...], Dict[str, int | bool]] = {}
    for idx, rec in enumerate(records):
        k = _key(rec)
        groups.setdefault(k, []).append(idx)
        # accumulate stats
        st = per_group_stats.setdefault(k, {"count": 0, "errors_4xx": 0, "ua_susp": False})
        st["count"] = int(st["count"]) + 1
        try:
            status = int(rec.get("status", 0))
        except Exception:
            status = 0
        if 400 <= status < 500:
            st["errors_4xx"] = int(st["errors_4xx"]) + 1
        ua_str = str(rec.get("ua") or rec.get("user_agent") or "")
        if ua_str:
            settings = get_settings()
            susp, _ = detect_suspicious_user_agent(ua_str, patterns=settings.suspicious_ua_patterns or None)
            st["ua_susp"] = bool(st["ua_susp"]) or susp

    # Select which groups to actually send to LLM
    group_keys: List[Tuple[object, ...]] = list(groups.keys())
    # Prefer larger groups first to maximize coverage
    group_keys.sort(key=lambda k: len(groups[k]), reverse=True)
    # Apply gating if requested
    if llm_gate_min_4xx is not None or llm_gate_ua:
        gated: List[Tuple[object, ...]] = []
        for k in group_keys:
            stats = per_group_stats.get(k, {})
            ok = True
            if llm_gate_min_4xx is not None:
                ok = ok and int(stats.get("errors_4xx", 0)) >= int(llm_gate_min_4xx)
            if llm_gate_ua:
                ok = ok and bool(stats.get("ua_susp", False))
            if ok:
                gated.append(k)
        group_keys = gated
    if llm_sample is not None and llm_sample >= 0:
        group_keys = group_keys[:llm_sample]

    client = GroqRotatingClient()
    # Map group key -> parsed enrichment
    parsed_by_group: Dict[Tuple[object, ...], Dict[str, object]] = {}

    # Enrich selected groups
    for k in group_keys:
        rep_index = groups[k][0]
        r = records[rep_index]
        user = f"Log: {json.dumps(r, ensure_ascii=False)}"
        try:
            content = client.chat([
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user},
            ])
        except Exception as e:  # budget/rate/network
            parsed_by_group[k] = {"severity": "unknown", "iocs": [], "rationale": f"LLM unavailable: {str(e)[:120]}"}
            continue
        try:
            parsed = json.loads(content)
        except Exception:
            parsed = {"severity": "unknown", "iocs": [], "rationale": content[:200]}
        parsed_by_group[k] = parsed

    enriched: List[Dict[str, object]] = []
    for idx, r in enumerate(records):
        k = _key(r)
        parsed = parsed_by_group.get(k)
        if parsed is None:
            reason = "LLM sampled out"
            # If gating was applied, clarify
            if llm_gate_min_4xx is not None or llm_gate_ua:
                reason = "LLM gated out"
            parsed = {"severity": "unknown", "iocs": [r.get("ip")] if r.get("ip") else [], "rationale": reason}
        enriched.append({**r, **parsed})
    return enriched
