from __future__ import annotations

import json
from typing import Dict, List

from ..groq_client import GroqRotatingClient


SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. Given a log record, "
    "classify severity (low, medium, high), extract any indicators of compromise (IPs, URLs), "
    "and provide a one-sentence rationale. Return strict JSON with keys: severity, iocs (list), rationale."
)


def enrich_log_records(records: List[Dict[str, object]], use_llm: bool = True) -> List[Dict[str, object]]:
    if not use_llm:
        # Pass-through with default annotations
        return [
            {**r, "severity": "unknown", "iocs": [r.get("ip")] if r.get("ip") else [], "rationale": "LLM disabled"}
            for r in records
        ]

    client = GroqRotatingClient()
    enriched: List[Dict[str, object]] = []
    for r in records:
        user = f"Log: {json.dumps(r, ensure_ascii=False)}"
        content = client.chat([
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
        ])
        try:
            parsed = json.loads(content)
        except Exception:
            parsed = {"severity": "unknown", "iocs": [], "rationale": content[:200]}
        enriched.append({**r, **parsed})
    return enriched

