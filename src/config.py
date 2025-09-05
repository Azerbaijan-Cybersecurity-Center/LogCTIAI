from __future__ import annotations

import os
import random
from dataclasses import dataclass
from typing import List, Optional

from dotenv import load_dotenv


@dataclass
class Settings:
    groq_api_keys: List[str]
    groq_model: str
    risk_4xx_threshold: int
    suspicious_ua_patterns: List[str]
    virustotal_api_key: Optional[str]
    otx_api_key: Optional[str]
    greynoise_api_key: Optional[str]
    ipinfo_token: Optional[str]
    offline_ip_blocklist: Optional[str]


def get_settings() -> Settings:
    load_dotenv(override=False)
    keys_raw = os.getenv("GROQ_API_KEYS", "").strip()
    keys: List[str] = [k.strip() for k in keys_raw.split(",") if k.strip()]
    # Shuffle order to distribute load if multiple keys are provided
    random.shuffle(keys)
    model = os.getenv("GROQ_MODEL", "llama3-8b-8192")
    # Risk/UA configuration
    try:
        risk_4xx_threshold = int(os.getenv("RISK_4XX_THRESHOLD", "5"))
    except ValueError:
        risk_4xx_threshold = 5
    ua_raw = os.getenv("SUSPICIOUS_UA_REGEX", "").strip()
    ua_patterns: List[str] = [p.strip() for p in ua_raw.split(",") if p.strip()]
    vt_key = os.getenv("VT_API_KEY") or None
    otx_key = os.getenv("OTX_API_KEY") or None
    gn_key = os.getenv("GREYNOISE_API_KEY") or None
    ipinfo = os.getenv("IPINFO_TOKEN") or None
    offline_blocklist = os.getenv("OFFLINE_IP_BLOCKLIST") or None
    return Settings(
        groq_api_keys=keys,
        groq_model=model,
        risk_4xx_threshold=risk_4xx_threshold,
        suspicious_ua_patterns=ua_patterns,
        virustotal_api_key=vt_key,
        otx_api_key=otx_key,
        greynoise_api_key=gn_key,
        ipinfo_token=ipinfo,
        offline_ip_blocklist=offline_blocklist,
    )
