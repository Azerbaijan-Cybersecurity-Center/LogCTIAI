from __future__ import annotations

import re
from typing import List, Tuple


SUSPICIOUS_AGENTS = [
    r"sqlmap",
    r"nmap",
    r"hydra",
    r"nikto",
    r"zgrab",
    r"masscan",
    r"wpscan",
    r"acunetix",
    r"dirbuster",
    r"python-requests",
    r"curl/\d",
]


def detect_suspicious_user_agent(ua: str | None) -> Tuple[bool, str | None]:
    if not ua:
        return False, None
    ua_l = ua.lower()
    for pat in SUSPICIOUS_AGENTS:
        if re.search(pat, ua_l):
            return True, pat
    return False, None

