from __future__ import annotations

import re
from typing import List, Tuple, Optional


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


def detect_suspicious_user_agent(ua: Optional[str], patterns: Optional[List[str]] = None) -> Tuple[bool, Optional[str]]:
    if not ua:
        return False, None
    ua_l = ua.lower()
    pats = patterns if patterns else SUSPICIOUS_AGENTS
    for pat in pats:
        if re.search(pat, ua_l):
            return True, pat
    return False, None
