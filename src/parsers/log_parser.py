from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, Iterator, Optional
import json


# Basic combined log format (common for nginx/apache). Adjust if needed.
LOG_PATTERN = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^\"]+)\" (?P<status>\d{3}) (?P<size>\S+)( \"(?P<ref>[^\"]*)\" \"(?P<ua>[^\"]*)\")?"
)


@dataclass
class LogRecord:
    ip: str
    time: str
    method: str
    path: str
    proto: str
    status: int
    size: Optional[int]
    ref: Optional[str] = None
    ua: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def parse_line(line: str) -> Optional[LogRecord]:
    s = line.strip()
    # Try JSON payload fallback (e.g., timestamp\tiso\t{json})
    try:
        json_start = s.find("{")
        if json_start != -1:
            obj = json.loads(s[json_start:])
            if not (
                ("method" in obj) and ("status" in obj) and ("uri" in obj or "path" in obj)
            ):
                return None
            return LogRecord(
                ip=str(obj.get("remote_addr", "")),
                time=str(obj.get("timestamp", "")),
                method=str(obj.get("method", "")),
                path=str(obj.get("uri", obj.get("path", ""))),
                proto=str(obj.get("proto", obj.get("ssl_protocol", ""))),
                status=int(obj.get("status", 0)),
                size=None,
                ref=str(obj.get("referrer", "")) or None,
                ua=str(obj.get("user_agent", "")) or None,
            )
    except Exception:
        pass

    # Fallback: Combined log format regex
    m = LOG_PATTERN.match(s)
    if not m:
        return None
    gd = m.groupdict()
    size_str = gd.get("size")
    size = int(size_str) if size_str and size_str.isdigit() else None
    return LogRecord(
        ip=gd.get("ip", ""),
        time=gd.get("time", ""),
        method=gd.get("method", ""),
        path=gd.get("path", ""),
        proto=gd.get("proto", ""),
        status=int(gd.get("status", "0")),
        size=size,
        ref=gd.get("ref"),
        ua=gd.get("ua"),
    )


def parse_lines(lines: Iterable[str]) -> Iterator[LogRecord]:
    for line in lines:
        rec = parse_line(line)
        if rec:
            yield rec
