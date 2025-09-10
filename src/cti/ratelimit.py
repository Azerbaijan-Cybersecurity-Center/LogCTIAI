from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class RateLimitConfig:
    per_second: float = 1.0  # requests per second
    burst: int = 1           # initial burst tokens


class RateLimiter:
    """Simple token-bucket rate limiter (thread-safe)."""

    def __init__(self, cfg: RateLimitConfig) -> None:
        self.cfg = cfg
        self.tokens = float(cfg.burst)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.last = now
            self.tokens = min(
                self.cfg.burst, self.tokens + elapsed * self.cfg.per_second
            )
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            # Need to wait
            need = 1.0 - self.tokens
            delay = need / max(self.cfg.per_second, 1e-9)
        time.sleep(delay)
        # Recurse once after sleep to consume
        self.acquire()

